//go:build e2e

package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- A TokenReview API for the kubernetes auth method ---
//
// The e2e cluster runs no Kubernetes API server, and the kubernetes auth method
// verifies a workload token with one call: a TokenReview. TokenReviewer stands
// in for that one endpoint, the way the recording upstreams stand in for a
// provider's API. Everything Warden does with a review is real: the issuer
// pre-filter, the audiences it asks for and the ones it requires back, the
// reviewed username naming a service account, max_age against the token's iat,
// the facts, the cache, discovery and the warnings. What is not covered is the
// cluster's half: that a real API server signs the tokens and honours
// spec.audiences, which this stub models as the Kubernetes API documents it.
//
// It counts every review, so a test can prove how often a credential was
// admitted: one review is one admission.

// ServiceAccount is what a TokenReview reports about a token the stub issued.
type ServiceAccount struct {
	Namespace string
	Name      string
	UID       string
	Groups    []string
	// Audiences are the token's own audiences. A review asking for audiences
	// validates the intersection, and fails when it is empty; one asking for
	// none validates all of them, as an API server checks its own audience.
	Audiences []string
}

// Username is the service account's username, as TokenReview reports it.
func (sa ServiceAccount) Username() string {
	return "system:serviceaccount:" + sa.Namespace + ":" + sa.Name
}

// KubeAPIAudience is the audience an API server gives its own service account
// tokens.
const KubeAPIAudience = "https://kubernetes.default.svc"

// TokenReviewer is the stub API server.
type TokenReviewer struct {
	// URL is the base URL to configure as kubernetes_host.
	URL string
	// CACertPEM is the certificate to configure as kubernetes_ca_cert: the
	// stub serves TLS, and the mount verifies it.
	CACertPEM string

	server  *httptest.Server
	reviews atomic.Int64

	mu     sync.Mutex
	tokens map[string]ServiceAccount
}

// StartTokenReviewer starts a stub API server, closed when the test ends.
func StartTokenReviewer(t *testing.T) *TokenReviewer {
	t.Helper()
	r := &TokenReviewer{tokens: map[string]ServiceAccount{}}
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serveTokenReview))
	r.URL = r.server.URL
	r.CACertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.server.Certificate().Raw}))
	t.Cleanup(r.server.Close)
	return r
}

// Reviews returns how many TokenReviews the stub has answered, refused ones
// included.
func (r *TokenReviewer) Reviews() int64 { return r.reviews.Load() }

// Issue returns a new JWT-shaped token for sa, which the stub's reviews then
// authenticate. issuer is its iss claim; withIat false leaves the iat claim
// out, as a legacy secret-based token does.
func (r *TokenReviewer) Issue(t *testing.T, sa ServiceAccount, issuer string, withIat bool) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": issuer,
		"sub": sa.Username(),
		"aud": sa.Audiences,
		"exp": now.Add(time.Hour).Unix(),
		"jti": randomHex(t, 8),
	}
	if withIat {
		claims["iat"] = now.Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal token claims: %v", err)
	}
	enc := base64.RawURLEncoding
	token := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"e2e-stub"}`)) + "." +
		enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("e2e-stub-signature"))
	r.Register(token, sa)
	return token
}

// Register makes the stub authenticate token as sa: the API server of a
// cluster that trusts the token's issuer.
func (r *TokenReviewer) Register(token string, sa ServiceAccount) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token] = sa
}

// stubInternalDetail is what the stub puts into the body of a refused call. A
// response that repeats it to a caller leaks what the API server said.
const stubInternalDetail = "e2e-apiserver-internal-detail"

func (r *TokenReviewer) serveTokenReview(w http.ResponseWriter, req *http.Request) {
	r.reviews.Add(1)
	if req.Method != http.MethodPost || req.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
		http.Error(w, "not found: "+stubInternalDetail, http.StatusNotFound)
		return
	}

	// Self-review: the bearer is the workload token itself, which the API
	// server must authenticate before it reviews anything.
	bearer := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	r.mu.Lock()
	_, known := r.tokens[bearer]
	r.mu.Unlock()
	if !known {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"kind":"Status","status":"Failure","message":"Unauthorized: %s","code":401}`, stubInternalDetail)
		return
	}

	body, _ := io.ReadAll(req.Body)
	var review struct {
		Spec struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "bad review: "+stubInternalDetail, http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	sa, ok := r.tokens[review.Spec.Token]
	r.mu.Unlock()

	status := map[string]any{"authenticated": false}
	switch {
	case !ok:
		status["error"] = "invalid bearer token"
	default:
		audiences := sa.Audiences
		if len(review.Spec.Audiences) > 0 {
			audiences = nil
			for _, a := range review.Spec.Audiences {
				if slices.Contains(sa.Audiences, a) {
					audiences = append(audiences, a)
				}
			}
		}
		if len(audiences) == 0 {
			status["error"] = "token audiences are invalid for the target audiences"
			break
		}
		status = map[string]any{
			"authenticated": true,
			"user": map[string]any{
				"username": sa.Username(),
				"uid":      sa.UID,
				"groups":   append([]string{"system:serviceaccounts", "system:serviceaccounts:" + sa.Namespace}, sa.Groups...),
			},
			"audiences": audiences,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"status":     status,
	})
}

// LeaksStubDetail reports whether body repeats what the stub said in the body
// of a refused call.
func LeaksStubDetail(body []byte) bool {
	return strings.Contains(string(body), stubInternalDetail)
}

// EnableKubernetesAuth mounts a kubernetes auth method at mount in namespace
// (the root namespace when empty), configured against r with config merged
// over the connection settings, and disables it when the test ends.
func EnableKubernetesAuth(t *testing.T, port int, namespace, mount string, r *TokenReviewer, config map[string]any) {
	t.Helper()
	path := strings.TrimSuffix(AuthMountPath(mount), "/")
	sysPath := "sys/" + path
	nsRequest(t, port, namespace, "DELETE", sysPath, "")
	mustNS(t, port, namespace, "POST", sysPath, `{"type":"kubernetes"}`, "mount kubernetes auth at "+path)
	t.Cleanup(func() { nsRequest(t, port, namespace, "DELETE", sysPath, "") })
	cfg := map[string]any{
		"kubernetes_host":    r.URL,
		"kubernetes_ca_cert": r.CACertPEM,
	}
	for k, v := range config {
		cfg[k] = v
	}
	mustNS(t, port, namespace, "PUT", path+"/config", jsonBody(t, cfg), "configure kubernetes auth at "+path)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return hex.EncodeToString(b)
}
