//go:build e2e

// Package gws drives Google Workspace domain-wide delegation end to end: an agent
// presenting a user, Warden federating its own assertion at a fake Google STS,
// having the fake IAM Credentials API sign the delegation assertion, trading it at
// a fake OAuth2 token endpoint, and the user's token reaching a stand-in for the
// Workspace APIs through the gws provider.
//
// The fakes answer as the real services did in a hand run against a Workspace
// tenant: a user Google does not know is a 400 invalid_grant, a scope the Admin
// console did not authorize a 401 unauthorized_client.
//
// The gws provider reaches the stand-in through gws_url, which the e2e build
// allows (provider/gws/hosts_e2e.go); the stand-in receives each request's whole
// path, host segment first.
package gws

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const (
	userAuthMount = "gws-user-jwt"
	sourceName    = "e2e-gws-dwd"
	specName      = "e2e-gws-user"
	unauthSpec    = "e2e-gws-unauthorized-scope"
	agentRole     = "e2e-gws-agent"
	unauthRole    = "e2e-gws-unauthorized"
	gcpRole       = "e2e-gws-on-gcp"
	policyName    = "e2e-gws-access"
	gwsMount      = "gws-e2e"
	gcpMount      = "gcp-gws-e2e"

	delegatingAccount = "dwd@e2e-project.iam.gserviceaccount.com"
	wifProvider       = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/e2e/providers/gws"
	domain            = "gws.e2e.test"

	// The fake STS's federated token: signJwt refuses any other bearer, so a
	// signature proves the federation leg ran first.
	federatedToken = "e2e-federated-token"

	// The upload session the stand-in opens, on Google's own host as Drive's is.
	uploadSession = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=e2e-session"
)

// Users, each a Hydra client whose client_id is the address (e2e/setup.sh).
const (
	alice = "alice@gws.e2e.test"
	bob   = "bob@gws.e2e.test"
	ghost = "ghost@gws.e2e.test" // in the domain, unknown to the fake Google
	eve   = "eve@other.e2e.test" // outside the domain
)

// apiCall is one request the Workspace stand-in received.
type apiCall struct {
	Method, Path, Query, Bearer string
}

var (
	envOnce    sync.Once
	leaderPort int

	// agentJWT is the agent's token for every request. It is fetched once: the
	// credential cache is keyed by the agent's token as well as the user's, so a
	// fresh agent token per request would make every request a cache miss.
	agentJWT string

	google    *httptest.Server // STS, IAM Credentials and the OAuth2 token endpoint
	workspace *httptest.Server // the Workspace APIs, by host segment
	issued    atomic.Int64

	mu          sync.Mutex
	stsSubjects []map[string]any // claims of each subject token STS was shown
	signedSets  []map[string]any // claims signJwt was asked to sign
	trades      []map[string]any // claims of each assertion traded for a token
	apiCalls    []apiCall
)

func TestMain(m *testing.M) {
	code := m.Run()
	if leaderPort != 0 {
		teardownBestEffort(leaderPort)
	}
	if google != nil {
		google.Close()
	}
	if workspace != nil {
		workspace.Close()
	}
	os.Exit(code)
}

// payloadClaims decodes a JWT's claims without verifying it; nil if it is not one.
func payloadClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil
	}
	return claims
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// startGoogle stands in for STS, the IAM Credentials signJwt API and Google's
// OAuth2 token endpoint, recording what each was asked.
func startGoogle() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		stsSubjects = append(stsSubjects, payloadClaims(r.PostForm.Get("subject_token")))
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": federatedToken, "token_type": "Bearer", "expires_in": 3600})
	})

	mux.HandleFunc("/v1/projects/-/serviceAccounts/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":signJwt") {
			http.Error(w, "unexpected call "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+federatedToken {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
				"code": 403, "status": "PERMISSION_DENIED", "message": "Permission 'iam.serviceAccounts.signJwt' denied"}})
			return
		}
		var req struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var claims map[string]any
		_ = json.Unmarshal([]byte(req.Payload), &claims)
		mu.Lock()
		signedSets = append(signedSets, claims)
		mu.Unlock()
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"e2e","typ":"JWT"}`))
		body := base64.RawURLEncoding.EncodeToString([]byte(req.Payload))
		writeJSON(w, http.StatusOK, map[string]any{"keyId": "e2e", "signedJwt": header + "." + body + ".e2e-signature"})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
			return
		}
		claims := payloadClaims(r.PostForm.Get("assertion"))
		mu.Lock()
		trades = append(trades, claims)
		mu.Unlock()
		sub, _ := claims["sub"].(string)
		scope, _ := claims["scope"].(string)
		switch {
		case sub == ghost:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "Invalid email or User ID"})
		case strings.Contains(scope, "drive.readonly"):
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized_client",
				"error_description": "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."})
		default:
			n := issued.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": fmt.Sprintf("ya29.e2e.%s.%d", sub, n), "token_type": "Bearer", "expires_in": 3599})
		}
	})

	return httptest.NewServer(mux)
}

// startWorkspace stands in for the Workspace APIs. Gmail's profile names the user
// the token acts as; a resumable Drive upload opens a session on Google's own host,
// as Drive does, and takes the content at it.
func startWorkspace() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		mu.Lock()
		apiCalls = append(apiCalls, apiCall{r.Method, r.URL.Path, r.URL.RawQuery, bearer})
		mu.Unlock()

		switch {
		case r.URL.Path == "/gmail.googleapis.com/gmail/v1/users/me/profile":
			// ya29.e2e.<address>.<n>
			parts := strings.Split(strings.TrimPrefix(bearer, "Bearer ya29.e2e."), ".")
			addr := strings.Join(parts[:len(parts)-1], ".")
			writeJSON(w, http.StatusOK, map[string]any{"emailAddress": addr})
		case r.URL.Path == "/www.googleapis.com/upload/drive/v3/files" && r.Method == http.MethodPost &&
			r.URL.Query().Get("uploadType") == "resumable":
			w.Header().Set("Location", uploadSession)
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/www.googleapis.com/upload/drive/v3/files" && r.Method == http.MethodPut &&
			r.URL.Query().Get("upload_id") == "e2e-session":
			writeJSON(w, http.StatusOK, map[string]any{"id": "e2e-file", "name": "e2e.bin"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
}

// resetRecordings clears what the fakes recorded, so each test counts only its
// own traffic.
func resetRecordings() {
	mu.Lock()
	defer mu.Unlock()
	stsSubjects, signedSets, trades, apiCalls = nil, nil, nil, nil
}

func recorded() (sts, signed, traded []map[string]any, calls []apiCall) {
	mu.Lock()
	defer mu.Unlock()
	return append([]map[string]any(nil), stsSubjects...), append([]map[string]any(nil), signedSets...),
		append([]map[string]any(nil), trades...), append([]apiCall(nil), apiCalls...)
}

// ensureEnv builds the shared environment once for the package.
func ensureEnv(t *testing.T) {
	t.Helper()
	envOnce.Do(func() {
		leaderPort = h.GetLeaderPort(t)
		agentJWT = h.GetDefaultJWT(t)
		google = startGoogle()
		workspace = startWorkspace()
		setup(t, leaderPort)
	})
	if google == nil || workspace == nil {
		t.Fatal("the gws e2e environment is not available")
	}
}

func mustAPI(t *testing.T, port int, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, port, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

func setup(t *testing.T, port int) {
	t.Helper()
	teardownBestEffort(port)

	// The user leg: Hydra-issued tokens on a mount that admits humans only and
	// publishes the address — the client_id, for these clients — as the email fact.
	mustAPI(t, port, "POST", "sys/auth/"+userAuthMount, `{"type":"jwt"}`, "mount the user auth method")
	time.Sleep(time.Second)
	mustAPI(t, port, "PUT", "auth/"+userAuthMount+"/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q,"bound_audiences":[%q],"user_claim":"sub","entity_kind":"human","facts":{"client_id":"email"}}`,
			h.HydraIssuer, h.HydraIssuer, h.HydraAudience),
		"configure the user auth method")

	// The keyless source sends all three of its calls to the fake Google.
	mustAPI(t, port, "POST", "sys/cred/sources/"+sourceName, fmt.Sprintf(`{
		"type":"gcp","config":{
			"auth_method":"oidc_federation","workload_identity_provider":%q,
			"sts_endpoint":%q,"iamcredentials_endpoint":%q,"oauth_token_endpoint":%q}}`,
		wifProvider, google.URL, google.URL, google.URL+"/token"),
		"create the keyless gcp source")

	spec := func(name, scopes string) string {
		return fmt.Sprintf(`{
			"type":"gcp_delegated_token","source":%q,"config":{
				"mint_method":"delegated_access_token",
				"subject_token_source":"warden_identity","assertion_user_claims":"email",
				"delegated_user_claim":"email","delegated_user_domains":%q,
				"target_service_account":%q,"scopes":%q}}`, sourceName, domain, delegatingAccount, scopes)
	}
	mustAPI(t, port, "POST", "sys/cred/specs/"+specName,
		spec(specName, "https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/drive.file"),
		"create the delegated spec")
	mustAPI(t, port, "POST", "sys/cred/specs/"+unauthSpec,
		spec(unauthSpec, "https://www.googleapis.com/auth/drive.readonly"),
		"create the spec asking for a scope the Admin console did not authorize")

	mustAPI(t, port, "POST", "sys/policies/cbp/"+policyName, fmt.Sprintf(`{"policy":"%s"}`, strings.Join([]string{
		fmt.Sprintf(`path \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\"]\n}`, gwsMount),
		fmt.Sprintf(`path \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\"]\n}`, gcpMount),
	}, `\n`)), "create the policy")
	h.GrantRole(t, port, "auth/jwt/", agentRole, h.Role{Policies: []string{policyName}, CredSpec: specName}, nil)
	h.GrantRole(t, port, "auth/jwt/", unauthRole, h.Role{Policies: []string{policyName}, CredSpec: unauthSpec}, nil)
	h.GrantRole(t, port, "auth/jwt/", gcpRole, h.Role{Policies: []string{policyName}, CredSpec: specName}, nil)

	userLeg := fmt.Sprintf(`"auto_auth_path":"auth/jwt/","user_auth_path":"auth/%s/"`, userAuthMount)
	mustAPI(t, port, "POST", "sys/providers/"+gwsMount, `{"type":"gws","description":"Google Workspace (local stand-in)"}`, "mount gws")
	mustAPI(t, port, "POST", "sys/providers/"+gcpMount, `{"type":"gcp","description":"GCP"}`, "mount gcp")
	time.Sleep(time.Second)
	mustAPI(t, port, "PUT", gwsMount+"/config",
		fmt.Sprintf(`{"gws_url":%q,"tls_skip_verify":true,"timeout":"30s",%s}`, workspace.URL, userLeg),
		"configure gws")
	mustAPI(t, port, "PUT", gcpMount+"/config", fmt.Sprintf(`{"timeout":"30s",%s}`, userLeg), "configure gcp")

	// Upload sessions are rewritten onto Warden's external base, the
	// protected-resource resource_url.
	h.EnableProtectedResourceMetadata(t, port)
}

func teardownBestEffort(port int) {
	token := rootTokenBestEffort()
	if token == "" {
		return
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed e2e cert
	}
	del := func(path string) {
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/%s", h.NodeURL(port), path), nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Warden-Token", token)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	for _, mount := range []string{gwsMount, gcpMount} {
		del("sys/providers/" + mount)
	}
	for _, role := range []string{agentRole, unauthRole, gcpRole} {
		h.RevokeRoleBestEffort(port, "auth/jwt/", role)
	}
	del("sys/policies/cbp/" + policyName)
	del("sys/cred/specs/" + specName)
	del("sys/cred/specs/" + unauthSpec)
	del("sys/cred/sources/" + sourceName)
	del("sys/auth/" + userAuthMount)
}

func rootTokenBestEffort() string {
	b, err := os.ReadFile(filepath.Join(h.E2EDir(), ".root_token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// userToken is a fresh token for the user whose Hydra client is addr: a new
// token is a new cache key, so each test starts from a mint.
func userToken(t *testing.T, addr string) string {
	t.Helper()
	return h.GetJWT(t, addr, "gws-user-secret")
}

// gatewayCall calls a mount's gateway under role, with the agent's JWT out of band
// and the user's token in Authorization.
func gatewayCall(t *testing.T, role, method, mount, apiPath, user, body string, extra map[string]string) (int, []byte, http.Header) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s/role/%s/gateway/%s", h.NodeURL(leaderPort), mount, role, strings.TrimPrefix(apiPath, "/"))
	if _, err := url.Parse(u); err != nil {
		t.Fatalf("bad gateway URL %q: %v", u, err)
	}
	hdrs := map[string]string{"X-Warden-Agent-Token": agentJWT}
	if user != "" {
		hdrs["Authorization"] = "Bearer " + user
	}
	for k, v := range extra {
		hdrs[k] = v
	}
	status, respBody, headers := h.DoRequestWithResponseHeaders(t, method, u, hdrs, body)
	return status, respBody, http.Header(headers)
}

// googleError decodes Google's error envelope.
func googleError(t *testing.T, body []byte) (status, reason, message string) {
	t.Helper()
	var env struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Error.Errors) == 0 {
		t.Fatalf("not Google's error shape: %s", body)
	}
	return env.Error.Status, env.Error.Errors[0].Reason, env.Error.Message
}
