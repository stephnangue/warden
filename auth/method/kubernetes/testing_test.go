package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Logger
// =============================================================================

func testLogger() *logger.GatedLogger {
	cfg := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(cfg, logger.GatedWriterConfig{Underlying: io.Discard})
	return gl
}

// =============================================================================
// Inmem storage
// =============================================================================

type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{data: make(map[string]*sdklogical.StorageEntry)}
}

func (s *inmemStorage) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}

func (s *inmemStorage) Get(_ context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(_ context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *inmemStorage) ListPage(ctx context.Context, prefix string, _ string, _ int) ([]string, error) {
	return s.List(ctx, prefix)
}

var _ sdklogical.Storage = (*inmemStorage)(nil)

// =============================================================================
// Backend constructor
// =============================================================================

// newTestBackend builds a kubernetesAuthBackend with inmem storage and
// no upstream apiserver configured. Use newTestBackendWithFakeAPI when
// the test actually exercises TokenReview.
func newTestBackend(t *testing.T) (*kubernetesAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	storage := newInmemStorage()
	be, err := Factory(ctx, &logical.BackendConfig{
		Logger:      testLogger(),
		StorageView: storage,
	})
	require.NoError(t, err)
	return be.(*kubernetesAuthBackend), ctx
}

// =============================================================================
// Fake kube-apiserver — httptest.Server returning canned TokenReview responses
// =============================================================================

// fakeAPIServerOpts configures a single test apiserver.
type fakeAPIServerOpts struct {
	// Response is the canned status payload returned for any TokenReview
	// request. Authenticated/User/Audiences/Error fields drive test
	// assertions about login outcomes.
	Response tokenReviewStatus

	// ResponseStatus overrides the HTTP status code; defaults to 201.
	ResponseStatus int

	// Failures: number of leading requests that should fail with status
	// FailWithStatus (drives retry tests). After Failures responses are
	// returned, subsequent requests get the canned Response.
	Failures       int
	FailWithStatus int // default 500
}

// fakeAPIServer is the test handle returned by newFakeAPIServer. Exposes
// the server URL + records what bearer was used + the spec.token /
// spec.audiences seen by the apiserver.
type fakeAPIServer struct {
	URL         string
	Calls       int32
	BearerSeen  string
	TokenSeen   string
	AudsSeen    []string
	RawBodySeen []byte
}

// newFakeAPIServer spins up an httptest.Server that responds to TokenReview
// POSTs at /apis/authentication.k8s.io/v1/tokenreviews. Records the
// authorization bearer + spec for inspection in tests.
func newFakeAPIServer(t *testing.T, opts fakeAPIServerOpts) *fakeAPIServer {
	t.Helper()
	fake := &fakeAPIServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&fake.Calls, 1)
		fake.BearerSeen = r.Header.Get("Authorization")

		body, _ := io.ReadAll(r.Body)
		fake.RawBodySeen = body
		var req tokenReviewRequest
		_ = json.Unmarshal(body, &req)
		fake.TokenSeen = req.Spec.Token
		fake.AudsSeen = req.Spec.Audiences

		// Failure injection for retry tests.
		if opts.Failures > 0 && int32(opts.Failures) >= n {
			status := opts.FailWithStatus
			if status == 0 {
				status = http.StatusInternalServerError
			}
			w.WriteHeader(status)
			return
		}

		respStatus := opts.ResponseStatus
		if respStatus == 0 {
			respStatus = http.StatusCreated
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(respStatus)
		_ = json.NewEncoder(w).Encode(tokenReviewResponse{Status: opts.Response})
	}))
	t.Cleanup(srv.Close)
	fake.URL = srv.URL
	return fake
}

// =============================================================================
// JWT mint — produces well-formed (unsigned) JWTs for unverified-parse tests
// =============================================================================

// mintJWT returns a JWT with the given payload claims and a dummy
// signature. ParseJWTClaimsUnverified accepts these because it doesn't
// verify signatures; TokenReview-based login also accepts them because
// the kube-apiserver (real or our fake) is the only signature authority.
func mintJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	signature := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payloadEnc + "." + signature
}

// mintK8sSAJWT returns a K8s SA-shaped JWT with the standard sub claim.
// Useful for the issuer-pin and shape-detection paths.
func mintK8sSAJWT(issuer, namespace, name string) string {
	return mintJWT(map[string]any{
		"iss": issuer,
		"sub": "system:serviceaccount:" + namespace + ":" + name,
	})
}
