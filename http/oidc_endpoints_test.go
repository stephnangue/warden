package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOIDCEndpoints_HandlerFailClosedAndMethod tests the handlers directly: they
// serve only GET, and fail closed with 503 when the issuer is not ready (as on
// this sealed test core, whose OIDCIssuer() is nil).
func TestOIDCEndpoints_HandlerFailClosedAndMethod(t *testing.T) {
	c, log := createTestCoreForHTTP(t)

	for name, h := range map[string]http.Handler{
		"discovery": handleOIDCDiscovery(c, log),
		"jwks":      handleOIDCJWKS(c, log),
	} {
		// GET with a not-ready issuer -> 503.
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		assert.Equalf(t, http.StatusServiceUnavailable, w.Code, "%s: GET must fail closed when issuer not ready", name)

		// POST -> 405.
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		assert.Equalf(t, http.StatusMethodNotAllowed, w.Code, "%s: must reject non-GET", name)
	}
}

// TestOIDCEndpoints_ExemptFromV1Prefix verifies the discovery/JWKS paths bypass
// the /v1/ prefix requirement and reach the inner handler, while unrelated
// non-/v1/ paths still 404. A nil core is not standby, so it serves locally.
func TestOIDCEndpoints_ExemptFromV1Prefix(t *testing.T) {
	var called string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	wrapped := wrapGenericHandler(nil, inner, nil, nil)

	for _, path := range []string{oidcDiscoveryPath, oidcJWKSPath} {
		called = ""
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equalf(t, path, called, "%s must bypass the /v1/ check and reach the handler", path)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Control: an unrelated non-/v1/ path still 404s and never reaches the inner handler.
	called = ""
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/other", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, called)
}
