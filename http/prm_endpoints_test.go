package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsPRMPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/.well-known/oauth-protected-resource", true},
		{"/.well-known/oauth-protected-resource/", true},
		{"/.well-known/oauth-protected-resource/v1/github", true},
		{"/.well-known/oauth-protected-resource/v1/team-a/github", true},
		{"/.well-known/openid-configuration", false},
		{"/.well-known/oauth-authorization-server", false},
		// Prefix-adjacent but not beneath it: must not match, or an unrelated
		// path could bypass the /v1/ requirement.
		{"/.well-known/oauth-protected-resource-other", false},
		{"/v1/github", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, isPRMPath(tc.path))
		})
	}
}

// TestPRMEndpoint_MethodAndSeal covers the two guards that must hold before any
// mount state is touched. The seal guard matters because this handler is
// registered at the origin root and so bypasses handleLogical's seal check,
// while dereferencing the namespace store and mount table.
func TestPRMEndpoint_MethodAndSeal(t *testing.T) {
	core, log := createTestCoreForHTTP(t)
	h := handlePRM(core, log)

	t.Run("POST is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, prmPath+"/v1/github", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("GET while sealed is 503, not a panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, prmPath+"/v1/github", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

// TestPRMSuffix pins the hand-off from URL to the resource identifier core
// resolves. Both the bare prefix and its subtree route to this handler, so the
// bare form must yield "" (naming no resource) rather than something that could
// accidentally match a mount.
func TestPRMSuffix(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{prmPath, ""},
		{prmPath + "/", "/"},
		{prmPath + "/v1/github", "/v1/github"},
		{prmPath + "/v1/team-a/github", "/v1/team-a/github"},
		// Passed through verbatim: core rejects non-canonical forms rather than
		// normalizing, so a published identifier is always the one requested.
		{prmPath + "/v1/github/../plain", "/v1/github/../plain"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			assert.Equal(t, tc.want, prmSuffix(tc.url))
		})
	}
}

// TestPRMCacheControl covers the header rendering. The TTL travels with the
// document from the same config generation, so the header can never describe a
// different document than the one being served.
func TestPRMCacheControl(t *testing.T) {
	assert.Equal(t, "public, max-age=3600", prmCacheControl(time.Hour))
	assert.Equal(t, "public, max-age=300", prmCacheControl(5*time.Minute))
	assert.Empty(t, prmCacheControl(0), "no TTL means no caching directive")
	assert.Empty(t, prmCacheControl(-time.Second))
}

// TestPRMEndpoint_ExemptFromV1Prefix pins that metadata paths reach the handler
// rather than being rejected by the /v1/ prefix check.
func TestPRMEndpoint_ExemptFromV1Prefix(t *testing.T) {
	var reached bool
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	wrapped := wrapGenericHandler(nil, inner, nil, nil)

	for _, p := range []string{
		prmPath,
		prmPath + "/v1/github",
		prmPath + "/v1/team-a/github",
	} {
		t.Run(p, func(t *testing.T) {
			reached = false
			wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
			assert.True(t, reached, "metadata path must bypass the /v1/ prefix check")
		})
	}

	t.Run("control: an unrelated well-known path is still rejected", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/other", nil))
		assert.False(t, reached)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestPRMEndpoint_SurvivesProviderHeaderRewrite is the regression test for the
// ordering bug this endpoint would otherwise hit. wrapGenericHandler rewrites
// non-/v1/ paths to /v1/... whenever X-Warden-Provider is set, and MCP clients
// commonly set that header connection-wide. If the rewrite ran first, a
// discovery fetch would become /v1/.well-known/... and 404 — silently breaking
// the bootstrap the document exists to drive.
func TestPRMEndpoint_SurvivesProviderHeaderRewrite(t *testing.T) {
	for _, p := range []string{
		prmPath + "/v1/github",
		"/.well-known/openid-configuration",
	} {
		t.Run(p, func(t *testing.T) {
			var gotPath string
			inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
			})
			req := httptest.NewRequest(http.MethodGet, p, nil)
			req.Header.Set("X-Warden-Provider", "github")

			wrapGenericHandler(nil, inner, nil, nil).ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, p, gotPath, "the path must reach the handler unrewritten")
		})
	}
}
