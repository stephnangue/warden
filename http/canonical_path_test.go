package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
)

func TestCanonicalRequestPath(t *testing.T) {
	ok := []string{
		"/v1/",
		"/v1/sys/policies/cbp/",
		"/v1/github/role/dev/gateway",
		"/v1/github/role/dev/gateway/",
		"/v1/github/role/dev/gateway/repos/org/.github/contents/x",
		"/v1/gitlab/gateway/group/repo.git/info/refs",
		"/v1/s3/gateway/bucket/a..b",
		"/v1/aws/role/bedrock/gateway/model/arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.amazon.nova-lite-v1:0/converse",
	}
	for _, p := range ok {
		assert.True(t, canonicalRequestPath(p), "%q", p)
	}
	refused := []string{
		"/v1/github/role/dev/gateway/repos/org/public/../secret",
		"/v1/github/role/dev/gateway/repos/org/./secret",
		"/v1/github/role/dev/gateway/repos/org//secret",
		"/v1/github/role/dev/gateway/..",
		"/v1/github/role/dev/gateway/.",
		"/v1//github",
		"/v1/github//",
		"/v1/..",
	}
	for _, p := range refused {
		assert.False(t, canonicalRequestPath(p), "%q", p)
	}
}

func TestCanonicalRequestPath_NoAlloc(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = canonicalRequestPath("/v1/github/role/dev/gateway/repos/org/x/contents/a/b/c")
	})
	assert.Zero(t, allocs)
}

// TestWrapGenericHandler_RefusesNonCanonicalPaths drives the encoded forms the
// router lets through: each reaches the handler decoded, and is refused before
// anything routes or forwards it.
func TestWrapGenericHandler_RefusesNonCanonicalPaths(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := wrapGenericHandler(nil, inner, nil, nil)

	for _, target := range []string{
		"/v1/github/role/dev/gateway/repos/org/public/%2e%2e/secret/contents/x",
		"/v1/github/role/dev/gateway/repos/org/public/%2E%2E/secret/contents/x",
		"/v1/github/role/dev/gateway/repos/org/%2e/secret",
		"/v1/github/role/dev/gateway/repos/org/public%2F..%2Fsecret",
		"/v1/github/role/dev/gateway/repos/org/%2Fsecret/contents/x",
		"/v1/sys/policies/cbp/x/%2e%2e/admin",
	} {
		called = false
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusBadRequest, w.Code, "%s", target)
		assert.Contains(t, w.Body.String(), "segments", "%s", target)
		assert.False(t, called, "%s must not reach the router", target)
	}

	for _, target := range []string{
		// An encoded slash inside a segment is an identifier, not a separator.
		"/v1/aws/role/bedrock/gateway/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.amazon.nova-lite-v1%3A0/converse",
		// Double-encoded: authorized and forwarded as the literal "%2e%2e".
		"/v1/github/role/dev/gateway/repos/org/public/%252e%252e/secret",
		"/v1/github/role/dev/gateway/",
	} {
		called = false
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusOK, w.Code, "%s", target)
		assert.True(t, called, "%s", target)
	}
}

// TestWrapGenericHandler_LiteralFormsLeftToTheRouter: a literal dot segment or
// doubled slash is not checked by the wrapper, because the router behind it
// redirects it to the clean path before any handler sees it — as it always
// has. Only the encoded spelling needs the check.
func TestWrapGenericHandler_LiteralFormsLeftToTheRouter(t *testing.T) {
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	wrapped := wrapGenericHandler(nil, mux, nil, nil)

	for target, location := range map[string]string{
		"/v1/github/gateway/repos/org/public/../secret": "/v1/github/gateway/repos/org/secret",
		"/v1/github/gateway/repos/org/./secret":         "/v1/github/gateway/repos/org/secret",
		"/v1/github/gateway/repos/org//secret":          "/v1/github/gateway/repos/org/secret",
	} {
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusTemporaryRedirect, w.Code, "%s", target)
		assert.Equal(t, location, w.Header().Get("Location"), "%s", target)
	}
	assert.Empty(t, seen, "no handler sees a literal dot segment or doubled slash")
}

// TestHandler_NoDotSegmentReachesALogicalRequest pins, on the wrapper, the
// router and the logical handler Handler assembles, the three things the
// encoded-only check relies on: an encoded dot segment is refused; a literal
// one is redirected by the router before any handler runs; and CONNECT, the
// one method the router does not clean, is refused by the logical handler
// before a request is built from its path. The core is nil: none of these
// reaches it.
func TestHandler_NoDotSegmentReachesALogicalRequest(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	mux := http.NewServeMux()
	mux.Handle("/v1/", handleLogical(nil, log, nil))
	handler := wrapGenericHandler(nil, mux, log, nil)

	for _, tc := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/v1/github/gateway/repos/org/public/%2e%2e/secret", http.StatusBadRequest},
		{http.MethodGet, "/v1/github/gateway/repos/org/public/../secret", http.StatusTemporaryRedirect},
		{http.MethodGet, "/v1/github/gateway/repos/org//secret", http.StatusTemporaryRedirect},
		{http.MethodConnect, "/v1/github/gateway/repos/org/public/../secret", http.StatusMethodNotAllowed},
		{http.MethodConnect, "/v1/github/gateway/repos/org//secret", http.StatusMethodNotAllowed},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))
		assert.Equal(t, tc.want, w.Code, "%s %s", tc.method, tc.target)
	}
}

// A path the X-Warden-Provider rewrite produces is checked too.
func TestWrapGenericHandler_RefusesNonCanonicalProviderHeaderPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	wrapped := wrapGenericHandler(nil, inner, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/repos/org/public/%2e%2e/secret", nil)
	req.Header.Set("X-Warden-Provider", "github")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
