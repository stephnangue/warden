package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPPutPublisher(t *testing.T) {
	type got struct{ method, auth, cc string }
	seen := map[string]got{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		seen[r.URL.Path] = got{r.Method, r.Header.Get("Authorization"), r.Header.Get("Cache-Control")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := newJWKSPublisher(publisherConfig{
		Type: "http_put", BaseURL: srv.URL, AuthValue: "Bearer cf-token",
	}, "public, max-age=60")
	require.NoError(t, err)
	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, ok := seen["/.well-known/openid-configuration"]
	require.True(t, ok, "discovery must be PUT")
	assert.Equal(t, http.MethodPut, disc.method)
	assert.Equal(t, "Bearer cf-token", disc.auth, "auth header must be sent")
	assert.Equal(t, "public, max-age=60", disc.cc)

	jwks, ok := seen["/oidc/jwks"]
	require.True(t, ok, "jwks must be PUT")
	assert.Equal(t, "Bearer cf-token", jwks.auth)
}

func TestHTTPPutPublisher_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	p, err := newJWKSPublisher(publisherConfig{Type: "http_put", BaseURL: srv.URL, AuthValue: "Bearer x"}, "")
	require.NoError(t, err)
	require.Error(t, p.Publish(context.Background(), []byte(`{}`), []byte(`{}`)))
}
