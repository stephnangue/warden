package core

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureBlobPublisher(t *testing.T) {
	type got struct{ method, contentType, cacheControl string }
	seen := map[string]got{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodPut {
			// The blob's content type / cache control ride on x-ms-blob-* headers,
			// not the request's own Content-Type.
			seen[r.URL.Path] = got{r.Method, r.Header.Get("x-ms-blob-content-type"), r.Header.Get("x-ms-blob-cache-control")}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	// Build through the real constructor via the endpoint override, pointing at the
	// fake server. SharedKey signing is client-side; the server ignores the
	// signature, and the account key just needs to be valid base64.
	p, err := newJWKSPublisher(publisherConfig{
		Type: "azure_blob", AccountName: "wardenoidc", Container: "jwks", Prefix: "prod",
		AccountKey: base64.StdEncoding.EncodeToString([]byte("dummy-account-key")),
		Endpoint:   srv.URL,
	}, "public, max-age=60")
	require.NoError(t, err)

	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, ok := seen["/jwks/prod/.well-known/openid-configuration"]
	require.True(t, ok, "discovery blob must be PUT")
	assert.Equal(t, http.MethodPut, disc.method)
	assert.Equal(t, "application/json", disc.contentType)
	assert.Equal(t, "public, max-age=60", disc.cacheControl)

	jwks, ok := seen["/jwks/prod/oidc/jwks"]
	require.True(t, ok, "jwks blob must be PUT")
	assert.Equal(t, "application/json", jwks.contentType)
}
