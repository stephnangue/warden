package core

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewJWKSPublisher_Dispatch(t *testing.T) {
	// none -> nil publisher.
	p, err := newJWKSPublisher(publisherConfig{}, "")
	require.NoError(t, err)
	assert.Nil(t, p)

	// missing required fields error.
	_, err = newJWKSPublisher(publisherConfig{Type: "local_file"}, "")
	require.Error(t, err)
	_, err = newJWKSPublisher(publisherConfig{Type: "http_put"}, "")
	require.Error(t, err)
	_, err = newJWKSPublisher(publisherConfig{Type: "s3", Bucket: "b", Region: "r"}, "")
	require.Error(t, err) // missing keys
	_, err = newJWKSPublisher(publisherConfig{Type: "azure_blob", AccountName: "a", Container: "c"}, "")
	require.Error(t, err) // missing account_key
	_, err = newJWKSPublisher(publisherConfig{Type: "gcs"}, "")
	require.Error(t, err) // missing bucket
	_, err = newJWKSPublisher(publisherConfig{Type: "gcs", Bucket: "b"}, "")
	require.Error(t, err) // missing credentials_json

	// unsupported type.
	_, err = newJWKSPublisher(publisherConfig{Type: "ftp"}, "")
	require.Error(t, err)

	// valid constructions.
	p, err = newJWKSPublisher(publisherConfig{Type: "local_file", Dir: t.TempDir()}, "")
	require.NoError(t, err)
	assert.Equal(t, "local_file", p.Type())
	p, err = newJWKSPublisher(publisherConfig{Type: "http_put", BaseURL: "https://x"}, "")
	require.NoError(t, err)
	assert.Equal(t, "http_put", p.Type())
	p, err = newJWKSPublisher(publisherConfig{
		Type: "azure_blob", AccountName: "wardenoidc", Container: "jwks",
		AccountKey: base64.StdEncoding.EncodeToString([]byte("dummy-account-key")),
	}, "")
	require.NoError(t, err)
	assert.Equal(t, "azure_blob", p.Type())
}

func TestLocalFilePublisher(t *testing.T) {
	dir := t.TempDir()
	p := &localFilePublisher{dir: dir}
	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, err := os.ReadFile(filepath.Join(dir, ".well-known", "openid-configuration"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"issuer":"x"}`, string(disc))

	jwks, err := os.ReadFile(filepath.Join(dir, "oidc", "jwks"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"keys":[]}`, string(jwks))
}

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

func TestS3Publisher(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			seen[r.URL.Path] = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIA", "secret", ""),
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
	})
	p := &s3Publisher{client: client, bucket: "warden-oidc", prefix: "prod"}

	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	assert.True(t, seen["/warden-oidc/prod/.well-known/openid-configuration"], "discovery object must be PUT")
	assert.True(t, seen["/warden-oidc/prod/oidc/jwks"], "jwks object must be PUT")
}

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

func TestGCSPublisher(t *testing.T) {
	type got struct{ method, auth, contentType, cacheControl string }
	seen := map[string]got{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodPut {
			seen[r.URL.Path] = got{r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("Cache-Control")}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Inject a static token source and point the endpoint at the fake server, so the
	// upload path is exercised without a real Google token exchange.
	p := &gcsPublisher{
		tokenSource:  oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		endpoint:     srv.URL,
		bucket:       "warden-oidc",
		prefix:       "prod",
		cacheControl: "public, max-age=60",
		client:       srv.Client(),
	}

	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, ok := seen["/warden-oidc/prod/.well-known/openid-configuration"]
	require.True(t, ok, "discovery object must be PUT")
	assert.Equal(t, http.MethodPut, disc.method)
	assert.Equal(t, "Bearer test-token", disc.auth)
	assert.Equal(t, "application/json", disc.contentType)
	assert.Equal(t, "public, max-age=60", disc.cacheControl)

	jwks, ok := seen["/warden-oidc/prod/oidc/jwks"]
	require.True(t, ok, "jwks object must be PUT")
	assert.Equal(t, "application/json", jwks.contentType)
}
