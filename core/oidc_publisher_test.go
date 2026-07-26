package core

import (
	"context"
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
