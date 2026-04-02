package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGateway(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.Header().Set("X-Received-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Received-Version", r.Header.Get("X-GitHub-Api-Version"))
		w.Header().Set("X-Received-Accept", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.githubURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	t.Run("successful proxy", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("GET", "/github/gateway/repos/owner/repo", strings.NewReader(""))
		httpReq.URL, _ = url.Parse(upstream.URL + "/github/gateway/repos/owner/repo")

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{"token": "ghp_test123"},
			},
		}

		b.handleGateway(context.Background(), req)

		resp := rec.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), `"ok":true`)
	})

	t.Run("no credential returns 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("GET", "/github/gateway/user", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
		}

		b.handleGateway(context.Background(), req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("invalid gateway path returns 500", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("GET", "/github/repos/owner/repo", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{"token": "ghp_test"},
			},
		}

		b.handleGateway(context.Background(), req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleGatewayStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.githubURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/github/gateway/user", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/github/gateway/user")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeGitHubToken,
			Data: map[string]string{"token": "ghp_test"},
		},
	}

	err := b.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
}

func TestHandleTransparentGatewayStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.githubURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/github/role/reader/gateway/repos/owner/repo", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/github/role/reader/gateway/repos/owner/repo")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Path:           "role/reader/gateway/repos/owner/repo",
		Credential: &credential.Credential{
			Type: credential.TypeGitHubToken,
			Data: map[string]string{"token": "ghp_test"},
		},
	}

	err := b.handleTransparentGatewayStreaming(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Contains(t, req.Path, "gateway")
}

func TestPaths(t *testing.T) {
	b := setupBackend(t)
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)

	_, hasRead := paths[0].Operations[logical.ReadOperation]
	_, hasUpdate := paths[0].Operations[logical.UpdateOperation]
	assert.True(t, hasRead)
	assert.True(t, hasUpdate)

	assert.Contains(t, paths[0].Fields, "github_url")
	assert.Contains(t, paths[0].Fields, "max_body_size")
	assert.Contains(t, paths[0].Fields, "timeout")
	assert.Contains(t, paths[0].Fields, "api_version")
	assert.Contains(t, paths[0].Fields, "auto_auth_path")
	assert.Contains(t, paths[0].Fields, "default_role")

	assert.Equal(t, DefaultGitHubURL, paths[0].Fields["github_url"].Default)
	assert.Equal(t, DefaultAPIVersion, paths[0].Fields["api_version"].Default)
	assert.Equal(t, framework.DefaultMaxBodySize, paths[0].Fields["max_body_size"].Default)
}
