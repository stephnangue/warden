package openai

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
		w.Header().Set("X-Received-Org", r.Header.Get("OpenAI-Organization"))
		w.Header().Set("X-Received-Project", r.Header.Get("OpenAI-Project"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.openaiURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	t.Run("successful proxy", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/openai/gateway/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
		httpReq.URL, _ = url.Parse(upstream.URL + "/openai/gateway/v1/chat/completions")

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{"api_key": "sk-test-123"},
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
		httpReq := httptest.NewRequest("POST", "/openai/gateway/v1/chat/completions", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
		}

		b.handleGateway(context.Background(), req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("invalid gateway path returns 500", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{"api_key": "sk-test"},
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
	b.openaiURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/openai/gateway/v1/chat/completions", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/openai/gateway/v1/chat/completions")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": "sk-test"},
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
	b.openaiURL = upstream.URL
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/openai/role/reader/gateway/v1/chat/completions", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/openai/role/reader/gateway/v1/chat/completions")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Path:           "role/reader/gateway/v1/chat/completions",
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": "sk-test"},
		},
	}

	err := b.handleTransparentGatewayStreaming(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Contains(t, req.Path, "gateway")
}

func TestNewOpenAITransport(t *testing.T) {
	transport := newOpenAITransport()
	assert.NotNil(t, transport)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 50, transport.MaxIdleConnsPerHost)
	assert.True(t, transport.ForceAttemptHTTP2)
	assert.Equal(t, 90*1000000000, int(transport.IdleConnTimeout))
}

func TestShutdownHTTPTransport(t *testing.T) {
	// Just verify it doesn't panic
	ShutdownHTTPTransport()
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

	assert.Contains(t, paths[0].Fields, "openai_url")
	assert.Contains(t, paths[0].Fields, "max_body_size")
	assert.Contains(t, paths[0].Fields, "timeout")
	assert.Contains(t, paths[0].Fields, "auto_auth_path")
	assert.Contains(t, paths[0].Fields, "default_role")

	assert.Equal(t, DefaultOpenAIURL, paths[0].Fields["openai_url"].Default)
	assert.Equal(t, framework.DefaultMaxBodySize, paths[0].Fields["max_body_size"].Default)
}
