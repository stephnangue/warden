package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A model call that outlasts the mount's timeout is answered 504, the
// deadline being the only bound on how long the upstream may take. That the
// transport has no header timeout of its own is TestTransport_NoResponseHeaderTimeout.
func TestHandleGateway_SlowUpstreamAnswers504(t *testing.T) {
	silent := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	b := setupBackend(t)
	b.StreamingBackend.InitProxy(silent)
	b.SetTimeout(20 * time.Millisecond)

	rec := httptest.NewRecorder()
	b.handleGateway(context.Background(), &logical.Request{
		HTTPRequest: httptest.NewRequest("POST",
			"/azure/gateway/my-resource.openai.azure.com/openai/v1/chat/completions", nil),
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAzureBearerToken,
			Data: map[string]string{"access_token": "test-token"},
		},
	})

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHandleGateway(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.Header().Set("X-Received-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	t.Run("no credential returns 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/azure/gateway/management.azure.com/subscriptions", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
		}

		b.handleGateway(context.Background(), req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("invalid gateway path returns 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/azure/config", nil)

		req := &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{"access_token": "test-token"},
			},
		}

		b.handleGateway(context.Background(), req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestHandleGatewayStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/azure/gateway/management.azure.com/subscriptions", nil)
	u, _ := url.Parse(upstream.URL + "/azure/gateway/management.azure.com/subscriptions")
	httpReq.URL = u

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAzureBearerToken,
			Data: map[string]string{"access_token": "test-token"},
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
	b.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/azure/role/reader/gateway/management.azure.com/subscriptions", nil)
	u, _ := url.Parse(upstream.URL + "/azure/role/reader/gateway/management.azure.com/subscriptions")
	httpReq.URL = u

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Path:           "role/reader/gateway/management.azure.com/subscriptions",
		Credential: &credential.Credential{
			Type: credential.TypeAzureBearerToken,
			Data: map[string]string{"access_token": "test-token"},
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

	// Verify operations are defined
	_, hasRead := paths[0].Operations[logical.ReadOperation]
	_, hasUpdate := paths[0].Operations[logical.UpdateOperation]
	assert.True(t, hasRead)
	assert.True(t, hasUpdate)

	// Verify fields exist (no URL field for Azure)
	assert.Contains(t, paths[0].Fields, "max_body_size")
	assert.Contains(t, paths[0].Fields, "timeout")
	assert.Contains(t, paths[0].Fields, "auto_auth_path")
	assert.Contains(t, paths[0].Fields, "default_role")
	assert.NotContains(t, paths[0].Fields, "url")
	assert.NotContains(t, paths[0].Fields, "azure_url")
}
