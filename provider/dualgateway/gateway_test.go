package dualgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
)

// --- extractAPIPath ---

func TestExtractAPIPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/provider/gateway/some/path", "/some/path"},
		{"/provider/gateway/me", "/me"},
		{"/provider/role/admin/gateway/cloud/project", "/cloud/project"},
		{"/provider/gateway", "/"},
		{"/no-gateway-here", "/no-gateway-here"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractAPIPath(tt.input))
		})
	}
}

// --- handleGateway auto-detection ---

func TestHandleGateway_RoutesToAPIForNonSigV4(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("X-Auth-Token"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	b := createBackend(t, headerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/gateway/test", nil)

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"secret_key": "val"},
		},
	}

	b.handleGateway(context.Background(), req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- handleAPIRequest: header auth (Scaleway-like) ---

func TestHandleAPIRequest_HeaderAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "warden-test-proxy", r.Header.Get("User-Agent"))
		assert.Equal(t, "test-secret-key", r.Header.Get("X-Auth-Token"))
		assert.Empty(t, r.Header.Get("X-Warden-Token"))
		assert.Equal(t, "/instance/v1/zones/fr-par-1/servers", r.URL.Path)
		assert.Equal(t, "page=2", r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"servers":[]}`))
	}))
	defer upstream.Close()

	b := createBackend(t, headerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/instance/v1/zones/fr-par-1/servers?page=2", nil)
	httpReq.Header.Set("X-Warden-Token", "should-be-stripped")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"access_key": "AK", "secret_key": "test-secret-key"},
		},
	}

	b.handleAPIRequest(context.Background(), req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "servers")
}

// --- handleAPIRequest: bearer auth (OVH-like) ---

func TestHandleAPIRequest_BearerAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "warden-bearer-proxy", r.Header.Get("User-Agent"))
		assert.Equal(t, "Bearer test-api-token", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Warden-Token"))
		assert.Equal(t, "/me", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"nichandle":"xx12345"}`))
	}))
	defer upstream.Close()

	b := createBackend(t, bearerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/me", nil)
	httpReq.Header.Set("Authorization", "Bearer client-jwt-should-be-stripped")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "bearer_keys",
			Data: map[string]string{"api_token": "test-api-token", "access_key": "AK", "secret_key": "SK"},
		},
	}

	b.handleAPIRequest(context.Background(), req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "nichandle")
}

// --- StripAuthorization: false (header auth keeps original Authorization) ---

func TestHandleAPIRequest_StripAuthorization_False(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer original-jwt", r.Header.Get("Authorization"))
		assert.Equal(t, "injected-secret", r.Header.Get("X-Auth-Token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := createBackend(t, headerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)
	httpReq.Header.Set("Authorization", "Bearer original-jwt")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"secret_key": "injected-secret"},
		},
	}

	b.handleAPIRequest(context.Background(), req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- StripAuthorization: true (bearer auth replaces Authorization) ---

func TestHandleAPIRequest_StripAuthorization_True(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer provider-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := createBackend(t, bearerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)
	httpReq.Header.Set("Authorization", "Bearer original-client-jwt")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "bearer_keys",
			Data: map[string]string{"api_token": "provider-token"},
		},
	}

	b.handleAPIRequest(context.Background(), req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Nil credential returns 401 ---

func TestHandleAPIRequest_NilCredential(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)

	b.handleAPIRequest(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Upstream connection error returns 502 ---

func TestHandleAPIRequest_UpstreamError(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	b.providerURL = "http://127.0.0.1:1"

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)

	b.handleAPIRequest(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"secret_key": "val"},
		},
	})
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// --- Proxy/Warden headers are stripped, custom headers survive ---

func TestHandleAPIRequest_StripsProxyHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("X-Warden-Token"))
		assert.Empty(t, r.Header.Get("X-Warden-Role"))
		assert.Empty(t, r.Header.Get("X-Forwarded-For"))
		assert.Empty(t, r.Header.Get("X-Real-Ip"))
		assert.Empty(t, r.Header.Get("Proxy-Authorization"))
		assert.Equal(t, "keep-me", r.Header.Get("X-Custom-Header"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := createBackend(t, headerAuthSpec)
	b.providerURL = upstream.URL

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)
	httpReq.Header.Set("X-Warden-Token", "strip")
	httpReq.Header.Set("X-Warden-Role", "strip")
	httpReq.Header.Set("X-Forwarded-For", "strip")
	httpReq.Header.Set("X-Real-Ip", "strip")
	httpReq.Header.Set("Proxy-Authorization", "strip")
	httpReq.Header.Set("X-Custom-Header", "keep-me")

	b.handleAPIRequest(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"secret_key": "val"},
		},
	})
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- S3 endpoint parameterization ---

func TestS3EndpointParameterization(t *testing.T) {
	assert.Equal(t, "s3.fr-par.test.cloud", headerAuthSpec.S3Endpoint(nil, "fr-par"))
	assert.Equal(t, "s3.gra.bearer.net", bearerAuthSpec.S3Endpoint(nil, "gra"))
}

func TestS3EndpointWithState(t *testing.T) {
	spec := &ProviderSpec{
		Name: "r2", HelpText: "h", CredentialType: "c",
		DefaultURL: "https://x.com", URLConfigKey: "r2_url",
		DefaultTimeout: 30e9, UserAgent: "u",
		APIAuth:    APIAuthStrategy{HeaderName: "X", HeaderValueFormat: "%s", CredentialField: "k"},
		S3Endpoint: func(state map[string]any, region string) string {
			acct, _ := state["account_id"].(string)
			return acct + ".r2.cloudflarestorage.com"
		},
	}
	state := map[string]any{"account_id": "abc123"}
	assert.Equal(t, "abc123.r2.cloudflarestorage.com", spec.S3Endpoint(state, "auto"))
}
