package vault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
)

// createTestLogger creates a logger for testing that discards output
func createTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

func TestBuildTargetURL(t *testing.T) {
	tests := []struct {
		name         string
		vaultAddress string
		path         string
		rawQuery     string
		expected     string
		expectError  bool
	}{
		{
			name:         "basic secret path",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/secret/data/myapp",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/secret/data/myapp",
			expectError:  false,
		},
		{
			name:         "path with query string",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/secret/data/myapp",
			rawQuery:     "version=2",
			expected:     "https://vault.example.com:8200/v1/secret/data/myapp?version=2",
			expectError:  false,
		},
		{
			name:         "gateway root path",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/",
			expectError:  false,
		},
		{
			name:         "gateway with trailing slash",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/",
			expectError:  false,
		},
		{
			name:         "path already has /v1 prefix",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/v1/sys/health",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/sys/health",
			expectError:  false,
		},
		{
			name:         "auth path",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/auth/token/lookup-self",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/auth/token/lookup-self",
			expectError:  false,
		},
		{
			name:         "sys path",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/sys/health",
			rawQuery:     "",
			expected:     "https://vault.example.com:8200/v1/sys/health",
			expectError:  false,
		},
		{
			name:         "missing gateway marker",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/secret/data/myapp",
			rawQuery:     "",
			expected:     "",
			expectError:  true,
		},
		{
			name:         "complex query string",
			vaultAddress: "https://vault.example.com:8200",
			path:         "/v1/vault/gateway/secret/data/myapp",
			rawQuery:     "version=2&list=true",
			expected:     "https://vault.example.com:8200/v1/secret/data/myapp?version=2&list=true",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &vaultBackend{
				vaultAddress: tt.vaultAddress,
			}

			result, err := b.buildTargetURL(tt.path, tt.rawQuery)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetVaultToken(t *testing.T) {
	tests := []struct {
		name        string
		credential  *credential.Credential
		expected    string
		expectError bool
		errMsg      string
	}{
		{
			name: "valid vault token credential",
			credential: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "hvs.CAESIJlmkG2lL8xPqU",
				},
			},
			expected:    "hvs.CAESIJlmkG2lL8xPqU",
			expectError: false,
		},
		{
			name:        "nil credential",
			credential:  nil,
			expected:    "",
			expectError: true,
			errMsg:      "no credential available",
		},
		{
			name: "wrong credential type",
			credential: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id": "AKIA...",
				},
			},
			expected:    "",
			expectError: true,
			errMsg:      "unsupported credential type",
		},
		{
			name: "missing token field",
			credential: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{},
			},
			expected:    "",
			expectError: true,
			errMsg:      "missing token field",
		},
		{
			name: "empty token",
			credential: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "",
				},
			},
			expected:    "",
			expectError: true,
			errMsg:      "missing token field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &vaultBackend{}
			req := &logical.Request{
				Credential: tt.credential,
			}

			result, err := b.getVaultToken(req)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPrepareHeaders(t *testing.T) {
	tests := []struct {
		name           string
		initialHeaders map[string]string
		vaultToken     string
		checkRemoved   []string
		checkPresent   map[string]string
	}{
		{
			name: "removes security headers and injects token",
			initialHeaders: map[string]string{
				"X-Vault-Token":   "old-token",
				"X-Vault-Request": "true",
				"Content-Type":    "application/json",
			},
			vaultToken:   "new-real-token",
			checkRemoved: []string{"X-Vault-Request"},
			checkPresent: map[string]string{
				"X-Vault-Token": "new-real-token",
				"Content-Type":  "application/json",
			},
		},
		{
			name: "removes hop-by-hop headers",
			initialHeaders: map[string]string{
				"Connection":        "keep-alive",
				"Keep-Alive":        "timeout=5",
				"Transfer-Encoding": "chunked",
				"Upgrade":           "h2c",
				"Accept":            "application/json",
			},
			vaultToken:   "test-token",
			checkRemoved: []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade"},
			checkPresent: map[string]string{
				"X-Vault-Token": "test-token",
				"Accept":        "application/json",
			},
		},
		{
			name: "removes proxy headers",
			initialHeaders: map[string]string{
				"X-Forwarded-For":   "192.168.1.1",
				"X-Forwarded-Host":  "original.host.com",
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Port":  "443",
				"X-Real-Ip":         "10.0.0.1",
				"Forwarded":         "for=192.168.1.1",
				"User-Agent":        "test-client",
			},
			vaultToken: "test-token",
			checkRemoved: []string{
				"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
				"X-Forwarded-Port", "X-Real-Ip", "Forwarded",
			},
			checkPresent: map[string]string{
				"X-Vault-Token": "test-token",
				"User-Agent":    "test-client",
			},
		},
		{
			name: "preserves X-Vault-Namespace",
			initialHeaders: map[string]string{
				"X-Vault-Namespace": "admin/team-a",
				"X-Vault-Token":     "old-token",
			},
			vaultToken:   "new-token",
			checkRemoved: []string{},
			checkPresent: map[string]string{
				"X-Vault-Token":     "new-token",
				"X-Vault-Namespace": "admin/team-a",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &vaultBackend{}
			req := httptest.NewRequest(http.MethodPost, "/test", nil)

			// Set initial headers
			for k, v := range tt.initialHeaders {
				req.Header.Set(k, v)
			}

			b.prepareHeaders(req, tt.vaultToken)

			// Check removed headers
			for _, h := range tt.checkRemoved {
				assert.Empty(t, req.Header.Get(h), "Header %s should have been removed", h)
			}

			// Check present headers
			for k, v := range tt.checkPresent {
				assert.Equal(t, v, req.Header.Get(k), "Header %s should be %s", k, v)
			}
		})
	}
}

func TestPrepareHeaders_ConnectionListedHeaders(t *testing.T) {
	b := &vaultBackend{}
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	// Connection header lists additional headers to remove
	req.Header.Set("Connection", "Custom-Header, Another-Header")
	req.Header.Set("Custom-Header", "value1")
	req.Header.Set("Another-Header", "value2")
	req.Header.Set("Keep-Header", "should-stay")

	b.prepareHeaders(req, "test-token")

	// Connection should be removed
	assert.Empty(t, req.Header.Get("Connection"))

	// Headers listed in Connection should also be removed
	assert.Empty(t, req.Header.Get("Custom-Header"))
	assert.Empty(t, req.Header.Get("Another-Header"))

	// Other headers should remain
	assert.Equal(t, "should-stay", req.Header.Get("Keep-Header"))
	assert.Equal(t, "test-token", req.Header.Get("X-Vault-Token"))
}

func BenchmarkBuildTargetURL(b *testing.B) {
	backend := &vaultBackend{
		vaultAddress: "https://vault.example.com:8200",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.buildTargetURL("/v1/vault/gateway/secret/data/myapp", "version=2")
	}
}

func BenchmarkPrepareHeaders(b *testing.B) {
	backend := &vaultBackend{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.Header.Set("X-Vault-Token", "old-token")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.Header.Set("Content-Type", "application/json")

		backend.prepareHeaders(req, "new-token")
	}
}

func TestPrepareHeaders_EmptyToken(t *testing.T) {
	// Test that prepareHeaders does not set X-Vault-Token when token is empty
	// This is the case for StreamUnauthenticated requests
	b := &vaultBackend{}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	// Set some initial headers including an old token
	req.Header.Set("X-Vault-Token", "old-token-to-remove")
	req.Header.Set("Content-Type", "application/json")

	// Call with empty token (transparent unauthenticated case)
	b.prepareHeaders(req, "")

	// X-Vault-Token should be removed and NOT set again
	assert.Empty(t, req.Header.Get("X-Vault-Token"), "X-Vault-Token should not be set for empty token")

	// Other headers should be preserved
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
}

func TestHandleGateway_StreamUnauthenticated(t *testing.T) {
	// Create a mock upstream Vault server
	upstreamCalled := false
	upstreamReceivedToken := ""
	mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		upstreamReceivedToken = r.Header.Get("X-Vault-Token")
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"))
	}))
	defer mockVault.Close()

	// Create the backend
	b := &vaultBackend{
		vaultAddress: mockVault.URL,
		logger:       createTestLogger(),
		proxy: &httputil.ReverseProxy{
			Director: func(req *http.Request) {},
		},
	}

	tests := []struct {
		name                       string
		transparentUnauthenticated bool
		credential                 *credential.Credential
		expectUpstreamCalled       bool
		expectTokenSent            bool
		expectStatusCode           int
	}{
		{
			name:                       "transparent unauthenticated request - no credential needed",
			transparentUnauthenticated: true,
			credential:                 nil,
			expectUpstreamCalled:       true,
			expectTokenSent:            false,
			expectStatusCode:           http.StatusOK,
		},
		{
			name:                       "authenticated request with credential",
			transparentUnauthenticated: false,
			credential: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "hvs.test-token-123",
				},
			},
			expectUpstreamCalled: true,
			expectTokenSent:      true,
			expectStatusCode:     http.StatusOK,
		},
		{
			name:                       "authenticated request without credential - should fail",
			transparentUnauthenticated: false,
			credential:                 nil,
			expectUpstreamCalled:       false,
			expectTokenSent:            false,
			expectStatusCode:           http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamCalled = false
			upstreamReceivedToken = ""

			// Create request
			httpReq := httptest.NewRequest(http.MethodGet, "/v1/vault/gateway/v1/pki/issuer/abc/pem", nil)
			rr := httptest.NewRecorder()

			req := &logical.Request{
				Path:                       "gateway/v1/pki/issuer/abc/pem",
				HTTPRequest:                httpReq,
				ResponseWriter:             rr,
				Credential:                 tt.credential,
				StreamUnauthenticated: tt.transparentUnauthenticated,
			}

			// Call handleGateway
			b.handleGateway(t.Context(), req)

			// Check results
			assert.Equal(t, tt.expectUpstreamCalled, upstreamCalled, "upstream called mismatch")
			assert.Equal(t, tt.expectStatusCode, rr.Code, "status code mismatch")

			if tt.expectUpstreamCalled {
				if tt.expectTokenSent {
					assert.NotEmpty(t, upstreamReceivedToken, "expected token to be sent")
					assert.Equal(t, "hvs.test-token-123", upstreamReceivedToken)
				} else {
					assert.Empty(t, upstreamReceivedToken, "expected no token to be sent")
				}
			}
		})
	}
}

func TestGetVaultToken_StreamUnauthenticated(t *testing.T) {
	// This test verifies that for StreamUnauthenticated requests,
	// the caller should NOT call getVaultToken (the handleGateway function
	// checks StreamUnauthenticated before calling getVaultToken)

	b := &vaultBackend{}

	// StreamUnauthenticated request with nil credential
	// would fail if getVaultToken is called
	req := &logical.Request{
		Credential:                 nil,
		StreamUnauthenticated: true,
	}

	// This should fail - demonstrating why we skip getVaultToken for StreamUnauthenticated
	_, err := b.getVaultToken(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no credential available")
}
