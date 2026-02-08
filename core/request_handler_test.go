package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleRequest_SealedCore tests that requests are rejected when core is sealed
func TestHandleRequest_SealedCore(t *testing.T) {
	core := createTestCore(t)

	// Seal the core
	core.Seal()

	req := &logical.Request{
		Path:        "sys/mounts",
		Operation:   logical.ReadOperation,
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/v1/sys/mounts", nil),
	}

	resp, err := core.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestHandleRequest_NamespaceNotFound tests that requests fail when namespace is not found
func TestHandleRequest_NamespaceNotFound(t *testing.T) {
	core := createTestCore(t)

	req := &logical.Request{
		Path:        "nonexistent-ns/sys/mounts",
		Operation:   logical.ReadOperation,
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/v1/nonexistent-ns/sys/mounts", nil),
	}

	resp, err := core.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestHandleRequest_NoHandlerForPath tests that requests fail when no backend handles the path
func TestHandleRequest_NoHandlerForPath(t *testing.T) {
	core := createTestCore(t)

	req := &logical.Request{
		Path:        "nonexistent/path",
		Operation:   logical.ReadOperation,
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/v1/nonexistent/path", nil),
	}

	resp, err := core.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestHandleRequest_RestrictedSysAPIs tests that restricted sys APIs are blocked in non-root namespaces
func TestHandleRequest_RestrictedSysAPIs(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// First create a child namespace
	childNs := &namespace.Namespace{
		Path: "child/",
	}
	err := core.namespaceStore.SetNamespace(ctx, childNs)
	require.NoError(t, err)

	// Try to access restricted API in child namespace
	req := &logical.Request{
		Path:        "child/sys/seal",
		Operation:   logical.UpdateOperation,
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/v1/child/sys/seal", nil),
	}

	resp, err := core.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestHandleRequest_NamespaceHeader tests that X-Warden-Namespace header is respected
func TestHandleRequest_NamespaceHeader(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a child namespace
	testNs := &namespace.Namespace{
		Path: "test-ns/",
	}
	err := core.namespaceStore.SetNamespace(ctx, testNs)
	require.NoError(t, err)

	// Request with namespace header - sys/namespaces requires auth
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/namespaces", nil)
	httpReq.Header.Set("X-Warden-Namespace", "test-ns")

	req := &logical.Request{
		Path:        "sys/namespaces",
		Operation:   logical.ListOperation,
		HTTPRequest: httpReq,
	}

	resp, err := core.HandleRequest(context.Background(), req)
	// The request should be processed (namespace header respected)
	// It may fail with permission denied since we don't have a token
	// The key thing is that the namespace was resolved correctly
	require.NotNil(t, resp)
	// Either succeeds, permission denied, or error - all are acceptable
	// as long as we didn't get "namespace not found"
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
		"namespace should have been found via header")
	_ = err // err may contain permission denied
}

// TestParseRequestBody tests the parseRequestBody function
func TestParseRequestBody(t *testing.T) {
	core := createTestCore(t)

	t.Run("nil HTTPRequest", func(t *testing.T) {
		req := &logical.Request{}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Nil(t, req.Data)
	})

	t.Run("query params only", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/v1/test?foo=bar&baz=qux", nil)
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Equal(t, "bar", req.Data["foo"])
		assert.Equal(t, "qux", req.Data["baz"])
	})

	t.Run("multiple values for same param", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/v1/test?tags=a&tags=b&tags=c", nil)
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		tags, ok := req.Data["tags"].([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"a", "b", "c"}, tags)
	})

	t.Run("GET request ignores body", func(t *testing.T) {
		body := `{"should": "be ignored"}`
		httpReq := httptest.NewRequest(http.MethodGet, "/v1/test?query=value", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Equal(t, "value", req.Data["query"])
		assert.Nil(t, req.Data["should"])
	})

	t.Run("DELETE request ignores body", func(t *testing.T) {
		body := `{"should": "be ignored"}`
		httpReq := httptest.NewRequest(http.MethodDelete, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Nil(t, req.Data["should"])
	})

	t.Run("POST request parses JSON body", func(t *testing.T) {
		body := `{"name": "test", "value": 123}`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Equal(t, "test", req.Data["name"])
		assert.Equal(t, float64(123), req.Data["value"])
	})

	t.Run("PUT request parses JSON body", func(t *testing.T) {
		body := `{"key": "updated"}`
		httpReq := httptest.NewRequest(http.MethodPut, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Equal(t, "updated", req.Data["key"])
	})

	t.Run("body overwrites query params", func(t *testing.T) {
		body := `{"name": "from-body"}`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test?name=from-query", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		assert.Equal(t, "from-body", req.Data["name"])
	})

	t.Run("empty body is OK", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(""))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
	})

	t.Run("non-JSON content type is skipped", func(t *testing.T) {
		body := `name=test&value=123`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)
		// Body should not be parsed
		assert.Nil(t, req.Data["name"])
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		body := `{"invalid json`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.Error(t, err)
	})

	t.Run("body is restored after reading", func(t *testing.T) {
		body := `{"test": "data"}`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
		}
		err := core.parseRequestBody(req)
		require.NoError(t, err)

		// Body should be re-readable
		restoredBody, err := io.ReadAll(req.HTTPRequest.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(restoredBody))
	})
}

// TestParseJSONBody tests the parseJSONBody function
func TestParseJSONBody(t *testing.T) {
	core := createTestCore(t)

	t.Run("nil body", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", nil)
		req := &logical.Request{
			HTTPRequest: httpReq,
			Data:        make(map[string]any),
		}
		err := core.parseJSONBody(req)
		require.NoError(t, err)
	})

	t.Run("complex JSON object", func(t *testing.T) {
		body := `{
			"string": "value",
			"number": 42,
			"float": 3.14,
			"bool": true,
			"null": null,
			"array": [1, 2, 3],
			"nested": {"key": "value"}
		}`
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			HTTPRequest: httpReq,
			Data:        make(map[string]any),
		}
		err := core.parseJSONBody(req)
		require.NoError(t, err)

		assert.Equal(t, "value", req.Data["string"])
		assert.Equal(t, float64(42), req.Data["number"])
		assert.Equal(t, 3.14, req.Data["float"])
		assert.Equal(t, true, req.Data["bool"])
		assert.Nil(t, req.Data["null"])
		assert.Equal(t, []interface{}{float64(1), float64(2), float64(3)}, req.Data["array"])
		nested, ok := req.Data["nested"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "value", nested["key"])
	})
}

// TestIsStreamingRequest tests the isStreamingRequest function
func TestIsStreamingRequest(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Mount a backend with streaming paths
	backend := &mockBackendWithStreamingPaths{}
	entry := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		Class:       mountClassProvider,
		UUID:        "aws-uuid",
		Accessor:    "aws_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/aws-uuid/"}
	err := core.router.Mount("aws/", backend, entry, view)
	require.NoError(t, err)

	t.Run("streaming path returns true", func(t *testing.T) {
		isStreaming := core.isStreamingRequest(ctx, "aws/gateway/s3/bucket")
		assert.True(t, isStreaming)
	})

	t.Run("non-streaming path returns false", func(t *testing.T) {
		isStreaming := core.isStreamingRequest(ctx, "aws/config")
		assert.False(t, isStreaming)
	})

	t.Run("non-existent path returns false", func(t *testing.T) {
		isStreaming := core.isStreamingRequest(ctx, "nonexistent/path")
		assert.False(t, isStreaming)
	})
}

// TestCheckToken_UnauthenticatedRequest tests CheckToken with unauthenticated requests
func TestCheckToken_UnauthenticatedRequest(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("unauthenticated without token succeeds", func(t *testing.T) {
		req := &logical.Request{
			Path:      "auth/jwt/login",
			Operation: logical.UpdateOperation,
		}
		auth, cbp, te, err := core.CheckToken(ctx, req, true)
		require.NoError(t, err)
		require.NotNil(t, auth)
		assert.Nil(t, cbp)
		assert.Nil(t, te)
	})
}

// TestCheckToken_MissingToken tests CheckToken when token is required but missing
func TestCheckToken_MissingToken(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{
		Path:        "sys/mounts",
		Operation:   logical.ReadOperation,
		ClientToken: "",
	}
	_, _, _, err := core.CheckToken(ctx, req, false)
	require.Error(t, err)
}

// TestPopulateTokenEntry tests the PopulateTokenEntry function
func TestPopulateTokenEntry(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("empty token does nothing", func(t *testing.T) {
		req := &logical.Request{
			ClientToken: "",
		}
		err := core.PopulateTokenEntry(ctx, req)
		require.NoError(t, err)
		assert.Empty(t, req.ClientTokenAccessor)
		assert.Empty(t, req.ClientTokenID)
	})

	t.Run("invalid token does not error", func(t *testing.T) {
		req := &logical.Request{
			ClientToken: "invalid-token",
		}
		err := core.PopulateTokenEntry(ctx, req)
		require.NoError(t, err)
		// Token entry not found, but no error
	})
}

// TestLoginCreateToken tests the LoginCreateToken function
func TestLoginCreateToken(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("root token rejected", func(t *testing.T) {
		resp := &logical.Response{
			Auth: &logical.Auth{
				Policies: []string{"root"},
			},
		}
		result, err := core.LoginCreateToken(ctx, resp)
		require.Error(t, err)
		require.NotNil(t, result)
		assert.Equal(t, http.StatusForbidden, result.StatusCode)
	})

	t.Run("non-assignable policy rejected", func(t *testing.T) {
		resp := &logical.Response{
			Auth: &logical.Auth{
				Policies: []string{"response-wrapping"},
			},
		}
		result, err := core.LoginCreateToken(ctx, resp)
		require.Error(t, err)
		require.NotNil(t, result)
		// Should be forbidden (403) for policy rejection
		assert.True(t, result.StatusCode == http.StatusForbidden || result.StatusCode == http.StatusInternalServerError,
			"expected Forbidden or InternalServerError, got %d", result.StatusCode)
	})
}

// TestHandleLoginRequest tests the handleLoginRequest function
func TestHandleLoginRequest(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("sets unauthenticated flag", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/auth/test/login", bytes.NewReader([]byte(`{}`)))
		httpReq.Header.Set("Content-Type", "application/json")
		req := &logical.Request{
			Path:        "sys/namespaces",
			Operation:   logical.ListOperation,
			HTTPRequest: httpReq,
		}

		resp, auth, err := core.handleLoginRequest(ctx, req)
		// The path might not exist, but we're testing that Unauthenticated is set
		assert.True(t, req.Unauthenticated)
		// Response depends on whether the path exists
		_ = resp
		_ = auth
		_ = err
	})
}

// TestHandleNonLoginRequest_ParsesBody tests that handleNonLoginRequest parses body before CheckToken
func TestHandleNonLoginRequest_ParsesBody(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	body := `{"key": "value"}`
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sys/test", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	req := &logical.Request{
		Path:        "sys/test",
		Operation:   logical.CreateOperation,
		HTTPRequest: httpReq,
	}

	// This will fail due to missing token, but req.Data should be populated
	_, _, _ = core.handleNonLoginRequest(ctx, req)

	// Verify body was parsed
	assert.Equal(t, "value", req.Data["key"])
}

// TestMintCredentialForRequest tests the mintCredentialForRequest function
func TestMintCredentialForRequest(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("nil token entry returns error", func(t *testing.T) {
		req := &logical.Request{}
		err := core.mintCredentialForRequest(ctx, req, nil)
		// The implementation returns an error for nil token entry
		require.Error(t, err)
		assert.Nil(t, req.Credential)
	})

	t.Run("empty credential spec returns error", func(t *testing.T) {
		req := &logical.Request{}
		te := &logical.TokenEntry{
			ID:             "test-token",
			CredentialSpec: "",
		}
		err := core.mintCredentialForRequest(ctx, req, te)
		// The implementation returns an error when credential spec is empty
		require.Error(t, err)
		assert.Nil(t, req.Credential)
	})
}

// TestLogical_ErrorResponse_StatusCodes tests that ErrorResponse returns correct status codes
func TestLogical_ErrorResponse_StatusCodes(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "service unavailable",
			err:            logical.ErrServiceUnavailable("service down"),
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "not found",
			err:            logical.ErrNotFound("not found"),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "bad request",
			err:            logical.ErrBadRequest("invalid input"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "forbidden",
			err:            logical.ErrForbidden("access denied"),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "internal error",
			err:            logical.ErrInternal("internal error"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "conflict",
			err:            logical.ErrConflict("conflict"),
			expectedStatus: http.StatusConflict,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := logical.ErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// TestRestrictedSysAPIs_Paths tests that restrictedSysAPIs contains expected paths
func TestRestrictedSysAPIs_Paths(t *testing.T) {
	restrictedPaths := []string{
		"seal",
		"unseal",
		"init",
		"audit",
		"key-status",
		"rotate",
	}

	for _, path := range restrictedPaths {
		t.Run(path, func(t *testing.T) {
			assert.True(t, restrictedSysAPIs.HasPathSegments(path),
				"path %s should be restricted", path)
		})
	}
}

// TestRestrictedSysAPIs_AllowedPaths tests that non-restricted paths are allowed
func TestRestrictedSysAPIs_AllowedPaths(t *testing.T) {
	allowedPaths := []string{
		"namespaces",
		"providers",
		"auth",
		"policies",
		"credentials",
	}

	for _, path := range allowedPaths {
		t.Run(path, func(t *testing.T) {
			assert.False(t, restrictedSysAPIs.HasPathSegments(path),
				"path %s should be allowed", path)
		})
	}
}

// mockTransparentModeProvider implements both logical.Backend and logical.TransparentModeProvider
type mockTransparentModeProvider struct {
	mockProvider
	transparentMode bool
	autoAuthPath    string
	defaultRole     string
}

func (m *mockTransparentModeProvider) IsTransparentMode() bool {
	return m.transparentMode
}

func (m *mockTransparentModeProvider) GetAutoAuthPath() string {
	return m.autoAuthPath
}

func (m *mockTransparentModeProvider) GetTransparentRole(path string) string {
	// Simple pattern matching for testing: role/{role}/gateway...
	if strings.HasPrefix(path, "role/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 && parts[2] == "gateway" {
			return parts[1]
		}
	}
	return m.defaultRole
}

func (m *mockTransparentModeProvider) IsUnauthenticatedPath(path string) bool {
	// Default to requiring auth for tests
	return false
}

func (m *mockTransparentModeProvider) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Stream: []string{
			"gateway/*",
			"role/*/gateway/*",
		},
	}
}

// TestIsTransparentRequest tests the isTransparentRequest function
func TestIsTransparentRequest(t *testing.T) {
	core := createTestCore(t)

	t.Run("returns false for non-TransparentModeProvider backend", func(t *testing.T) {
		backend := &mockProvider{}
		req := &logical.Request{Path: "role/terraform/gateway/v1/secret"}

		isTransparent, role := core.isTransparentRequest(req, backend)
		assert.False(t, isTransparent)
		assert.Empty(t, role)
	})

	t.Run("returns false when transparent mode is disabled", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: false,
			autoAuthPath:    "auth/jwt/",
			defaultRole:     "default",
		}
		req := &logical.Request{Path: "role/terraform/gateway/v1/secret"}

		isTransparent, role := core.isTransparentRequest(req, backend)
		assert.False(t, isTransparent)
		assert.Empty(t, role)
	})

	t.Run("returns false when path does not match transparent pattern", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
			defaultRole:     "", // No default role
		}
		req := &logical.Request{Path: "config"}

		isTransparent, role := core.isTransparentRequest(req, backend)
		assert.False(t, isTransparent)
		assert.Empty(t, role)
	})

	t.Run("returns true with role for matching path", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
		}
		req := &logical.Request{Path: "role/terraform/gateway/v1/secret/data/foo"}

		isTransparent, role := core.isTransparentRequest(req, backend)
		assert.True(t, isTransparent)
		assert.Equal(t, "terraform", role)
	})

	t.Run("returns true with default role when path does not match but default is set", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
			defaultRole:     "default-role",
		}
		req := &logical.Request{Path: "gateway/v1/secret"}

		isTransparent, role := core.isTransparentRequest(req, backend)
		assert.True(t, isTransparent)
		assert.Equal(t, "default-role", role)
	})
}

// TestHandleTransparentAuth tests the handleTransparentAuth function
func TestHandleTransparentAuth(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("returns error when no token provided", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
		}
		req := &logical.Request{
			ClientToken: "",
		}

		err := core.handleTransparentAuth(ctx, req, backend, "terraform")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no token provided")
	})

	t.Run("returns error for non-JWT token", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
		}
		req := &logical.Request{
			ClientToken: "cws.not-a-jwt-token",
		}

		err := core.handleTransparentAuth(ctx, req, backend, "terraform")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transparent mode requires a JWT token")
	})

	t.Run("uses existing JWT token when found in cache", func(t *testing.T) {
		// Create a JWT token using GenerateToken with the jwt_role type
		sampleJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.test-sig"

		authData := &AuthData{
			TokenValue:     sampleJWT,
			RoleName:       "terraform",
			PrincipalID:    "test-user",
			ExpireAt:       time.Now().Add(24 * time.Hour),
			Policies:       []string{"default"},
			CredentialSpec: "test-spec",
		}
		te, err := core.tokenStore.GenerateToken(ctx, TypeJWTRole, authData)
		require.NoError(t, err)
		require.NotNil(t, te)

		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
		}
		req := &logical.Request{
			ClientToken: sampleJWT,
		}

		err = core.handleTransparentAuth(ctx, req, backend, "terraform")
		require.NoError(t, err)
		assert.NotNil(t, req.TokenEntry())
		assert.Equal(t, te.ID, req.TokenEntry().ID)
	})

	t.Run("returns error when implicit auth fails - auth backend not mounted", func(t *testing.T) {
		backend := &mockTransparentModeProvider{
			transparentMode: true,
			autoAuthPath:    "auth/jwt/",
		}
		// Use a JWT that won't be found in the token store
		req := &logical.Request{
			ClientToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/v1/vault/role/terraform/gateway", nil),
		}

		err := core.handleTransparentAuth(ctx, req, backend, "terraform")
		// Should fail because the auth backend is not mounted
		require.Error(t, err)
	})
}

// TestHandleTransparentAuth_Singleflight tests that concurrent requests with the same JWT token
// all resolve to the same cached token entry
func TestHandleTransparentAuth_Singleflight(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a JWT token using GenerateToken
	sampleJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzaW5nbGVmbGlnaHQtdXNlciJ9.test-sig"

	authData := &AuthData{
		TokenValue:     sampleJWT,
		RoleName:       "terraform",
		PrincipalID:    "test-user-singleflight",
		ExpireAt:       time.Now().Add(24 * time.Hour),
		Policies:       []string{"default"},
		CredentialSpec: "test-spec",
	}
	te, err := core.tokenStore.GenerateToken(ctx, TypeJWTRole, authData)
	require.NoError(t, err)
	require.NotNil(t, te)

	backend := &mockTransparentModeProvider{
		transparentMode: true,
		autoAuthPath:    "auth/jwt/",
	}

	// Simulate multiple concurrent requests with the same JWT token
	const numGoroutines = 10
	var wg sync.WaitGroup
	results := make(chan *TokenEntry, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &logical.Request{
				ClientToken: sampleJWT,
			}
			err := core.handleTransparentAuth(ctx, req, backend, "terraform")
			if err != nil {
				errors <- err
				return
			}
			results <- req.TokenEntry()
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// Check no errors occurred
	for err := range errors {
		t.Errorf("unexpected error: %v", err)
	}

	// All requests should get the same token (verified by ID and accessor)
	var firstTE *TokenEntry
	resultCount := 0
	for result := range results {
		resultCount++
		if firstTE == nil {
			firstTE = result
		} else {
			// Check same ID - proves all requests resolved to the same token
			assert.Equal(t, firstTE.ID, result.ID, "all requests should get the same token ID")
			assert.Equal(t, firstTE.Accessor, result.Accessor, "all requests should get the same token accessor")
		}
	}

	// Verify we got results from all goroutines
	assert.Equal(t, numGoroutines, resultCount, "should have received results from all goroutines")
}

// TestHandleTransparentAuth_JWTDifferentRoles tests that the same JWT with different roles
// produces different tokens, preventing JWT+Role1 from being reused for JWT+Role2
func TestHandleTransparentAuth_JWTDifferentRoles(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Sample JWT for testing (format is valid but signature is not verified in tests)
	sampleJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

	t.Run("same JWT with different roles should produce different token IDs", func(t *testing.T) {
		jwtType := &JWTRoleTokenType{}

		// Create token for JWT + Role1
		entry1 := &TokenEntry{
			Data: map[string]string{},
		}
		authData1 := &AuthData{
			TokenValue:  sampleJWT,
			RoleName:    "role1",
			PrincipalID: "test-user",
			ExpireAt:    time.Now().Add(1 * time.Hour),
			Policies:    []string{"policy1"},
		}
		_, err := jwtType.Generate(authData1, entry1)
		require.NoError(t, err)
		id1 := jwtType.ComputeID(entry1.Data["jwt"])

		// Create token for JWT + Role2
		entry2 := &TokenEntry{
			Data: map[string]string{},
		}
		authData2 := &AuthData{
			TokenValue:  sampleJWT,
			RoleName:    "role2",
			PrincipalID: "test-user",
			ExpireAt:    time.Now().Add(1 * time.Hour),
			Policies:    []string{"policy2"},
		}
		_, err = jwtType.Generate(authData2, entry2)
		require.NoError(t, err)
		id2 := jwtType.ComputeID(entry2.Data["jwt"])

		// The token IDs should be different
		assert.NotEqual(t, id1, id2, "Same JWT with different roles should have different token IDs")
	})

	t.Run("LookupJWTTokenWithRole returns error for non-existent token", func(t *testing.T) {
		sampleJWT2 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"

		// Looking up a token that doesn't exist should return an error
		_, err := core.LookupJWTTokenWithRole(ctx, sampleJWT2, "terraform")
		assert.Error(t, err, "Looking up non-existent JWT token should return error")

		// Looking up with different role should also fail
		_, err = core.LookupJWTTokenWithRole(ctx, sampleJWT2, "different-role")
		assert.Error(t, err, "Looking up with different role should not find the token")
	})

	t.Run("ComputeData and ComputeID match token creation ID", func(t *testing.T) {
		jwtType := &JWTRoleTokenType{}

		// Simulate token creation: Generate stores hash of JWT+role in entry.Data["jwt"]
		entry := &TokenEntry{
			Data: map[string]string{},
		}
		authData := &AuthData{TokenValue: sampleJWT, RoleName: "terraform"}
		jwtType.Generate(authData, entry)

		// Verify the stored value is a hash of JWT+role (not raw value)
		expectedHash := sha256.Sum256([]byte(sampleJWT + ":terraform"))
		assert.Equal(t, hex.EncodeToString(expectedHash[:]), entry.Data["jwt"])

		// Token ID is computed from the stored hash
		tokenID := jwtType.ComputeID(entry.Data["jwt"])

		// Lookup: hash first, then compute ID - should match
		lookupHash := jwtType.ComputeData(sampleJWT, "terraform")
		lookupID := jwtType.ComputeID(lookupHash)

		assert.Equal(t, tokenID, lookupID, "Token creation and lookup should produce same ID")
	})
}
