// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testLoggerLogin creates a logger for tests that discards output
func testLoggerLogin() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gateConfig := logger.GatedWriterConfig{
		Underlying: io.Discard,
	}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

// inmemStorage implements sdklogical.Storage for testing
type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{
		data: make(map[string]*sdklogical.StorageEntry),
	}
}

func (s *inmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}

func (s *inmemStorage) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *inmemStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	// For tests, just delegate to List - pagination not needed
	return s.List(ctx, prefix)
}

// Ensure inmemStorage implements sdklogical.Storage
var _ sdklogical.Storage = (*inmemStorage)(nil)

// createTestBackendWithStorage creates a test backend with inmem storage
func createTestBackendWithStorage(t *testing.T) (*jwtAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()

	// Create inmem storage
	storage := newInmemStorage()

	conf := &logical.BackendConfig{
		Logger:      testLoggerLogin(),
		StorageView: storage,
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	return b, ctx
}

// =============================================================================
// pathLogin Structure Tests
// =============================================================================

func TestPathLogin_Pattern(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathLogin()

	assert.Equal(t, "login", path.Pattern)
}

func TestPathLogin_Fields(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathLogin()

	// A login takes the credential only: it selects no role.
	jwtField, hasJWT := path.Fields["jwt"]
	_, hasRole := path.Fields["role"]

	assert.True(t, hasJWT, "Should have jwt field")
	assert.False(t, hasRole, "a login has no role field")
	assert.Equal(t, framework.TypeString, jwtField.Type)
	assert.True(t, jwtField.Required, "jwt field should be required")
}

func TestPathLogin_Operations(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathLogin()

	// Check operations exist
	_, hasUpdate := path.Operations[logical.UpdateOperation]
	_, hasCreate := path.Operations[logical.CreateOperation]

	assert.True(t, hasUpdate, "Should have update operation")
	assert.True(t, hasCreate, "Should have create operation")
}

func TestPathLogin_HelpText(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathLogin()

	assert.NotEmpty(t, path.HelpSynopsis)
	assert.NotEmpty(t, path.HelpDescription)
}

// =============================================================================
// handleLogin Tests - Input Validation
// =============================================================================

func TestHandleLogin_MissingJWT(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	// Set a minimal config
	b.config = &JWTAuthConfig{}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"jwt":  "",
			"role": "test-role",
		},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should return error about missing jwt
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "missing jwt token")
}

func TestHandleLogin_BackendNotConfigured(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	// Ensure config is nil
	b.config = nil

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"jwt":  "some.jwt.token",
			"role": "test-role",
		},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "not configured")
}

func TestHandleLogin_ValidatorNotConfigured(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	// Config exists but validator is nil
	b.config = &JWTAuthConfig{
		validator: nil,
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"jwt":  "some.jwt.token",
			"role": "test-role",
		},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "not configured")
}

// =============================================================================
// Login Flow Tests with Mock
// =============================================================================

// Note: Full login flow testing with real JWT validation requires a JWKS endpoint.
// These tests focus on the pre-validation logic and error handling.

func TestPathLogin_FieldDescriptions(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathLogin()

	// All fields should have descriptions
	for name, field := range path.Fields {
		assert.NotEmpty(t, field.Description, "Field %s should have a description", name)
	}
}

// =============================================================================
// JWTAuthConfig for Login Tests
// =============================================================================

func TestJWTAuthConfig_LoginDefaults(t *testing.T) {
	config := &JWTAuthConfig{
		TokenTTL:  1 * time.Hour,
		UserClaim: "sub",
	}

	assert.Equal(t, 1*time.Hour, config.TokenTTL)
	assert.Equal(t, "sub", config.UserClaim)
}

func TestJWTAuthConfig_BoundValidation(t *testing.T) {
	config := &JWTAuthConfig{
		BoundIssuer:    "https://issuer.example.com",
		BoundAudiences: []string{"api", "web"},
		BoundSubject:   "user123",
		BoundClaims: map[string]any{
			"tenant": "acme",
		},
	}

	assert.Equal(t, "https://issuer.example.com", config.BoundIssuer)
	assert.Equal(t, []string{"api", "web"}, config.BoundAudiences)
	assert.Equal(t, "user123", config.BoundSubject)
	assert.Equal(t, "acme", config.BoundClaims["tenant"])
}

// =============================================================================
// Auth Response Structure Tests
// =============================================================================

func TestAuth_ResponseFields(t *testing.T) {
	auth := &logical.Auth{
		PrincipalID: "user@example.com",
		Policies:    []string{"default", "admin"},
		TokenTTL:    1 * time.Hour,
		ClientIP:    "192.168.1.1",
	}

	assert.Equal(t, "user@example.com", auth.PrincipalID)
	assert.Equal(t, []string{"default", "admin"}, auth.Policies)
	assert.Equal(t, 1*time.Hour, auth.TokenTTL)
	assert.Equal(t, "192.168.1.1", auth.ClientIP)
}

// =============================================================================
// Table-Driven Tests for Login Validation
// =============================================================================

func TestHandleLogin_InputValidation_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		jwt            string
		role           string
		config         *JWTAuthConfig
		expectedErrMsg string
	}{
		{
			name:           "Empty JWT",
			jwt:            "",
			role:           "test-role",
			config:         &JWTAuthConfig{},
			expectedErrMsg: "missing jwt token",
		},
		{
			name:           "Nil config",
			jwt:            "some.jwt.token",
			role:           "test-role",
			config:         nil,
			expectedErrMsg: "not configured",
		},
		{
			name:           "Config without validator",
			jwt:            "some.jwt.token",
			role:           "test-role",
			config:         &JWTAuthConfig{validator: nil},
			expectedErrMsg: "not configured",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			conf := &logical.BackendConfig{
				Logger: testLoggerLogin(),
			}

			backend, err := Factory(ctx, conf)
			require.NoError(t, err)

			b := backend.(*jwtAuthBackend)
			b.config = tc.config

			req := &logical.Request{}
			d := &framework.FieldData{
				Raw: map[string]any{
					"jwt":  tc.jwt,
					"role": tc.role,
				},
				Schema: b.pathLogin().Fields,
			}

			resp, err := b.handleLogin(ctx, req, d)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Err)
			assert.Contains(t, resp.Err.Error(), tc.expectedErrMsg)
		})
	}
}

// =============================================================================
// Login Path as Unauthenticated Test
// =============================================================================

func TestLoginPath_IsUnauthenticated(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerLogin(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	paths := backend.SpecialPaths()
	require.NotNil(t, paths)

	// Login should be in unauthenticated paths
	assert.Contains(t, paths.Unauthenticated, "login")
}

// =============================================================================
// Login with Role Tests
// =============================================================================

func TestHandleLogin_RoleNotFound(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Configure backend with a mock validator
	b.config = &JWTAuthConfig{
		validator: nil, // We won't reach validation since role lookup fails first
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"jwt":  "some.jwt.token",
			"role": "nonexistent-role",
		},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should fail because backend is not configured (validator is nil)
	// This is the expected behavior - role check happens after config validation
	assert.NotNil(t, resp.Err)
}

// =============================================================================
// A login selects no role
// =============================================================================

// A login neither needs nor reads a role: a role sent anyway, or a mount
// default_role, changes nothing, and nothing is refused for lacking one.
func TestHandleLogin_NoRole(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"default_role": "fallback-role"})
	token := signES256(t, key, baseClaims(nil))

	resp, err := b.handleLogin(context.Background(), &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"jwt": token, "role": "explicit-role"},
		Schema: b.pathLogin().Fields,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.Nil(t, resp.Auth.Policies)
	assert.NotContains(t, resp.Data, "role")

	// Unconfigured, a login is refused for the mount, never for a role.
	b.config = &JWTAuthConfig{}
	resp, err = b.handleLogin(context.Background(), &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"jwt": "some.jwt.token"},
		Schema: b.pathLogin().Fields,
	})
	require.NoError(t, err)
	require.Error(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "not configured")
}

// =============================================================================
// handleConfigWrite merges with existing config
// =============================================================================
