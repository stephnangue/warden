// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testLoggerConfig creates a logger for tests that discards output
func testLoggerConfig() *logger.GatedLogger {
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

// =============================================================================
// pathConfig Structure Tests
// =============================================================================

func TestPathConfig_Pattern(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	assert.Equal(t, "config", path.Pattern)
}

func TestPathConfig_Fields(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check required fields exist
	expectedFields := []string{
		"oidc_discovery_url",
		"oidc_discovery_ca_pem",
		"jwks_url",
		"jwks_ca_pem",
		"bound_issuer",
		"bound_audiences",
		"bound_subject",
		"user_claim",
		"groups_claim",
		"token_ttl",
		"auth_deadline",
	}

	for _, field := range expectedFields {
		_, exists := path.Fields[field]
		assert.True(t, exists, "Field %s should exist", field)
	}
}

func TestPathConfig_FieldTypes(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	tests := []struct {
		field        string
		expectedType framework.FieldType
	}{
		{"oidc_discovery_url", framework.TypeString},
		{"oidc_discovery_ca_pem", framework.TypeString},
		{"jwks_url", framework.TypeString},
		{"jwks_ca_pem", framework.TypeString},
		{"bound_issuer", framework.TypeString},
		{"bound_audiences", framework.TypeCommaStringSlice},
		{"bound_subject", framework.TypeString},
		{"user_claim", framework.TypeString},
		{"groups_claim", framework.TypeString},
		{"token_ttl", framework.TypeDurationSecond},
		{"auth_deadline", framework.TypeDurationSecond},
	}

	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			field, exists := path.Fields[tc.field]
			require.True(t, exists, "Field %s should exist", tc.field)
			assert.Equal(t, tc.expectedType, field.Type, "Field %s should have correct type", tc.field)
		})
	}
}

func TestPathConfig_DefaultValues(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check defaults
	userClaimField := path.Fields["user_claim"]
	assert.Equal(t, "sub", userClaimField.Default)

	groupsClaimField := path.Fields["groups_claim"]
	assert.Equal(t, "groups", groupsClaimField.Default)
}

func TestPathConfig_Operations(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check operations exist
	_, hasRead := path.Operations[logical.ReadOperation]
	_, hasUpdate := path.Operations[logical.UpdateOperation]

	assert.True(t, hasRead, "Should have read operation")
	assert.True(t, hasUpdate, "Should have update operation")
}

// =============================================================================
// handleConfigRead Tests
// =============================================================================

func TestHandleConfigRead_NoConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	// Ensure config is nil
	b.config = nil

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

func TestHandleConfigRead_WithConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	b.config = &JWTAuthConfig{
		Mode:           "jwt",
		JWKSURL:        "https://example.com/.well-known/jwks.json",
		BoundIssuer:    "https://issuer.example.com",
		BoundAudiences: []string{"aud1", "aud2"},
		BoundSubject:   "expected-subject",
		UserClaim:      "email",
		GroupsClaim:    "roles",
		TokenTTL:       2 * time.Hour,
		AuthDeadline:   30 * time.Minute,
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "jwt", resp.Data["mode"])
	assert.Equal(t, "https://example.com/.well-known/jwks.json", resp.Data["jwks_url"])
	assert.Equal(t, "https://issuer.example.com", resp.Data["bound_issuer"])
	assert.Equal(t, []string{"aud1", "aud2"}, resp.Data["bound_audiences"])
	assert.Equal(t, "expected-subject", resp.Data["bound_subject"])
	assert.Equal(t, "email", resp.Data["user_claim"])
	assert.Equal(t, "roles", resp.Data["groups_claim"])
	assert.Equal(t, "2h0m0s", resp.Data["token_ttl"])
	assert.Equal(t, "30m0s", resp.Data["auth_deadline"])
}

func TestHandleConfigRead_OIDCMode(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	b.config = &JWTAuthConfig{
		Mode:             "oidc",
		OIDCDiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		UserClaim:        "sub",
		GroupsClaim:      "groups",
		TokenTTL:         1 * time.Hour,
		AuthDeadline:     10 * time.Minute,
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "oidc", resp.Data["mode"])
	assert.Equal(t, "https://issuer.example.com/.well-known/openid-configuration", resp.Data["oidc_discovery_url"])
}

// =============================================================================
// handleConfigWrite Tests
// =============================================================================

func TestHandleConfigWrite_MissingRequiredFields(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"mode": "jwt",
			// Missing jwks_url
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should fail because jwks_url is required for JWT mode
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotNil(t, resp.Err)
}

func TestHandleConfigWrite_InvalidMode(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"mode": "invalid",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "invalid mode")
}

func TestHandleConfigWrite_NoModeNoDiscoveryNoJWKS(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			// Mode is required but not provided
			"user_claim": "email",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should fail because mode is required
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "mode is required")
}

// =============================================================================
// Help Text Tests
// =============================================================================

func TestPathConfig_HelpText(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	assert.NotEmpty(t, path.HelpSynopsis)
	assert.NotEmpty(t, path.HelpDescription)
}

// =============================================================================
// Field Description Tests
// =============================================================================

func TestPathConfig_FieldDescriptions(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// All fields should have descriptions
	for name, field := range path.Fields {
		assert.NotEmpty(t, field.Description, "Field %s should have a description", name)
	}
}
