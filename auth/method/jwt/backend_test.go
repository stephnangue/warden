// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testLogger creates a logger for tests that discards output
func testLogger() *logger.GatedLogger {
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
// Factory Tests
// =============================================================================

func TestFactory_BasicCreation(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Config: nil,
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestFactory_WithEmptyConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Config: map[string]any{},
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestFactory_BackendType(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	assert.Equal(t, "jwt", backend.Type())
}

func TestFactory_SpecialPaths(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	paths := backend.SpecialPaths()
	require.NotNil(t, paths)
	assert.Contains(t, paths.Unauthenticated, "login")
}

// =============================================================================
// JWTAuthConfig Tests
// =============================================================================

func TestJWTAuthConfig_Defaults(t *testing.T) {
	config := &JWTAuthConfig{}
	assert.Empty(t, config.Name)
	assert.Empty(t, config.Mode)
	assert.Empty(t, config.JWKSURL)
	assert.Empty(t, config.OIDCDiscoveryURL)
}

func TestJWTAuthConfig_ModeJWT(t *testing.T) {
	config := &JWTAuthConfig{
		Mode:    "jwt",
		JWKSURL: "https://example.com/.well-known/jwks.json",
	}
	assert.Equal(t, "jwt", config.Mode)
	assert.Equal(t, "https://example.com/.well-known/jwks.json", config.JWKSURL)
}

func TestJWTAuthConfig_ModeOIDC(t *testing.T) {
	config := &JWTAuthConfig{
		Mode:             "oidc",
		OIDCDiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
	}
	assert.Equal(t, "oidc", config.Mode)
	assert.Equal(t, "https://issuer.example.com/.well-known/openid-configuration", config.OIDCDiscoveryURL)
}

func TestJWTAuthConfig_BoundClaims(t *testing.T) {
	config := &JWTAuthConfig{
		BoundClaims: map[string]any{
			"tenant": "acme",
			"role":   "admin",
		},
	}
	assert.Equal(t, "acme", config.BoundClaims["tenant"])
	assert.Equal(t, "admin", config.BoundClaims["role"])
}

func TestJWTAuthConfig_BoundAudiences(t *testing.T) {
	config := &JWTAuthConfig{
		BoundAudiences: []string{"aud1", "aud2"},
	}
	assert.Equal(t, []string{"aud1", "aud2"}, config.BoundAudiences)
}

func TestJWTAuthConfig_ClaimMappings(t *testing.T) {
	config := &JWTAuthConfig{
		ClaimMappings: map[string]string{
			"email": "user_email",
			"name":  "display_name",
		},
	}
	assert.Equal(t, "user_email", config.ClaimMappings["email"])
	assert.Equal(t, "display_name", config.ClaimMappings["name"])
}

// =============================================================================
// setupJWTConfig Tests
// =============================================================================

func TestSetupJWTConfig_InvalidMode(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"mode": "invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

func TestSetupJWTConfig_OIDCMissingDiscoveryURL(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"mode": "oidc",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc_discovery_url is required")
}

func TestSetupJWTConfig_JWTMissingJWKS(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"mode": "jwt",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either jwks_url or jwt_validation_pubkeys is required")
}

func TestSetupJWTConfig_StaticKeysNotImplemented(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"mode":                   "jwt",
		"jwt_validation_pubkeys": []string{"-----BEGIN PUBLIC KEY-----\nMIIB..."},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "static public keys not yet implemented")
}

// =============================================================================
// Initialize Tests
// =============================================================================

func TestInitialize_NoStorageView(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.Initialize(ctx)
	require.NoError(t, err)
}

// =============================================================================
// Backend Interface Tests
// =============================================================================

func TestBackend_ImplementsLogicalBackend(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	// Verify it implements the interface
	var _ logical.Backend = backend
}

func TestBackend_HasCorrectPaths(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	// Check that paths are configured
	require.NotNil(t, b.Backend)
	require.NotEmpty(t, b.Backend.Paths)

	// We should have login and config paths
	pathPatterns := make([]string, 0)
	for _, p := range b.Backend.Paths {
		pathPatterns = append(pathPatterns, p.Pattern)
	}

	assert.Contains(t, pathPatterns, "login")
	assert.Contains(t, pathPatterns, "config")
}

func TestBackend_Class(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	assert.Equal(t, logical.ClassAuth, b.Backend.BackendClass)
}
