// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Factory Tests
// =============================================================================

func TestFactory_BasicCreation(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
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
	assert.Equal(t, "cert", backend.Type())
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
// setupCertConfig token_type Enforcement Tests
// =============================================================================

func TestSetupCertConfig_JWTRoleAlwaysForbidden(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*certAuthBackend)
	_, _, caPEM := testCA(t)
	err = b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem": caPEM,
		"token_type":     "jwt_role",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwt auth backends")
}

func TestSetupCertConfig_CertRoleDefaultsWhenEmpty(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*certAuthBackend)
	_, _, caPEM := testCA(t)
	err = b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem": caPEM,
		// token_type omitted — should default to cert_role
	})
	require.NoError(t, err)
	assert.Equal(t, "cert_role", b.config.TokenType)
}

func TestSetupCertConfig_CertRoleAlwaysAllowed(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*certAuthBackend)
	_, _, caPEM := testCA(t)
	err = b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem": caPEM,
		"token_type":     "cert_role",
	})
	require.NoError(t, err)
	assert.Equal(t, "cert_role", b.config.TokenType)
}
