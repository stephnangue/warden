// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// createTestBackendWithAllTokenTypes creates a cert backend that includes
// jwt_role and cert_role in its valid token types.
func createTestBackendWithAllTokenTypes(t *testing.T) (*certAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		Logger:          testLogger(),
		StorageView:     storage,
		ValidTokenTypes: []string{"service", "batch", "user_pass", "aws_access_keys", "warden_token", "jwt_role", "cert_role"},
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	return backend.(*certAuthBackend), ctx
}

// roleFieldData builds a FieldData for role creation with the given raw values.
// Includes a default allowed_common_names constraint to satisfy role validation.
func roleFieldData(raw map[string]any) *framework.FieldData {
	if _, ok := raw["allowed_common_names"]; !ok {
		raw["allowed_common_names"] = []string{"test-*"}
	}
	return &framework.FieldData{
		Raw: raw,
		Schema: map[string]*framework.FieldSchema{
			"name":                 {Type: framework.TypeString},
			"token_type":           {Type: framework.TypeString},
			"token_ttl":            {Type: framework.TypeDurationSecond, Default: 3600},
			"allowed_common_names": {Type: framework.TypeCommaStringSlice},
		},
	}
}

// =============================================================================
// token_type Enforcement Tests
// =============================================================================

func TestPathRole_TokenType_JWTRoleAlwaysForbidden(t *testing.T) {
	b, ctx := createTestBackendWithAllTokenTypes(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	fd := roleFieldData(map[string]any{
		"name":       "jwt-role-test",
		"token_type": "jwt_role",
		"token_ttl":  3600,
	})

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "jwt auth backends")
}

func TestPathRole_TokenType_CertRoleDefaultsWhenEmpty(t *testing.T) {
	b, ctx := createTestBackendWithAllTokenTypes(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	fd := roleFieldData(map[string]any{
		"name":      "cert-default",
		"token_ttl": 3600,
		// token_type intentionally omitted — should default to cert_role
	})

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	role, err := b.getRole(ctx, "cert-default")
	require.NoError(t, err)
	assert.Equal(t, "cert_role", role.TokenType)
}

func TestPathRole_TokenType_CertRoleAlwaysAllowed(t *testing.T) {
	b, ctx := createTestBackendWithAllTokenTypes(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	fd := roleFieldData(map[string]any{
		"name":       "cert-role-explicit",
		"token_type": "transparent",
		"token_ttl":  3600,
	})

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	role, err := b.getRole(ctx, "cert-role-explicit")
	require.NoError(t, err)
	assert.Equal(t, "cert_role", role.TokenType)
}

func TestPathRole_TokenType_OtherTypesAlwaysAllowed(t *testing.T) {
	b, ctx := createTestBackendWithAllTokenTypes(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	for _, tokenType := range []string{"aws", "warden", "service"} {
		t.Run(tokenType, func(t *testing.T) {
			fd := roleFieldData(map[string]any{
				"name":       "mixed-" + tokenType,
				"token_type": tokenType,
				"token_ttl":  3600,
			})

			resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
			require.NoError(t, err)
			assert.Nil(t, resp.Err, "token_type=%q should always be allowed", tokenType)
			assert.Equal(t, http.StatusCreated, resp.StatusCode)
		})
	}
}
