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

// createTestBackend creates a cert backend for testing.
func createTestBackend(t *testing.T) (*certAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		Logger:      testLogger(),
		StorageView: storage,
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
			"token_ttl":            {Type: framework.TypeDurationSecond, Default: 3600},
			"allowed_common_names": {Type: framework.TypeCommaStringSlice},
		},
	}
}

func TestPathRole_TokenTypeAlwaysCertRole(t *testing.T) {
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	fd := roleFieldData(map[string]any{
		"name":      "cert-default",
		"token_ttl": 3600,
	})

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	role, err := b.getRole(ctx, "cert-default")
	require.NoError(t, err)
	assert.Equal(t, "cert_role", role.TokenType)
}
