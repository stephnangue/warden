// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

func TestPathIntrospect_Structure(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	p := b.pathIntrospect()

	assert.Equal(t, "introspect/roles", p.Pattern)
	_, hasRead := p.Operations[logical.ReadOperation]
	assert.True(t, hasRead)
}

func TestHandleIntrospect_NoConfig(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)
	b.config = nil

	resp, err := b.handleIntrospectRoles(ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

func TestHandleIntrospect_NoValidator(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)
	b.config = &JWTAuthConfig{}

	resp, err := b.handleIntrospectRoles(ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

func TestExtractJWTFromRequest(t *testing.T) {
	t.Run("from Authorization header", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/foo", nil)
		httpReq.Header.Set("Authorization", "Bearer eyJ.payload.sig")
		got := extractJWTFromRequest(&logical.Request{HTTPRequest: httpReq})
		assert.Equal(t, "eyJ.payload.sig", got)
	})

	t.Run("no Bearer prefix → empty", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/foo", nil)
		httpReq.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		got := extractJWTFromRequest(&logical.Request{HTTPRequest: httpReq})
		assert.Equal(t, "", got)
	})

	t.Run("falls back to ClientToken when no HTTP request", func(t *testing.T) {
		got := extractJWTFromRequest(&logical.Request{ClientToken: "eyJ.from.aggregator"})
		assert.Equal(t, "eyJ.from.aggregator", got)
	})

	t.Run("empty when neither present", func(t *testing.T) {
		got := extractJWTFromRequest(&logical.Request{})
		assert.Equal(t, "", got)
	})
}

func TestMatchRole_EmptyConstraintsMatchAnyClaims(t *testing.T) {
	claims := map[string]any{"sub": "alice", "email": "alice@example.com"}
	role := &JWTRole{Name: "any"}

	assert.NoError(t, matchRole(claims, nil, role))
}

func TestMatchRole_ConfigBoundClaimMismatch(t *testing.T) {
	claims := map[string]any{"sub": "alice", "dept": "eng"}
	configBound := map[string]any{"dept": "sales"}

	err := matchRole(claims, configBound, &JWTRole{Name: "r"})
	assert.Error(t, err)
}

func TestMatchRole_RoleBoundClaimMismatch(t *testing.T) {
	claims := map[string]any{"sub": "alice", "dept": "eng"}
	role := &JWTRole{Name: "r", BoundClaims: map[string]any{"dept": "sales"}}

	err := matchRole(claims, nil, role)
	assert.Error(t, err)
}

func TestMatchRole_RoleBoundClaimMatches(t *testing.T) {
	claims := map[string]any{"sub": "alice", "dept": "eng"}
	role := &JWTRole{Name: "r", BoundClaims: map[string]any{"dept": "eng"}}

	assert.NoError(t, matchRole(claims, nil, role))
}

func TestMatchRole_URIPatternMismatch(t *testing.T) {
	claims := map[string]any{"sub": "spiffe://other/ns/foo"}
	role := &JWTRole{
		Name:             "r",
		BoundURIPatterns: []string{"spiffe://trusted/ns/*"},
	}

	err := matchRole(claims, nil, role)
	assert.Error(t, err)
}

func TestMatchRole_URIPatternMatches(t *testing.T) {
	claims := map[string]any{"sub": "spiffe://trusted/ns/foo"}
	role := &JWTRole{
		Name:             "r",
		BoundURIPatterns: []string{"spiffe://trusted/ns/*"},
	}

	assert.NoError(t, matchRole(claims, nil, role))
}

func TestMatchRole_URIPatternUsesConfiguredClaim(t *testing.T) {
	claims := map[string]any{"sub": "alice", "spiffe_id": "spiffe://trusted/ns/foo"}
	role := &JWTRole{
		Name:             "r",
		URIClaim:         "spiffe_id",
		BoundURIPatterns: []string{"spiffe://trusted/ns/*"},
	}

	assert.NoError(t, matchRole(claims, nil, role))
}

