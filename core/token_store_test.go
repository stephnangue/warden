// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenStore_GenerateToken tests token generation
func TestTokenStore_GenerateToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
		Policies:     []string{"default", "admin"},
		ClientIP:     "192.168.1.100",
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ID)
	assert.NotEmpty(t, entry.Accessor)
	assert.Equal(t, TypeUserPass, entry.Type)
	assert.Equal(t, "test-user", entry.PrincipalID)
	assert.Equal(t, "test-role", entry.RoleName)
	assert.Equal(t, namespace.RootNamespaceID, entry.NamespaceID)
	assert.Equal(t, []string{"default", "admin"}, entry.Policies)
	assert.Equal(t, "192.168.1.100", entry.CreatedByIP)
}

// TestTokenStore_GenerateToken_DifferentTypes tests token generation for different token types
func TestTokenStore_GenerateToken_DifferentTypes(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	tests := []struct {
		name      string
		tokenType string
	}{
		{"UserPass", TypeUserPass},
		{"AWSAccessKeys", TypeAWSAccessKeys},
		{"WardenToken", TypeWardenToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authData := &AuthData{
				PrincipalID:  "test-user-" + tt.tokenType,
				RoleName:     "test-role",
						ExpireAt:     time.Now().Add(24 * time.Hour),
			}

			entry, err := core.tokenStore.GenerateToken(ctx, tt.tokenType, authData)
			require.NoError(t, err)
			require.NotNil(t, entry)
			assert.Equal(t, tt.tokenType, entry.Type)
		})
	}
}

// TestTokenStore_GenerateToken_UnsupportedType tests generating with unsupported token type
func TestTokenStore_GenerateToken_UnsupportedType(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	_, err := core.tokenStore.GenerateToken(ctx, "unsupported_type", authData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported token type")
}

// TestTokenStore_GenerateToken_NilAuthData tests generating with nil auth data
func TestTokenStore_GenerateToken_NilAuthData(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authData cannot be nil")
}

// TestTokenStore_GenerateToken_NoNamespace tests generating without namespace in context
func TestTokenStore_GenerateToken_NoNamespace(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	_, err := core.tokenStore.GenerateToken(context.Background(), TypeUserPass, authData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace not found")
}

// TestTokenStore_ResolveToken tests token resolution
func TestTokenStore_ResolveToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue)

	// Resolve token
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
	assert.Equal(t, "test-role", roleName)
}

// TestTokenStore_ResolveToken_NotFound tests resolving a non-existent token
func TestTokenStore_ResolveToken_NotFound(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	_, _, err := core.tokenStore.ResolveToken(ctx, "nonexistent_token")
	require.Error(t, err)
}

// TestTokenStore_ResolveToken_Expired tests resolving an expired token
func TestTokenStore_ResolveToken_Expired(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(-1 * time.Hour), // Already expired
	}

	_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token already expired")
}

// TestTokenStore_LookupToken tests the LookupToken function with security checks
func TestTokenStore_LookupToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
		Policies:     []string{"default"},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue)

	// Lookup token
	lookedUpEntry, err := core.LookupToken(ctx, tokenValue)
	require.NoError(t, err)
	require.NotNil(t, lookedUpEntry)

	assert.Equal(t, entry.ID, lookedUpEntry.ID)
	assert.Equal(t, entry.Accessor, lookedUpEntry.Accessor)
	assert.Equal(t, entry.PrincipalID, lookedUpEntry.PrincipalID)
	assert.Equal(t, entry.RoleName, lookedUpEntry.RoleName)
	assert.Equal(t, entry.Policies, lookedUpEntry.Policies)
}

// TestTokenStore_LookupToken_NotFound tests looking up a non-existent token
func TestTokenStore_LookupToken_NotFound(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	_, err := core.LookupToken(ctx, "nonexistent_token")
	require.Error(t, err)
}

// TestTokenStore_LookupToken_Expired tests looking up an expired token
func TestTokenStore_LookupToken_Expired(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(50 * time.Millisecond), // Short expiration
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Wait for token to expire
	time.Sleep(100 * time.Millisecond)

	_, err = core.LookupToken(ctx, tokenValue)
	require.Error(t, err)
	assert.Equal(t, ErrTokenExpired, err)
}

// TestTokenStore_LookupToken_SameOriginViolation tests same-origin policy enforcement
func TestTokenStore_LookupToken_SameOriginViolation(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
		ClientIP:     "192.168.1.100",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Lookup with different IP
	ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.200")
	_, err = core.LookupToken(ctxWithIP, tokenValue)
	require.Error(t, err)
	assert.Equal(t, ErrOriginViolation, err)
}

// TestTokenStore_LookupToken_SameOriginPass tests same-origin policy with matching IP
func TestTokenStore_LookupToken_SameOriginPass(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
		ClientIP:     "192.168.1.100",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Lookup with same IP
	ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.100")
	lookedUpEntry, err := core.LookupToken(ctxWithIP, tokenValue)
	require.NoError(t, err)
	require.NotNil(t, lookedUpEntry)
}

// TestTokenStore_LookupToken_NoNamespace tests looking up without namespace in context
func TestTokenStore_LookupToken_NoNamespace(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Lookup without namespace
	_, err = core.LookupToken(context.Background(), tokenValue)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace not found")
}

// TestTokenStore_LookupByAccessor tests looking up tokens by accessor
func TestTokenStore_LookupByAccessor(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Lookup by accessor
	lookedUpEntry, err := core.tokenStore.LookupByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)
	require.NotNil(t, lookedUpEntry)

	assert.Equal(t, entry.ID, lookedUpEntry.ID)
	assert.Equal(t, entry.Accessor, lookedUpEntry.Accessor)
	assert.Equal(t, entry.PrincipalID, lookedUpEntry.PrincipalID)
}

// TestTokenStore_LookupByAccessor_NotFound tests looking up with invalid accessor
func TestTokenStore_LookupByAccessor_NotFound(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	_, err := core.tokenStore.LookupByAccessor(ctx, "nonexistent_accessor")
	require.Error(t, err)
	assert.Equal(t, ErrAccessorNotFound, err)
}

// TestTokenStore_RevokeByAccessor tests token revocation by accessor
func TestTokenStore_RevokeByAccessor(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Revoke by accessor
	err = core.tokenStore.RevokeByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)

	// Verify token is no longer accessible
	_, err = core.tokenStore.LookupByAccessor(ctx, entry.Accessor)
	require.Error(t, err)
}

// TestTokenStore_GenerateRootToken tests root token generation
func TestTokenStore_GenerateRootToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Generate root token
	rootToken, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	require.NotEmpty(t, rootToken)
}

// TestTokenStore_GenerateRootToken_RevokesPrevious tests that generating a new root token revokes the previous one
func TestTokenStore_GenerateRootToken_RevokesPrevious(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Generate first root token
	rootToken1, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	// Generate second root token (should revoke first)
	rootToken2, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	assert.NotEqual(t, rootToken1, rootToken2)
}

// TestTokenStore_RevokeRootToken tests root token revocation
func TestTokenStore_RevokeRootToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Generate root token
	_, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	// Revoke root token
	err = core.tokenStore.RevokeRootToken()
	require.NoError(t, err)

	// Verify no root token exists
	err = core.tokenStore.RevokeRootToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root token exists")
}

// TestTokenStore_GetMetrics tests metrics retrieval
func TestTokenStore_GetMetrics(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate some tokens
	for i := 0; i < 3; i++ {
		authData := &AuthData{
			PrincipalID:  "test-user",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
		}
		_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)
	}

	metrics := core.tokenStore.GetMetrics()
	require.NotNil(t, metrics)

	assert.Equal(t, int64(3), metrics["tokens_generated"])
}

// TestTokenStore_ListTokenTypes tests listing registered token types
func TestTokenStore_ListTokenTypes(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	types := core.tokenStore.ListTokenTypes()
	require.NotEmpty(t, types)

	// Check built-in types are registered
	assert.Contains(t, types, TypeUserPass)
	assert.Contains(t, types, TypeAWSAccessKeys)
	assert.Contains(t, types, TypeWardenToken)
}

// TestTokenStore_Close tests closing the token store
func TestTokenStore_Close(t *testing.T) {
	core := createTestCore(t)

	core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Attempting to generate after close should fail
	_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.Error(t, err)
	assert.Equal(t, ErrStoreClosed, err)
}

// TestTokenStore_Sealed tests that LookupToken fails when core is sealed
func TestTokenStore_Sealed(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Seal the core
	err = core.Seal()
	require.NoError(t, err)

	// LookupToken should fail
	_, err = core.LookupToken(ctx, tokenValue)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sealed")
}

// TestTokenStore_AWSAccessKeys tests AWS access key token generation and resolution
func TestTokenStore_AWSAccessKeys(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "aws-user",
		RoleName:     "aws-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate AWS access key token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeAWSAccessKeys, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, TypeAWSAccessKeys, entry.Type)
	assert.NotEmpty(t, entry.Data["access_key_id"])
	assert.NotEmpty(t, entry.Data["secret_access_key"])

	// Resolve by access key ID
	accessKeyID := entry.Data["access_key_id"]
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, accessKeyID)
	require.NoError(t, err)
	assert.Equal(t, "aws-user", principalID)
	assert.Equal(t, "aws-role", roleName)
}

// TestTokenStore_WardenToken tests Warden token generation and resolution
func TestTokenStore_WardenToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "warden-user",
		RoleName:     "warden-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate Warden token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenToken, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, TypeWardenToken, entry.Type)
	assert.NotEmpty(t, entry.Data["token"])

	// Resolve by token
	token := entry.Data["token"]
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "warden-user", principalID)
	assert.Equal(t, "warden-role", roleName)
}

// TestTokenStore_ConcurrentAccess tests thread safety of the token store
func TestTokenStore_ConcurrentAccess(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	const numGoroutines = 10
	const tokensPerGoroutine = 5

	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < tokensPerGoroutine; j++ {
				authData := &AuthData{
					PrincipalID:  "user",
					RoleName:     "role",
								ExpireAt:     time.Now().Add(24 * time.Hour),
				}

				entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
				if err != nil {
					t.Errorf("goroutine %d: failed to generate token: %v", id, err)
					done <- false
					return
				}

				tokenValue := entry.Data["username"]
				_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
				if err != nil {
					t.Errorf("goroutine %d: failed to resolve token: %v", id, err)
					done <- false
					return
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		success := <-done
		assert.True(t, success)
	}

	// Verify metrics
	metrics := core.tokenStore.GetMetrics()
	assert.Equal(t, int64(numGoroutines*tokensPerGoroutine), metrics["tokens_generated"])
}

// TestTokenStore_TokenWithNoExpiration tests tokens without expiration
func TestTokenStore_TokenWithNoExpiration(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID: "test-user",
		RoleName:    "test-role",
		// No ExpireAt - infinite TTL
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.True(t, entry.ExpireAt.IsZero())

	// Should still be resolvable
	tokenValue := entry.Data["username"]
	principalID, _, err := core.tokenStore.ResolveToken(ctx, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
}

// TestTokenStore_LoadFromStorage tests loading tokens from storage
func TestTokenStore_LoadFromStorage(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate a token
	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Unload from cache
	core.tokenStore.UnloadFromCache()

	// Load from storage
	err = core.tokenStore.LoadFromStorage(ctx)
	require.NoError(t, err)

	// Token should still be accessible
	tokenValue := entry.Data["username"]
	principalID, _, err := core.tokenStore.ResolveToken(ctx, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
}

// ============================================================================
// Token Revocation Tests (for ExpirationManager integration)
// ============================================================================

// TestTokenStore_RevokeByExpiration tests token revocation by ID
func TestTokenStore_RevokeByExpiration(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Verify token is accessible
	tokenValue := entry.Data["username"]
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	require.NoError(t, err)

	// Revoke by expiration (simulates ExpirationManager callback)
	err = core.tokenStore.RevokeByExpiration(entry.ID)
	require.NoError(t, err)

	// Token should no longer be accessible
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	require.Error(t, err)
	assert.Equal(t, ErrTokenNotFound, err)
}

// TestTokenStore_RevokeByExpiration_NotFound tests revocation of non-existent token
func TestTokenStore_RevokeByExpiration_NotFound(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Revoking a non-existent token should not error
	err := core.tokenStore.RevokeByExpiration("nonexistent-token-id")
	require.NoError(t, err)
}

// TestTokenStore_RevokeByExpiration_CleansAccessor tests that revocation cleans up accessor index
func TestTokenStore_RevokeByExpiration_CleansAccessor(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Verify accessor lookup works
	lookedUp, err := core.tokenStore.LookupByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)
	assert.Equal(t, entry.ID, lookedUp.ID)

	// Revoke by expiration
	err = core.tokenStore.RevokeByExpiration(entry.ID)
	require.NoError(t, err)

	// Accessor should no longer work
	_, err = core.tokenStore.LookupByAccessor(ctx, entry.Accessor)
	require.Error(t, err)
	assert.Equal(t, ErrAccessorNotFound, err)
}

// TestTokenStore_RevokeByExpiration_CleansStorage tests that revocation cleans up persistent storage
func TestTokenStore_RevokeByExpiration_CleansStorage(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)
	tokenValue := entry.Data["username"]

	// Revoke by expiration
	err = core.tokenStore.RevokeByExpiration(entry.ID)
	require.NoError(t, err)

	// Unload cache to force storage lookup
	core.tokenStore.UnloadFromCache()

	// Token should not be found even from storage
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	require.Error(t, err)
}

// TestTokenStore_RevokeByExpiration_MultipleTimes tests idempotency of revocation
func TestTokenStore_RevokeByExpiration_MultipleTimes(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Revoke multiple times - should be idempotent
	for i := 0; i < 3; i++ {
		err = core.tokenStore.RevokeByExpiration(entry.ID)
		require.NoError(t, err, "revocation attempt %d should succeed", i+1)
	}
}

// TestTokenStore_ExpirationManagerRevoker tests the revoker callback format for ExpirationManager
func TestTokenStore_ExpirationManagerRevoker(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Create expiration entry as ExpirationManager would
	expEntry := &ExpirationEntry{
		ID:        entry.ID,
		EntryType: ExpirationTypeToken,
		ExpiresAt: entry.ExpireAt,
		IssuedAt:  entry.CreatedAt,
		Namespace: entry.NamespaceID,
	}

	// Simulate what ExpirationManager does - call the revoker function
	revokerFn := func(ctx context.Context, e *ExpirationEntry) error {
		return core.tokenStore.RevokeByExpiration(e.ID)
	}

	err = revokerFn(ctx, expEntry)
	require.NoError(t, err)

	// Verify token is gone
	tokenValue := entry.Data["username"]
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	require.Error(t, err)
}

// TestTokenStore_RevokeByExpiration_JWTToken tests revocation of JWT tokens
func TestTokenStore_RevokeByExpiration_JWTToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a JWT role token
	authData := &AuthData{
		PrincipalID:  "jwt-user",
		RoleName:     "jwt-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeJWTRole, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, TypeJWTRole, entry.Type)

	// Revoke by expiration
	err = core.tokenStore.RevokeByExpiration(entry.ID)
	require.NoError(t, err)

	// Token should no longer be in cache
	_, found := core.tokenStore.byID.Get(entry.ID)
	assert.False(t, found, "JWT token should be removed from cache after revocation")
}

// TestTokenStore_RevokeByExpiration_ConcurrentRevocation tests concurrent revocation safety
func TestTokenStore_RevokeByExpiration_ConcurrentRevocation(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate multiple tokens
	const numTokens = 10
	entries := make([]*TokenEntry, numTokens)

	for i := 0; i < numTokens; i++ {
		authData := &AuthData{
			PrincipalID:  "test-user",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)
		entries[i] = entry
	}

	// Concurrently revoke all tokens
	done := make(chan error, numTokens)
	for _, entry := range entries {
		go func(tokenID string) {
			done <- core.tokenStore.RevokeByExpiration(tokenID)
		}(entry.ID)
	}

	// Wait for all revocations to complete
	for i := 0; i < numTokens; i++ {
		err := <-done
		assert.NoError(t, err)
	}

	// Verify all tokens are revoked
	for _, entry := range entries {
		tokenValue := entry.Data["username"]
		_, _, err := core.tokenStore.ResolveToken(ctx, tokenValue)
		assert.Error(t, err, "token %s should be revoked", entry.ID)
	}
}

// TestTokenStore_RevokeByExpiration_WithRootToken tests that root token revocation works correctly
func TestTokenStore_RevokeByExpiration_WithRootToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Generate root token
	rootToken, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	require.NotEmpty(t, rootToken)

	// Get root token ID
	rootTokenID := core.tokenStore.rootTokenManager.GetCurrentRootTokenID()
	require.NotEmpty(t, rootTokenID)

	// Revoke by expiration
	err = core.tokenStore.RevokeByExpiration(rootTokenID)
	require.NoError(t, err)

	// Root token manager should still think it has a root token
	// (RevokeByExpiration doesn't clear the rootTokenManager state - that's expected)
	// The token is gone from cache/storage but manager state is separate
	// This is because ExpirationManager doesn't know about root token semantics

	// Verify token is no longer in cache
	_, found := core.tokenStore.byID.Get(rootTokenID)
	assert.False(t, found, "root token should be removed from cache after revocation")
}

// ============================================================================
// Security Fix Tests
// ============================================================================

// TestGenerateAccessor tests the secure accessor generation function
func TestGenerateAccessor(t *testing.T) {
	// Test successful generation
	accessor, err := generateAccessor()
	require.NoError(t, err)
	assert.NotEmpty(t, accessor)
	assert.Len(t, accessor, 32) // 24 bytes base64 encoded = 32 chars

	// Test uniqueness
	accessor2, err := generateAccessor()
	require.NoError(t, err)
	assert.NotEqual(t, accessor, accessor2, "accessors should be unique")
}

// TestIPBindingPolicy_Disabled tests that disabled policy skips all IP checks
func TestIPBindingPolicy_Disabled(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Set policy to disabled
	core.tokenStore.config.IPBindingPolicy = IPBindingDisabled

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create token with IP binding
	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		ExpireAt:     time.Now().Add(24 * time.Hour),
		ClientIP:     "192.168.1.100",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Lookup with different IP should succeed when disabled
	ctxWithDifferentIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.200")
	_, err = core.LookupToken(ctxWithDifferentIP, tokenValue)
	require.NoError(t, err, "should succeed when IP binding is disabled")
}

// TestIPBindingPolicy_Optional tests the default optional policy behavior
func TestIPBindingPolicy_Optional(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Default policy is optional
	assert.Equal(t, IPBindingOptional, core.tokenStore.config.IPBindingPolicy)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("both IPs present and match", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-1",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			ClientIP:     "192.168.1.100",
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.100")
		_, err = core.LookupToken(ctxWithIP, tokenValue)
		require.NoError(t, err)
	})

	t.Run("both IPs present but mismatch", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-2",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			ClientIP:     "192.168.1.100",
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		ctxWithDifferentIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.200")
		_, err = core.LookupToken(ctxWithDifferentIP, tokenValue)
		require.Error(t, err)
		assert.Equal(t, ErrOriginViolation, err)
	})

	t.Run("no creation IP allows any request IP", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-3",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			// No ClientIP
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "10.0.0.1")
		_, err = core.LookupToken(ctxWithIP, tokenValue)
		require.NoError(t, err, "should succeed when token has no creation IP")
	})

	t.Run("no request IP allows access", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-4",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			ClientIP:     "192.168.1.100",
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		// No IP in context
		_, err = core.LookupToken(ctx, tokenValue)
		require.NoError(t, err, "should succeed when request has no client IP")
	})
}

// TestIPBindingPolicy_Required tests the strict required policy behavior
func TestIPBindingPolicy_Required(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Set policy to required
	core.tokenStore.config.IPBindingPolicy = IPBindingRequired

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("both IPs present and match succeeds", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-req-1",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			ClientIP:     "192.168.1.100",
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.100")
		_, err = core.LookupToken(ctxWithIP, tokenValue)
		require.NoError(t, err)
	})

	t.Run("no creation IP fails", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-req-2",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			// No ClientIP
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		ctxWithIP := context.WithValue(ctx, logical.ClientIPKey, "192.168.1.100")
		_, err = core.LookupToken(ctxWithIP, tokenValue)
		require.Error(t, err)
		assert.Equal(t, ErrOriginViolation, err)
	})

	t.Run("no request IP fails", func(t *testing.T) {
		authData := &AuthData{
			PrincipalID:  "test-user-req-3",
			RoleName:     "test-role",
				ExpireAt:     time.Now().Add(24 * time.Hour),
			ClientIP:     "192.168.1.100",
		}

		entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
		require.NoError(t, err)

		tokenValue := entry.Data["username"]
		// No IP in context
		_, err = core.LookupToken(ctx, tokenValue)
		require.Error(t, err)
		assert.Equal(t, ErrOriginViolation, err)
	})
}

// TestComputeCacheTTL tests the cache TTL computation logic
func TestComputeCacheTTL(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	minRetention := core.tokenStore.config.CacheMinRetention
	assert.Equal(t, 5*time.Minute, minRetention, "default min retention should be 5 minutes")

	t.Run("non-expiring token cached indefinitely", func(t *testing.T) {
		entry := &TokenEntry{
			ID:       "test-1",
			ExpireAt: time.Time{}, // zero time = no expiration
		}
		ttl := core.tokenStore.computeCacheTTL(entry)
		assert.Equal(t, time.Duration(0), ttl, "non-expiring tokens should have TTL=0 (no eviction)")
	})

	t.Run("expired token returns zero", func(t *testing.T) {
		entry := &TokenEntry{
			ID:       "test-2",
			ExpireAt: time.Now().Add(-1 * time.Hour), // already expired
		}
		ttl := core.tokenStore.computeCacheTTL(entry)
		assert.Equal(t, time.Duration(0), ttl)
	})

	t.Run("token with remaining time > min retention uses remaining time", func(t *testing.T) {
		entry := &TokenEntry{
			ID:       "test-3",
			ExpireAt: time.Now().Add(1 * time.Hour), // 1 hour remaining
		}
		ttl := core.tokenStore.computeCacheTTL(entry)
		assert.True(t, ttl > minRetention, "should use remaining time when greater than min retention")
		assert.True(t, ttl <= 1*time.Hour, "should not exceed remaining time")
	})

	t.Run("token with remaining time < min retention uses min retention", func(t *testing.T) {
		entry := &TokenEntry{
			ID:       "test-4",
			ExpireAt: time.Now().Add(1 * time.Minute), // 1 minute remaining
		}
		ttl := core.tokenStore.computeCacheTTL(entry)
		assert.Equal(t, minRetention, ttl, "should use min retention when remaining time is less")
	})
}

// TestTokenStore_RevokeByNamespace tests revoking all tokens for a namespace
func TestTokenStore_RevokeByNamespace(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Create two namespace contexts
	ns1 := &namespace.Namespace{ID: "ns-1", Path: "ns1/", UUID: "ns1-uuid"}
	ns2 := &namespace.Namespace{ID: "ns-2", Path: "ns2/", UUID: "ns2-uuid"}
	ctx1 := namespace.ContextWithNamespace(context.Background(), ns1)
	ctx2 := namespace.ContextWithNamespace(context.Background(), ns2)

	// Generate tokens in ns1
	for i := 0; i < 3; i++ {
		authData := &AuthData{
			PrincipalID: "user",
			RoleName:    "role",
			ExpireAt:    time.Now().Add(1 * time.Hour),
			Policies:    []string{"default"},
		}
		_, err := core.tokenStore.GenerateToken(ctx1, TypeUserPass, authData)
		require.NoError(t, err)
	}

	// Generate token in ns2
	authData := &AuthData{
		PrincipalID: "user",
		RoleName:    "role",
		ExpireAt:    time.Now().Add(1 * time.Hour),
		Policies:    []string{"default"},
	}
	ns2Entry, err := core.tokenStore.GenerateToken(ctx2, TypeUserPass, authData)
	require.NoError(t, err)

	// Revoke all ns1 tokens
	err = core.tokenStore.RevokeByNamespace("ns-1")
	require.NoError(t, err)

	// ns2 token should still exist
	te, found := core.tokenStore.byID.Get(ns2Entry.ID)
	assert.True(t, found, "ns2 token should still be in cache")
	assert.Equal(t, "ns-2", te.NamespaceID)

	// Verify ns1 tokens are gone from storage
	keys, err := core.tokenStore.storage.List(context.Background(), tokenIDPrefix)
	require.NoError(t, err)
	for _, key := range keys {
		entry, err := core.tokenStore.loadToken(key)
		if err != nil {
			continue
		}
		assert.NotEqual(t, "ns-1", entry.NamespaceID, "no ns1 tokens should remain in storage")
	}
}

// TestTokenStore_RevokeByNamespace_Empty tests revoking tokens for empty namespace
func TestTokenStore_RevokeByNamespace_Empty(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	err := core.tokenStore.RevokeByNamespace("nonexistent")
	require.NoError(t, err)
}

// TestDefaultTokenStoreConfig tests the default configuration values
func TestDefaultTokenStoreConfig(t *testing.T) {
	config := DefaultTokenStoreConfig()

	assert.Equal(t, int64(100<<20), config.CacheMaxCost, "default cache max cost should be 100MB")
	assert.Equal(t, int64(1e7), config.CacheNumCounters, "default cache num counters should be 10 million")
	assert.True(t, config.EnableMetrics, "metrics should be enabled by default")
	assert.Equal(t, IPBindingOptional, config.IPBindingPolicy, "default IP binding policy should be optional")
	assert.Equal(t, 5*time.Minute, config.CacheMinRetention, "default cache min retention should be 5 minutes")
}
