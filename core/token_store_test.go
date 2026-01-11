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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
				AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
		ExpireAt:     time.Now().Add(-1 * time.Hour), // Already expired
	}

	_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token already expired")
}

// TestTokenStore_ResolveToken_AuthDeadlineViolated tests resolving with violated auth deadline
func TestTokenStore_ResolveToken_AuthDeadlineViolated(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		AuthDeadline: time.Now().Add(-1 * time.Second), // Already passed
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	// Wait briefly for auth deadline to pass
	time.Sleep(10 * time.Millisecond)

	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	require.Error(t, err)
	assert.Equal(t, ErrAuthDeadlineViolated, err)
}

// TestTokenStore_LookupToken tests the LookupToken function with security checks
func TestTokenStore_LookupToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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

// TestTokenStore_LookupToken_AuthDeadlineViolated tests looking up with violated auth deadline
func TestTokenStore_LookupToken_AuthDeadlineViolated(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		AuthDeadline: time.Now().Add(-1 * time.Second), // Already passed
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	tokenValue := entry.Data["username"]

	_, err = core.LookupToken(ctx, tokenValue)
	require.Error(t, err)
	assert.Equal(t, ErrAuthDeadlineViolated, err)
}

// TestTokenStore_LookupToken_SameOriginViolation tests same-origin policy enforcement
func TestTokenStore_LookupToken_SameOriginViolation(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Lookup by accessor
	lookedUpEntry, err := core.tokenStore.LookupByAccessor(entry.Accessor)
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

	_, err := core.tokenStore.LookupByAccessor("nonexistent_accessor")
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
		ExpireAt:     time.Now().Add(24 * time.Hour),
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Revoke by accessor
	err = core.tokenStore.RevokeByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)

	// Verify token is no longer accessible
	_, err = core.tokenStore.LookupByAccessor(entry.Accessor)
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
			AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
					AuthDeadline: time.Now().Add(1 * time.Hour),
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
		// No AuthDeadline or ExpireAt - infinite TTL
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.True(t, entry.ExpireAt.IsZero())
	assert.True(t, entry.AuthDeadline.IsZero())

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
		AuthDeadline: time.Now().Add(1 * time.Hour),
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
