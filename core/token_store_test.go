// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenStore_GenerateToken tests basic token generation
func TestTokenStore_GenerateToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:  "test-user",
		RoleName:     "test-role",
		AuthDeadline: time.Now().Add(1 * time.Hour),
		ExpireAt:     time.Now().Add(24 * time.Hour),
		NamespaceID:  namespace.RootNamespace.UUID,
		NamespacePath: namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip":  "127.0.0.1",
			"request_id": "test-req-123",
		},
	}

	// Generate a user_pass token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ID)
	assert.NotEmpty(t, entry.Accessor)
	assert.Equal(t, TypeUserPass, entry.Type)
	assert.Equal(t, "test-user", entry.PrincipalID)
	assert.Equal(t, "test-role", entry.RoleName)
	assert.NotEmpty(t, entry.Data)
}

// TestTokenStore_GenerateToken_MultipleTypes tests generating different token types
func TestTokenStore_GenerateToken_MultipleTypes(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	tokenTypes := []string{TypeUserPass, TypeAWSAccessKeys, TypeWardenToken}

	for _, tokenType := range tokenTypes {
		t.Run(tokenType, func(t *testing.T) {
			entry, err := core.tokenStore.GenerateToken(ctx, tokenType, authData)
			require.NoError(t, err)
			require.NotNil(t, entry)
			assert.Equal(t, tokenType, entry.Type)
		})
	}
}

// TestTokenStore_ResolveToken tests token resolution
func TestTokenStore_ResolveToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get the token value from entry data (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

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

	// Generate a valid token first to get the format
	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Now revoke it to make it non-existent
	err = core.tokenStore.RevokeByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)

	// Wait for revocation to complete
	time.Sleep(50 * time.Millisecond)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Try to resolve a non-existent token
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// TestTokenStore_ResolveToken_Expired tests resolving an expired token
func TestTokenStore_ResolveToken_Expired(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate token with very short expiration
	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(50 * time.Millisecond),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Wait for token to expire
	time.Sleep(100 * time.Millisecond)

	// Try to resolve expired token (should be evicted from cache)
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	// Token may be not found due to eviction or expired
	assert.True(t, err == ErrTokenExpired || err == ErrTokenNotFound, "expected token expired or not found, got: %v", err)
}

// TestTokenStore_GetToken tests getting a token by value
func TestTokenStore_GetToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Get token
	retrievedEntry := core.tokenStore.GetToken(tokenValue)
	require.NotNil(t, retrievedEntry)
	assert.Equal(t, entry.ID, retrievedEntry.ID)
	assert.Equal(t, entry.Accessor, retrievedEntry.Accessor)
	assert.Equal(t, entry.Type, retrievedEntry.Type)
}

// TestTokenStore_LookupByAccessor tests looking up tokens by accessor
func TestTokenStore_LookupByAccessor(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Lookup by accessor
	retrievedEntry, err := core.tokenStore.LookupByAccessor(entry.Accessor)
	require.NoError(t, err)
	require.NotNil(t, retrievedEntry)
	assert.Equal(t, entry.ID, retrievedEntry.ID)
	assert.Equal(t, entry.Accessor, retrievedEntry.Accessor)
}

// TestTokenStore_LookupByAccessor_NotFound tests looking up non-existent accessor
func TestTokenStore_LookupByAccessor_NotFound(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Try to lookup non-existent accessor
	_, err := core.tokenStore.LookupByAccessor("nonexistent-accessor")
	assert.ErrorIs(t, err, ErrAccessorNotFound)
}

// TestTokenStore_RevokeByAccessor tests revoking tokens by accessor
func TestTokenStore_RevokeByAccessor(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Revoke by accessor
	err = core.tokenStore.RevokeByAccessor(ctx, entry.Accessor)
	require.NoError(t, err)

	// Try to resolve revoked token
	_, _, err = core.tokenStore.ResolveToken(ctx, tokenValue)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// TestTokenStore_GenerateRootToken tests root token generation
func TestTokenStore_GenerateRootToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Generate root token
	rootToken, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	require.NotEmpty(t, rootToken)

	// Verify root token can be resolved
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, rootToken)
	require.NoError(t, err)
	assert.Equal(t, "root", principalID)
	assert.Equal(t, "system_admin", roleName)
}

// TestTokenStore_RevokeRootToken tests root token revocation
func TestTokenStore_RevokeRootToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate root token
	rootToken, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	// Verify it works before revocation
	_, _, err = core.tokenStore.ResolveToken(ctx, rootToken)
	require.NoError(t, err)

	// Revoke root token
	err = core.tokenStore.RevokeRootToken()
	require.NoError(t, err)

	// Wait for revocation and storage deletion to complete
	time.Sleep(200 * time.Millisecond)

	// Try to resolve revoked root token
	_, _, err = core.tokenStore.ResolveToken(ctx, rootToken)
	assert.Error(t, err, "should get an error when resolving revoked root token")
}

// TestTokenStore_NamespaceBinding tests that tokens are namespace-bound
func TestTokenStore_NamespaceBinding(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate token in root namespace
	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Verify token has correct namespace binding
	assert.Equal(t, namespace.RootNamespace.UUID, entry.NamespaceID)
	assert.Equal(t, namespace.RootNamespace.Path, entry.NamespacePath)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Add client_ip to context for same-origin policy check
	ctxWithIP := context.WithValue(ctx, "client_ip", "127.0.0.1")

	// Should be able to resolve in same namespace
	principalID, roleName, err := core.tokenStore.ResolveToken(ctxWithIP, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
	assert.Equal(t, "test-role", roleName)
}

// TestTokenStore_CacheMissRecovery tests cache miss recovery from storage
func TestTokenStore_CacheMissRecovery(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// First, verify the token works before eviction
	ctxWithIP := context.WithValue(ctx, "client_ip", "127.0.0.1")
	principalID, roleName, err := core.tokenStore.ResolveToken(ctxWithIP, tokenValue)
	require.NoError(t, err, "token should resolve before eviction")
	assert.Equal(t, "test-user", principalID)
	assert.Equal(t, "test-role", roleName)

	// Wait for async storage writes to complete
	time.Sleep(500 * time.Millisecond)

	// Verify token is in storage before eviction
	storageView := NewBarrierView(core.barrier, tokenStorePath)
	storedEntry, err := storageView.Get(ctx, tokenIDPrefix+entry.ID)
	require.NoError(t, err, "failed to read from storage")
	require.NotNil(t, storedEntry, "token should be in storage before eviction")

	// Evict from cache (simulate capacity eviction)
	core.tokenStore.byID.Del(entry.ID)
	core.tokenStore.byAccessor.Del(entry.Accessor)
	core.tokenStore.byID.Wait()
	core.tokenStore.byAccessor.Wait()

	// Should be able to recover from storage
	principalID, roleName, err = core.tokenStore.ResolveToken(ctxWithIP, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
	assert.Equal(t, "test-role", roleName)
}

// TestTokenStore_LoadFromStorage tests loading tokens from storage on initialization
func TestTokenStore_LoadFromStorage(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Wait for storage writes to complete
	time.Sleep(200 * time.Millisecond)

	// Verify token is in storage before closing
	storageView := NewBarrierView(core.barrier, tokenStorePath)
	storedEntry, err := storageView.Get(ctx, tokenIDPrefix+entry.ID)
	require.NoError(t, err, "token should be persisted to storage")
	require.NotNil(t, storedEntry, "token should exist in storage")

	// Close the token store
	core.tokenStore.Close()

	// Create a new token store (simulating server restart)
	newTokenStore, err := NewTokenStore(core, DefaultTokenStoreConfig())
	require.NoError(t, err)
	defer newTokenStore.Close()

	core.tokenStore = newTokenStore

	// Add client_ip to context for same-origin policy check
	ctxWithIP := context.WithValue(ctx, "client_ip", "127.0.0.1")

	// Token should be loaded from storage
	principalID, roleName, err := newTokenStore.ResolveToken(ctxWithIP, tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "test-user", principalID)
	assert.Equal(t, "test-role", roleName)
}

// TestTokenStore_Metrics tests that metrics are tracked correctly
func TestTokenStore_Metrics(t *testing.T) {
	config := DefaultTokenStoreConfig()
	config.EnableMetrics = true

	core := createTestCore(t)
	core.tokenStore.Close()

	// Create new token store with metrics enabled
	tokenStore, err := NewTokenStore(core, config)
	require.NoError(t, err)
	defer tokenStore.Close()
	core.tokenStore = tokenStore

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Generate token
	entry, err := tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value
	tokenValue := ""
	for _, v := range entry.Data {
		tokenValue = v
		break
	}

	// Resolve token (should be cache hit)
	_, _, err = tokenStore.ResolveToken(ctx, tokenValue)
	require.NoError(t, err)

	// Check metrics
	metrics := tokenStore.GetMetrics()
	assert.Greater(t, metrics["tokens_generated"], int64(0))
	assert.Greater(t, metrics["cache_hits"], int64(0))
}

// TestTokenStore_ConcurrentAccess tests concurrent token operations
func TestTokenStore_ConcurrentAccess(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate multiple tokens concurrently
	numTokens := 100
	tokens := make([]string, numTokens)
	accessors := make([]string, numTokens)

	t.Run("ConcurrentGenerate", func(t *testing.T) {
		for i := 0; i < numTokens; i++ {
			i := i // capture
			t.Run("", func(t *testing.T) {
				t.Parallel()

				authData := &AuthData{
					PrincipalID:    "test-user",
					RoleName:       "test-role",
					AuthDeadline:   time.Now().Add(1 * time.Hour),
					ExpireAt:       time.Now().Add(24 * time.Hour),
					NamespaceID:    namespace.RootNamespace.UUID,
					NamespacePath:  namespace.RootNamespace.Path,
					RequestContext: map[string]string{},
				}

				entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
				require.NoError(t, err)

				// Get token value (username for user_pass tokens)
				tokens[i] = entry.Data["username"]
				accessors[i] = entry.Accessor
			})
		}
	})

	// Resolve tokens concurrently
	t.Run("ConcurrentResolve", func(t *testing.T) {
		for i := 0; i < numTokens; i++ {
			i := i // capture
			t.Run("", func(t *testing.T) {
				t.Parallel()

				if tokens[i] != "" {
					_, _, err := core.tokenStore.ResolveToken(ctx, tokens[i])
					require.NoError(t, err)
				}
			})
		}
	})

	// Lookup by accessor concurrently
	t.Run("ConcurrentLookup", func(t *testing.T) {
		for i := 0; i < numTokens; i++ {
			i := i // capture
			t.Run("", func(t *testing.T) {
				t.Parallel()

				if accessors[i] != "" {
					_, err := core.tokenStore.LookupByAccessor(accessors[i])
					require.NoError(t, err)
				}
			})
		}
	})
}

// TestTokenStore_Close tests that closing the store prevents new operations
func TestTokenStore_Close(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Close the store
	core.tokenStore.Close()

	// Try to generate token after close
	_, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// TestTokenStore_AuthDeadlineValidation tests auth deadline validation
func TestTokenStore_AuthDeadlineValidation(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate token with short auth deadline
	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(50 * time.Millisecond), // Short deadline
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Get token value (username for user_pass tokens)
	tokenValue := entry.Data["username"]
	require.NotEmpty(t, tokenValue, "username should exist in token data")

	// Wait for auth deadline to pass
	time.Sleep(100 * time.Millisecond)

	// Add client_ip to context for same-origin policy check
	ctxWithIP := context.WithValue(ctx, "client_ip", "127.0.0.1")

	// Try to resolve token with expired auth deadline
	_, _, err = core.tokenStore.ResolveToken(ctxWithIP, tokenValue)
	assert.ErrorIs(t, err, ErrAuthDeadlineViolated)
}

// TestTokenStore_OneTimeUse tests one-time use token functionality
func TestTokenStore_OneTimeUse(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		AuthDeadline:   time.Now().Add(1 * time.Hour),
		ExpireAt:       time.Now().Add(24 * time.Hour),
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Generate token
	entry, err := core.tokenStore.GenerateToken(ctx, TypeUserPass, authData)
	require.NoError(t, err)

	// Mark as used
	entry.MarkUsed()

	// Verify it's marked as used
	assert.True(t, entry.IsUsed())
}
