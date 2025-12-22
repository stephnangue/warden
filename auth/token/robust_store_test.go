package token

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRobustStore_GenerateUserPassToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user123",
		RoleName:     "admin",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, USER_PASS, token.Type)
	assert.NotEmpty(t, token.Data["username"])
	assert.NotEmpty(t, token.Data["password"])
	assert.Equal(t, authData.ExpireAt, token.ExpireAt)
}

func TestRobustStore_GenerateAWSAccessKeysToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user456",
		RoleName:     "developer",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "10.0.0.1",
		},
	}

	token, err := store.GenerateToken(AWS_ACCESS_KEYS, authData)
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, AWS_ACCESS_KEYS, token.Type)
	assert.NotEmpty(t, token.Data["access_key_id"])
	assert.NotEmpty(t, token.Data["secret_access_key"])
}

func TestRobustStore_ResolveToken_Success(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user789",
		RoleName:     "viewer",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "172.16.0.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)

	reqContext := map[string]string{
		"client_ip": "172.16.0.1",
	}

	principalID, roleName, err := store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	require.NoError(t, err)
	assert.Equal(t, "user789", principalID)
	assert.Equal(t, "viewer", roleName)
}

func TestRobustStore_ResolveToken_ExpiredToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Test 1: Reject token that's already expired at creation time
	authData1 := &AuthData{
		PrincipalID:  "user999",
		RoleName:     "temp",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(-1 * time.Hour), // Already expired
		RequestContext: map[string]string{
			"client_ip": "192.168.1.100",
		},
	}

	_, err = store.GenerateToken(USER_PASS, authData1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token already expired")

	// Test 2: Token expires after creation
	authData2 := &AuthData{
		PrincipalID:  "user888",
		RoleName:     "temp",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(100 * time.Millisecond), // Expires soon
		RequestContext: map[string]string{
			"client_ip": "192.168.1.100",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData2)
	require.NoError(t, err)
	require.NotNil(t, token)

	// Wait for token to expire
	time.Sleep(200 * time.Millisecond)

	reqContext := map[string]string{
		"client_ip": "192.168.1.100",
	}

	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestRobustStore_ResolveToken_AuthDeadlineViolated(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user111",
		RoleName:     "guest",
		AuthDeadline: time.Now().Add(-1 * time.Minute), // Deadline passed
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "10.1.1.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)

	reqContext := map[string]string{
		"client_ip": "10.1.1.1",
	}

	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	assert.ErrorIs(t, err, ErrAuthDeadlineViolated)
}

func TestRobustStore_ResolveToken_OriginViolation(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user222",
		RoleName:     "member",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.50",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)

	// Try to resolve from different IP
	reqContext := map[string]string{
		"client_ip": "192.168.1.99", // Different IP
	}

	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	assert.ErrorIs(t, err, ErrOriginViolation)
}

func TestRobustStore_ResolveToken_TokenNotFound(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	_, _, err = store.ResolveToken(context.Background(), "nonexistent-token", reqContext)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestRobustStore_GetToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user333",
		RoleName:     "admin",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "10.10.10.10",
		},
	}

	token, err := store.GenerateToken(AWS_ACCESS_KEYS, authData)
	require.NoError(t, err)

	retrievedToken := store.GetToken(token.Data["access_key_id"])
	assert.Equal(t, token.Type, retrievedToken.Type)
	assert.Equal(t, token.Data["access_key_id"], retrievedToken.Data["access_key_id"])
}

func TestRobustStore_CleanUpTokens(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Create expired token (expires in 200ms)
	authData1 := &AuthData{
		PrincipalID:    "user444",
		RoleName:       "temp",
		AuthDeadline:   time.Now().Add(5 * time.Minute),
		ExpireAt:       time.Now().Add(200 * time.Millisecond),
		RequestContext: map[string]string{},
	}
	token1, err := store.GenerateToken(USER_PASS, authData1)
	require.NoError(t, err)

	// Create valid token
	authData2 := &AuthData{
		PrincipalID:    "user555",
		RoleName:       "permanent",
		AuthDeadline:   time.Now().Add(5 * time.Minute),
		ExpireAt:       time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{},
	}
	token2, err := store.GenerateToken(USER_PASS, authData2)
	require.NoError(t, err)

	// Wait for Ristretto's TTL to expire the first token
	time.Sleep(300 * time.Millisecond)

	// Expired token should be gone (Ristretto TTL)
	assert.Nil(t, store.GetToken(token1.Data["username"]))

	// Valid token should still exist
	assert.NotNil(t, store.GetToken(token2.Data["username"]))
}

func TestRobustStore_Metrics(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()
	config.EnableMetrics = true

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user666",
		RoleName:     "tester",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.200",
		},
	}

	// Generate token
	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)

	// Resolve token
	reqContext := map[string]string{
		"client_ip": "192.168.1.200",
	}
	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	require.NoError(t, err)

	// Check metrics
	metrics := store.GetMetrics()
	assert.Equal(t, int64(1), metrics["tokens_generated"])
	assert.Equal(t, int64(1), metrics["tokens_resolved"])
}

func TestRobustStore_ConcurrentAccess(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent token generation
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			authData := &AuthData{
				PrincipalID:    "user" + string(rune(id)),
				RoleName:       "concurrent",
				AuthDeadline:   time.Now().Add(5 * time.Minute),
				ExpireAt:       time.Now().Add(1 * time.Hour),
				RequestContext: map[string]string{},
			}
			_, err := store.GenerateToken(USER_PASS, authData)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	metrics := store.GetMetrics()
	assert.Equal(t, int64(numGoroutines), metrics["tokens_generated"])
}

func TestRobustStore_Close(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)

	authData := &AuthData{
		PrincipalID:    "user777",
		RoleName:       "closing",
		AuthDeadline:   time.Now().Add(5 * time.Minute),
		ExpireAt:       time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)
	assert.NotNil(t, store.GetToken(token.Data["username"]))

	// Close the store
	store.Close()

	// Verify store is closed
	_, err = store.GenerateToken(USER_PASS, authData)
	assert.ErrorIs(t, err, ErrStoreClosed)

	reqContext := map[string]string{}
	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestRobustStore_NilAuthData(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	_, err = store.GenerateToken(USER_PASS, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authData cannot be nil")
}

func TestRobustStore_UnsupportedTokenType(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:    "user888",
		RoleName:       "test",
		AuthDeadline:   time.Now().Add(5 * time.Minute),
		ExpireAt:       time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{},
	}

	_, err = store.GenerateToken("invalidtype", authData)
	assert.ErrorIs(t, err, ErrUnsupportedTokenType)
}

func TestRobustStore_CacheHitMiss(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()
	config.EnableMetrics = true

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "user999",
		RoleName:     "cached",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	require.NoError(t, err)

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	// First resolve - cache miss
	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	require.NoError(t, err)

	// Second resolve - cache hit
	_, _, err = store.ResolveToken(context.Background(), token.Data["username"], reqContext)
	require.NoError(t, err)

	metrics := store.GetMetrics()
	assert.Greater(t, metrics["cache_hits"], int64(0))
}

// Root Token Tests

func TestRobustStore_GenerateRootToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)
	assert.NotEmpty(t, rootToken)
	assert.Equal(t, 68, len(rootToken)) // "cws." (4) + 64 hex chars
	assert.Contains(t, rootToken, "cws.")

	// Verify token is stored in cache
	token := store.GetToken(rootToken)
	assert.NotNil(t, token)
	assert.Equal(t, WARDEN_TOKEN, token.Type)
	assert.Equal(t, rootToken, token.Data["token"])
	assert.True(t, token.ExpireAt.IsZero()) // Never expires
}

func TestRobustStore_GenerateRootToken_Format(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	// Verify format
	assert.True(t, len(rootToken) > 4)
	assert.Equal(t, "cws.", rootToken[:4])

	// Verify it's a valid hex string after prefix
	tokenBody := rootToken[4:]
	assert.Equal(t, 64, len(tokenBody))
}

func TestRobustStore_GenerateRootToken_ReplacesPrevious(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate first root token
	rootToken1, err := store.GenerateRootToken()
	require.NoError(t, err)
	assert.NotEmpty(t, rootToken1)

	// Verify first token is stored
	token1 := store.GetToken(rootToken1)
	assert.NotNil(t, token1)

	// Generate second root token (should revoke first)
	rootToken2, err := store.GenerateRootToken()
	require.NoError(t, err)
	assert.NotEmpty(t, rootToken2)
	assert.NotEqual(t, rootToken1, rootToken2)

	// First token should be revoked
	token1After := store.GetToken(rootToken1)
	assert.Nil(t, token1After)

	// Second token should exist
	token2 := store.GetToken(rootToken2)
	assert.NotNil(t, token2)
}

func TestRobustStore_RevokeRootToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	// Verify token exists
	token := store.GetToken(rootToken)
	assert.NotNil(t, token)

	// Revoke root token
	err = store.RevokeRootToken()
	require.NoError(t, err)

	// Token should be gone
	tokenAfter := store.GetToken(rootToken)
	assert.Nil(t, tokenAfter)
}

func TestRobustStore_RevokeRootToken_NoToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Try to revoke when no root token exists
	err = store.RevokeRootToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no root token to revoke")
}

func TestRobustStore_RootToken_InfiniteTTL(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	// Resolve token immediately
	principalID, roleName, err := store.ResolveToken(context.Background(), rootToken, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "root", principalID)
	assert.Equal(t, "system_admin", roleName)

	// Wait a bit and resolve again (should still work - infinite TTL)
	time.Sleep(100 * time.Millisecond)
	principalID2, roleName2, err := store.ResolveToken(context.Background(), rootToken, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "root", principalID2)
	assert.Equal(t, "system_admin", roleName2)
}

func TestRobustStore_RootToken_NoAuthDeadline(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	// Wait longer than typical auth deadline
	time.Sleep(200 * time.Millisecond)

	// Should still resolve (no auth deadline)
	principalID, roleName, err := store.ResolveToken(context.Background(), rootToken, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "root", principalID)
	assert.Equal(t, "system_admin", roleName)
}

func TestRobustStore_RootToken_NoOriginCheck(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	// Resolve from first IP
	reqContext1 := map[string]string{"client_ip": "192.168.1.1"}
	principalID1, roleName1, err := store.ResolveToken(context.Background(), rootToken, reqContext1)
	require.NoError(t, err)
	assert.Equal(t, "root", principalID1)
	assert.Equal(t, "system_admin", roleName1)

	// Resolve from different IP (should work - no origin restrictions)
	reqContext2 := map[string]string{"client_ip": "10.0.0.1"}
	principalID2, roleName2, err := store.ResolveToken(context.Background(), rootToken, reqContext2)
	require.NoError(t, err)
	assert.Equal(t, "root", principalID2)
	assert.Equal(t, "system_admin", roleName2)
}

func TestRobustStore_RootToken_ClosedStore(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)

	// Close the store
	store.Close()

	// Try to generate root token after closing
	_, err = store.GenerateRootToken()
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestRobustStore_RootToken_Concurrent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	// Generate initial root token
	rootToken, err := store.GenerateRootToken()
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent resolutions of root token
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			principalID, roleName, err := store.ResolveToken(context.Background(), rootToken, map[string]string{})
			assert.NoError(t, err)
			assert.Equal(t, "root", principalID)
			assert.Equal(t, "system_admin", roleName)
		}()
	}
	wg.Wait()
}

func TestRootTokenManager_SetAndGet(t *testing.T) {
	rtm := NewRootTokenManager()

	tokenValue := "cws.test123"
	tokenID := "wtkn_abc"

	rtm.SetRootToken(tokenValue, tokenID)

	assert.Equal(t, tokenValue, rtm.GetCurrentRootToken())
	assert.Equal(t, tokenID, rtm.GetCurrentRootTokenID())
	assert.True(t, rtm.HasRootToken())
	assert.True(t, rtm.IsRootToken(tokenValue))
	assert.False(t, rtm.IsRootToken("different-token"))
}

func TestRootTokenManager_Clear(t *testing.T) {
	rtm := NewRootTokenManager()

	rtm.SetRootToken("cws.test456", "wtkn_def")
	assert.True(t, rtm.HasRootToken())

	rtm.ClearRootToken()
	assert.False(t, rtm.HasRootToken())
	assert.Empty(t, rtm.GetCurrentRootToken())
	assert.Empty(t, rtm.GetCurrentRootTokenID())
}

func TestRootTokenManager_Concurrent(t *testing.T) {
	rtm := NewRootTokenManager()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			rtm.SetRootToken("cws.test", "wtkn_test")
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = rtm.GetCurrentRootToken()
			_ = rtm.HasRootToken()
			_ = rtm.IsRootToken("cws.test")
		}()
	}
	wg.Wait()
}
