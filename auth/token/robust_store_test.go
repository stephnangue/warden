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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	require.NoError(t, err)
	defer store.Close()

	_, err = store.GenerateToken(USER_PASS, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authData cannot be nil")
}

func TestRobustStore_UnsupportedTokenType(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
	log := logger.NewZerologLogger(logger.DefaultConfig())
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
