package drivers

import (
	"sync"
	"time"
)

// TokenCacheEntry represents a cached token with expiry and generation
type TokenCacheEntry struct {
	Token      string
	ExpiresAt  time.Time
	Generation uint64
}

// TokenCache provides thread-safe token caching with generation tracking
// for rotation invalidation
type TokenCache struct {
	cache      map[string]*TokenCacheEntry
	generation uint64
	mu         sync.Mutex
}

// NewTokenCache creates a new token cache
func NewTokenCache() *TokenCache {
	return &TokenCache{
		cache: make(map[string]*TokenCacheEntry),
	}
}

// Get retrieves a cached token if it's still valid
// Returns token, expiry time, and whether the token was found and valid
// refreshBuffer is the duration before expiry to consider the token expired
func (tc *TokenCache) Get(key string, refreshBuffer time.Duration) (string, time.Time, bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	entry, ok := tc.cache[key]
	if !ok {
		return "", time.Time{}, false
	}

	// Check if entry is from current generation and not expired
	if entry.Generation != tc.generation {
		return "", time.Time{}, false
	}

	// Check if token will expire within the refresh buffer
	if time.Now().Add(refreshBuffer).After(entry.ExpiresAt) {
		return "", time.Time{}, false
	}

	return entry.Token, entry.ExpiresAt, true
}

// Set stores a token in the cache with its expiry time
func (tc *TokenCache) Set(key string, token string, expiresAt time.Time) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache[key] = &TokenCacheEntry{
		Token:      token,
		ExpiresAt:  expiresAt,
		Generation: tc.generation,
	}
}

// InvalidateGeneration bumps the generation counter, effectively invalidating
// all cached tokens. Used during rotation to ensure old tokens aren't used.
func (tc *TokenCache) InvalidateGeneration() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.generation++
}

// Clear removes all cached tokens
func (tc *TokenCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cache = make(map[string]*TokenCacheEntry)
}

// GetGeneration returns the current generation (for testing/debugging)
func (tc *TokenCache) GetGeneration() uint64 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.generation
}
