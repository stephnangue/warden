package drivers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCache_GetSet(t *testing.T) {
	tc := NewTokenCache()

	_, _, ok := tc.Get("absent", 0)
	assert.False(t, ok)

	expiresAt := time.Now().Add(time.Hour)
	tc.Set("key", "token", expiresAt)

	token, gotExpiry, ok := tc.Get("key", 30*time.Second)
	require.True(t, ok)
	assert.Equal(t, "token", token)
	assert.WithinDuration(t, expiresAt, gotExpiry, time.Second)
}

func TestTokenCache_RefreshBufferRefusesImminentExpiry(t *testing.T) {
	tc := NewTokenCache()
	tc.Set("key", "token", time.Now().Add(10*time.Second))

	_, _, ok := tc.Get("key", 30*time.Second)
	assert.False(t, ok, "a token expiring inside the refresh buffer must not be served")

	_, _, ok = tc.Get("key", 0)
	assert.True(t, ok, "without a buffer the same token is still valid")
}

func TestTokenCache_InvalidateGeneration(t *testing.T) {
	tc := NewTokenCache()
	tc.Set("key", "token", time.Now().Add(time.Hour))

	tc.InvalidateGeneration()

	_, _, ok := tc.Get("key", 0)
	assert.False(t, ok, "a superseded generation must not be served")
}

func TestTokenCache_Delete(t *testing.T) {
	tc := NewTokenCache()
	tc.Set("keep", "token-keep", time.Now().Add(time.Hour))
	tc.Set("drop", "token-drop", time.Now().Add(time.Hour))

	tc.Delete("drop")

	_, _, ok := tc.Get("drop", 0)
	assert.False(t, ok, "a deleted entry must not be served even before it expires")

	_, _, ok = tc.Get("keep", 0)
	assert.True(t, ok, "deleting one entry must leave the others alone")
}

func TestTokenCache_SetPrunesDeadEntries(t *testing.T) {
	// Entries keyed by a credential fingerprint are never read again once that
	// credential is retired, so Set sweeps what Get would already refuse rather than
	// letting the map grow for the process lifetime.
	tc := NewTokenCache()
	tc.Set("live", "token", time.Now().Add(time.Hour))
	// Expire an entry behind Set's back, so the sweep is what removes it rather
	// than it never having been stored.
	tc.Set("expired", "token", time.Now().Add(time.Hour))
	tc.cache["expired"].ExpiresAt = time.Now().Add(-time.Minute)

	tc.Set("fresh", "token", time.Now().Add(time.Hour))

	assert.NotContains(t, tc.cache, "expired", "an expired entry must be swept")
	assert.Contains(t, tc.cache, "live", "a live entry must survive the sweep")
	assert.Contains(t, tc.cache, "fresh")
}

func TestTokenCache_SetPrunesSupersededGenerations(t *testing.T) {
	tc := NewTokenCache()
	tc.Set("old-generation", "token", time.Now().Add(time.Hour))

	tc.InvalidateGeneration()
	tc.Set("new-generation", "token", time.Now().Add(time.Hour))

	assert.NotContains(t, tc.cache, "old-generation", "a superseded entry must be swept")
	assert.Contains(t, tc.cache, "new-generation")
}

func TestTokenCache_SetIfGenerationRefusesRotatedMint(t *testing.T) {
	tc := NewTokenCache()

	// A caller reads the generation, then mints. Nothing rotates, so the store lands.
	gen := tc.GetGeneration()
	require.True(t, tc.SetIfGeneration("key", "fresh", time.Now().Add(time.Hour), gen))

	token, _, ok := tc.Get("key", 30*time.Second)
	require.True(t, ok)
	assert.Equal(t, "fresh", token)

	// Now the credentials rotate while a second mint is in flight: the caller still
	// holds the pre-rotation generation, so its result must be refused rather than
	// filed under the new one, where Get would happily serve it.
	stale := tc.GetGeneration()
	tc.InvalidateGeneration()
	assert.False(t, tc.SetIfGeneration("key", "minted-by-retired-credential", time.Now().Add(time.Hour), stale))

	_, _, ok = tc.Get("key", 30*time.Second)
	assert.False(t, ok, "the retired credential's token must not be readable after rotation")

	// A mint that started after the rotation stores normally.
	require.True(t, tc.SetIfGeneration("key", "post-rotation", time.Now().Add(time.Hour), tc.GetGeneration()))
	token, _, ok = tc.Get("key", 30*time.Second)
	require.True(t, ok)
	assert.Equal(t, "post-rotation", token)
}
