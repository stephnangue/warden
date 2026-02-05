// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestNamespaceContext creates a context with a test namespace for expiration tests
func createTestNamespaceContext(nsID string) context.Context {
	ns := &namespace.Namespace{
		ID:   nsID,
		Path: nsID + "/",
	}
	return namespace.ContextWithNamespace(context.Background(), ns)
}

// createTestExpirationManager creates an ExpirationManager for testing.
// Core is nil for unit tests - revocation will be skipped but registration/expiration works.
func createTestExpirationManager(t *testing.T) *ExpirationManager {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	// No Core and no storage for basic tests
	return NewExpirationManager(nil, log, nil)
}

func TestExpirationManager_NewAndStop(t *testing.T) {
	m := createTestExpirationManager(t)
	require.NotNil(t, m)

	// Verify initial state
	assert.Equal(t, int64(0), m.GetPendingCount())
	assert.Equal(t, int64(0), m.GetNonexpiringCount())
	assert.Equal(t, int64(0), m.GetIrrevocableCount())

	// Stop should not panic
	m.Stop()
}

func TestExpirationManager_RegisterToken(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")
	err := m.RegisterToken(ctx, "token-123", 10*time.Minute, true)
	require.NoError(t, err)

	assert.Equal(t, int64(1), m.GetPendingCount())
}

func TestExpirationManager_RegisterCredential(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")
	err := m.RegisterCredential(
		ctx,
		"cred-uuid-123",  // Credential ID (UUID)
		"ns-1:token-123", // Cache key
		5*time.Minute,
		"lease-abc",
		"vault-source",
		"hvault",
		"db-spec",
		true,
	)
	require.NoError(t, err)

	assert.Equal(t, int64(1), m.GetPendingCount())
}

func TestExpirationManager_RegisterNonExpiring(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	// Zero TTL should go to nonexpiring tier
	ctx := createTestNamespaceContext("root")
	err := m.RegisterToken(ctx, "root-token", 0, true)
	require.NoError(t, err)

	assert.Equal(t, int64(0), m.GetPendingCount())
	assert.Equal(t, int64(1), m.GetNonexpiringCount())
}

func TestExpirationManager_Unregister(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	// Register and then unregister
	ctx := createTestNamespaceContext("ns-1")
	err := m.RegisterToken(ctx, "token-123", 10*time.Minute, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.GetPendingCount())

	m.Unregister(ExpirationTypeToken, "token-123")
	assert.Equal(t, int64(0), m.GetPendingCount())
}

func TestExpirationManager_UnregisterNonExpiring(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	// Register nonexpiring and then unregister
	ctx := createTestNamespaceContext("root")
	err := m.RegisterToken(ctx, "root-token", 0, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.GetNonexpiringCount())

	m.Unregister(ExpirationTypeToken, "root-token")
	assert.Equal(t, int64(0), m.GetNonexpiringCount())
}

func TestExpirationManager_TimerExpiration(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	// Register with short TTL
	ctx := createTestNamespaceContext("ns-1")
	err := m.RegisterToken(ctx, "token-expiring", 50*time.Millisecond, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.GetPendingCount())

	// Wait for the revocation signal (timer fired and job processed)
	// Note: Without Core, revocation will fail but the signal is still sent
	select {
	case <-m.revocationDoneCh:
		// Timer fired and job was processed
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for timer expiration")
	}
}

func TestExpirationManager_MultipleEntries(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register multiple entries
	for i := 0; i < 10; i++ {
		err := m.RegisterToken(ctx, "token-"+string(rune('a'+i)), 10*time.Minute, true)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(10), m.GetPendingCount())

	// Unregister half
	for i := 0; i < 5; i++ {
		m.Unregister(ExpirationTypeToken, "token-"+string(rune('a'+i)))
	}

	assert.Equal(t, int64(5), m.GetPendingCount())
}

func TestExpirationManager_ReplaceEntry(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register same ID twice - should replace
	err := m.RegisterToken(ctx, "token-123", 10*time.Minute, true)
	require.NoError(t, err)

	err = m.RegisterToken(ctx, "token-123", 5*time.Minute, true)
	require.NoError(t, err)

	// Should still be only 1
	assert.Equal(t, int64(1), m.GetPendingCount())
}

func TestExpirationManager_ConcurrentRegistrations(t *testing.T) {
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "token-" + string(rune('A'+(idx%26))) + string(rune('0'+(idx/26)))
			err := m.RegisterToken(ctx, id, 10*time.Minute, true)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// All should be registered
	assert.Equal(t, int64(numGoroutines), m.GetPendingCount())
}

func TestBuildKey(t *testing.T) {
	tests := []struct {
		entryType ExpirationType
		id        string
		expected  string
	}{
		{ExpirationTypeToken, "abc123", "token:abc123"},
		{ExpirationTypeCredential, "cred-xyz", "credential:cred-xyz"},
	}

	for _, tt := range tests {
		result := buildKey(tt.entryType, tt.id)
		assert.Equal(t, tt.expected, result)
	}
}

func TestTruncateError(t *testing.T) {
	tests := []struct {
		err      error
		maxLen   int
		expected string
	}{
		{nil, 10, ""},
		{errors.New("short"), 10, "short"},
		{errors.New("this is a very long error message"), 10, "this is a "},
	}

	for _, tt := range tests {
		result := truncateError(tt.err, tt.maxLen)
		assert.Equal(t, tt.expected, result)
	}
}

func TestExpirationManager_NilCore(t *testing.T) {
	// Test that expiration works gracefully when Core is nil (unit test scenario)
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register entry - Core is nil so revocation will be skipped
	err := m.RegisterToken(ctx, "token-nil-core", 50*time.Millisecond, true)
	require.NoError(t, err)

	// Wait for the revocation signal (timer fired and job was processed)
	select {
	case <-m.revocationDoneCh:
		// Timer fired, job processed, entry cleaned up
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for timer expiration")
	}

	// Entry should be cleaned up even though Core is nil
	assert.Equal(t, int64(0), m.GetPendingCount())
}

func TestExpirationManager_StopCancelsTimers(t *testing.T) {
	m := createTestExpirationManager(t)

	ctx := createTestNamespaceContext("ns-1")

	// Register entries with long TTL
	for i := 0; i < 5; i++ {
		err := m.RegisterToken(ctx, "token-"+string(rune('a'+i)), 1*time.Hour, true)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(5), m.GetPendingCount())

	// Stop should cancel all timers
	m.Stop()

	// Pending map should be cleared
	count := 0
	m.pending.Range(func(key, value any) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}

func TestExpirationManager_UniqueCredentialIDs(t *testing.T) {
	// This test verifies that credentials with unique IDs (UUIDs) are tracked independently.
	// Even if they have the same cache key, each has its own expiration entry.
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register first credential with unique ID
	err := m.RegisterCredential(
		ctx,
		"cred-uuid-1",       // Unique credential ID (UUID)
		"ns-1:jwt-token-id", // Cache key (same for both)
		10*time.Minute,
		"lease-1",
		"vault-source",
		"hvault",
		"db-spec",
		true,
	)
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.GetPendingCount())

	// Register second credential with different unique ID but same cache key
	// This simulates a new credential being issued for the same token
	err = m.RegisterCredential(
		ctx,
		"cred-uuid-2",       // Different credential ID (UUID)
		"ns-1:jwt-token-id", // Same cache key
		10*time.Minute,
		"lease-2",
		"vault-source",
		"hvault",
		"db-spec",
		true,
	)
	require.NoError(t, err)

	// Both credentials should be tracked independently (different UUIDs = different entries)
	assert.Equal(t, int64(2), m.GetPendingCount())
}

func TestExpirationManager_CredentialEntryHasCacheKey(t *testing.T) {
	// This test verifies that ExpirationEntry stores both ID (UUID) and CacheKey
	// We test by accessing the pending map directly since Core is nil in unit tests
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register credential with all metadata
	err := m.RegisterCredential(
		ctx,
		"cred-uuid-123",  // Credential ID (UUID)
		"ns-1:token-456", // Cache key
		10*time.Minute,   // Long TTL so it stays in pending
		"lease-abc",
		"vault-source",
		"hvault",
		"db-spec",
		true,
	)
	require.NoError(t, err)

	// Verify entry is stored with correct metadata by checking the pending map
	key := buildKey(ExpirationTypeCredential, "cred-uuid-123")
	val, ok := m.pending.Load(key)
	require.True(t, ok, "entry should be in pending map")

	pi := val.(*pendingInfo)
	entry := pi.entry

	assert.Equal(t, "cred-uuid-123", entry.ID, "ID should be the credential UUID")
	assert.Equal(t, "ns-1:token-456", entry.CacheKey, "CacheKey should be stored for cache operations")
	assert.Equal(t, "lease-abc", entry.LeaseID, "LeaseID should be stored for source revocation")
	assert.Equal(t, "vault-source", entry.SourceName)
	assert.Equal(t, "hvault", entry.SourceType)
	assert.Equal(t, "db-spec", entry.SpecName)
	assert.True(t, entry.Revocable)
}

func TestExpirationManager_ReplaceTokenEntry(t *testing.T) {
	// This test verifies that tokens (which use tokenID as ID) can still be replaced
	m := createTestExpirationManager(t)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Register same token ID twice - should replace
	err := m.RegisterToken(ctx, "token-123", 10*time.Minute, true)
	require.NoError(t, err)

	err = m.RegisterToken(ctx, "token-123", 5*time.Minute, true)
	require.NoError(t, err)

	// Should still be only 1 (tokens use same ID so they replace)
	assert.Equal(t, int64(1), m.GetPendingCount())
}

// BenchmarkExpirationManager_Register benchmarks registration performance
func BenchmarkExpirationManager_Register(b *testing.B) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	m := NewExpirationManager(nil, log, nil)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := "token-" + string(rune('A'+(i%26))) + string(rune('0'+((i/26)%10)))
		m.RegisterToken(ctx, id, 10*time.Minute, true)
	}
}

// BenchmarkExpirationManager_Unregister benchmarks unregistration performance
func BenchmarkExpirationManager_Unregister(b *testing.B) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	m := NewExpirationManager(nil, log, nil)
	defer m.Stop()

	ctx := createTestNamespaceContext("ns-1")

	// Pre-register entries
	for i := 0; i < b.N; i++ {
		id := "token-" + string(rune('A'+(i%26))) + string(rune('0'+((i/26)%10)))
		m.RegisterToken(ctx, id, 10*time.Minute, true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := "token-" + string(rune('A'+(i%26))) + string(rune('0'+((i/26)%10)))
		m.Unregister(ExpirationTypeToken, id)
	}
}
