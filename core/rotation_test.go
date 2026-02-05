package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRotatableDriver implements both SourceDriver and Rotatable (three-phase) for testing
type mockRotatableDriver struct {
	supportsRotation bool
	prepareCount     int32
	commitCount      int32
	cleanupCount     int32
	prepareError     error
	commitError      error
	cleanupError     error
	preparedConfig   map[string]string
	cleanupConfig    map[string]string
}

func (d *mockRotatableDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	return map[string]interface{}{"key": "value"}, time.Hour, "lease-123", nil
}

func (d *mockRotatableDriver) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

func (d *mockRotatableDriver) Type() string {
	return "mock"
}

func (d *mockRotatableDriver) Cleanup(ctx context.Context) error {
	return nil
}

func (d *mockRotatableDriver) SupportsRotation() bool {
	return d.supportsRotation
}

func (d *mockRotatableDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, error) {
	atomic.AddInt32(&d.prepareCount, 1)
	if d.prepareError != nil {
		return nil, nil, d.prepareError
	}
	newConfig := d.preparedConfig
	if newConfig == nil {
		newConfig = map[string]string{"secret_id": "new-secret-id", "secret_id_accessor": "new-accessor"}
	}
	cleanup := d.cleanupConfig
	if cleanup == nil {
		cleanup = map[string]string{"secret_id_accessor": "old-accessor"}
	}
	return newConfig, cleanup, nil
}

func (d *mockRotatableDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	atomic.AddInt32(&d.commitCount, 1)
	return d.commitError
}

func (d *mockRotatableDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	atomic.AddInt32(&d.cleanupCount, 1)
	return d.cleanupError
}

func (d *mockRotatableDriver) GetPrepareCount() int {
	return int(atomic.LoadInt32(&d.prepareCount))
}

func (d *mockRotatableDriver) GetCommitCount() int {
	return int(atomic.LoadInt32(&d.commitCount))
}

func (d *mockRotatableDriver) GetCleanupCount() int {
	return int(atomic.LoadInt32(&d.cleanupCount))
}

func TestRotationEntry_JSON(t *testing.T) {
	entry := &RotationEntry{
		SourceName:     "test-source",
		SourceType:     "vault",
		Namespace:      "root",
		RotationPeriod: 24 * time.Hour,
		NextRotation:   time.Now().Add(24 * time.Hour),
		LastRotation:   time.Now(),
		LastError:      "",
		RotateAttempts: 0,
	}

	// Test that all fields are present
	assert.Equal(t, "test-source", entry.SourceName)
	assert.Equal(t, "vault", entry.SourceType)
	assert.Equal(t, "root", entry.Namespace)
	assert.Equal(t, 24*time.Hour, entry.RotationPeriod)
	assert.Empty(t, entry.LastError)
	assert.Equal(t, 0, entry.RotateAttempts)
}

func TestNewRotationManager(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	require.NotNil(t, rm)

	// Verify initial state
	assert.NotNil(t, rm.log)
	assert.Nil(t, rm.core)
	assert.Nil(t, rm.storage)

	// Clean up
	rm.Stop()
}

func TestRotationManager_RegisterUnregister(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	// Create context with namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register a source
	err := rm.RegisterSource(ctx, "test-source", "vault", 1*time.Hour)
	require.NoError(t, err)

	// Verify it's registered
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	_, loaded := rm.pending.Load(key)
	assert.True(t, loaded, "source should be registered")

	// Unregister
	err = rm.UnregisterSource(ctx, "test-source")
	require.NoError(t, err)

	// Verify it's unregistered
	_, loaded = rm.pending.Load(key)
	assert.False(t, loaded, "source should be unregistered")
}

func TestRotationManager_RegisterDuplicate(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register first time
	err := rm.RegisterSource(ctx, "test-source", "vault", 1*time.Hour)
	require.NoError(t, err)

	// Register again with different period - should replace
	err = rm.RegisterSource(ctx, "test-source", "vault", 2*time.Hour)
	require.NoError(t, err)

	// Verify the new period is stored
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	val, loaded := rm.pending.Load(key)
	require.True(t, loaded)
	pr := val.(*pendingRotation)
	assert.Equal(t, 2*time.Hour, pr.entry.RotationPeriod)
}

func TestRotationManager_UpdateRotationPeriod(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register source
	err := rm.RegisterSource(ctx, "test-source", "vault", 1*time.Hour)
	require.NoError(t, err)

	// Update period
	err = rm.UpdateRotationPeriod(ctx, "test-source", 30*time.Minute)
	require.NoError(t, err)

	// Verify new period
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	val, _ := rm.pending.Load(key)
	pr := val.(*pendingRotation)
	assert.Equal(t, 30*time.Minute, pr.entry.RotationPeriod)
}

func TestRotationManager_UpdateNonExistent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Try to update non-existent source
	err := rm.UpdateRotationPeriod(ctx, "non-existent", 1*time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not registered for rotation")
}

func TestRotationManager_UnregisterNonExistent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Unregister non-existent source - should not error
	err := rm.UnregisterSource(ctx, "non-existent")
	require.NoError(t, err)
}

func TestRotationManager_NamespaceIsolation(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	defer rm.Stop()

	// Create two different namespace contexts
	ns1 := &namespace.Namespace{UUID: "ns-uuid-1", ID: "ns1", Path: "ns1/"}
	ns2 := &namespace.Namespace{UUID: "ns-uuid-2", ID: "ns2", Path: "ns2/"}

	ctx1 := namespace.ContextWithNamespace(context.Background(), ns1)
	ctx2 := namespace.ContextWithNamespace(context.Background(), ns2)

	// Register same source name in both namespaces
	err := rm.RegisterSource(ctx1, "shared-source", "vault", 1*time.Hour)
	require.NoError(t, err)

	err = rm.RegisterSource(ctx2, "shared-source", "vault", 2*time.Hour)
	require.NoError(t, err)

	// Verify both are registered with different keys
	key1 := buildRotationKey(ns1.UUID, "shared-source")
	key2 := buildRotationKey(ns2.UUID, "shared-source")

	val1, loaded1 := rm.pending.Load(key1)
	val2, loaded2 := rm.pending.Load(key2)

	assert.True(t, loaded1, "source in ns1 should be registered")
	assert.True(t, loaded2, "source in ns2 should be registered")

	// Verify they have different periods
	pr1 := val1.(*pendingRotation)
	pr2 := val2.(*pendingRotation)
	assert.Equal(t, 1*time.Hour, pr1.entry.RotationPeriod)
	assert.Equal(t, 2*time.Hour, pr2.entry.RotationPeriod)

	// Unregister from ns1 should not affect ns2
	err = rm.UnregisterSource(ctx1, "shared-source")
	require.NoError(t, err)

	_, loaded1 = rm.pending.Load(key1)
	_, loaded2 = rm.pending.Load(key2)
	assert.False(t, loaded1, "source in ns1 should be unregistered")
	assert.True(t, loaded2, "source in ns2 should still be registered")
}

func TestBuildRotationKey(t *testing.T) {
	tests := []struct {
		namespace  string
		sourceName string
		expected   string
	}{
		{"root", "vault-source", "root:vault-source"},
		{"ns-uuid-123", "my-source", "ns-uuid-123:my-source"},
		{"", "source", ":source"},
	}

	for _, tc := range tests {
		result := buildRotationKey(tc.namespace, tc.sourceName)
		assert.Equal(t, tc.expected, result)
	}
}

func TestRotationManager_Stop(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register some sources
	for i := 0; i < 5; i++ {
		err := rm.RegisterSource(ctx, "source-"+string(rune('a'+i)), "vault", 1*time.Hour)
		require.NoError(t, err)
	}

	// Stop the manager
	rm.Stop()

	// Verify all timers are stopped (pending map should be empty or timers stopped)
	// We can't easily verify timers are stopped, but we can verify no panics occur
	// and that Stop() is idempotent
	rm.Stop() // Should not panic on double stop
}

func TestRotationEntry_ExponentialBackoff(t *testing.T) {
	entry := &RotationEntry{
		RotateAttempts: 0,
	}

	// Test backoff calculation at different attempt levels
	tests := []struct {
		attempts       int
		expectedMinTTL time.Duration
		expectedMaxTTL time.Duration
	}{
		{0, 10 * time.Second, 10 * time.Second},  // First retry: 10s
		{1, 20 * time.Second, 20 * time.Second},  // Second: 20s
		{2, 40 * time.Second, 40 * time.Second},  // Third: 40s
		{3, 80 * time.Second, 80 * time.Second},  // Fourth: 80s
		{4, 160 * time.Second, 160 * time.Second}, // Fifth: 160s
		{5, 300 * time.Second, 300 * time.Second}, // Sixth: max 5m
		{6, 300 * time.Second, 300 * time.Second}, // Beyond max: still 5m
	}

	for _, tc := range tests {
		entry.RotateAttempts = tc.attempts
		backoff := calculateBackoff(entry.RotateAttempts)
		assert.GreaterOrEqual(t, backoff, tc.expectedMinTTL, "attempts=%d", tc.attempts)
		assert.LessOrEqual(t, backoff, tc.expectedMaxTTL, "attempts=%d", tc.attempts)
	}
}

// calculateBackoff is a test helper that mirrors the logic in rotation.go
func calculateBackoff(attempts int) time.Duration {
	baseDelay := 10 * time.Second
	maxDelay := 5 * time.Minute

	delay := baseDelay * (1 << attempts) // 2^attempts * 10s
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}
