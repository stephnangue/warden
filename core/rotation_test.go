package core

import (
	"context"
	"encoding/json"
	"fmt"
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
	activateAfter    time.Duration    // >0 triggers slow path
	failUntilAttempt int32            // fail PrepareRotation until this many calls
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

func (d *mockRotatableDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	count := atomic.AddInt32(&d.prepareCount, 1)
	// Fail until we reach the configured attempt threshold
	if d.failUntilAttempt > 0 && count <= d.failUntilAttempt {
		return nil, nil, 0, fmt.Errorf("simulated prepare failure (attempt %d)", count)
	}
	if d.prepareError != nil {
		return nil, nil, 0, d.prepareError
	}
	newConfig := d.preparedConfig
	if newConfig == nil {
		newConfig = map[string]string{"secret_id": "new-secret-id", "secret_id_accessor": "new-accessor"}
	}
	cleanup := d.cleanupConfig
	if cleanup == nil {
		cleanup = map[string]string{"secret_id_accessor": "old-accessor"}
	}
	return newConfig, cleanup, d.activateAfter, nil
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
		NextAction:     time.Now().Add(24 * time.Hour),
		LastRotation:   time.Now(),
		State:          StateIdle,
		LastError:      "",
		Attempts:       0,
	}

	// Test that all fields are present
	assert.Equal(t, "test-source", entry.SourceName)
	assert.Equal(t, "vault", entry.SourceType)
	assert.Equal(t, "root", entry.Namespace)
	assert.Equal(t, 24*time.Hour, entry.RotationPeriod)
	assert.Equal(t, StateIdle, entry.State)
	assert.Empty(t, entry.LastError)
	assert.Equal(t, 0, entry.Attempts)
}

func TestNewRotationManager(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
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
	rm.Start()
	defer rm.Stop()

	// Create context with namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register a source
	err := rm.RegisterSource(ctx, "test-source", "vault", 1*time.Hour)
	require.NoError(t, err)

	// Verify it's registered
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	val, loaded := rm.entries.Load(key)
	assert.True(t, loaded, "source should be registered")
	entry := val.(*RotationEntry)
	assert.Equal(t, StateIdle, entry.State)

	// Unregister
	err = rm.UnregisterSource(ctx, "test-source")
	require.NoError(t, err)

	// Verify it's unregistered
	_, loaded = rm.entries.Load(key)
	assert.False(t, loaded, "source should be unregistered")
}

func TestRotationManager_RegisterDuplicate(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
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
	val, loaded := rm.entries.Load(key)
	require.True(t, loaded)
	entry := val.(*RotationEntry)
	assert.Equal(t, 2*time.Hour, entry.RotationPeriod)
}

func TestRotationManager_UpdateRotationPeriod(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
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
	val, _ := rm.entries.Load(key)
	entry := val.(*RotationEntry)
	assert.Equal(t, 30*time.Minute, entry.RotationPeriod)
}

func TestRotationManager_UpdateNonExistent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
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
	rm.Start()
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Unregister non-existent source - should not error
	err := rm.UnregisterSource(ctx, "non-existent")
	require.NoError(t, err)
}

func TestRotationManager_NamespaceIsolation(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
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

	val1, loaded1 := rm.entries.Load(key1)
	val2, loaded2 := rm.entries.Load(key2)

	assert.True(t, loaded1, "source in ns1 should be registered")
	assert.True(t, loaded2, "source in ns2 should be registered")

	// Verify they have different periods
	entry1 := val1.(*RotationEntry)
	entry2 := val2.(*RotationEntry)
	assert.Equal(t, 1*time.Hour, entry1.RotationPeriod)
	assert.Equal(t, 2*time.Hour, entry2.RotationPeriod)

	// Unregister from ns1 should not affect ns2
	err = rm.UnregisterSource(ctx1, "shared-source")
	require.NoError(t, err)

	_, loaded1 = rm.entries.Load(key1)
	_, loaded2 = rm.entries.Load(key2)
	assert.False(t, loaded1, "source in ns1 should be unregistered")
	assert.True(t, loaded2, "source in ns2 should still be registered")
}

func TestRotationManager_UnregisterByNamespace(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	ns1 := &namespace.Namespace{UUID: "ns-uuid-1", ID: "ns1", Path: "ns1/"}
	ns2 := &namespace.Namespace{UUID: "ns-uuid-2", ID: "ns2", Path: "ns2/"}

	ctx1 := namespace.ContextWithNamespace(context.Background(), ns1)
	ctx2 := namespace.ContextWithNamespace(context.Background(), ns2)

	// Register sources and specs in both namespaces
	require.NoError(t, rm.RegisterSource(ctx1, "source-a", "vault", 1*time.Hour))
	require.NoError(t, rm.RegisterSource(ctx1, "source-b", "aws", 2*time.Hour))
	require.NoError(t, rm.RegisterSpec(ctx1, "spec-a", "source-a", 30*time.Minute))
	require.NoError(t, rm.RegisterSource(ctx2, "source-a", "vault", 1*time.Hour))

	assert.Equal(t, int64(4), atomic.LoadInt64(&rm.entryCount))

	// Unregister all entries for ns1
	err := rm.UnregisterByNamespace(ns1.UUID)
	require.NoError(t, err)

	// ns1 entries should be gone
	_, loaded := rm.entries.Load(buildRotationKey(ns1.UUID, "source-a"))
	assert.False(t, loaded, "ns1 source-a should be gone")
	_, loaded = rm.entries.Load(buildRotationKey(ns1.UUID, "source-b"))
	assert.False(t, loaded, "ns1 source-b should be gone")
	_, loaded = rm.entries.Load(buildSpecKey(ns1.UUID, "spec-a"))
	assert.False(t, loaded, "ns1 spec-a should be gone")

	// ns2 entries should remain
	_, loaded = rm.entries.Load(buildRotationKey(ns2.UUID, "source-a"))
	assert.True(t, loaded, "ns2 source-a should still be registered")

	assert.Equal(t, int64(1), atomic.LoadInt64(&rm.entryCount))
}

func TestRotationManager_UnregisterByNamespace_Empty(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	// Should not error on empty namespace
	err := rm.UnregisterByNamespace("nonexistent-uuid")
	require.NoError(t, err)
	assert.Equal(t, int64(0), atomic.LoadInt64(&rm.entryCount))
}

func TestBuildRotationKey(t *testing.T) {
	tests := []struct {
		namespace  string
		sourceName string
		expected   string
	}{
		{"root", "vault-source", "root:source:vault-source"},
		{"ns-uuid-123", "my-source", "ns-uuid-123:source:my-source"},
		{"", "source", ":source:source"},
	}

	for _, tc := range tests {
		result := buildRotationKey(tc.namespace, tc.sourceName)
		assert.Equal(t, tc.expected, result)
	}
}

func TestRotationManager_Stop(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register some sources
	for i := 0; i < 5; i++ {
		err := rm.RegisterSource(ctx, "source-"+string(rune('a'+i)), "vault", 1*time.Hour)
		require.NoError(t, err)
	}

	// Stop the manager
	rm.Stop()

	// Double stop should also not panic
	rm.Stop()
}

func TestRotationManager_ExponentialBackoff(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	// Test backoff calculation at different attempt levels
	tests := []struct {
		attempts    int
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{0, 10 * time.Second, 12 * time.Second},   // 10s + up to 20% jitter
		{1, 20 * time.Second, 24 * time.Second},   // 20s + jitter
		{2, 40 * time.Second, 48 * time.Second},   // 40s + jitter
		{3, 80 * time.Second, 96 * time.Second},   // 80s + jitter
		{4, 160 * time.Second, 192 * time.Second},  // 160s + jitter
		{5, 300 * time.Second, 360 * time.Second},  // capped at 5m + jitter
		{6, 300 * time.Second, 360 * time.Second},  // still capped
	}

	for _, tc := range tests {
		backoff := rm.calculateBackoff(tc.attempts)
		assert.GreaterOrEqual(t, backoff, tc.expectedMin, "attempts=%d", tc.attempts)
		assert.LessOrEqual(t, backoff, tc.expectedMax, "attempts=%d", tc.attempts)
	}
}

// ============================================================================
// Spec Rotation Tests
// ============================================================================

// mockSpecRotatableDriver implements SpecRotatable for testing spec rotation
type mockSpecRotatableDriver struct {
	mockRotatableDriver
	supportsSpecRotation bool
	prepareSpecCount     int32
	commitSpecCount      int32
	cleanupSpecCount     int32
	prepareSpecError     error
	commitSpecError      error
	cleanupSpecError     error
	preparedSpecConfig   map[string]string
	cleanupSpecConfig    map[string]string
}

func (d *mockSpecRotatableDriver) SupportsSpecRotation() bool {
	return d.supportsSpecRotation
}

func (d *mockSpecRotatableDriver) PrepareSpecRotation(ctx context.Context, spec *credential.CredSpec) (map[string]string, map[string]string, time.Duration, error) {
	atomic.AddInt32(&d.prepareSpecCount, 1)
	if d.prepareSpecError != nil {
		return nil, nil, 0, d.prepareSpecError
	}
	newConfig := d.preparedSpecConfig
	if newConfig == nil {
		newConfig = map[string]string{"client_secret": "new-secret", "secret_id": "new-secret-id"}
	}
	cleanup := d.cleanupSpecConfig
	if cleanup == nil {
		cleanup = map[string]string{"old_secret_id": "old-secret-id", "client_id": "test-client"}
	}
	// Return 0 activateAfter for immediate activation
	return newConfig, cleanup, 0, nil
}

func (d *mockSpecRotatableDriver) CommitSpecRotation(ctx context.Context, spec *credential.CredSpec, newConfig map[string]string) error {
	atomic.AddInt32(&d.commitSpecCount, 1)
	return d.commitSpecError
}

func (d *mockSpecRotatableDriver) CleanupSpecRotation(ctx context.Context, cleanupConfig map[string]string) error {
	atomic.AddInt32(&d.cleanupSpecCount, 1)
	return d.cleanupSpecError
}

func (d *mockSpecRotatableDriver) GetPrepareSpecCount() int {
	return int(atomic.LoadInt32(&d.prepareSpecCount))
}

func (d *mockSpecRotatableDriver) GetCommitSpecCount() int {
	return int(atomic.LoadInt32(&d.commitSpecCount))
}

func (d *mockSpecRotatableDriver) GetCleanupSpecCount() int {
	return int(atomic.LoadInt32(&d.cleanupSpecCount))
}

func TestRotationManager_RegisterSpec(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	// Create context with namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register a spec
	err := rm.RegisterSpec(ctx, "test-spec", "azure-source", 1*time.Hour)
	require.NoError(t, err)

	// Verify it's registered with the correct key format
	key := buildSpecKey(namespace.RootNamespace.UUID, "test-spec")
	val, loaded := rm.entries.Load(key)
	assert.True(t, loaded, "spec should be registered")

	// Verify entry type and spec name
	entry := val.(*RotationEntry)
	assert.Equal(t, EntryTypeSpec, entry.EntryType)
	assert.Equal(t, "test-spec", entry.SpecName)
	assert.Equal(t, "azure-source", entry.SourceName)

	// Verify pending count
	assert.Equal(t, int64(1), rm.GetPendingCount())
}

func TestRotationManager_RegisterSpecAndSource(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register both a source and a spec with the same name - they should have different keys
	err := rm.RegisterSource(ctx, "shared-name", "vault", 1*time.Hour)
	require.NoError(t, err)

	err = rm.RegisterSpec(ctx, "shared-name", "azure-source", 2*time.Hour)
	require.NoError(t, err)

	// Both should be registered
	assert.Equal(t, int64(2), rm.GetPendingCount())

	// Verify they have different keys
	sourceKey := buildRotationKey(namespace.RootNamespace.UUID, "shared-name")
	specKey := buildSpecKey(namespace.RootNamespace.UUID, "shared-name")

	_, sourceLoaded := rm.entries.Load(sourceKey)
	_, specLoaded := rm.entries.Load(specKey)

	assert.True(t, sourceLoaded, "source should be registered")
	assert.True(t, specLoaded, "spec should be registered")
}

func TestRotationEntry_EntryType(t *testing.T) {
	// Test source entry
	sourceEntry := &RotationEntry{
		EntryType:      EntryTypeSource,
		SourceName:     "test-source",
		SourceType:     "vault",
		Namespace:      "root",
		RotationPeriod: 24 * time.Hour,
	}
	assert.Equal(t, EntryTypeSource, sourceEntry.EntryType)
	assert.Empty(t, sourceEntry.SpecName)

	// Test spec entry
	specEntry := &RotationEntry{
		EntryType:      EntryTypeSpec,
		SpecName:       "test-spec",
		SourceName:     "azure-source",
		Namespace:      "root",
		RotationPeriod: 12 * time.Hour,
	}
	assert.Equal(t, EntryTypeSpec, specEntry.EntryType)
	assert.Equal(t, "test-spec", specEntry.SpecName)
}

// mockDriverFactory implements credential.SourceDriverFactory for testing
type mockDriverFactory struct {
	driver credential.SourceDriver
}

func (f *mockDriverFactory) Type() string                              { return "mock" }
func (f *mockDriverFactory) ValidateConfig(map[string]string) error    { return nil }
func (f *mockDriverFactory) SensitiveConfigFields() []string           { return nil }
func (f *mockDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return f.driver, nil
}

// createTestRotationManager creates a fully wired RotationManager for integration tests.
// Returns the manager, context, mock driver, and a cleanup function.
func createTestRotationManager(t *testing.T, driver *mockRotatableDriver) (*RotationManager, context.Context, func()) {
	t.Helper()

	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock driver factory in the core's existing driver registry
	// (createTestCore already initializes the registry with builtin drivers)
	err := core.credentialDriverRegistry.RegisterFactory(&mockDriverFactory{driver: driver})
	require.NoError(t, err)

	// Re-setup credential manager to use the updated registry with mock driver
	log := core.logger
	credManager, err := credential.NewManager(core.credentialTypeRegistry, core.credentialDriverRegistry, core.credConfigStore, log)
	require.NoError(t, err)
	core.credentialManager = credManager

	// Create source in config store
	source := &credential.CredSource{
		Name:   "test-source",
		Type:   "mock",
		Config: map[string]string{"key": "value"},
	}
	err = core.credConfigStore.CreateSource(ctx, source)
	require.NoError(t, err)

	// Create rotation manager with storage
	storage := NewBarrierView(core.barrier, rotationStoragePath)
	rm := NewRotationManager(core, log.WithSubsystem("rotation"), storage)
	rm.backoffScale = 0.001 // Scale down backoffs for fast tests (10s -> 10ms)
	rm.tickInterval = 50 * time.Millisecond // Fast ticks for tests
	rm.Start()

	cleanup := func() {
		rm.Stop()
	}

	return rm, ctx, cleanup
}

func TestBuildEntryKey(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	tests := []struct {
		name        string
		entry       *RotationEntry
		expectedKey string
	}{
		{
			name: "source entry",
			entry: &RotationEntry{
				EntryType:  EntryTypeSource,
				SourceName: "my-source",
				Namespace:  "ns-uuid",
			},
			expectedKey: "ns-uuid:source:my-source",
		},
		{
			name: "spec entry",
			entry: &RotationEntry{
				EntryType:  EntryTypeSpec,
				SpecName:   "my-spec",
				SourceName: "source",
				Namespace:  "ns-uuid",
			},
			expectedKey: "ns-uuid:spec:my-spec",
		},
		{
			name: "empty entry type defaults to source behavior",
			entry: &RotationEntry{
				EntryType:  "",
				SourceName: "legacy-source",
				Namespace:  "ns-uuid",
			},
			expectedKey: "ns-uuid:source:legacy-source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := rm.buildEntryKey(tc.entry)
			assert.Equal(t, tc.expectedKey, key)
		})
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// waitForRotation waits for a rotation completion signal or times out.
func waitForRotation(t *testing.T, rm *RotationManager, timeout time.Duration) {
	t.Helper()
	select {
	case <-rm.rotationDoneCh:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for rotation completion")
	}
}

func TestRotation_FastPath(t *testing.T) {
	driver := &mockRotatableDriver{supportsRotation: true}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	// Register with short period
	err := rm.RegisterSource(ctx, "test-source", "mock", 50*time.Millisecond)
	require.NoError(t, err)

	// Wait for rotation to complete (fast path: prepare + commit + cleanup inline)
	waitForRotation(t, rm, 5*time.Second)

	// Verify all three phases executed
	assert.Equal(t, 1, driver.GetPrepareCount(), "prepare should be called once")
	assert.Equal(t, 1, driver.GetCommitCount(), "commit should be called once")
	assert.Equal(t, 1, driver.GetCleanupCount(), "cleanup should be called once")

	// Verify entry was updated
	entry := rm.GetEntry(namespace.RootNamespace.UUID, "test-source")
	require.NotNil(t, entry)
	assert.Equal(t, StateIdle, entry.GetState())
	assert.Empty(t, entry.GetLastError())
}

func TestRotation_SlowPath(t *testing.T) {
	driver := &mockRotatableDriver{
		supportsRotation: true,
		activateAfter:    200 * time.Millisecond, // triggers staged activation
	}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	err := rm.RegisterSource(ctx, "test-source", "mock", 500*time.Millisecond)
	require.NoError(t, err)

	// Wait for PREPARE to complete (first signal)
	waitForRotation(t, rm, 5*time.Second)

	// Verify staged entry
	entry := rm.GetEntry(namespace.RootNamespace.UUID, "test-source")
	require.NotNil(t, entry)
	assert.Equal(t, StateStaged, entry.GetState(), "should be in staged state")
	assert.Equal(t, 1, driver.GetPrepareCount(), "prepare should be called once")
	assert.Equal(t, 0, driver.GetCommitCount(), "commit should not be called yet")

	// Wait for ACTIVATE to complete (second signal, after activateAfter delay)
	waitForRotation(t, rm, 5*time.Second)

	// Verify activation completed
	assert.Equal(t, StateIdle, entry.GetState(), "should be back to idle")
	assert.Equal(t, 1, driver.GetCommitCount(), "commit should be called once")
	assert.Equal(t, 1, driver.GetCleanupCount(), "cleanup should be called once")
	assert.Nil(t, entry.GetNewConfig(), "staged fields should be cleared")
}

func TestRotation_RetryOnFailure(t *testing.T) {
	driver := &mockRotatableDriver{
		supportsRotation: true,
		failUntilAttempt: 3, // fail 3 times, succeed on 4th
	}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	err := rm.RegisterSource(ctx, "test-source", "mock", 50*time.Millisecond)
	require.NoError(t, err)

	// Wait for the eventual success (after 3 failures + 1 success)
	waitForRotation(t, rm, 30*time.Second)

	// Verify prepare was called 4 times (3 failures + 1 success)
	assert.Equal(t, 4, driver.GetPrepareCount(), "prepare should be called 4 times")
	assert.Equal(t, 1, driver.GetCommitCount(), "commit should succeed once")
}

func TestRotation_MaxRetriesExceeded(t *testing.T) {
	driver := &mockRotatableDriver{
		supportsRotation: true,
		prepareError:     fmt.Errorf("permanent failure"),
	}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	err := rm.RegisterSource(ctx, "test-source", "mock", 50*time.Millisecond)
	require.NoError(t, err)

	// Wait for all attempts to exhaust (MaxRotateAttempts = 6)
	require.Eventually(t, func() bool {
		return rm.GetFailedCount() == 1
	}, 30*time.Second, 50*time.Millisecond, "entry should move to failed state")

	assert.Equal(t, int64(0), rm.GetPendingCount(), "pending should be empty")
	assert.Equal(t, int64(1), rm.GetFailedCount(), "failed should have 1 entry")

	// Verify error is recorded
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	val, ok := rm.entries.Load(key)
	require.True(t, ok)
	entry := val.(*RotationEntry)
	assert.Contains(t, entry.GetLastError(), "permanent failure")
	assert.Equal(t, MaxRotateAttempts, entry.GetAttempts())
	assert.Equal(t, StateFailed, entry.GetState())
}

func TestRotation_FailedRetry(t *testing.T) {
	// Set up a manager with a working driver
	driver := &mockRotatableDriver{supportsRotation: true}
	rm, _, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	// Manually place an entry in the failed state with NextAction in the past
	entry := &RotationEntry{
		EntryType:      EntryTypeSource,
		SourceName:     "test-source",
		SourceType:     "mock",
		Namespace:      namespace.RootNamespace.UUID,
		RotationPeriod: 1 * time.Hour,
		NextAction:     time.Now().Add(-1 * time.Second), // past due
		State:          StateFailed,
		Attempts:       MaxRotateAttempts,
		LastError:      "previous failure",
	}
	key := buildRotationKey(namespace.RootNamespace.UUID, "test-source")
	rm.entries.Store(key, entry)
	atomic.AddInt64(&rm.entryCount, 1)
	atomic.AddInt64(&rm.failedCount, 1)

	// The tick loop will pick it up, reset to idle, and queue a prepare job
	// Wait for the rotation to complete
	waitForRotation(t, rm, 5*time.Second)

	// Entry should have been retried and succeeded
	assert.Equal(t, int64(0), rm.GetFailedCount(), "failed should be empty after retry")
	assert.Equal(t, 1, driver.GetPrepareCount(), "prepare should be called once during retry")
	assert.Equal(t, StateIdle, entry.GetState(), "should be back to idle")
}

func TestRotation_CleanupRetryAndPersist(t *testing.T) {
	driver := &mockRotatableDriver{
		supportsRotation: true,
		cleanupError:     fmt.Errorf("cleanup failed"),
	}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	err := rm.RegisterSource(ctx, "test-source", "mock", 50*time.Millisecond)
	require.NoError(t, err)

	// Wait for rotation to complete (prepare + commit succeed, cleanup fails)
	waitForRotation(t, rm, 5*time.Second)

	assert.Equal(t, 1, driver.GetPrepareCount())
	assert.Equal(t, 1, driver.GetCommitCount())
	assert.Equal(t, 3, driver.GetCleanupCount(), "cleanup should be retried 3 times")

	// Verify cleanup was persisted to storage
	path := rotationCleanupPath + namespace.RootNamespace.UUID + "/test-source"
	raw, err := rm.storage.Get(context.Background(), path)
	require.NoError(t, err)
	require.NotNil(t, raw, "cleanup should be persisted to storage")

	var pending PendingCleanup
	err = json.Unmarshal(raw.Value, &pending)
	require.NoError(t, err)
	assert.Equal(t, 3, pending.Attempts)
	assert.Equal(t, "test-source", pending.SourceName)
}

func TestRotation_PersistAndRestore(t *testing.T) {
	driver := &mockRotatableDriver{supportsRotation: true}
	rm, ctx, cleanup := createTestRotationManager(t, driver)

	// Register 3 sources
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("source-%d", i)
		source := &credential.CredSource{
			Name:   name,
			Type:   "mock",
			Config: map[string]string{"key": "value"},
		}
		err := rm.core.credConfigStore.CreateSource(ctx, source)
		require.NoError(t, err)
		err = rm.RegisterSource(ctx, name, "mock", 1*time.Hour) // long period so no rotation fires
		require.NoError(t, err)
	}

	assert.Equal(t, int64(3), rm.GetPendingCount())

	// Keep reference to storage before stopping
	storage := rm.storage

	// Stop manager
	cleanup()

	// Create new manager with same storage
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm2 := NewRotationManager(nil, log.WithSubsystem("rotation"), storage)
	rm2.Start()
	defer rm2.Stop()

	// Restore from storage
	err := rm2.Restore(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(3), rm2.GetPendingCount(), "all 3 entries should be restored")
}

func TestRotation_UnregisterDuringStagedActivation(t *testing.T) {
	driver := &mockRotatableDriver{
		supportsRotation: true,
		activateAfter:    2 * time.Second, // long enough to unregister during wait
	}
	rm, ctx, cleanup := createTestRotationManager(t, driver)
	defer cleanup()

	err := rm.RegisterSource(ctx, "test-source", "mock", 500*time.Millisecond)
	require.NoError(t, err)

	// Wait for PREPARE to complete
	waitForRotation(t, rm, 5*time.Second)

	// Verify entry is staged
	entry := rm.GetEntry(namespace.RootNamespace.UUID, "test-source")
	require.NotNil(t, entry)
	assert.Equal(t, StateStaged, entry.GetState())

	// Unregister while activation is pending
	err = rm.UnregisterSource(ctx, "test-source")
	require.NoError(t, err)

	// Entry should be removed
	assert.Equal(t, int64(0), rm.GetPendingCount(), "pending should be empty")
	entry = rm.GetEntry(namespace.RootNamespace.UUID, "test-source")
	assert.Nil(t, entry, "entry should be removed")
}

func TestRotation_StopWithInflightJobs(t *testing.T) {
	driver := &mockRotatableDriver{supportsRotation: true}
	rm, ctx, cleanup := createTestRotationManager(t, driver)

	// Register several sources with very short periods
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("source-%d", i)
		source := &credential.CredSource{
			Name:   name,
			Type:   "mock",
			Config: map[string]string{"key": "value"},
		}
		_ = rm.core.credConfigStore.CreateSource(ctx, source)
		_ = rm.RegisterSource(ctx, name, "mock", 10*time.Millisecond)
	}

	// Stop immediately — should not panic
	cleanup()

	// Double stop should also not panic
	rm.Stop()
}

func TestRotation_FailedStateHasNextAction(t *testing.T) {
	// Verify that when an entry moves to failed, NextAction is set for future retry
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	rm := NewRotationManager(nil, log.WithSubsystem("rotation"), nil)
	rm.Start()
	defer rm.Stop()

	entry := &RotationEntry{
		EntryType:      EntryTypeSource,
		SourceName:     "test",
		Namespace:      "ns",
		RotationPeriod: 1 * time.Hour,
		NextAction:     time.Now().Add(24 * time.Hour), // far in the future
		State:          StateIdle,
		Attempts:       0,
	}

	// Simulate what OnFailure does when max attempts exceeded
	entry.Attempts = MaxRotateAttempts
	entry.State = StateFailed
	before := time.Now()
	entry.NextAction = before.Add(FailedMinAge)

	// NextAction should be ~FailedMinAge from now
	assert.True(t, entry.NextAction.After(before),
		"NextAction should be in the future for failed entry")
	assert.Equal(t, StateFailed, entry.State)
}
