package credential

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// mockConfigStore implements ConfigStoreAccessor for testing. It models the two
// layers of the real store separately: a node-local "cache" (read by GetSpec)
// and shared "storage" (read by ReloadSpec, written by PersistRotatedSpec). This
// lets tests reproduce the cross-node staleness the real Ristretto-backed store
// has: a remote node's persist updates storage but not this node's cache.
type mockConfigStore struct {
	mu        sync.Mutex
	cache     map[string]*CredSpec // read by GetSpec (node-local)
	storage   map[string]*CredSpec // read by ReloadSpec (shared)
	sources   map[string]*CredSource
	persisted []*CredSpec // specs captured by PersistRotatedSpec, in order
	persistFn func(spec *CredSpec) error
}

func newMockConfigStore() *mockConfigStore {
	return &mockConfigStore{
		cache:   make(map[string]*CredSpec),
		storage: make(map[string]*CredSpec),
		sources: make(map[string]*CredSource),
	}
}

func (m *mockConfigStore) GetSpec(ctx context.Context, name string) (*CredSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := m.cache[name]
	if !ok {
		return nil, errors.New("spec not found")
	}
	return spec, nil
}

func (m *mockConfigStore) ReloadSpec(ctx context.Context, name string) (*CredSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := m.storage[name]
	if !ok {
		return nil, errors.New("spec not found")
	}
	m.cache[name] = spec // re-reading from storage refreshes the local cache
	return spec, nil
}

func (m *mockConfigStore) GetSource(ctx context.Context, name string) (*CredSource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	source, ok := m.sources[name]
	if !ok {
		return nil, errors.New("source not found")
	}
	return source, nil
}

func (m *mockConfigStore) PersistRotatedSpec(ctx context.Context, spec *CredSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.persistFn != nil {
		if err := m.persistFn(spec); err != nil {
			return err
		}
	}
	m.persisted = append(m.persisted, spec)
	// A same-node persist updates both storage and this node's cache.
	m.storage[spec.Name] = spec
	m.cache[spec.Name] = spec
	return nil
}

func (m *mockConfigStore) AddSpec(spec *CredSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[spec.Name] = spec
	m.storage[spec.Name] = spec
}

func (m *mockConfigStore) AddSource(source *CredSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources[source.Name] = source
}

// rotateOnOtherNode simulates another HA node rotating+persisting a refresh
// token: shared storage advances, but this node's cache stays stale.
func (m *mockConfigStore) rotateOnOtherNode(name, refreshToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.storage[name]
	updated := &CredSpec{Name: cur.Name, Type: cur.Type, Source: cur.Source, Config: map[string]string{}}
	for k, v := range cur.Config {
		updated.Config[k] = v
	}
	updated.Config["refresh_token"] = refreshToken
	m.storage[name] = updated // cache intentionally left stale
}

// mockSourceDriver implements SourceDriver for testing
type mockSourceDriver struct {
	driverType   string
	mintFunc     func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error)
	revokeFunc   func(ctx context.Context, leaseID string) error
	revokeCalls  atomic.Int32
	mintCalls    atomic.Int32
	lastRevokeID string
	lastRevokeMu sync.Mutex
}

func newMockSourceDriver(driverType string) *mockSourceDriver {
	return &mockSourceDriver{
		driverType: driverType,
		mintFunc: func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
			return map[string]interface{}{
				"username": "test-user",
				"password": "test-pass",
			}, nil, time.Hour, "lease-123", nil
		},
		revokeFunc: func(ctx context.Context, leaseID string) error {
			return nil
		},
	}
}

func (d *mockSourceDriver) MintCredential(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.mintCalls.Add(1)
	return d.mintFunc(ctx, spec)
}

func (d *mockSourceDriver) Revoke(ctx context.Context, leaseID string) error {
	d.revokeCalls.Add(1)
	d.lastRevokeMu.Lock()
	d.lastRevokeID = leaseID
	d.lastRevokeMu.Unlock()
	return d.revokeFunc(ctx, leaseID)
}

func (d *mockSourceDriver) Type() string {
	return d.driverType
}

func (d *mockSourceDriver) Cleanup(ctx context.Context) error {
	return nil
}

// mockSourceDriverFactory implements SourceDriverFactory for testing
type mockSourceDriverFactory struct {
	driverType string
	driver     *mockSourceDriver
}

func newMockSourceDriverFactory(driverType string) *mockSourceDriverFactory {
	return &mockSourceDriverFactory{
		driverType: driverType,
		driver:     newMockSourceDriver(driverType),
	}
}

func (f *mockSourceDriverFactory) Type() string {
	return f.driverType
}

func (f *mockSourceDriverFactory) Create(config map[string]string, logger *logger.GatedLogger) (SourceDriver, error) {
	return f.driver, nil
}

func (f *mockSourceDriverFactory) ValidateConfig(config map[string]string) error {
	return nil
}

func (f *mockSourceDriverFactory) SensitiveConfigFields() []string {
	return []string{"password", "secret"}
}

func (f *mockSourceDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("mock driver cannot infer type")
}

// mockCredentialType implements Type for testing
type mockCredentialType struct {
	name     string
	category string
}

func newMockCredentialType(name, category string) *mockCredentialType {
	return &mockCredentialType{name: name, category: category}
}

func (t *mockCredentialType) Metadata() TypeMetadata {
	return TypeMetadata{
		Name:        t.name,
		Category:    t.category,
		Description: "Mock credential type for testing",
		DefaultTTL:  time.Hour,
	}
}

func (t *mockCredentialType) ConfigSchema() []*FieldValidator {
	return nil // No schema required for mock
}

func (t *mockCredentialType) ValidateConfig(config map[string]string, sourceType string) error {
	return nil
}

func (t *mockCredentialType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*Credential, error) {
	data := make(map[string]string)
	for k, v := range rawData {
		if s, ok := v.(string); ok {
			data[k] = s
		}
	}
	return &Credential{
		Type:      t.name,
		Category:  t.category,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Data:      data,
		Revocable: leaseID != "",
	}, nil
}

func (t *mockCredentialType) Validate(cred *Credential) error {
	return nil
}

func (t *mockCredentialType) Revoke(ctx context.Context, cred *Credential, driver SourceDriver) error {
	if cred.LeaseID != "" {
		return driver.Revoke(ctx, cred.LeaseID)
	}
	return nil
}

func (t *mockCredentialType) RequiresSpecRotation() bool {
	return false
}

func (t *mockCredentialType) SensitiveConfigFields() []string { return nil }

func (t *mockCredentialType) FieldSchemas() map[string]*CredentialFieldSchema {
	return map[string]*CredentialFieldSchema{
		"username": {Description: "Username", Sensitive: false},
		"password": {Description: "Password", Sensitive: true},
	}
}

// ============================================================================
// Test Helpers
// ============================================================================

func createTestManager(t *testing.T) (*Manager, *mockConfigStore, *mockSourceDriverFactory) {
	t.Helper()

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	// Create registries
	typeRegistry := NewTypeRegistry()
	driverRegistry := NewDriverRegistry(nil)
	configStore := newMockConfigStore()

	// Register mock credential type
	mockType := newMockCredentialType(TypeVaultToken, CategoryAPI)
	err := typeRegistry.Register(mockType)
	require.NoError(t, err)

	// Register mock driver factory
	factory := newMockSourceDriverFactory(SourceTypeLocal)
	err = driverRegistry.RegisterFactory(factory)
	require.NoError(t, err)

	// Create manager (credentials are cache-only, no storage needed)
	manager, err := NewManager(typeRegistry, driverRegistry, configStore, log)
	require.NoError(t, err)

	return manager, configStore, factory
}

func createNamespaceContext() context.Context {
	ns := &namespace.Namespace{
		ID:   "test-namespace-id",
		Path: "test/",
	}
	return namespace.ContextWithNamespace(context.Background(), ns)
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestNewManager(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	typeRegistry := NewTypeRegistry()
	driverRegistry := NewDriverRegistry(nil)
	configStore := newMockConfigStore()

	manager, err := NewManager(typeRegistry, driverRegistry, configStore, log)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Verify cache is created
	assert.NotNil(t, manager.cache)

	manager.Stop()
}

func TestManager_IssueCredential_Success(t *testing.T) {
	manager, configStore, _ := createTestManager(t)
	defer manager.Stop()

	// Setup spec and source
	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-123"
	tokenTTL := time.Hour

	cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, TypeVaultToken, cred.Type)
	assert.Equal(t, CategoryAPI, cred.Category)
	assert.Equal(t, tokenID, cred.TokenID)
	assert.Equal(t, "test-spec", cred.SpecName)
	assert.Equal(t, "test-user", cred.Data["username"])
	assert.Equal(t, "test-pass", cred.Data["password"])
}

func TestManager_IssueCredential_CacheHit(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	// Setup spec and source
	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-123"
	tokenTTL := time.Hour

	// First call - should mint
	cred1, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)

	// Second call - should use cache
	cred2, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)

	// Should be the same credential
	assert.Equal(t, cred1.TokenID, cred2.TokenID)
	assert.Equal(t, cred1.IssuedAt, cred2.IssuedAt)

	// Driver should only be called once
	assert.Equal(t, int32(1), factory.driver.mintCalls.Load())
}

func TestManager_IssueCredential_ExpiredNotServed(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	// A short-lived, non-revocable credential (LeaseTTL>0, no leaseID) — the shape
	// of an exchanged bearer token. It must not be served from cache once its lease
	// has elapsed; the manager must re-mint.
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"username": "u", "password": "p"}, nil, 40 * time.Millisecond, "", nil
	}

	configStore.AddSource(&CredSource{Name: "test-source", Type: SourceTypeLocal, Config: map[string]string{}})
	configStore.AddSpec(&CredSpec{Name: "test-spec", Type: TypeVaultToken, Source: "test-source", Config: map[string]string{}})

	ctx := createNamespaceContext()
	tokenID := "token-expiry"
	tokenTTL := time.Hour

	_, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), factory.driver.mintCalls.Load())

	// Within the lease: cache hit, no re-mint.
	_, err = manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), factory.driver.mintCalls.Load(), "should serve from cache before expiry")

	// After the lease elapses: the expired entry is not served — re-mint.
	time.Sleep(80 * time.Millisecond)
	_, err = manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), factory.driver.mintCalls.Load(), "expired credential must be re-minted, not served stale")
}

func TestManager_IssueCredential_SpecNotFound(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-123", "nonexistent-spec", time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_IssueCredential_SourceNotFound(t *testing.T) {
	manager, configStore, _ := createTestManager(t)
	defer manager.Stop()

	// Add spec without corresponding source
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "nonexistent-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-123", "test-spec", time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source")
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_IssueCredential_NoNamespace(t *testing.T) {
	manager, configStore, _ := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	// Context without namespace
	ctx := context.Background()

	_, err := manager.IssueCredential(ctx, "token-123", "test-spec", time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace")
}

func TestManager_RevokeByExpiration_Success(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()

	// Issue a credential first
	cred, err := manager.IssueCredential(ctx, "token-revoke", "test-spec", time.Hour, nil)
	require.NoError(t, err)

	// Driver is automatically created during IssueCredential, no need to manually create it
	// The GetOrCreateDriver call in RevokeByExpiration will find it

	// Revoke by expiration
	credentialID := cred.CredentialID
	cacheKey := "test-namespace-id:token-revoke"
	err = manager.RevokeByExpiration(ctx, credentialID, cacheKey, cred.LeaseID, "test-source", true)
	require.NoError(t, err)

	// Verify driver revoke was called
	assert.Equal(t, int32(1), factory.driver.revokeCalls.Load())
}

func TestManager_RevokeByExpiration_NonRevocable(t *testing.T) {
	manager, _, factory := createTestManager(t)
	defer manager.Stop()

	ctx := context.Background()

	// Revoke non-revocable credential
	err := manager.RevokeByExpiration(ctx, "cred-uuid-123", "ns:token", "", "", false)
	require.NoError(t, err)

	// Driver revoke should not be called
	assert.Equal(t, int32(0), factory.driver.revokeCalls.Load())
}

func TestManager_RevokeByExpiration_SourceNotFound(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	ctx := createNamespaceContext()

	// Revoke with non-existent source - should return error to trigger retry
	err := manager.RevokeByExpiration(ctx, "cred-uuid-123", "ns:token", "lease-123", "nonexistent-source", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_RevokeByExpiration_CreatesDriverIfNeeded(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	// Add source to config store but DON'T pre-create the driver
	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()

	// Driver doesn't exist yet, but revocation should create it and succeed
	err := manager.RevokeByExpiration(ctx, "cred-uuid-123", "ns:token", "lease-123", "test-source", true)
	require.NoError(t, err)

	// Driver should have been created and revoke called
	assert.Equal(t, int32(1), factory.driver.revokeCalls.Load())
}

func TestManager_RevokeByExpiration_RevokeFails(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})

	// Configure driver to fail revocation
	factory.driver.revokeFunc = func(ctx context.Context, leaseID string) error {
		return errors.New("revoke failed")
	}

	ctx := createNamespaceContext()

	// Revoke should return error to trigger retry (driver will be auto-created)
	err := manager.RevokeByExpiration(ctx, "cred-uuid-123", "ns:token", "lease-123", "test-source", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoke failed")
}

func TestManager_IssueCredential_Concurrent(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "concurrent-token"

	// Concurrent requests for the same token
	var wg sync.WaitGroup
	numRequests := 10
	results := make([]*Credential, numRequests)
	errs := make([]error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour, nil)
			results[idx] = cred
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	// All should succeed
	for i := 0; i < numRequests; i++ {
		require.NoError(t, errs[i])
		require.NotNil(t, results[i])
	}

	// All should have the same IssuedAt (same credential due to singleflight)
	issuedAt := results[0].IssuedAt
	for i := 1; i < numRequests; i++ {
		assert.Equal(t, issuedAt, results[i].IssuedAt)
	}

	// Driver should only be called once (singleflight dedup)
	assert.Equal(t, int32(1), factory.driver.mintCalls.Load())
}

func TestManager_Stop(t *testing.T) {
	manager, _, _ := createTestManager(t)

	// Should not panic
	manager.Stop()
}

func TestManager_IssueCredential_Timeout(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	// Set a very short timeout
	manager.SetIssuanceTimeout(50 * time.Millisecond)

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	// Configure driver to block longer than timeout
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		select {
		case <-ctx.Done():
			return nil, nil, 0, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return map[string]interface{}{
				"username": "test-user",
				"password": "test-pass",
			}, nil, time.Hour, "lease-123", nil
		}
	}

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-timeout", "test-spec", time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestManager_IssueCredential_ErrorNotCached(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeVaultToken,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-error-retry"

	// First call fails
	callCount := 0
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		callCount++
		if callCount == 1 {
			return nil, nil, 0, "", errors.New("transient error")
		}
		return map[string]interface{}{
			"username": "test-user",
			"password": "test-pass",
		}, nil, time.Hour, "lease-123", nil
	}

	// First request should fail
	_, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transient error")

	// Second request should succeed (error not cached)
	cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour, nil)
	require.NoError(t, err)
	require.NotNil(t, cred)

	// Driver should have been called twice (error not cached, retry worked)
	assert.Equal(t, 2, callCount)
}

func TestManager_SetIssuanceTimeout(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	// Default timeout should be set
	assert.Equal(t, DefaultIssuanceTimeout, manager.issuanceTimeout)

	// Set custom timeout
	manager.SetIssuanceTimeout(10 * time.Second)
	assert.Equal(t, 10*time.Second, manager.issuanceTimeout)

	// Setting zero resets to default
	manager.SetIssuanceTimeout(0)
	assert.Equal(t, DefaultIssuanceTimeout, manager.issuanceTimeout)

	// Setting negative resets to default
	manager.SetIssuanceTimeout(-5 * time.Second)
	assert.Equal(t, DefaultIssuanceTimeout, manager.issuanceTimeout)
}

// ============================================================================
// Security Fix Tests - SpecExists
// ============================================================================

func TestManager_SpecExists(t *testing.T) {
	manager, configStore, _ := createTestManager(t)
	defer manager.Stop()

	ctx := createNamespaceContext()

	t.Run("spec exists", func(t *testing.T) {
		configStore.AddSpec(&CredSpec{
			Name:   "existing-spec",
			Type:   TypeVaultToken,
			Source: "test-source",
			Config: map[string]string{},
		})

		exists := manager.SpecExists(ctx, "existing-spec")
		assert.True(t, exists, "should return true for existing spec")
	})

	t.Run("spec does not exist", func(t *testing.T) {
		exists := manager.SpecExists(ctx, "nonexistent-spec")
		assert.False(t, exists, "should return false for nonexistent spec")
	})

	t.Run("nil config store", func(t *testing.T) {
		// Create manager with nil config store
		log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
		typeRegistry := NewTypeRegistry()
		driverRegistry := NewDriverRegistry(nil)

		managerWithNilStore, err := NewManager(typeRegistry, driverRegistry, nil, log)
		require.NoError(t, err)
		defer managerWithNilStore.Stop()

		// configStore is nil (passed to NewManager), so SpecResolver will handle nil gracefully
		exists := managerWithNilStore.SpecExists(ctx, "any-spec")
		assert.False(t, exists, "should return false when config store is nil")
	})
}

// ============================================================================
// Refresh-token write-back
// ============================================================================

func addRefreshSpecAndSource(configStore *mockConfigStore, refreshToken string) {
	configStore.AddSource(&CredSource{Name: "src", Type: SourceTypeLocal, Config: map[string]string{}})
	configStore.AddSpec(&CredSpec{Name: "gh", Type: TypeVaultToken, Source: "src", Config: map[string]string{
		"auth_method": "authorization_code", "refresh_token": refreshToken,
	}})
}

func TestManager_WriteBack_StripsReservedKeyAndPersists(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	addRefreshSpecAndSource(configStore, "rt-old")

	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{
			"api_key":                          "at-new",
			RawRotatedRefreshTokenKey:          "rt-new",
			RawRotatedRefreshTokenExpiresAtKey: "2030-01-01T00:00:00Z",
		}, nil, time.Hour, "", nil
	}

	cred, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.NoError(t, err)

	// The reserved rotated-token keys must be stripped before parsing.
	_, leaked := cred.Data[RawRotatedRefreshTokenKey]
	assert.False(t, leaked, "reserved rotated-token key must not reach credential Data")
	_, leakedExp := cred.Data[RawRotatedRefreshTokenExpiresAtKey]
	assert.False(t, leakedExp, "reserved rotated-expiry key must not reach credential Data")
	assert.Equal(t, "at-new", cred.Data["api_key"])

	// The rotated token and its refreshed expiry are persisted into a fresh spec copy.
	require.Len(t, configStore.persisted, 1)
	assert.Equal(t, "rt-new", configStore.persisted[0].Config["refresh_token"])
	assert.Equal(t, "2030-01-01T00:00:00Z", configStore.persisted[0].Config["refresh_token_expires_at"])
}

func TestManager_WriteBack_RotatingWithoutExpiry_KeepsPriorExpiry(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	configStore.AddSource(&CredSource{Name: "src", Type: SourceTypeLocal, Config: map[string]string{}})
	configStore.AddSpec(&CredSpec{Name: "gh", Type: TypeVaultToken, Source: "src", Config: map[string]string{
		"auth_method": "authorization_code", "refresh_token": "rt-old", "refresh_token_expires_at": "2027-01-01T00:00:00Z",
	}})

	// Rotates the token but surfaces no new expiry.
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"api_key": "at-new", RawRotatedRefreshTokenKey: "rt-new"}, nil, time.Hour, "", nil
	}

	_, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.NoError(t, err)

	require.Len(t, configStore.persisted, 1)
	assert.Equal(t, "rt-new", configStore.persisted[0].Config["refresh_token"])
	// The prior expiry is left untouched rather than dropped or overwritten.
	assert.Equal(t, "2027-01-01T00:00:00Z", configStore.persisted[0].Config["refresh_token_expires_at"])
}

func TestManager_WriteBack_NonRotating_NoPersist(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	addRefreshSpecAndSource(configStore, "rt-stable")

	// No reserved key → stable token, no write-back.
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"api_key": "at-1"}, nil, time.Hour, "", nil
	}

	_, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.NoError(t, err)
	assert.Empty(t, configStore.persisted, "non-rotating mint must not persist")
}

func TestManager_InvalidGrant_RetriesOnceWithReloadedSpec(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	addRefreshSpecAndSource(configStore, "rt-stale")

	// Cross-node rotation: attempt 1 reads this node's stale cache (rt-stale) and
	// is rejected; meanwhile another node rotated+persisted rt-fresh to shared
	// storage WITHOUT touching this node's cache. The retry must reload from
	// storage (not the cache) to pick up rt-fresh.
	var attempts int32
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			assert.Equal(t, "rt-stale", spec.Config["refresh_token"])
			configStore.rotateOnOtherNode("gh", "rt-fresh") // storage advances; cache stays stale
			return nil, nil, 0, "", ErrRefreshTokenRejected
		}
		assert.Equal(t, "rt-fresh", spec.Config["refresh_token"], "retry must reload from storage, bypassing the stale cache")
		return map[string]interface{}{"api_key": "at-ok"}, nil, time.Hour, "", nil
	}

	cred, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.NoError(t, err)
	assert.Equal(t, "at-ok", cred.Data["api_key"])
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts), "must mint exactly twice (one retry)")
}

func TestManager_InvalidGrant_RetryFailsOnce_SurfacesError(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	addRefreshSpecAndSource(configStore, "rt-dead")

	var attempts int32
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, nil, 0, "", ErrRefreshTokenRejected // never recovers
	}

	_, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRefreshTokenRejected))
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts), "retry is bounded to exactly one extra attempt")
}

func TestManager_WriteBack_PersistError_DoesNotFailIssuance(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()
	addRefreshSpecAndSource(configStore, "rt-old")

	configStore.persistFn = func(spec *CredSpec) error { return errors.New("storage down") }
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"api_key": "at-new", RawRotatedRefreshTokenKey: "rt-new"}, nil, time.Hour, "", nil
	}

	// A persist failure must not fail issuance — the access token is still valid.
	cred, err := manager.IssueCredential(createNamespaceContext(), "tok-1", "gh", time.Hour, nil)
	require.NoError(t, err)
	assert.Equal(t, "at-new", cred.Data["api_key"])
}

func TestManager_LockSpec_Mutex(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	unlock, err := manager.LockSpec(context.Background(), "ns-uuid", "gh")
	require.NoError(t, err)

	// A second lock for the same key blocks until unlock.
	locked := make(chan struct{})
	go func() {
		u2, e := manager.LockSpec(context.Background(), "ns-uuid", "gh")
		if e == nil {
			close(locked)
			u2()
		}
	}()
	select {
	case <-locked:
		t.Fatal("second LockSpec acquired while the first was held")
	case <-time.After(50 * time.Millisecond):
	}

	// A different key does not block.
	u3, err := manager.LockSpec(context.Background(), "ns-uuid", "other")
	require.NoError(t, err)
	u3()

	unlock()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("second LockSpec did not acquire after unlock")
	}
}

func TestManager_LockSpec_ContextCancel(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	unlock, err := manager.LockSpec(context.Background(), "ns-uuid", "gh")
	require.NoError(t, err)
	defer unlock()

	// A waiter whose context is cancelled must return an error, not block forever.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = manager.LockSpec(ctx, "ns-uuid", "gh")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// ============================================================================
// Token-exchange input tests
// ============================================================================

// exchangeDriverFactory builds a single exchangeDriver instance (defined in
// minting_service_test.go) so tests can observe its call count across issuances.
type exchangeDriverFactory struct {
	driver *exchangeDriver
}

func (f *exchangeDriverFactory) Type() string { return "exchange_src" }
func (f *exchangeDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (SourceDriver, error) {
	return f.driver, nil
}
func (f *exchangeDriverFactory) ValidateConfig(config map[string]string) error   { return nil }
func (f *exchangeDriverFactory) SensitiveConfigFields() []string                 { return nil }
func (f *exchangeDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("mock exchange driver cannot infer type")
}

// createExchangeTestManager builds a manager whose source driver implements
// ExchangeMinter, plus an exchange-enabled spec.
func createExchangeTestManager(t *testing.T) (*Manager, *exchangeDriverFactory) {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	typeRegistry := NewTypeRegistry()
	require.NoError(t, typeRegistry.Register(newMockCredentialType(TypeVaultToken, CategoryAPI)))

	driverRegistry := NewDriverRegistry(nil)
	factory := &exchangeDriverFactory{driver: &exchangeDriver{}}
	require.NoError(t, driverRegistry.RegisterFactory(factory))

	configStore := newMockConfigStore()
	configStore.AddSource(&CredSource{Name: "ex-source", Type: "exchange_src", Config: map[string]string{}})
	configStore.AddSpec(&CredSpec{
		Name:   "ex-spec",
		Type:   TypeVaultToken,
		Source: "ex-source",
		Config: map[string]string{ConfigSubjectTokenSource: SourceHeader},
	})

	manager, err := NewManager(typeRegistry, driverRegistry, configStore, log)
	require.NoError(t, err)
	return manager, factory
}

func exchangeInputsFor(subject string) *ExchangeInputs {
	return &ExchangeInputs{
		SubjectToken:       subject,
		SubjectTokenType:   TokenTypeJWT,
		SubjectTokenOrigin: ExchangeOriginUnverified,
	}
}

// Two callers sharing one session token but supplying different subject tokens
// must get distinct credentials (no cross-caller leak), while a repeat of the
// same inputs is served from cache.
func TestManager_IssueCredential_ExchangeInputs_DistinctCache(t *testing.T) {
	manager, factory := createExchangeTestManager(t)
	defer manager.Stop()

	ctx := createNamespaceContext()
	const sharedToken = "shared-session-token"
	inA := exchangeInputsFor("subject-A")
	inB := exchangeInputsFor("subject-B")

	credA1, err := manager.IssueCredential(ctx, sharedToken, "ex-spec", time.Hour, inA)
	require.NoError(t, err)
	credA2, err := manager.IssueCredential(ctx, sharedToken, "ex-spec", time.Hour, inA)
	require.NoError(t, err)
	credB, err := manager.IssueCredential(ctx, sharedToken, "ex-spec", time.Hour, inB)
	require.NoError(t, err)

	// Same inputs → cached (one mint); different inputs → separate credential.
	assert.Equal(t, credA1.CredentialID, credA2.CredentialID, "identical inputs should hit cache")
	assert.NotEqual(t, credA1.CredentialID, credB.CredentialID, "distinct inputs must not share a credential")
	assert.Equal(t, "subject-A", credA1.Data["username"])
	assert.Equal(t, "subject-B", credB.Data["username"])
	assert.Equal(t, int32(2), factory.driver.exchangeCount.Load(), "expected exactly two mints (A once, B once)")
}

// A spec that carries exchange inputs but whose driver is not an ExchangeMinter
// must fail closed, and nothing may be cached (a retry still errors).
func TestManager_IssueCredential_ExchangeInputs_NonExchangeDriver(t *testing.T) {
	manager, configStore, factory := createTestManager(t)
	defer manager.Stop()

	configStore.AddSource(&CredSource{Name: "test-source", Type: SourceTypeLocal, Config: map[string]string{}})
	configStore.AddSpec(&CredSpec{Name: "test-spec", Type: TypeVaultToken, Source: "test-source", Config: map[string]string{}})

	ctx := createNamespaceContext()
	_, err := manager.IssueCredential(ctx, "tok", "test-spec", time.Hour, exchangeInputsFor("s"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not accept token-exchange inputs")

	// Nothing should have been cached; a retry must error again (not serve a stale entry).
	_, err = manager.IssueCredential(ctx, "tok", "test-spec", time.Hour, exchangeInputsFor("s"))
	require.Error(t, err)
	assert.Equal(t, int32(0), factory.driver.mintCalls.Load(), "plain mint must never run for exchange inputs")
}
