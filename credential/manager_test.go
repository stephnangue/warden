package credential

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// mockConfigStore implements ConfigStoreAccessor for testing
type mockConfigStore struct {
	specs   map[string]*CredSpec
	sources map[string]*CredSource
}

func newMockConfigStore() *mockConfigStore {
	return &mockConfigStore{
		specs:   make(map[string]*CredSpec),
		sources: make(map[string]*CredSource),
	}
}

func (m *mockConfigStore) GetSpec(ctx context.Context, name string) (*CredSpec, error) {
	spec, ok := m.specs[name]
	if !ok {
		return nil, errors.New("spec not found")
	}
	return spec, nil
}

func (m *mockConfigStore) GetSource(ctx context.Context, name string) (*CredSource, error) {
	source, ok := m.sources[name]
	if !ok {
		return nil, errors.New("source not found")
	}
	return source, nil
}

func (m *mockConfigStore) AddSpec(spec *CredSpec) {
	m.specs[spec.Name] = spec
}

func (m *mockConfigStore) AddSource(source *CredSource) {
	m.sources[source.Name] = source
}

// mockSourceDriver implements SourceDriver for testing
type mockSourceDriver struct {
	driverType     string
	mintFunc       func(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error)
	revokeFunc     func(ctx context.Context, leaseID string) error
	revokeCalls    atomic.Int32
	mintCalls      atomic.Int32
	lastRevokeID   string
	lastRevokeMu   sync.Mutex
}

func newMockSourceDriver(driverType string) *mockSourceDriver {
	return &mockSourceDriver{
		driverType: driverType,
		mintFunc: func(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error) {
			return map[string]interface{}{
				"username": "test-user",
				"password": "test-pass",
			}, time.Hour, "lease-123", nil
		},
		revokeFunc: func(ctx context.Context, leaseID string) error {
			return nil
		},
	}
}

func (d *mockSourceDriver) MintCredential(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error) {
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

func (t *mockCredentialType) ValidateConfig(config map[string]string, sourceType string) error {
	return nil
}

func (t *mockCredentialType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*Credential, error) {
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
	mockType := newMockCredentialType(TypeDatabaseUserPass, CategoryDatabase)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-123"
	tokenTTL := time.Hour

	cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, TypeDatabaseUserPass, cred.Type)
	assert.Equal(t, CategoryDatabase, cred.Category)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-123"
	tokenTTL := time.Hour

	// First call - should mint
	cred1, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL)
	require.NoError(t, err)

	// Second call - should use cache
	cred2, err := manager.IssueCredential(ctx, tokenID, "test-spec", tokenTTL)
	require.NoError(t, err)

	// Should be the same credential
	assert.Equal(t, cred1.TokenID, cred2.TokenID)
	assert.Equal(t, cred1.IssuedAt, cred2.IssuedAt)

	// Driver should only be called once
	assert.Equal(t, int32(1), factory.driver.mintCalls.Load())
}

func TestManager_IssueCredential_SpecNotFound(t *testing.T) {
	manager, _, _ := createTestManager(t)
	defer manager.Stop()

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-123", "nonexistent-spec", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_IssueCredential_SourceNotFound(t *testing.T) {
	manager, configStore, _ := createTestManager(t)
	defer manager.Stop()

	// Add spec without corresponding source
	configStore.AddSpec(&CredSpec{
		Name:   "test-spec",
		Type:   TypeDatabaseUserPass,
		Source: "nonexistent-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-123", "test-spec", time.Hour)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	// Context without namespace
	ctx := context.Background()

	_, err := manager.IssueCredential(ctx, "token-123", "test-spec", time.Hour)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()

	// Issue a credential first
	cred, err := manager.IssueCredential(ctx, "token-revoke", "test-spec", time.Hour)
	require.NoError(t, err)

	// Create the driver instance so GetDriver will find it (with namespace context)
	_, _, err = manager.driverRegistry.CreateDriver(ctx, "test-source", &CredSource{
		Name:   "test-source",
		Type:   SourceTypeLocal,
		Config: map[string]string{},
	})
	require.NoError(t, err)

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
		Type:   TypeDatabaseUserPass,
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
			cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	// Configure driver to block longer than timeout
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error) {
		select {
		case <-ctx.Done():
			return nil, 0, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return map[string]interface{}{
				"username": "test-user",
				"password": "test-pass",
			}, time.Hour, "lease-123", nil
		}
	}

	ctx := createNamespaceContext()

	_, err := manager.IssueCredential(ctx, "token-timeout", "test-spec", time.Hour)
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
		Type:   TypeDatabaseUserPass,
		Source: "test-source",
		Config: map[string]string{},
	})

	ctx := createNamespaceContext()
	tokenID := "token-error-retry"

	// First call fails
	callCount := 0
	factory.driver.mintFunc = func(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error) {
		callCount++
		if callCount == 1 {
			return nil, 0, "", errors.New("transient error")
		}
		return map[string]interface{}{
			"username": "test-user",
			"password": "test-pass",
		}, time.Hour, "lease-123", nil
	}

	// First request should fail
	_, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transient error")

	// Second request should succeed (error not cached)
	cred, err := manager.IssueCredential(ctx, tokenID, "test-spec", time.Hour)
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
			Type:   TypeDatabaseUserPass,
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

		// configStore is nil, so set it to nil explicitly for this test
		managerWithNilStore.configStore = nil

		exists := managerWithNilStore.SpecExists(ctx, "any-spec")
		assert.False(t, exists, "should return false when config store is nil")
	})
}
