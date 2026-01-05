package core

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// setupTestCredentialConfigStore creates a test credential config store with in-memory storage
func setupTestCredentialConfigStore(t *testing.T) (*CredentialConfigStore, context.Context) {
	t.Helper()

	// Create test logger
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	// Create in-memory physical storage
	physical, _ := inmem.NewInmem(nil, nil)

	// Create barrier
	barrier, err := NewAESGCMBarrier(physical)
	if err != nil {
		t.Fatalf("failed to create barrier: %v", err)
	}

	// Initialize barrier with a test key
	testKey, _ := barrier.GenerateKey(rand.Reader)
	if err := barrier.Initialize(context.Background(), testKey, nil, rand.Reader); err != nil {
		t.Fatalf("failed to initialize barrier: %v", err)
	}

	// Unseal barrier
	if err := barrier.Unseal(context.Background(), testKey); err != nil {
		t.Fatalf("failed to unseal barrier: %v", err)
	}

	// Create storage view
	storage := NewBarrierView(barrier, credentialConfigStorePath)

	// Create minimal Core for testing
	core := &Core{
		barrier: barrier,
		logger:  log,
	}

	// Create credential config store
	config := DefaultCredConfigStoreConfig()
	store, err := NewCredentialConfigStore(core, config)
	if err != nil {
		t.Fatalf("failed to create credential config store: %v", err)
	}
	store.storage = storage

	// Create test namespace context
	rootNS := &namespace.Namespace{
		ID:   namespace.RootNamespaceID,
		Path: "",
		UUID: "root-uuid",
	}
	ctx := namespace.ContextWithNamespace(context.Background(), rootNS)

	return store, ctx
}

// TestCredentialConfigStore_CreateSpec tests creating a credential spec
func TestCredentialConfigStore_CreateSpec(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	spec := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "database_userpass",
		SourceName: "test-source",
		MinTTL:     time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	// Create spec
	err := store.CreateSpec(ctx, spec)
	if err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Verify spec exists in cache
	cacheKey := store.buildSpecCacheKey("root-uuid", "test-spec")
	if _, found := store.specsByID.Get(cacheKey); !found {
		t.Error("spec not found in cache")
	}

	// Retrieve spec
	retrieved, err := store.GetSpec(ctx, "test-spec")
	if err != nil {
		t.Fatalf("failed to get spec: %v", err)
	}

	// Verify spec data
	if retrieved.Name != spec.Name {
		t.Errorf("expected name %s, got %s", spec.Name, retrieved.Name)
	}
	if retrieved.Type != spec.Type {
		t.Errorf("expected type %s, got %s", spec.Type, retrieved.Type)
	}
	if retrieved.SourceName != spec.SourceName {
		t.Errorf("expected source name %s, got %s", spec.SourceName, retrieved.SourceName)
	}
}

// TestCredentialConfigStore_CreateSpecDuplicate tests creating duplicate spec
func TestCredentialConfigStore_CreateSpecDuplicate(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	spec := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "database_userpass",
		SourceName: "test-source",
	}

	// Create first spec
	err := store.CreateSpec(ctx, spec)
	if err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Try to create duplicate (same name, different type/source)
	spec2 := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "aws_access_keys",
		SourceName: "test-source", // Use same source
	}

	err = store.CreateSpec(ctx, spec2)
	if err != ErrSpecAlreadyExists {
		t.Errorf("expected ErrSpecAlreadyExists, got %v", err)
	}
}

// TestCredentialConfigStore_UpdateSpec tests updating a spec
func TestCredentialConfigStore_UpdateSpec(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	spec := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "database_userpass",
		SourceName: "test-source",
		MinTTL:     time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	// Create spec
	if err := store.CreateSpec(ctx, spec); err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Update spec
	spec.MinTTL = 2 * time.Hour
	spec.MaxTTL = 48 * time.Hour
	err := store.UpdateSpec(ctx, spec)
	if err != nil {
		t.Fatalf("failed to update spec: %v", err)
	}

	// Retrieve and verify
	retrieved, err := store.GetSpec(ctx, "test-spec")
	if err != nil {
		t.Fatalf("failed to get spec: %v", err)
	}

	if retrieved.MinTTL != 2*time.Hour {
		t.Errorf("expected MinTTL 2h, got %v", retrieved.MinTTL)
	}
	if retrieved.MaxTTL != 48*time.Hour {
		t.Errorf("expected MaxTTL 48h, got %v", retrieved.MaxTTL)
	}
}

// TestCredentialConfigStore_DeleteSpec tests deleting a spec
func TestCredentialConfigStore_DeleteSpec(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	spec := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "database_userpass",
		SourceName: "test-source",
	}

	// Create spec
	if err := store.CreateSpec(ctx, spec); err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Delete spec
	err := store.DeleteSpec(ctx, "test-spec")
	if err != nil {
		t.Fatalf("failed to delete spec: %v", err)
	}

	// Verify spec is gone
	_, err = store.GetSpec(ctx, "test-spec")
	if err != ErrSpecNotFound {
		t.Errorf("expected ErrSpecNotFound, got %v", err)
	}

	// Verify cache is cleared
	cacheKey := store.buildSpecCacheKey("root-uuid", "test-spec")
	if _, found := store.specsByID.Get(cacheKey); found {
		t.Error("spec still in cache after deletion")
	}
}

// TestCredentialConfigStore_ListSpecs tests listing specs
func TestCredentialConfigStore_ListSpecs(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Empty list
	specs, err := store.ListSpecs(ctx)
	if err != nil {
		t.Fatalf("failed to list specs: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("expected 0 specs, got %d", len(specs))
	}

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	// Create multiple specs
	for i := 1; i <= 3; i++ {
		spec := &credential.CredSpec{
			Name:       "spec-" + string(rune('0'+i)),
			Type:       "database_userpass",
			SourceName: "test-source",
		}
		if err := store.CreateSpec(ctx, spec); err != nil {
			t.Fatalf("failed to create spec %d: %v", i, err)
		}
	}

	// List specs
	specs, err = store.ListSpecs(ctx)
	if err != nil {
		t.Fatalf("failed to list specs: %v", err)
	}
	if len(specs) != 3 {
		t.Errorf("expected 3 specs, got %d", len(specs))
	}

	// Verify all specs are present
	names := make(map[string]bool)
	for _, spec := range specs {
		names[spec.Name] = true
	}

	for i := 1; i <= 3; i++ {
		expected := "spec-" + string(rune('0'+i))
		if !names[expected] {
			t.Errorf("expected spec %s in list", expected)
		}
	}
}

// TestCredentialConfigStore_CreateSource tests creating a credential source
func TestCredentialConfigStore_CreateSource(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
		Config: map[string]string{
			"path": "/secrets",
		},
	}

	// Create source
	err := store.CreateSource(ctx, source)
	if err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	// Verify source exists in cache
	cacheKey := store.buildSourceCacheKey("root-uuid", "test-source")
	if _, found := store.sourcesByID.Get(cacheKey); !found {
		t.Error("source not found in cache")
	}

	// Retrieve source
	retrieved, err := store.GetSource(ctx, "test-source")
	if err != nil {
		t.Fatalf("failed to get source: %v", err)
	}

	// Verify source data
	if retrieved.Name != source.Name {
		t.Errorf("expected name %s, got %s", source.Name, retrieved.Name)
	}
	if retrieved.Type != source.Type {
		t.Errorf("expected type %s, got %s", source.Type, retrieved.Type)
	}
	if retrieved.Config["path"] != "/secrets" {
		t.Errorf("expected path /secrets, got %s", retrieved.Config["path"])
	}
}

// TestCredentialConfigStore_DeleteSource tests deleting a source
func TestCredentialConfigStore_DeleteSource(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}

	// Create source
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	// Delete source
	err := store.DeleteSource(ctx, "test-source")
	if err != nil {
		t.Fatalf("failed to delete source: %v", err)
	}

	// Verify source is gone
	_, err = store.GetSource(ctx, "test-source")
	if err != ErrSourceNotFound {
		t.Errorf("expected ErrSourceNotFound, got %v", err)
	}
}

// TestCredentialConfigStore_CheckSourceReferences tests checking source references
func TestCredentialConfigStore_CheckSourceReferences(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create sources
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	otherSource := &credential.CredSource{
		Name: "other-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, otherSource); err != nil {
		t.Fatalf("failed to create other source: %v", err)
	}

	// Create specs referencing the source
	for i := 1; i <= 2; i++ {
		spec := &credential.CredSpec{
			Name:       "spec-" + string(rune('0'+i)),
			Type:       "database_userpass",
			SourceName: "test-source",
		}
		if err := store.CreateSpec(ctx, spec); err != nil {
			t.Fatalf("failed to create spec %d: %v", i, err)
		}
	}

	// Create spec NOT referencing the source
	otherSpec := &credential.CredSpec{
		Name:       "other-spec",
		Type:       "database_userpass",
		SourceName: "other-source",
	}
	if err := store.CreateSpec(ctx, otherSpec); err != nil {
		t.Fatalf("failed to create other spec: %v", err)
	}

	// Check references
	refs, err := store.CheckSourceReferences(ctx, "test-source")
	if err != nil {
		t.Fatalf("failed to check source references: %v", err)
	}

	if len(refs) != 2 {
		t.Errorf("expected 2 references, got %d", len(refs))
	}

	// Verify reference names
	for _, ref := range refs {
		if ref.SourceName != "test-source" {
			t.Errorf("expected source name test-source, got %s", ref.SourceName)
		}
	}
}

// TestCredentialConfigStore_NamespaceIsolation tests namespace isolation
func TestCredentialConfigStore_NamespaceIsolation(t *testing.T) {
	store, _ := setupTestCredentialConfigStore(t)

	// Create two namespace contexts
	ns1 := &namespace.Namespace{
		ID:   "ns1",
		Path: "ns1",
		UUID: "ns1-uuid",
	}
	ctx1 := namespace.ContextWithNamespace(context.Background(), ns1)

	ns2 := &namespace.Namespace{
		ID:   "ns2",
		Path: "ns2",
		UUID: "ns2-uuid",
	}
	ctx2 := namespace.ContextWithNamespace(context.Background(), ns2)

	// Create sources in both namespaces
	source1 := &credential.CredSource{
		Name: "source1",
		Type: "local",
	}
	if err := store.CreateSource(ctx1, source1); err != nil {
		t.Fatalf("failed to create source in ns1: %v", err)
	}

	source2 := &credential.CredSource{
		Name: "source2",
		Type: "local",
	}
	if err := store.CreateSource(ctx2, source2); err != nil {
		t.Fatalf("failed to create source in ns2: %v", err)
	}

	// Create spec in namespace 1
	spec1 := &credential.CredSpec{
		Name:       "shared-name",
		Type:       "database_userpass",
		SourceName: "source1",
	}
	if err := store.CreateSpec(ctx1, spec1); err != nil {
		t.Fatalf("failed to create spec in ns1: %v", err)
	}

	// Create spec with same name in namespace 2
	spec2 := &credential.CredSpec{
		Name:       "shared-name",
		Type:       "aws_access_keys",
		SourceName: "source2",
	}
	if err := store.CreateSpec(ctx2, spec2); err != nil {
		t.Fatalf("failed to create spec in ns2: %v", err)
	}

	// Retrieve from namespace 1
	retrieved1, err := store.GetSpec(ctx1, "shared-name")
	if err != nil {
		t.Fatalf("failed to get spec from ns1: %v", err)
	}
	if retrieved1.Type != "database_userpass" {
		t.Errorf("expected type database_userpass in ns1, got %s", retrieved1.Type)
	}

	// Retrieve from namespace 2
	retrieved2, err := store.GetSpec(ctx2, "shared-name")
	if err != nil {
		t.Fatalf("failed to get spec from ns2: %v", err)
	}
	if retrieved2.Type != "aws_access_keys" {
		t.Errorf("expected type aws_access_keys in ns2, got %s", retrieved2.Type)
	}
}

// TestCredentialConfigStore_LoadFromStorage tests loading from storage
func TestCredentialConfigStore_LoadFromStorage(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	// Create spec
	spec := &credential.CredSpec{
		Name:       "test-spec",
		Type:       "database_userpass",
		SourceName: "test-source",
	}
	if err := store.CreateSpec(ctx, spec); err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Clear cache
	store.UnloadFromCache()

	// Verify cache is empty
	specKey := store.buildSpecCacheKey("root-uuid", "test-spec")
	if _, found := store.specsByID.Get(specKey); found {
		t.Error("spec still in cache after unload")
	}
	sourceKey := store.buildSourceCacheKey("root-uuid", "test-source")
	if _, found := store.sourcesByID.Get(sourceKey); found {
		t.Error("source still in cache after unload")
	}

	// Load from storage
	if err := store.LoadFromStorage(context.Background()); err != nil {
		t.Fatalf("failed to load from storage: %v", err)
	}

	// Verify data is back in cache
	retrieved, err := store.GetSpec(ctx, "test-spec")
	if err != nil {
		t.Fatalf("failed to get spec after reload: %v", err)
	}
	if retrieved.Name != "test-spec" {
		t.Errorf("expected spec name test-spec, got %s", retrieved.Name)
	}

	retrievedSource, err := store.GetSource(ctx, "test-source")
	if err != nil {
		t.Fatalf("failed to get source after reload: %v", err)
	}
	if retrievedSource.Name != "test-source" {
		t.Errorf("expected source name test-source, got %s", retrievedSource.Name)
	}
}

// TestCredentialConfigStore_CacheEviction tests cache behavior under load
func TestCredentialConfigStore_CacheEviction(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	// Create many specs to potentially trigger eviction
	// (depends on cache configuration)
	for i := 0; i < 100; i++ {
		spec := &credential.CredSpec{
			Name:       "spec-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Type:       "database_userpass",
			SourceName: "test-source",
		}
		if err := store.CreateSpec(ctx, spec); err != nil {
			t.Fatalf("failed to create spec %d: %v", i, err)
		}
	}

	// All specs should still be retrievable from storage
	// even if evicted from cache
	spec, err := store.GetSpec(ctx, "spec-a0")
	if err != nil {
		t.Fatalf("failed to get spec after many creates: %v", err)
	}
	if spec.Name != "spec-a0" {
		t.Errorf("expected spec-a0, got %s", spec.Name)
	}
}

// TestCredentialConfigStore_ValidateSource_DriverValidation tests driver factory validation
func TestCredentialConfigStore_ValidateSource_DriverValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Initialize driver registry with built-in drivers
	store.core.credentialDriverRegistry = credential.NewDriverRegistry()

	// Register a test factory
	testFactory := &testDriverFactory{driverType: "test_driver"}
	if err := store.core.credentialDriverRegistry.RegisterFactory(testFactory); err != nil {
		t.Fatalf("failed to register test driver: %v", err)
	}

	tests := []struct {
		name        string
		source      *credential.CredSource
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid driver type",
			source: &credential.CredSource{
				Name: "valid-source",
				Type: "test_driver",
			},
			expectError: false,
		},
		{
			name: "invalid driver type",
			source: &credential.CredSource{
				Name: "invalid-source",
				Type: "nonexistent_driver",
			},
			expectError: true,
			errorMsg:    "unknown source type",
		},
		{
			name: "empty driver type",
			source: &credential.CredSource{
				Name: "empty-type-source",
				Type: "",
			},
			expectError: true,
			errorMsg:    "source type cannot be empty",
		},
		{
			name: "empty name",
			source: &credential.CredSource{
				Name: "",
				Type: "test_driver",
			},
			expectError: true,
			errorMsg:    "source name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSource(ctx, tt.source)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// testDriverFactory is a minimal driver factory for testing
type testDriverFactory struct {
	driverType string
}

func (f *testDriverFactory) Type() string {
	return f.driverType
}

func (f *testDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &testDriver{}, nil
}

func (f *testDriverFactory) ValidateConfig(config map[string]string) error {
	return nil
}

// testDriver is a minimal driver for testing
type testDriver struct{}

func (d *testDriver) Type() string {
	return "test_driver"
}

func (d *testDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	return nil, 0, "", nil
}

func (d *testDriver) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

func (d *testDriver) Cleanup(ctx context.Context) error {
	return nil
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestCredentialConfigStore_ValidateSpec_TypeValidation tests credential type validation
func TestCredentialConfigStore_ValidateSpec_TypeValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Initialize type registry
	store.core.credentialTypeRegistry = credential.NewTypeRegistry()

	// Register a test type
	testType := &testCredentialType{typeName: "test_cred_type"}
	if err := store.core.credentialTypeRegistry.Register(testType); err != nil {
		t.Fatalf("failed to register test type: %v", err)
	}

	// Create a source first (required for spec validation)
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	// Don't validate source for this test
	store.core.credentialDriverRegistry = nil
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	tests := []struct {
		name        string
		spec        *credential.CredSpec
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid credential type",
			spec: &credential.CredSpec{
				Name:       "valid-spec",
				Type:       "test_cred_type",
				SourceName: "test-source",
				MinTTL:     5 * time.Minute,
				MaxTTL:     1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "invalid credential type",
			spec: &credential.CredSpec{
				Name:       "invalid-spec",
				Type:       "nonexistent_type",
				SourceName: "test-source",
				MinTTL:     5 * time.Minute,
				MaxTTL:     1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "unknown credential type",
		},
		{
			name: "empty credential type",
			spec: &credential.CredSpec{
				Name:       "empty-type-spec",
				Type:       "",
				SourceName: "test-source",
				MinTTL:     5 * time.Minute,
				MaxTTL:     1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "spec type cannot be empty",
		},
		{
			name: "invalid source reference",
			spec: &credential.CredSpec{
				Name:       "bad-source-spec",
				Type:       "test_cred_type",
				SourceName: "nonexistent-source",
				MinTTL:     5 * time.Minute,
				MaxTTL:     1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "source 'nonexistent-source' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSpec(ctx, tt.spec)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// testCredentialType is a minimal credential type for testing
type testCredentialType struct {
	typeName string
}

func (t *testCredentialType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        t.typeName,
		Category:    "test",
		Description: "Test credential type",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *testCredentialType) ValidateSourceParams(params map[string]string, sourceName string) error {
	// No validation required for test type
	return nil
}

func (t *testCredentialType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Convert map[string]interface{} to map[string]string for Data field
	dataStr := make(map[string]string)
	for k, v := range rawData {
		if str, ok := v.(string); ok {
			dataStr[k] = str
		}
	}

	return &credential.Credential{
		Type:     t.typeName,
		Category: "test",
		Data:     dataStr,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
	}, nil
}

func (t *testCredentialType) Validate(cred *credential.Credential) error {
	return nil
}

func (t *testCredentialType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	return nil
}

func (t *testCredentialType) CanRotate() bool {
	return false
}

// TestCredentialConfigStore_ValidateSource_ConfigValidation tests source config validation
func TestCredentialConfigStore_ValidateSource_ConfigValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Initialize driver registry
	store.core.credentialDriverRegistry = credential.NewDriverRegistry()

	// Register a factory that validates config
	validatingFactory := &validatingDriverFactory{}
	if err := store.core.credentialDriverRegistry.RegisterFactory(validatingFactory); err != nil {
		t.Fatalf("failed to register validating driver: %v", err)
	}

	tests := []struct {
		name        string
		source      *credential.CredSource
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			source: &credential.CredSource{
				Name: "valid-config-source",
				Type: "validating_driver",
				Config: map[string]string{
					"required_param": "value",
				},
			},
			expectError: false,
		},
		{
			name: "missing required config",
			source: &credential.CredSource{
				Name:   "missing-config-source",
				Type:   "validating_driver",
				Config: map[string]string{},
			},
			expectError: true,
			errorMsg:    "invalid config for source type 'validating_driver'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSource(ctx, tt.source)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// validatingDriverFactory validates config during creation
type validatingDriverFactory struct{}

func (f *validatingDriverFactory) Type() string {
	return "validating_driver"
}

func (f *validatingDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &testDriver{}, nil
}

func (f *validatingDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateRequired(config, "required_param"); err != nil {
		return err
	}
	return nil
}

// TestCredentialConfigStore_ValidateSpec_SourceParamsValidation tests source params validation
func TestCredentialConfigStore_ValidateSpec_SourceParamsValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Initialize type registry
	store.core.credentialTypeRegistry = credential.NewTypeRegistry()

	// Register a type that validates source params
	validatingType := &validatingCredentialType{}
	if err := store.core.credentialTypeRegistry.Register(validatingType); err != nil {
		t.Fatalf("failed to register validating type: %v", err)
	}

	// Create a source first
	source := &credential.CredSource{
		Name: "test-source",
		Type: "local",
	}
	store.core.credentialDriverRegistry = nil
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	tests := []struct {
		name        string
		spec        *credential.CredSpec
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid source params",
			spec: &credential.CredSpec{
				Name:       "valid-params-spec",
				Type:       "validating_type",
				SourceName: "test-source",
				SourceParams: map[string]string{
					"required_field": "value",
				},
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "missing required params",
			spec: &credential.CredSpec{
				Name:         "missing-params-spec",
				Type:         "validating_type",
				SourceName:   "test-source",
				SourceParams: map[string]string{},
				MinTTL:       5 * time.Minute,
				MaxTTL:       1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "invalid source params for type 'validating_type'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSpec(ctx, tt.spec)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// validatingCredentialType validates source params
type validatingCredentialType struct{}

func (t *validatingCredentialType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        "validating_type",
		Category:    "test",
		Description: "Validating credential type",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *validatingCredentialType) ValidateSourceParams(params map[string]string, sourceName string) error {
	if err := credential.ValidateRequired(params, "required_field"); err != nil {
		return err
	}
	return nil
}

func (t *validatingCredentialType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	dataStr := make(map[string]string)
	for k, v := range rawData {
		if str, ok := v.(string); ok {
			dataStr[k] = str
		}
	}

	return &credential.Credential{
		Type:     "validating_type",
		Category: "test",
		Data:     dataStr,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
	}, nil
}

func (t *validatingCredentialType) Validate(cred *credential.Credential) error {
	return nil
}

func (t *validatingCredentialType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	return nil
}

func (t *validatingCredentialType) CanRotate() bool {
	return false
}

// TestCredentialConfigStore_BuiltinLocalSource tests the built-in local source
func TestCredentialConfigStore_BuiltinLocalSource(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	t.Run("GetSource returns local source", func(t *testing.T) {
		source, err := store.GetSource(ctx, "local")
		if err != nil {
			t.Fatalf("failed to get local source: %v", err)
		}

		if source.Name != "local" {
			t.Errorf("expected source name 'local', got '%s'", source.Name)
		}

		if source.Type != "local" {
			t.Errorf("expected source type 'local', got '%s'", source.Type)
		}
	})

	t.Run("ListSources includes local source", func(t *testing.T) {
		// Create a custom source
		customSource := &credential.CredSource{
			Name: "custom-source",
			Type: "local",
		}
		if err := store.CreateSource(ctx, customSource); err != nil {
			t.Fatalf("failed to create custom source: %v", err)
		}

		sources, err := store.ListSources(ctx)
		if err != nil {
			t.Fatalf("failed to list sources: %v", err)
		}

		// Should have 2 sources: built-in local + custom
		if len(sources) != 2 {
			t.Errorf("expected 2 sources, got %d", len(sources))
		}

		// Built-in local should be first
		if sources[0].Name != "local" {
			t.Errorf("expected first source to be 'local', got '%s'", sources[0].Name)
		}
	})

	t.Run("Cannot create source named 'local'", func(t *testing.T) {
		localSource := &credential.CredSource{
			Name: "local",
			Type: "local",
		}

		err := store.CreateSource(ctx, localSource)
		if err == nil {
			t.Fatal("expected error when creating source named 'local', got nil")
		}

		expectedMsg := "cannot create source with reserved name 'local' (built-in source)"
		if err.Error() != expectedMsg {
			t.Errorf("expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Cannot update built-in local source", func(t *testing.T) {
		localSource := &credential.CredSource{
			Name:   "local",
			Type:   "local",
			Config: map[string]string{"some": "config"},
		}

		err := store.UpdateSource(ctx, localSource)
		if err == nil {
			t.Fatal("expected error when updating built-in local source, got nil")
		}

		expectedMsg := "cannot update built-in source 'local'"
		if err.Error() != expectedMsg {
			t.Errorf("expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Cannot delete built-in local source", func(t *testing.T) {
		err := store.DeleteSource(ctx, "local")
		if err == nil {
			t.Fatal("expected error when deleting built-in local source, got nil")
		}

		expectedMsg := "cannot delete built-in source 'local'"
		if err.Error() != expectedMsg {
			t.Errorf("expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Can create spec using built-in local source", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name:       "test-local-spec",
			Type:       "database_userpass",
			SourceName: "local",
			SourceParams: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "db/creds",
			},
			MinTTL: time.Hour,
			MaxTTL: 24 * time.Hour,
		}

		err := store.CreateSpec(ctx, spec)
		if err != nil {
			t.Fatalf("failed to create spec with local source: %v", err)
		}

		// Verify spec was created
		retrieved, err := store.GetSpec(ctx, "test-local-spec")
		if err != nil {
			t.Fatalf("failed to get spec: %v", err)
		}

		if retrieved.SourceName != "local" {
			t.Errorf("expected source name 'local', got '%s'", retrieved.SourceName)
		}
	})
}
