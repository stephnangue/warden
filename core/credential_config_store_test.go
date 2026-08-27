package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Create minimal Core for testing. rawConfig must be non-nil even with nothing
	// stored in it: any validation path that checks rotation-period bounds loads it,
	// and a nil pointer there panics rather than falling back to the defaults.
	core := &Core{
		barrier:   barrier,
		logger:    log,
		rawConfig: new(atomic.Value),
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
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
		MinTTL: time.Hour,
		MaxTTL: 24 * time.Hour,
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
	if retrieved.Source != spec.Source {
		t.Errorf("expected source name %s, got %s", spec.Source, retrieved.Source)
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
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
	}

	// Create first spec
	err := store.CreateSpec(ctx, spec)
	if err != nil {
		t.Fatalf("failed to create spec: %v", err)
	}

	// Try to create duplicate (same name, different type/source)
	spec2 := &credential.CredSpec{
		Name:   "test-spec",
		Type:   "aws_access_keys",
		Source: "test-source", // Use same source
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
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
		MinTTL: time.Hour,
		MaxTTL: 24 * time.Hour,
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
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
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
			Name:   "spec-" + string(rune('0'+i)),
			Type:   "vault_token",
			Source: "test-source",
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

// TestCredentialConfigStore_SecretSpecReference covers credential chaining guards:
// a referenced secret-spec cannot be deleted while a consumer points at it, and
// the reference is validated at create time (must exist, one hop, request exchange).
func TestCredentialConfigStore_SecretSpecReference(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

	// Referencing a non-existent secret-spec is rejected.
	badConsumer := &credential.CredSpec{
		Name: "bad", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "missing"},
	}
	err := store.CreateSpec(ctx, badConsumer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// A secret-spec that does not request exchange is rejected as a reference.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "plain-secret", Type: "vault_token", Source: "src", Config: map[string]string{},
	}))
	err = store.CreateSpec(ctx, &credential.CredSpec{
		Name: "bad2", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "plain-secret"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source")

	// A valid referenced secret-spec requests exchange (minted as the caller).
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "secret-spec", Type: "vault_token", Source: "src",
		Config: map[string]string{
			"subject_token_source": "warden_identity",
			"assertion_audience":   "test-aud",
		},
	}))
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "consumer", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "secret-spec"},
	}))

	// Deleting the referenced secret-spec is blocked while a consumer points at it.
	err = store.DeleteSpec(ctx, "secret-spec")
	require.ErrorIs(t, err, ErrSpecInUse)

	// After removing the consumer, the secret-spec can be deleted.
	require.NoError(t, store.DeleteSpec(ctx, "consumer"))
	require.NoError(t, store.DeleteSpec(ctx, "secret-spec"))
}

// TestCredentialConfigStore_SecretSpecReference_Restrictions covers the security
// restrictions on a chained reference: the referenced spec must use a session-pinned
// subject (not user_identity), and a chained consumer must not carry its own exchange config.
func TestCredentialConfigStore_SecretSpecReference_Restrictions(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "sts-src", Type: credential.SourceTypeTokenExchange,
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "rfc8693"},
	}))

	// A user_identity referenced spec is per-request/per-user, not session-pinned →
	// rejected as a reference.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "user-secret", Type: "vault_token", Source: "sts-src",
		Config: map[string]string{"subject_token_source": "user_identity"},
	}))
	err := store.CreateSpec(ctx, &credential.CredSpec{
		Name: "consumer-user", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "user-secret"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session-pinned")

	// A valid warden_identity referenced spec.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "wid-secret", Type: "vault_token", Source: "src",
		Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "aud"},
	}))
	// A chained consumer that ALSO sets its own exchange config is rejected.
	err = store.CreateSpec(ctx, &credential.CredSpec{
		Name: "consumer-dbl", Type: "vault_token", Source: "src",
		Config: map[string]string{
			credential.ConfigSecretSpec: "wid-secret",
			"subject_token_source":      "warden_identity",
			"assertion_audience":        "aud",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not also set")
}

// TestCredentialConfigStore_SecretCacheTTLValidation: an unparsable secret_cache_ttl on
// a chained consumer is rejected at create (so a typo can't silently disable caching).
func TestCredentialConfigStore_SecretCacheTTLValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "secret-spec", Type: "vault_token", Source: "src",
		Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "aud"},
	}))

	err := store.CreateSpec(ctx, &credential.CredSpec{
		Name: "bad-ttl", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "secret-spec", credential.ConfigSecretCacheTTL: "30min"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid duration")

	// A valid duration (and "0" to opt out) are accepted.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "ok-ttl", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "secret-spec", credential.ConfigSecretCacheTTL: "30m"},
	}))
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "optout-ttl", Type: "vault_token", Source: "src",
		Config: map[string]string{credential.ConfigSecretSpec: "secret-spec", credential.ConfigSecretCacheTTL: "0"},
	}))
}

// TestCredentialConfigStore_ChainedExchangeAccepted: a token_exchange consumer may set
// BOTH secret_spec (chained client secret) AND its own subject_token_source — the combo
// that is rejected for any other source type (see consumer-dbl).
func TestCredentialConfigStore_ChainedExchangeAccepted(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))
	// Referenced secret-spec: session-pinned (warden_identity), as required. Must exist
	// before the source that references it.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "wid-secret", Type: "vault_token", Source: "src",
		Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "vault"},
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "sts-src", Type: credential.SourceTypeTokenExchange,
		// No client_id: a chained source holds neither half of the client credential,
		// so both come from the referenced spec's payload.
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "rfc8693", credential.ConfigSecretSpec: "wid-secret"},
	}))

	// A token_exchange consumer with secret_spec (source-level) + its own subject source
	// is accepted (unlike consumer-dbl on a non-exchange source).
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "internal-api", Type: "oauth_bearer_token", Source: "sts-src",
		Config: map[string]string{"subject_token_source": "user_identity", "audience": "https://api.internal.example.com"},
	}))
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
			Name:   "spec-" + string(rune('0'+i)),
			Type:   "vault_token",
			Source: "test-source",
		}
		if err := store.CreateSpec(ctx, spec); err != nil {
			t.Fatalf("failed to create spec %d: %v", i, err)
		}
	}

	// Create spec NOT referencing the source
	otherSpec := &credential.CredSpec{
		Name:   "other-spec",
		Type:   "vault_token",
		Source: "other-source",
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
		if ref.Source != "test-source" {
			t.Errorf("expected source name test-source, got %s", ref.Source)
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
		Name:   "shared-name",
		Type:   "vault_token",
		Source: "source1",
	}
	if err := store.CreateSpec(ctx1, spec1); err != nil {
		t.Fatalf("failed to create spec in ns1: %v", err)
	}

	// Create spec with same name in namespace 2
	spec2 := &credential.CredSpec{
		Name:   "shared-name",
		Type:   "aws_access_keys",
		Source: "source2",
	}
	if err := store.CreateSpec(ctx2, spec2); err != nil {
		t.Fatalf("failed to create spec in ns2: %v", err)
	}

	// Retrieve from namespace 1
	retrieved1, err := store.GetSpec(ctx1, "shared-name")
	if err != nil {
		t.Fatalf("failed to get spec from ns1: %v", err)
	}
	if retrieved1.Type != "vault_token" {
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
		Name:   "test-spec",
		Type:   "vault_token",
		Source: "test-source",
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
			Name:   "spec-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Type:   "vault_token",
			Source: "test-source",
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
	store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)

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

func (f *testDriverFactory) SensitiveConfigFields() []string {
	return []string{}
}

func (f *testDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("test driver cannot infer type")
}

// testDriver is a minimal driver for testing
type testDriver struct{}

func (d *testDriver) Type() string {
	return "test_driver"
}

func (d *testDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", nil
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
				Name:   "valid-spec",
				Type:   "test_cred_type",
				Source: "test-source",
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "invalid credential type",
			spec: &credential.CredSpec{
				Name:   "invalid-spec",
				Type:   "nonexistent_type",
				Source: "test-source",
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "unknown credential type",
		},
		{
			name: "empty credential type",
			spec: &credential.CredSpec{
				Name:   "empty-type-spec",
				Type:   "",
				Source: "test-source",
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "spec type cannot be empty",
		},
		{
			name: "invalid source reference",
			spec: &credential.CredSpec{
				Name:   "bad-source-spec",
				Type:   "test_cred_type",
				Source: "nonexistent-source",
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
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

// TestCredentialConfigStore_ValidateSpec_ExchangeRotation covers the rotation_period
// rules around token-exchange (keyless federation) specs: a rotating type still
// requires rotation_period normally, an exchange spec is exempt from that requirement,
// and an exchange spec must NOT carry a rotation_period (it mints fresh per request and
// enrolling it would schedule a rotation that can never persist).
func TestCredentialConfigStore_ValidateSpec_ExchangeRotation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialTypeRegistry = credential.NewTypeRegistry()

	rotType := &testCredentialType{typeName: "rotating_type", requiresRotation: true}
	if err := store.core.credentialTypeRegistry.Register(rotType); err != nil {
		t.Fatalf("failed to register type: %v", err)
	}

	// Local source: the test-mint block is skipped, so no driver is needed.
	store.core.credentialDriverRegistry = nil
	if err := store.CreateSource(ctx, &credential.CredSource{Name: "local-src", Type: "local"}); err != nil {
		t.Fatalf("failed to create source: %v", err)
	}

	exchangeCfg := map[string]string{
		"subject_token_source": "warden_identity",
		"assertion_audience":   "api://AzureADTokenExchange",
	}

	tests := []struct {
		name        string
		spec        *credential.CredSpec
		expectError bool
		errorMsg    string
	}{
		{
			name: "rotating type without rotation_period is rejected",
			spec: &credential.CredSpec{
				Name: "needs-rotation", Type: "rotating_type", Source: "local-src",
				MinTTL: time.Minute, MaxTTL: time.Hour,
			},
			expectError: true,
			errorMsg:    "rotation_period is required",
		},
		{
			name: "exchange spec is exempt from the rotation_period requirement",
			spec: &credential.CredSpec{
				Name: "exchange-no-rotation", Type: "rotating_type", Source: "local-src",
				Config: exchangeCfg, MinTTL: time.Minute, MaxTTL: time.Hour,
			},
			expectError: false,
		},
		{
			name: "exchange spec must not set rotation_period",
			spec: &credential.CredSpec{
				Name: "exchange-with-rotation", Type: "rotating_type", Source: "local-src",
				Config: exchangeCfg, RotationPeriod: 24 * time.Hour, MinTTL: time.Minute, MaxTTL: time.Hour,
			},
			expectError: true,
			errorMsg:    "not supported",
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
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestCredentialConfigStore_ValidateSpec_ActorWardenIdentity covers the two
// source-aware gates for actor_token_source=warden_identity: it must bind to a
// token_exchange source (only that driver consumes an actor token) and it must
// have a resolvable assertion audience.
func TestCredentialConfigStore_ValidateSpec_ActorWardenIdentity(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialDriverRegistry = nil // skip the test-mint block
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "sts-src", Type: credential.SourceTypeTokenExchange,
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "rfc8693"},
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "jwtbearer-src", Type: credential.SourceTypeTokenExchange,
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "jwt_bearer"},
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "local-src", Type: "local"}))

	spec := func(name, source string, cfg map[string]string) *credential.CredSpec {
		full := map[string]string{
			credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
			credential.ConfigActorTokenSource:   credential.SourceWardenIdentity,
		}
		for k, v := range cfg {
			full[k] = v
		}
		return &credential.CredSpec{Name: name, Type: "vault_token", Source: source, Config: full}
	}

	tests := []struct {
		name     string
		spec     *credential.CredSpec
		errorMsg string // empty => expect success
	}{
		{
			name: "accepted on token_exchange with explicit audience",
			spec: spec("obo-ok", "sts-src", map[string]string{
				credential.ConfigAssertionAudience: "https://sts.example/aud",
			}),
		},
		{
			name: "rejected on a non-token_exchange source",
			spec: spec("obo-bad-source", "local-src", map[string]string{
				credential.ConfigAssertionAudience: "https://sts.example/aud",
			}),
			errorMsg: "requires a 'token_exchange' source",
		},
		{
			name:     "rejected when audience missing and not derivable",
			spec:     spec("obo-no-aud", "sts-src", map[string]string{}),
			errorMsg: "is required when the subject or actor is",
		},
		{
			name: "rejected on a jwt_bearer grant (no actor slot)",
			spec: spec("obo-jwtbearer", "jwtbearer-src", map[string]string{
				credential.ConfigAssertionAudience: "https://sts.example/aud",
			}),
			errorMsg: "grant=jwt_bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreateSpec(ctx, tt.spec)
			if tt.errorMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if !contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}
		})
	}
}

// TestCredentialConfigStore_ValidateSpec_UserIdentitySubjectRequiresTokenExchange
// isolates the subject pin that makes retiring the federation-driver origin guards
// safe: subject_token_source=user_identity forwards the raw user credential as the
// RFC 8693 subject, so it must bind ONLY to a token_exchange source — a federation
// driver (vault/gcp/aws/azure) must never be handed the user's raw JWT as its own
// login token. Tested with NO actor, so the separate actor pin cannot mask it.
func TestCredentialConfigStore_ValidateSpec_UserIdentitySubjectRequiresTokenExchange(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialDriverRegistry = nil // skip the test-mint block
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "sts-src", Type: credential.SourceTypeTokenExchange,
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "rfc8693"},
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "local-src", Type: "local"}))

	// Accepted on a token_exchange source (no actor, no assertion → no audience).
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "user-subj-ok", Type: "vault_token", Source: "sts-src",
		Config: map[string]string{credential.ConfigSubjectTokenSource: credential.SourceUserIdentity},
	}))

	// Rejected on a non-token_exchange (federation) source — the subject pin fires
	// on its own, no actor present to mask it.
	err := store.CreateSpec(ctx, &credential.CredSpec{
		Name: "user-subj-bad", Type: "vault_token", Source: "local-src",
		Config: map[string]string{credential.ConfigSubjectTokenSource: credential.SourceUserIdentity},
	})
	require.Error(t, err)
	if !contains(err.Error(), "user_identity") || !contains(err.Error(), "token_exchange") {
		t.Errorf("expected the subject pin to name user_identity + token_exchange, got %q", err.Error())
	}
}

// TestCredentialConfigStore_ValidateSpec_ActorSourceRequiresTokenExchange locks
// in that ANY actor token source — not just warden_identity — is pinned to a
// token_exchange source, since only that driver consumes an actor token; every
// other driver would silently drop it.
func TestCredentialConfigStore_ValidateSpec_ActorSourceRequiresTokenExchange(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialDriverRegistry = nil // skip the test-mint block
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "sts-src", Type: credential.SourceTypeTokenExchange,
		Config: map[string]string{"token_url": "https://sts.example/token", "grant": "rfc8693"},
	}))
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "local-src", Type: "local"}))

	tests := []struct {
		name     string
		source   string
		actorSrc string
		errorMsg string // empty => expect success
	}{
		{"agent_identity actor on local source rejected", "local-src", credential.SourceAgentIdentity, "requires a 'token_exchange' source"},
		{"warden_identity actor on local source rejected", "local-src", credential.SourceWardenIdentity, "requires a 'token_exchange' source"},
		{"agent_identity actor on token_exchange accepted", "sts-src", credential.SourceAgentIdentity, ""},
		{"warden_identity actor on token_exchange accepted", "sts-src", credential.SourceWardenIdentity, ""},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// subject=user_identity so the actor pairing is valid regardless of actor source.
			err := store.CreateSpec(ctx, &credential.CredSpec{
				Name: fmt.Sprintf("actor-spec-%d", i), Type: "vault_token", Source: tt.source,
				Config: map[string]string{
					credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
					credential.ConfigActorTokenSource:   tt.actorSrc,
					credential.ConfigAssertionAudience:  "https://sts.example/aud",
				},
			})
			if tt.errorMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if !contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}
		})
	}
}

// testCredentialType is a minimal credential type for testing
type testCredentialType struct {
	typeName         string
	requiresRotation bool
}

func (t *testCredentialType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        t.typeName,
		Category:    "test",
		Description: "Test credential type",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *testCredentialType) ConfigSchema() []*credential.FieldValidator {
	return nil // No schema required for test type
}

func (t *testCredentialType) ValidateConfig(config map[string]string, sourceName string) error {
	// No validation required for test type
	return nil
}

func (t *testCredentialType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
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

func (t *testCredentialType) RequiresSpecRotation() bool {
	return t.requiresRotation
}

func (t *testCredentialType) SensitiveConfigFields() []string { return nil }

func (t *testCredentialType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{}
}

// TestCredentialConfigStore_ValidateSource_ConfigValidation tests source config validation
func TestCredentialConfigStore_ValidateSource_ConfigValidation(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Initialize driver registry
	store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)

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

func (f *validatingDriverFactory) SensitiveConfigFields() []string {
	return []string{}
}

func (f *validatingDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("validating driver cannot infer type")
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
				Name:   "valid-params-spec",
				Type:   "validating_type",
				Source: "test-source",
				Config: map[string]string{
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
				Name:   "missing-params-spec",
				Type:   "validating_type",
				Source: "test-source",
				Config: map[string]string{},
				MinTTL: 5 * time.Minute,
				MaxTTL: 1 * time.Hour,
			},
			expectError: true,
			errorMsg:    "invalid config for type 'validating_type'",
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

func (t *validatingCredentialType) ConfigSchema() []*credential.FieldValidator {
	return nil // No schema required for test type
}

func (t *validatingCredentialType) ValidateConfig(config map[string]string, sourceName string) error {
	if err := credential.ValidateRequired(config, "required_field"); err != nil {
		return err
	}
	return nil
}

func (t *validatingCredentialType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
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

func (t *validatingCredentialType) RequiresSpecRotation() bool {
	return false
}

func (t *validatingCredentialType) SensitiveConfigFields() []string { return nil }

func (t *validatingCredentialType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{}
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
			Name:   "test-local-spec",
			Type:   "vault_token",
			Source: "local",
			Config: map[string]string{
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

		if retrieved.Source != "local" {
			t.Errorf("expected source name 'local', got '%s'", retrieved.Source)
		}
	})
}

// TestCredentialConfigStore_ClearNamespace tests clearing all specs and sources for a namespace
func TestCredentialConfigStore_ClearNamespace(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	// Create sources
	for _, name := range []string{"src-a", "src-b"} {
		err := store.CreateSource(ctx, &credential.CredSource{
			Name: name,
			Type: "local",
		})
		require.NoError(t, err)
	}

	// Create specs referencing the sources
	for _, name := range []string{"spec-a", "spec-b"} {
		err := store.CreateSpec(ctx, &credential.CredSpec{
			Name:   name,
			Type:   "vault_token",
			Source: "src-a",
			MinTTL: 1 * time.Minute,
			MaxTTL: 1 * time.Hour,
		})
		require.NoError(t, err)
	}

	// Verify resources exist
	specs, err := store.ListSpecs(ctx)
	require.NoError(t, err)
	assert.Len(t, specs, 2)

	sources, err := store.ListSources(ctx)
	require.NoError(t, err)
	// ListSources includes the built-in "local" source
	assert.GreaterOrEqual(t, len(sources), 3)

	// Clear namespace
	err = store.ClearNamespace(ctx)
	require.NoError(t, err)

	// Verify specs are gone
	specs, err = store.ListSpecs(ctx)
	require.NoError(t, err)
	assert.Len(t, specs, 0)

	// Verify user sources are gone (built-in "local" is virtual, not in storage)
	sources, err = store.ListSources(ctx)
	require.NoError(t, err)
	// Only the built-in local source should remain
	assert.Len(t, sources, 1)
	assert.Equal(t, "local", sources[0].Name)
}

// TestCredentialConfigStore_ClearNamespace_Empty tests clearing an empty namespace
func TestCredentialConfigStore_ClearNamespace_Empty(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	err := store.ClearNamespace(ctx)
	require.NoError(t, err)
}

// TestCredentialConfigStore_ClearNamespace_Isolation tests that clearing one namespace
// doesn't affect another
func TestCredentialConfigStore_ClearNamespace_Isolation(t *testing.T) {
	store, _ := setupTestCredentialConfigStore(t)

	// Create two namespace contexts
	ns1 := &namespace.Namespace{ID: "ns1", Path: "ns1/", UUID: "ns1-uuid"}
	ns2 := &namespace.Namespace{ID: "ns2", Path: "ns2/", UUID: "ns2-uuid"}
	ctx1 := namespace.ContextWithNamespace(context.Background(), ns1)
	ctx2 := namespace.ContextWithNamespace(context.Background(), ns2)

	// Create source and spec in ns1
	require.NoError(t, store.CreateSource(ctx1, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, store.CreateSpec(ctx1, &credential.CredSpec{
		Name: "spec", Type: "vault_token", Source: "src", MinTTL: time.Minute, MaxTTL: time.Hour,
	}))

	// Create source and spec in ns2
	require.NoError(t, store.CreateSource(ctx2, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, store.CreateSpec(ctx2, &credential.CredSpec{
		Name: "spec", Type: "vault_token", Source: "src", MinTTL: time.Minute, MaxTTL: time.Hour,
	}))

	// Clear ns1
	require.NoError(t, store.ClearNamespace(ctx1))

	// ns1 should be empty
	specs1, err := store.ListSpecs(ctx1)
	require.NoError(t, err)
	assert.Len(t, specs1, 0)

	// ns2 should still have its resources
	specs2, err := store.ListSpecs(ctx2)
	require.NoError(t, err)
	assert.Len(t, specs2, 1)
}

// connectGatedDriver mints into an error so tests can detect whether the
// validation test-mint ran; connect-gating itself is a credential-type property
// (connectGatedCredType), not a driver one.
type connectGatedDriverFactory struct{}

func (f *connectGatedDriverFactory) Type() string { return "connect_driver" }
func (f *connectGatedDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &connectGatedDriver{}, nil
}
func (f *connectGatedDriverFactory) ValidateConfig(config map[string]string) error { return nil }
func (f *connectGatedDriverFactory) SensitiveConfigFields() []string               { return nil }
func (f *connectGatedDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "connect_cred", nil
}

type connectGatedDriver struct{}

func (d *connectGatedDriver) Type() string { return "connect_driver" }
func (d *connectGatedDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mint must not run for an unconnected spec")
}
func (d *connectGatedDriver) Revoke(ctx context.Context, leaseID string) error { return nil }
func (d *connectGatedDriver) Cleanup(ctx context.Context) error                { return nil }

// connectGatedCredType implements credential.ConnectGated: authorization_code
// specs require connecting, and count as connected once a token is sealed.
type connectGatedCredType struct {
	testCredentialType
}

func (t *connectGatedCredType) RequiresConnect(config map[string]string) bool {
	return config["auth_method"] == "authorization_code"
}
func (t *connectGatedCredType) IsConnected(config map[string]string) bool {
	return config["refresh_token"] != "" || config["access_token"] != ""
}

func TestCredentialConfigStore_ValidateSpec_ConnectGating(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)

	store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)
	require.NoError(t, store.core.credentialDriverRegistry.RegisterFactory(&connectGatedDriverFactory{}))
	store.core.credentialTypeRegistry = credential.NewTypeRegistry()
	require.NoError(t, store.core.credentialTypeRegistry.Register(&connectGatedCredType{testCredentialType{typeName: "connect_cred"}}))

	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "gh-src", Type: "connect_driver"}))

	// (a) An unconnected authorization_code spec creates: the test-mint is skipped
	// even though MintCredential would error.
	unconnected := &credential.CredSpec{
		Name: "gh", Type: "connect_cred", Source: "gh-src",
		Config: map[string]string{"auth_method": "authorization_code"},
	}
	require.NoError(t, store.CreateSpec(ctx, unconnected),
		"unconnected authcode spec should create with the test-mint skipped")

	// (b) rotation_period is rejected for a connect-gated spec.
	err := store.CreateSpec(ctx, &credential.CredSpec{
		Name: "gh-rot", Type: "connect_cred", Source: "gh-src",
		Config:         map[string]string{"auth_method": "authorization_code"},
		RotationPeriod: time.Hour,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation_period is not supported")

	// (c) A connected spec runs the test-mint (which errors with this mock) — both
	// the refresh-token and the static access-token connected states.
	for _, connectedCfg := range []map[string]string{
		{"auth_method": "authorization_code", "refresh_token": "rt"},
		{"auth_method": "authorization_code", "access_token": "static"},
	} {
		err := store.CreateSpec(ctx, &credential.CredSpec{
			Name: "gh-conn-" + connectedCfg["refresh_token"] + connectedCfg["access_token"],
			Type: "connect_cred", Source: "gh-src", Config: connectedCfg,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential test failed")
	}

	// (d) Updating the unconnected spec to a connected config runs the test-mint
	// (fails) — unless SkipVerification is set, which the connect seal / write-back use.
	unconnected.Config["refresh_token"] = "rt"
	err = store.UpdateSpec(ctx, unconnected)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential test failed")

	require.NoError(t, store.UpdateSpec(ctx, unconnected, UpdateSpecOptions{SkipVerification: true}),
		"UpdateSpec with SkipVerification should skip the test-mint")
}

// fakeHvaultFactory registers under the hvault source type with no-op create/validate,
// so tests can exercise the hvault-specific rotation_period rule without a live OpenBao.
type fakeHvaultFactory struct{}

func (f *fakeHvaultFactory) Type() string { return credential.SourceTypeVault }
func (f *fakeHvaultFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &testDriver{}, nil
}
func (f *fakeHvaultFactory) ValidateConfig(config map[string]string) error { return nil }
func (f *fakeHvaultFactory) SensitiveConfigFields() []string               { return nil }
func (f *fakeHvaultFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeVaultToken, nil
}

// TestCredentialConfigStore_ValidateSource_HvaultRotationPeriod verifies that a keyless
// hvault federation source may omit rotation_period, while the rotatable approle/token
// path still requires it.
func TestCredentialConfigStore_ValidateSource_HvaultRotationPeriod(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)
	if err := store.core.credentialDriverRegistry.RegisterFactory(&fakeHvaultFactory{}); err != nil {
		t.Fatalf("register fake hvault factory: %v", err)
	}

	tests := []struct {
		name        string
		config      map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "oidc_federation without rotation_period is allowed",
			config:      map[string]string{"auth_method": "oidc_federation", "jwt_role": "warden-agents"},
			expectError: false,
		},
		{
			name:        "approle without rotation_period is rejected",
			config:      map[string]string{"auth_method": "approle"},
			expectError: true,
			errorMsg:    "rotation_period is required",
		},
		{
			name:        "empty auth_method without rotation_period is rejected",
			config:      map[string]string{},
			expectError: true,
			errorMsg:    "rotation_period is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &credential.CredSource{Name: "src", Type: credential.SourceTypeVault, Config: tt.config}
			err := store.ValidateSource(ctx, src)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
				}
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// fakeFederationFactory registers under an arbitrary source type with no-op
// create/validate, so the cross-type federation rule can be exercised without a
// live provider behind any of them.
type fakeFederationFactory struct{ sourceType string }

func (f *fakeFederationFactory) Type() string { return f.sourceType }
func (f *fakeFederationFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	return &testDriver{}, nil
}
func (f *fakeFederationFactory) ValidateConfig(config map[string]string) error { return nil }
func (f *fakeFederationFactory) SensitiveConfigFields() []string               { return nil }
func (f *fakeFederationFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// TestCredentialConfigStore_FederationSourceRejectsRotationPeriod covers the rule
// across every federation-capable source type, not just the one that prompted it.
//
// A federated source holds no secret, so the driver reports SupportsRotation false
// and the manager can never complete a cycle: it retries, parks the entry as
// failed, and comes back an hour later, forever. Rejecting at create is what keeps
// that entry from existing.
func TestCredentialConfigStore_FederationSourceRejectsRotationPeriod(t *testing.T) {
	federationTypes := []string{
		credential.SourceTypeAWS,
		credential.SourceTypeAzure,
		credential.SourceTypeGCP,
		credential.SourceTypeVault,
		credential.SourceTypeKubernetes,
	}

	for _, sourceType := range federationTypes {
		t.Run(sourceType, func(t *testing.T) {
			store, ctx := setupTestCredentialConfigStore(t)
			store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)
			require.NoError(t, store.core.credentialDriverRegistry.RegisterFactory(
				&fakeFederationFactory{sourceType: sourceType}))

			err := store.CreateSource(ctx, &credential.CredSource{
				Name:           "fed-src",
				Type:           sourceType,
				Config:         map[string]string{"auth_method": "oidc_federation"},
				RotationPeriod: 48 * time.Hour,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rotation_period does not apply to a federated credential source")

			// Without the period the same source is fine, and is not enrolled.
			require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
				Name:   "fed-src",
				Type:   sourceType,
				Config: map[string]string{"auth_method": "oidc_federation"},
			}))
		})
	}
}

// TestCredentialConfigStore_FederationRotationGateRunsOnUpdate pins that the rule
// is in the shared validator, so an edit cannot slip a rotation_period onto a
// federated source that create would have refused.
func TestCredentialConfigStore_FederationRotationGateRunsOnUpdate(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	store.core.credentialDriverRegistry = credential.NewDriverRegistry(nil)
	require.NoError(t, store.core.credentialDriverRegistry.RegisterFactory(
		&fakeFederationFactory{sourceType: credential.SourceTypeAWS}))

	// The update path presents the whole record, carrying rotation_period over from
	// the stored entry — so this is the shape every edit of such a source takes.
	updated := &credential.CredSource{
		Name:           "fed-src",
		Type:           credential.SourceTypeAWS,
		Config:         map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"},
		RotationPeriod: 48 * time.Hour,
	}

	err := store.validateSource(ctx, updated, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation_period does not apply to a federated credential source")

	// Clearing the period is what makes the record editable again.
	updated.RotationPeriod = 0
	require.NoError(t, store.validateSource(ctx, updated, false))
}

// TestCredentialConfigStore_ChainedSpecRejectsRotationPeriod covers the spec half
// of the same rule.
//
// A chained source was already refused a rotation_period; a chained *spec* was not,
// though it embeds no secret either — its material is fetched per request from the
// spec it references. Such a spec was accepted and enrolled, then failed every
// cycle because its driver is not a SpecRotatable.
//
// Both places a spec can be chained are covered: on the spec itself, and inherited
// from its source. They resolve spec-over-source, matching the minting path.
func TestCredentialConfigStore_ChainedSpecRejectsRotationPeriod(t *testing.T) {
	setup := func(t *testing.T) (*CredentialConfigStore, context.Context) {
		t.Helper()
		store, ctx := setupTestCredentialConfigStore(t)
		require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))
		// Session-pinned, as validateSecretSpecRef requires of a referenced spec.
		require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
			Name: "ref-secret", Type: "vault_token", Source: "src",
			Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "vault"},
		}))
		return store, ctx
	}

	t.Run("chained on the spec", func(t *testing.T) {
		store, ctx := setup(t)
		require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
			Name: "apikey-src", Type: credential.SourceTypeAPIKey, Config: map[string]string{},
		}))

		chained := &credential.CredSpec{
			Name: "chained-rotating", Type: credential.TypeAPIKey, Source: "apikey-src",
			Config: map[string]string{
				credential.ConfigSecretSpec:  "ref-secret",
				credential.ConfigSecretField: "api_key",
			},
			RotationPeriod: 24 * time.Hour,
		}
		err := store.CreateSpec(ctx, chained)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotation_period does not apply to a chained credential spec")

		// Without the period the same spec is fine.
		chained.RotationPeriod = 0
		require.NoError(t, store.CreateSpec(ctx, chained))

		// And the rule is in the shared validator, so an edit cannot add one back.
		chained.RotationPeriod = 24 * time.Hour
		err = store.validateSpec(ctx, chained, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotation_period does not apply to a chained credential spec")
	})

	t.Run("chained on the source", func(t *testing.T) {
		store, ctx := setup(t)
		require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
			Name: "apikey-chained-src", Type: credential.SourceTypeAPIKey,
			Config: map[string]string{credential.ConfigSecretSpec: "ref-secret"},
		}))

		err := store.CreateSpec(ctx, &credential.CredSpec{
			Name: "inherits-chaining", Type: credential.TypeAPIKey, Source: "apikey-chained-src",
			Config:         map[string]string{credential.ConfigSecretField: "api_key"},
			RotationPeriod: 24 * time.Hour,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotation_period does not apply to a chained credential spec")
	})
}

// TestCredentialConfigStore_GitLabChaining covers the two gitlab-specific chaining
// guards: chaining is a source concern (never spec-level), and a chained source
// owns no secret so it has nothing to rotate.
func TestCredentialConfigStore_GitLabChaining(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

	// Referenced secret-spec: session-pinned, as validateSecretSpecRef requires.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "gl-pat", Type: "vault_token", Source: "src",
		Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "vault"},
	}))

	gitlabSource := func(name string, extra map[string]string) *credential.CredSource {
		cfg := map[string]string{
			"gitlab_address":            "https://gitlab.example.com",
			"auth_method":               "pat",
			credential.ConfigSecretSpec: "gl-pat",
		}
		for k, v := range extra {
			cfg[k] = v
		}
		return &credential.CredSource{Name: name, Type: credential.SourceTypeGitLab, Config: cfg}
	}

	// A chained gitlab source carries no inline token and is accepted.
	require.NoError(t, store.CreateSource(ctx, gitlabSource("gl-keyless", nil)))

	// Rotation belongs to whoever owns the referenced secret, not to this source.
	rotating := gitlabSource("gl-rotating", nil)
	rotating.RotationPeriod = 24 * time.Hour
	err := store.CreateSource(ctx, rotating)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation_period does not apply to a chained source")

	specConfig := func(extra map[string]string) map[string]string {
		cfg := map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   "42",
			"token_name":   "warden-minted",
			"scopes":       "api",
			"access_level": "30",
		}
		for k, v := range extra {
			cfg[k] = v
		}
		return cfg
	}

	// An ordinary spec on a chained source is unchanged — it inherits the chain from
	// the source and needs no chaining config of its own.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "gl-backend", Type: credential.TypeGitLabAccessToken, Source: "gl-keyless",
		Config: specConfig(nil),
	}))

	// Spec-level secret_spec would leave the source's inline token as dead config
	// and slip past the source-level auth_method gate, so it is rejected with
	// guidance rather than silently accepted.
	err = store.CreateSpec(ctx, &credential.CredSpec{
		Name: "gl-spec-level", Type: credential.TypeGitLabAccessToken, Source: "gl-keyless",
		Config: specConfig(map[string]string{credential.ConfigSecretSpec: "gl-pat"}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set secret_spec on the source")
}

// TestCredentialConfigStore_OAuth2Chaining covers the guards on an oauth2 source that
// fetches its whole client credential per mint: chaining is a source concern, the pair
// must not be half-configured, and the consent flow cannot reach chained material.
func TestCredentialConfigStore_OAuth2Chaining(t *testing.T) {
	store, ctx := setupTestCredentialConfigStore(t)
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))

	// Referenced secret-spec: session-pinned, as validateSecretSpecRef requires.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "idp-client-credential", Type: "vault_token", Source: "src",
		Config: map[string]string{"subject_token_source": "warden_identity", "assertion_audience": "vault"},
	}))

	// The keyless source stores neither half of the client credential.
	require.NoError(t, store.CreateSource(ctx, &credential.CredSource{
		Name: "oauth-keyless", Type: credential.SourceTypeOAuth2,
		Config: map[string]string{
			"token_url":                  "https://identity.example.com/oauth/token",
			credential.ConfigSecretSpec:  "idp-client-credential",
			credential.ConfigSecretField: "client_secret",
		},
	}))

	// Rotation belongs to whoever owns the referenced secret, not to this source.
	rotating := &credential.CredSource{
		Name: "oauth-rotating", Type: credential.SourceTypeOAuth2,
		Config: map[string]string{
			"token_url":                 "https://identity.example.com/oauth/token",
			credential.ConfigSecretSpec: "idp-client-credential",
		},
		RotationPeriod: 24 * time.Hour,
	}
	err := store.CreateSource(ctx, rotating)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation_period does not apply to a chained source")

	// An ordinary spec on a chained source inherits the chain and needs no chaining
	// config of its own.
	require.NoError(t, store.CreateSpec(ctx, &credential.CredSpec{
		Name: "api", Type: credential.TypeOAuthBearerToken, Source: "oauth-keyless",
		Config: map[string]string{"scope": "read"},
	}))

	// Spec-level secret_spec would shadow the source's and leave the mint with no
	// client credential.
	err = store.CreateSpec(ctx, &credential.CredSpec{
		Name: "spec-level", Type: credential.TypeOAuthBearerToken, Source: "oauth-keyless",
		Config: map[string]string{credential.ConfigSecretSpec: "idp-client-credential"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "for an oauth2 source, set secret_spec on the source")

	// The consent steps run on the system backend with no caller, so they have no
	// identity to fetch the chained pair as.
	err = store.CreateSpec(ctx, &credential.CredSpec{
		Name: "consent", Type: credential.TypeOAuthBearerToken, Source: "oauth-keyless",
		Config: map[string]string{"auth_method": "authorization_code"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supports auth_method=client_credentials only")

	// client_id/client_secret resolve spec-over-source, so a half left on the spec
	// would be presented against the other half fetched from the chain.
	for _, key := range []string{"client_id", "client_secret"} {
		err = store.CreateSpec(ctx, &credential.CredSpec{
			Name: "inline-" + key, Type: credential.TypeOAuthBearerToken, Source: "oauth-keyless",
			Config: map[string]string{key: "inline-value"},
		})
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), key+" must be omitted when the source sets secret_spec")
	}
}
