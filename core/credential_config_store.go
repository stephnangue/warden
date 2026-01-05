package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

const (
	credentialConfigStorePath = "core/credconfig/" // Base path
	credSpecPrefix            = "specs/"            // CredSpec storage prefix
	credSourcePrefix          = "sources/"          // CredSource storage prefix
	builtinLocalSourceName    = "local"             // Virtual local source name
)

var (
	ErrConfigStoreClosed     = errors.New("credential config store is closed")
	ErrSpecNotFound          = errors.New("credential spec not found")
	ErrSpecAlreadyExists     = errors.New("credential spec already exists")
	ErrSourceNotFound        = errors.New("credential source not found")
	ErrSourceAlreadyExists   = errors.New("credential source already exists")
	ErrSourceInUse           = errors.New("credential source is referenced by specs")
	ErrNamespaceNotInContext = errors.New("namespace not found in context")
)

// CredentialConfigStoreConfig holds configuration for the credential config store
type CredentialConfigStoreConfig struct {
	CacheMaxCost     int64 // Maximum cache cost in bytes (default: 50 MB)
	CacheNumCounters int64 // Number of counters for Ristretto (default: 1 million)
}

// DefaultCredConfigStoreConfig returns the default configuration
func DefaultCredConfigStoreConfig() *CredentialConfigStoreConfig {
	return &CredentialConfigStoreConfig{
		CacheMaxCost:     50 << 20, // 50 MB
		CacheNumCounters: 1e6,       // 1 million
	}
}

// CredentialConfigStore manages credential specifications and sources with namespace isolation
type CredentialConfigStore struct {
	core   *Core
	logger *logger.GatedLogger
	config *CredentialConfigStoreConfig

	// Storage at "core/credconfig/"
	storage sdklogical.Storage

	// Two-tier caching
	specsByID   *ristretto.Cache[string, *credential.CredSpec]   // {ns-uuid}:spec:{name}
	sourcesByID *ristretto.Cache[string, *credential.CredSource] // {ns-uuid}:source:{name}

	mu     sync.RWMutex
	closed bool
}

// NewCredentialConfigStore creates a new credential config store
func NewCredentialConfigStore(c *Core, config *CredentialConfigStoreConfig) (*CredentialConfigStore, error) {
	if config == nil {
		config = DefaultCredConfigStoreConfig()
	}

	s := &CredentialConfigStore{
		core:   c,
		logger: c.logger.WithSystem("credential-config-store"),
		config: config,
	}

	// Create Ristretto cache for specs
	specsCache, err := ristretto.NewCache(&ristretto.Config[string, *credential.CredSpec]{
		NumCounters: config.CacheNumCounters,
		MaxCost:     config.CacheMaxCost / 2, // Split cache budget
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create specs cache: %w", err)
	}
	s.specsByID = specsCache

	// Create Ristretto cache for sources
	sourcesCache, err := ristretto.NewCache(&ristretto.Config[string, *credential.CredSource]{
		NumCounters: config.CacheNumCounters,
		MaxCost:     config.CacheMaxCost / 2, // Split cache budget
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sources cache: %w", err)
	}
	s.sourcesByID = sourcesCache

	return s, nil
}

// LoadFromStorage loads all credential specs and sources from barrier storage
func (s *CredentialConfigStore) LoadFromStorage(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	// Storage view will be set when barrier is ready
	if s.storage == nil {
		s.storage = NewBarrierView(s.core.barrier, credentialConfigStorePath)
	}

	// Load specs and sources will be implemented in storage.go
	// For now, just log that we're ready
	s.logger.Debug("credential config store initialized")

	return nil
}

// UnloadFromCache clears the in-memory caches but preserves storage
func (s *CredentialConfigStore) UnloadFromCache() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.specsByID.Clear()
	s.sourcesByID.Clear()

	s.logger.Debug("credential config store caches cleared")
}

// Close gracefully shuts down the store
func (s *CredentialConfigStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	s.specsByID.Close()
	s.sourcesByID.Close()

	s.logger.Debug("credential config store closed")
	return nil
}

// buildSpecCacheKey creates a cache key for a spec
func (s *CredentialConfigStore) buildSpecCacheKey(namespaceID, specName string) string {
	return fmt.Sprintf("%s:spec:%s", namespaceID, specName)
}

// buildSourceCacheKey creates a cache key for a source
func (s *CredentialConfigStore) buildSourceCacheKey(namespaceID, sourceName string) string {
	return fmt.Sprintf("%s:source:%s", namespaceID, sourceName)
}

// getNamespaceFromContext extracts namespace from context
func (s *CredentialConfigStore) getNamespaceFromContext(ctx context.Context) (*namespace.Namespace, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	return ns, nil
}

// getBuiltinLocalSource returns a virtual local source that's always available
// This source is never stored - it exists implicitly in all namespaces
func (s *CredentialConfigStore) getBuiltinLocalSource() *credential.CredSource {
	return &credential.CredSource{
		Name:   builtinLocalSourceName,
		Type:   "local",
		Config: make(map[string]string), // Local driver needs no config
	}
}

// isBuiltinSource checks if a source name refers to a built-in virtual source
func (s *CredentialConfigStore) isBuiltinSource(name string) bool {
	return name == builtinLocalSourceName
}

// ============================================================================
// CredSpec Operations
// ============================================================================

// CreateSpec creates a new credential spec in the namespace from context
func (s *CredentialConfigStore) CreateSpec(ctx context.Context, spec *credential.CredSpec) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Validate spec
	if err := s.ValidateSpec(ctx, spec); err != nil {
		return err
	}

	// Check if spec already exists
	cacheKey := s.buildSpecCacheKey(ns.UUID, spec.Name)
	if _, found := s.specsByID.Get(cacheKey); found {
		return ErrSpecAlreadyExists
	}

	// Persist to storage
	if err := s.persistSpec(ns.UUID, spec); err != nil {
		return fmt.Errorf("failed to persist spec: %w", err)
	}

	// Cache the spec
	s.specsByID.Set(cacheKey, spec, 1)
	s.specsByID.Wait()

	s.logger.Debug("created credential spec",
		logger.String("namespace", ns.UUID),
		logger.String("spec_name", spec.Name),
		logger.String("type", spec.Type),
	)

	return nil
}

// GetSpec retrieves a spec by name from the namespace in context
func (s *CredentialConfigStore) GetSpec(ctx context.Context, name string) (*credential.CredSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return nil, err
	}

	cacheKey := s.buildSpecCacheKey(ns.UUID, name)

	// Check cache
	if spec, found := s.specsByID.Get(cacheKey); found {
		return spec, nil
	}

	// Load from storage
	spec, err := s.loadSpec(ns.UUID, name)
	if err != nil {
		return nil, err
	}

	// Cache the spec
	s.specsByID.Set(cacheKey, spec, 1)
	s.specsByID.Wait()

	return spec, nil
}

// UpdateSpec updates an existing spec
func (s *CredentialConfigStore) UpdateSpec(ctx context.Context, spec *credential.CredSpec) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Validate spec
	if err := s.ValidateSpec(ctx, spec); err != nil {
		return err
	}

	// Check if spec exists
	cacheKey := s.buildSpecCacheKey(ns.UUID, spec.Name)
	if _, err := s.loadSpec(ns.UUID, spec.Name); err != nil {
		return ErrSpecNotFound
	}

	// Persist to storage
	if err := s.persistSpec(ns.UUID, spec); err != nil {
		return fmt.Errorf("failed to persist spec: %w", err)
	}

	// Update cache
	s.specsByID.Set(cacheKey, spec, 1)
	s.specsByID.Wait()

	s.logger.Debug("updated credential spec",
		logger.String("namespace", ns.UUID),
		logger.String("spec_name", spec.Name),
	)

	return nil
}

// DeleteSpec removes a spec by name
func (s *CredentialConfigStore) DeleteSpec(ctx context.Context, name string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Delete from storage
	if err := s.deleteSpec(ns.UUID, name); err != nil {
		return err
	}

	// Remove from cache
	cacheKey := s.buildSpecCacheKey(ns.UUID, name)
	s.specsByID.Del(cacheKey)

	s.logger.Debug("deleted credential spec",
		logger.String("namespace", ns.UUID),
		logger.String("spec_name", name),
	)

	return nil
}

// ListSpecs lists all specs in the namespace from context
func (s *CredentialConfigStore) ListSpecs(ctx context.Context) ([]*credential.CredSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Load all specs from storage
	specs, err := s.loadAllSpecs(ns.UUID)
	if err != nil {
		return nil, err
	}

	// Cache them
	for _, spec := range specs {
		cacheKey := s.buildSpecCacheKey(ns.UUID, spec.Name)
		s.specsByID.Set(cacheKey, spec, 1)
	}
	s.specsByID.Wait()

	return specs, nil
}

// ============================================================================
// CredSource Operations
// ============================================================================

// CreateSource creates a new credential source in the namespace from context
func (s *CredentialConfigStore) CreateSource(ctx context.Context, source *credential.CredSource) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	// Prevent creating sources with built-in names
	if s.isBuiltinSource(source.Name) {
		return fmt.Errorf("cannot create source with reserved name '%s' (built-in source)", source.Name)
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Validate source
	if err := s.ValidateSource(ctx, source); err != nil {
		return err
	}

	// Check if source already exists
	cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
	if _, found := s.sourcesByID.Get(cacheKey); found {
		return ErrSourceAlreadyExists
	}

	// Persist to storage
	if err := s.persistSource(ns.UUID, source); err != nil {
		return fmt.Errorf("failed to persist source: %w", err)
	}

	// Cache the source
	s.sourcesByID.Set(cacheKey, source, 1)
	s.sourcesByID.Wait()

	s.logger.Debug("created credential source",
		logger.String("namespace", ns.UUID),
		logger.String("source_name", source.Name),
		logger.String("type", source.Type),
	)

	return nil
}

// GetSource retrieves a source by name from the namespace in context
func (s *CredentialConfigStore) GetSource(ctx context.Context, name string) (*credential.CredSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrConfigStoreClosed
	}

	// Return built-in virtual source if requested
	if s.isBuiltinSource(name) {
		return s.getBuiltinLocalSource(), nil
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return nil, err
	}

	cacheKey := s.buildSourceCacheKey(ns.UUID, name)

	// Check cache
	if source, found := s.sourcesByID.Get(cacheKey); found {
		return source, nil
	}

	// Load from storage
	source, err := s.loadSource(ns.UUID, name)
	if err != nil {
		return nil, err
	}

	// Cache the source
	s.sourcesByID.Set(cacheKey, source, 1)
	s.sourcesByID.Wait()

	return source, nil
}

// UpdateSource updates an existing source
func (s *CredentialConfigStore) UpdateSource(ctx context.Context, source *credential.CredSource) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	// Prevent updating built-in sources
	if s.isBuiltinSource(source.Name) {
		return fmt.Errorf("cannot update built-in source '%s'", source.Name)
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Validate source
	if err := s.ValidateSource(ctx, source); err != nil {
		return err
	}

	// Check if source exists
	cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
	if _, err := s.loadSource(ns.UUID, source.Name); err != nil {
		return ErrSourceNotFound
	}

	// Persist to storage
	if err := s.persistSource(ns.UUID, source); err != nil {
		return fmt.Errorf("failed to persist source: %w", err)
	}

	// Update cache
	s.sourcesByID.Set(cacheKey, source, 1)
	s.sourcesByID.Wait()

	s.logger.Debug("updated credential source",
		logger.String("namespace", ns.UUID),
		logger.String("source_name", source.Name),
	)

	return nil
}

// DeleteSource removes a source by name
func (s *CredentialConfigStore) DeleteSource(ctx context.Context, name string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	// Prevent deleting built-in sources
	if s.isBuiltinSource(name) {
		return fmt.Errorf("cannot delete built-in source '%s'", name)
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Check if source is in use
	refs, err := s.CheckSourceReferences(ctx, name)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return ErrSourceInUse
	}

	// Delete from storage
	if err := s.deleteSource(ns.UUID, name); err != nil {
		return err
	}

	// Remove from cache
	cacheKey := s.buildSourceCacheKey(ns.UUID, name)
	s.sourcesByID.Del(cacheKey)

	s.logger.Debug("deleted credential source",
		logger.String("namespace", ns.UUID),
		logger.String("source_name", name),
	)

	return nil
}

// ListSources lists all sources in the namespace from context
func (s *CredentialConfigStore) ListSources(ctx context.Context) ([]*credential.CredSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Load all sources from storage
	sources, err := s.loadAllSources(ns.UUID)
	if err != nil {
		return nil, err
	}

	// Cache them
	for _, source := range sources {
		cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
		s.sourcesByID.Set(cacheKey, source, 1)
	}
	s.sourcesByID.Wait()

	// Add built-in local source to the list
	sources = append([]*credential.CredSource{s.getBuiltinLocalSource()}, sources...)

	return sources, nil
}

// ============================================================================
// Validation
// ============================================================================

// ValidateSpec validates a spec before creation/update
func (s *CredentialConfigStore) ValidateSpec(ctx context.Context, spec *credential.CredSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("spec name cannot be empty")
	}

	if spec.Type == "" {
		return fmt.Errorf("spec type cannot be empty")
	}

	if spec.SourceName == "" {
		return fmt.Errorf("spec source_name cannot be empty")
	}

	// Verify source exists in same namespace
	_, err := s.GetSource(ctx, spec.SourceName)
	if err != nil {
		if errors.Is(err, ErrSourceNotFound) {
			return fmt.Errorf("source '%s' not found in namespace", spec.SourceName)
		}
		return fmt.Errorf("failed to validate source reference: %w", err)
	}

	// Validate TTL constraints
	if spec.MinTTL > spec.MaxTTL && spec.MaxTTL != 0 {
		return fmt.Errorf("min_ttl cannot be greater than max_ttl")
	}

	// Validate credential type exists
	if s.core.credentialTypeRegistry != nil {
		if !s.core.credentialTypeRegistry.HasType(spec.Type) {
			return fmt.Errorf("unknown credential type: %s (available types: %v)",
				spec.Type,
				s.core.credentialTypeRegistry.ListTypes())
		}

		// Validate SourceParams using the credential type's validation
		credType, err := s.core.credentialTypeRegistry.GetByName(spec.Type)
		if err == nil {
			if err := credType.ValidateSourceParams(spec.SourceParams, spec.SourceName); err != nil {
				return fmt.Errorf("invalid source params for type '%s': %w", spec.Type, err)
			}
		}
	}

	return nil
}

// ValidateSource validates a source before creation/update
func (s *CredentialConfigStore) ValidateSource(ctx context.Context, source *credential.CredSource) error {
	if source.Name == "" {
		return fmt.Errorf("source name cannot be empty")
	}

	if source.Type == "" {
		return fmt.Errorf("source type cannot be empty")
	}

	// Validate driver factory exists
	if s.core.credentialDriverRegistry != nil {
		if !s.core.credentialDriverRegistry.HasFactory(source.Type) {
			return fmt.Errorf("unknown source type: %s (available types: %v)",
				source.Type,
				s.core.credentialDriverRegistry.ListFactories())
		}

		// Validate config using the driver factory's validation
		factory, err := s.core.credentialDriverRegistry.GetFactory(source.Type)
		if err == nil {
			if err := factory.ValidateConfig(source.Config); err != nil {
				return fmt.Errorf("invalid config for source type '%s': %w", source.Type, err)
			}
		}
	}

	return nil
}

// CheckSourceReferences checks if a source is referenced by any specs
func (s *CredentialConfigStore) CheckSourceReferences(ctx context.Context, sourceName string) ([]*credential.CredSpec, error) {
	// Get all specs in the namespace
	specs, err := s.ListSpecs(ctx)
	if err != nil {
		return nil, err
	}

	// Find specs that reference this source
	var refs []*credential.CredSpec
	for _, spec := range specs {
		if spec.SourceName == sourceName {
			refs = append(refs, spec)
		}
	}

	return refs, nil
}

// ============================================================================
// Core Integration Methods
// ============================================================================

// setupCredentialConfigStore is used to initialize the credential config store
// when the vault is being unsealed.
func (c *Core) setupCredentialConfigStore(ctx context.Context) error {
	if c.credConfigStore == nil {
		return fmt.Errorf("credential config store not initialized")
	}

	// Load specs and sources from storage
	return c.credConfigStore.LoadFromStorage(ctx)
}

// teardownCredentialConfigStore is used to reverse setupCredentialConfigStore
// when the vault is being sealed.
func (c *Core) teardownCredentialConfigStore() error {
	if c.credConfigStore != nil {
		c.credConfigStore.UnloadFromCache()
	}
	return nil
}

// setupCredentialManager creates and initializes the global credential manager
// This is called during unseal after setupCredentialConfigStore
func (c *Core) setupCredentialManager(ctx context.Context) error {
	// Create storage view for credentials
	credStorage := NewBarrierView(c.barrier, credential.StoragePath)

	// Create global Manager with CredentialConfigStore as ConfigStoreAccessor
	manager, err := credential.NewManager(
		c.credentialTypeRegistry,
		c.credentialDriverRegistry,
		credStorage,
		c.credConfigStore, // Implements ConfigStoreAccessor interface
		c.logger.WithSystem("credential-manager"),
	)
	if err != nil {
		return fmt.Errorf("failed to create credential manager: %w", err)
	}

	// Load persisted credentials from storage across all namespaces
	if err := manager.LoadFromStorage(ctx); err != nil {
		return fmt.Errorf("failed to load credentials from storage: %w", err)
	}

	c.credentialManager = manager

	c.logger.Info("global credential manager initialized")

	return nil
}

// teardownCredentialManager stops the global credential manager
func (c *Core) teardownCredentialManager() error {
	if c.credentialManager != nil {
		c.credentialManager.Stop()
		c.logger.Info("credential manager stopped")
		c.credentialManager = nil
	}

	return nil
}

// GetCredentialManager returns the global credential manager
// The manager uses namespace-aware cache keys and storage paths for isolation
func (c *Core) GetCredentialManager(ctx context.Context) (*credential.Manager, error) {
	if c.credentialManager == nil {
		return nil, fmt.Errorf("credential manager not initialized")
	}

	return c.credentialManager, nil
}

// startCredentialBackgroundCleanup starts background cleanup for the global credential manager
func (c *Core) startCredentialBackgroundCleanup(ctx context.Context, interval time.Duration) {
	if c.credentialManager != nil {
		c.credentialManager.StartBackgroundCleanup(ctx, interval)
		c.logger.Debug("started credential background cleanup",
			logger.String("interval", interval.String()))
	}
}
