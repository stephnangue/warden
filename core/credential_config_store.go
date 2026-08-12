package core

import (
	"context"
	"errors"
	"fmt"
	"sync"

	ristretto "github.com/dgraph-io/ristretto/v2"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	credentialConfigStorePath = "core/credconfig/" // Base path
	credSpecPrefix            = "specs/"           // CredSpec storage prefix
	credSourcePrefix          = "sources/"         // CredSource storage prefix
	builtinLocalSourceName    = "local"            // Virtual local source name
)

var (
	ErrConfigStoreClosed     = errors.New("credential config store is closed")
	ErrSpecNotFound          = errors.New("credential spec not found")
	ErrSpecAlreadyExists     = errors.New("credential spec already exists")
	ErrSourceNotFound        = errors.New("credential source not found")
	ErrSourceAlreadyExists   = errors.New("credential source already exists")
	ErrSourceInUse           = errors.New("credential source is referenced by specs")
	ErrSpecInUse             = errors.New("credential spec is referenced via secret_spec")
	ErrNamespaceNotInContext = errors.New("namespace not found in context")
)

// CredentialConfigStoreConfig holds configuration for the credential config store
type CredentialConfigStoreConfig struct {
	CacheMaxCost         int64 // Maximum cache cost in bytes (default: 50 MB)
	CacheNumCounters     int64 // Number of counters for Ristretto (default: 1 million)
	SkipSpecVerification bool  // Skip SpecVerifier validation (for testing only)
}

// DefaultCredConfigStoreConfig returns the default configuration
func DefaultCredConfigStoreConfig() *CredentialConfigStoreConfig {
	return &CredentialConfigStoreConfig{
		CacheMaxCost:     50 << 20, // 50 MB
		CacheNumCounters: 1e6,      // 1 million
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

	// Rotation manager for periodic credential source rotation
	rotationManager *RotationManager

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
		logger: c.logger.WithSystem("credential.config-store"),
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

	// Check if spec already exists (check both cache and storage)
	cacheKey := s.buildSpecCacheKey(ns.UUID, spec.Name)
	if _, found := s.specsByID.Get(cacheKey); found {
		return ErrSpecAlreadyExists
	}
	// Also check storage in case cache was evicted or server restarted
	if _, err := s.loadSpec(ns.UUID, spec.Name); err == nil {
		return ErrSpecAlreadyExists
	}

	// Persist to storage
	if err := s.persistSpec(ns.UUID, spec); err != nil {
		return fmt.Errorf("failed to persist spec: %w", err)
	}

	// Cache the spec
	s.specsByID.Set(cacheKey, spec, 1)
	s.specsByID.Wait()

	// Register with rotation manager if RotationPeriod is configured
	if spec.RotationPeriod > 0 {
		if s.rotationManager != nil {
			if err := s.rotationManager.RegisterSpec(ctx, spec.Name, spec.Source, spec.RotationPeriod); err != nil {
				s.logger.Warn("failed to register spec for rotation",
					logger.String("spec_name", spec.Name),
					logger.Err(err),
				)
				// Don't fail spec creation for rotation registration errors
			} else {
				s.logger.Debug("registered spec for rotation",
					logger.String("spec_name", spec.Name),
					logger.String("rotation_period", spec.RotationPeriod.String()),
				)
			}
		}
	}

	s.logger.Info("created credential spec",
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

// UpdateSpecOptions controls UpdateSpec behavior.
type UpdateSpecOptions struct {
	// SkipVerification skips the test-mint / SpecVerifier checks during validation.
	// Used by the connect seal and refresh-token write-back, which persist a
	// known-good token and must not re-mint (which would consume/rotate it).
	SkipVerification bool
}

// PersistRotatedSpec persists a spec without re-running verification, satisfying
// credential.ConfigStoreAccessor for the refresh-token write-back. Verification
// is skipped because re-minting would consume the just-rotated refresh token.
func (s *CredentialConfigStore) PersistRotatedSpec(ctx context.Context, spec *credential.CredSpec) error {
	return s.UpdateSpec(ctx, spec, UpdateSpecOptions{SkipVerification: true})
}

// ReloadSpec evicts the node-local cache entry for a spec and re-reads it,
// forcing a load from shared storage. The refresh-token write-back uses this on
// a rejection so a token another node rotated and persisted is actually seen
// (the spec cache has no cross-node invalidation).
func (s *CredentialConfigStore) ReloadSpec(ctx context.Context, name string) (*credential.CredSpec, error) {
	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	s.specsByID.Del(s.buildSpecCacheKey(ns.UUID, name))
	return s.GetSpec(ctx, name)
}

// UpdateSpec updates an existing spec
func (s *CredentialConfigStore) UpdateSpec(ctx context.Context, spec *credential.CredSpec, opts ...UpdateSpecOptions) error {
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
	var skipVerification bool
	if len(opts) > 0 {
		skipVerification = opts[0].SkipVerification
	}
	if err := s.validateSpec(ctx, spec, skipVerification); err != nil {
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

	// Prevent deleting a spec still referenced as a chaining secret source
	// (secret_spec) by another source or spec.
	refs, err := s.CheckSpecReferences(ctx, name)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return ErrSpecInUse
	}

	// Unregister from rotation manager first (if registered)
	if s.rotationManager != nil {
		if err := s.rotationManager.UnregisterSpec(ctx, name); err != nil {
			s.logger.Debug("spec was not registered for rotation (or already unregistered)",
				logger.String("spec_name", name),
			)
		}
	}

	// Delete from storage
	if err := s.deleteSpec(ns.UUID, name); err != nil {
		return err
	}

	// Remove from cache
	cacheKey := s.buildSpecCacheKey(ns.UUID, name)
	s.specsByID.Del(cacheKey)

	s.logger.Info("deleted credential spec",
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

	// Check if source already exists (check both cache and storage)
	cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
	if _, found := s.sourcesByID.Get(cacheKey); found {
		return ErrSourceAlreadyExists
	}
	// Also check storage in case cache was evicted or server restarted
	if _, err := s.loadSource(ns.UUID, source.Name); err == nil {
		return ErrSourceAlreadyExists
	}

	// Persist to storage
	if err := s.persistSource(ns.UUID, source); err != nil {
		return fmt.Errorf("failed to persist source: %w", err)
	}

	// Cache the source
	s.sourcesByID.Set(cacheKey, source, 1)
	s.sourcesByID.Wait()

	// Register with rotation manager if RotationPeriod is configured
	if source.RotationPeriod > 0 {
		if s.rotationManager != nil {
			if err := s.rotationManager.RegisterSource(ctx, source.Name, source.Type, source.RotationPeriod); err != nil {
				s.logger.Warn("failed to register source for rotation",
					logger.String("source_name", source.Name),
					logger.Err(err),
				)
				// Don't fail source creation for rotation registration errors
			} else {
				s.logger.Debug("registered source for rotation",
					logger.String("source_name", source.Name),
					logger.String("rotation_period", source.RotationPeriod.String()),
				)
			}
		}
	}

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

// UpdateSourceOptions controls UpdateSource behavior
type UpdateSourceOptions struct {
	// SkipConnectionTest skips the credential connectivity check during validation.
	// Used by the rotation manager where new credentials are known-good but may
	// not yet be propagated at the provider (e.g., AWS IAM key propagation delay).
	SkipConnectionTest bool
}

// UpdateSource updates an existing source
func (s *CredentialConfigStore) UpdateSource(ctx context.Context, source *credential.CredSource, opts ...UpdateSourceOptions) error {
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
	var skipConnectionTest bool
	if len(opts) > 0 {
		skipConnectionTest = opts[0].SkipConnectionTest
	}
	if err := s.validateSource(ctx, source, skipConnectionTest); err != nil {
		return err
	}

	// Check if source exists, and pin its type: a source's Type is immutable once
	// created. Bound specs are validated against the source type (e.g. the
	// user_identity subject and any actor source require a token_exchange source),
	// so letting Type change in place would silently invalidate those guards for
	// already-bound specs. The API handler already forces the type; this defends the
	// invariant at the store layer for any other caller.
	cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
	existing, err := s.loadSource(ns.UUID, source.Name)
	if err != nil {
		return ErrSourceNotFound
	}
	if source.Type != existing.Type {
		return logical.ErrBadRequestf("cannot change the type of source %q (%s → %s); source type is immutable", source.Name, existing.Type, source.Type)
	}

	// Close old driver instance since config has changed
	// This ensures the driver will be recreated with the new config on next use
	if err := s.core.credentialManager.CloseDriver(ctx, source.Name); err != nil {
		s.logger.Warn("failed to close driver during source update",
			logger.String("source_name", source.Name),
			logger.Err(err))
		// Continue with update even if driver cleanup fails
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

	// Unregister from rotation manager first (if registered)
	if s.rotationManager != nil {
		if err := s.rotationManager.UnregisterSource(ctx, name); err != nil {
			s.logger.Debug("source was not registered for rotation (or already unregistered)",
				logger.String("source_name", name),
			)
		}
	}

	// Close driver instance to prevent resource leaks
	// This releases any connections, HTTP clients, or other resources held by the driver
	if s.core.credentialManager != nil {
		if err := s.core.credentialManager.CloseDriver(ctx, name); err != nil {
			s.logger.Warn("failed to close driver during source deletion",
				logger.String("source_name", name),
				logger.Err(err))
			// Continue with deletion even if driver cleanup fails
		}
	}

	// Delete from storage
	if err := s.deleteSource(ns.UUID, name); err != nil {
		return err
	}

	// Remove from cache
	cacheKey := s.buildSourceCacheKey(ns.UUID, name)
	s.sourcesByID.Del(cacheKey)

	s.logger.Info("deleted credential source",
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
// Namespace Cleanup
// ============================================================================

// ClearNamespace deletes all credential specs and sources for the namespace in context.
// Specs are deleted first (to clear references), then sources.
// Rotation unregistration is handled for each entry.
// This is called during namespace deletion.
func (s *CredentialConfigStore) ClearNamespace(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrConfigStoreClosed
	}

	ns, err := s.getNamespaceFromContext(ctx)
	if err != nil {
		return err
	}

	// Delete all specs first (removes references to sources)
	specs, err := s.loadAllSpecs(ns.UUID)
	if err != nil {
		return fmt.Errorf("failed to list specs for namespace cleanup: %w", err)
	}

	for _, spec := range specs {
		if s.rotationManager != nil {
			s.rotationManager.UnregisterSpec(ctx, spec.Name)
		}

		if err := s.deleteSpec(ns.UUID, spec.Name); err != nil {
			return fmt.Errorf("failed to delete spec %s during namespace cleanup: %w", spec.Name, err)
		}

		cacheKey := s.buildSpecCacheKey(ns.UUID, spec.Name)
		s.specsByID.Del(cacheKey)
	}

	// Delete all sources (no reference check needed since specs are already deleted)
	sources, err := s.loadAllSources(ns.UUID)
	if err != nil {
		return fmt.Errorf("failed to list sources for namespace cleanup: %w", err)
	}

	for _, source := range sources {
		if s.isBuiltinSource(source.Name) {
			continue
		}

		if s.rotationManager != nil {
			s.rotationManager.UnregisterSource(ctx, source.Name)
		}

		if err := s.deleteSource(ns.UUID, source.Name); err != nil {
			return fmt.Errorf("failed to delete source %s during namespace cleanup: %w", source.Name, err)
		}

		cacheKey := s.buildSourceCacheKey(ns.UUID, source.Name)
		s.sourcesByID.Del(cacheKey)
	}

	if len(specs) > 0 || len(sources) > 0 {
		s.logger.Info("cleared credential configs for namespace",
			logger.String("namespace", ns.UUID),
			logger.Int("specs_deleted", len(specs)),
			logger.Int("sources_deleted", len(sources)))
	}

	return nil
}

// ============================================================================
// Validation
// ============================================================================

// ValidateSpec validates a spec before creation/update.
func (s *CredentialConfigStore) ValidateSpec(ctx context.Context, spec *credential.CredSpec) error {
	return s.validateSpec(ctx, spec, false)
}

// validateSpec validates a spec. When skipVerification is true the test-mint and
// SpecVerifier checks are skipped — used by the connect seal and refresh-token
// write-back, which already hold a known-good token and must not re-mint it.
func (s *CredentialConfigStore) validateSpec(ctx context.Context, spec *credential.CredSpec, skipVerification bool) error {
	if spec.Name == "" {
		return logical.ErrBadRequest("spec name cannot be empty")
	}

	if spec.Type == "" {
		return logical.ErrBadRequest("spec type cannot be empty")
	}

	if spec.Source == "" {
		return logical.ErrBadRequest("spec source cannot be empty")
	}

	// Verify source exists in same namespace and get its type
	source, err := s.GetSource(ctx, spec.Source)
	if err != nil {
		if errors.Is(err, ErrSourceNotFound) {
			return logical.ErrBadRequestf("source '%s' not found in namespace", spec.Source)
		}
		return fmt.Errorf("failed to validate source reference: %w", err)
	}

	// Validate TTL constraints
	if spec.MinTTL > spec.MaxTTL && spec.MaxTTL != 0 {
		return logical.ErrBadRequest("min_ttl cannot be greater than max_ttl")
	}

	// Validate credential type exists
	var credType credential.Type
	if s.core.credentialTypeRegistry != nil {
		if !s.core.credentialTypeRegistry.HasType(spec.Type) {
			return logical.ErrBadRequestf("unknown credential type: %s (available types: %v)",
				spec.Type,
				s.core.credentialTypeRegistry.ListTypes())
		}

		// Validate Config using the credential type's validation
		// Pass the source type (not source name) to enable source-specific validation
		var typeErr error
		credType, typeErr = s.core.credentialTypeRegistry.GetByName(spec.Type)
		if typeErr != nil {
			credType = nil
		} else {
			if err := credType.ValidateConfig(spec.Config, source.Type); err != nil {
				return logical.ErrBadRequestf("invalid config for type '%s': %s", spec.Type, err.Error())
			}

			// A token-exchange spec (subject_token_source set) is minted fresh per
			// request from a caller-derived assertion; it embeds no secret, so
			// scheduled rotation is meaningless. Reject rotation_period outright —
			// otherwise the spec is enrolled for a rotation that can never persist,
			// and a spec-rotating type would mutate the upstream every failed cycle.
			if credential.SpecRequestsExchange(spec.Config) {
				if spec.RotationPeriod > 0 {
					return logical.ErrBadRequestf("rotation_period is not supported for credential type '%s' (token-exchange spec; credentials are minted per request, not rotated)", spec.Type)
				}
			} else if credType.RequiresSpecRotation() && spec.RotationPeriod <= 0 {
				// Types that embed rotatable credentials must schedule rotation.
				return logical.ErrBadRequestf("rotation_period is required for credential type '%s' which embeds rotatable credentials", spec.Type)
			}

			// Connect-gated specs (e.g. OAuth2 authorization_code) are refreshed on
			// use, not scheduled — reject rotation_period. This is a config rule, so
			// it runs here rather than in the test-mint block below (which can be
			// skipped via SkipVerification or in test mode).
			if cg, ok := credType.(credential.ConnectGated); ok && cg.RequiresConnect(spec.Config) && spec.RotationPeriod > 0 {
				return logical.ErrBadRequestf("rotation_period is not supported for credential type '%s' (connect-gated; tokens are refreshed on use, not on a schedule)", spec.Type)
			}
		}
	}

	// Structurally validate any token-exchange keys. Whether a driver supports
	// exchange is enforced at mint time (fail closed), not here.
	if err := credential.ValidateExchangeSpecConfig(spec.Config); err != nil {
		return logical.ErrBadRequestf("invalid token-exchange config: %s", err.Error())
	}

	// Any actor token source (agent_identity, warden_identity) is consumed only by
	// the token_exchange driver, which forwards the actor to an RFC 8693 STS; every
	// other driver ignores ActorToken entirely. Pin any actor source to a
	// token_exchange source so a delegation spec can't be bound to a source that
	// would silently drop the actor (losing the delegation and its audit
	// attribution), and reject a grant with no actor slot — otherwise the spec is
	// accepted but every request fails at mint time. These are source-aware, so
	// they live here, not in the structural validator above.
	if actorSrc := spec.Config[credential.ConfigActorTokenSource]; actorSrc != "" && actorSrc != credential.SourceNone {
		if source.Type != credential.SourceTypeTokenExchange {
			return logical.ErrBadRequestf("field '%s': an actor token requires a '%s' source (only token exchange consumes an actor token)",
				credential.ConfigActorTokenSource, credential.SourceTypeTokenExchange)
		}
		if !drivers.TokenExchangeSupportsActor(source.Config) {
			return logical.ErrBadRequestf("field '%s': an actor token is not supported with grant=jwt_bearer (no actor slot)",
				credential.ConfigActorTokenSource)
		}
	}

	// subject_token_source=user_identity forwards the raw user credential as the
	// RFC 8693 subject_token, which only the token_exchange driver consumes. Pin it
	// to a token_exchange source so a federation driver (gcp/aws/azure/vault) can
	// never be handed the raw user JWT as its own federation login token.
	if spec.Config[credential.ConfigSubjectTokenSource] == credential.SourceUserIdentity &&
		source.Type != credential.SourceTypeTokenExchange {
		return logical.ErrBadRequestf("field '%s': '%s' requires a '%s' source",
			credential.ConfigSubjectTokenSource, credential.SourceUserIdentity, credential.SourceTypeTokenExchange)
	}

	// A warden_identity assertion — whether the subject or the actor — must declare
	// its audience. The spec may omit it only when the source can derive one (e.g. a
	// GCP federation source derives it from its workload_identity_provider);
	// otherwise it is required. This check is source-aware, so it lives here rather
	// than in the source-agnostic structural validator above. Re-checked at mint
	// time (defence in depth).
	mintsAssertion := spec.Config[credential.ConfigSubjectTokenSource] == credential.SourceWardenIdentity ||
		spec.Config[credential.ConfigActorTokenSource] == credential.SourceWardenIdentity
	if mintsAssertion && spec.Config[credential.ConfigAssertionAudience] == "" {
		if _, ok := drivers.DeriveAssertionAudience(source.Type, source.Config, spec.Config); !ok {
			return logical.ErrBadRequestf("field '%s': is required when the subject or actor is '%s'",
				credential.ConfigAssertionAudience, credential.SourceWardenIdentity)
		}
	}

	// Credential chaining: when this spec (spec-level, wins) or its source
	// (source-level) references another cred spec as its secret source, validate the
	// referenced secret-spec. The consuming driver's eligibility (it must implement
	// ChainedSecretMinter) is checked in the test-mint block below as a create-time
	// fail-fast; that block is skipped when verification is disabled or the source is
	// local, so the authoritative eligibility guard is at mint time
	// (MintFromSecretWithCleanup fails closed if the driver isn't a ChainedSecretMinter).
	chainedRef := spec.Config[credential.ConfigSecretSpec]
	if chainedRef == "" {
		chainedRef = source.Config[credential.ConfigSecretSpec]
	}
	if chainedRef != "" {
		// A chained consumer's identity flows through the referenced secret-spec, so
		// its own subject/actor exchange config would be silently ignored at mint —
		// reject the confusing combination rather than accept dead config.
		if credential.SpecRequestsExchange(spec.Config) {
			return logical.ErrBadRequestf("a chained spec (secret_spec set) must not also set its own subject_token_source/actor_token_source; the caller identity is carried by the referenced secret_spec %q", chainedRef)
		}
		if err := s.validateSecretSpecRef(ctx, chainedRef); err != nil {
			return err
		}
	}

	// Test credential minting if driver registry is available.
	// This catches invalid auth credentials early (e.g., wrong GitHub app_id,
	// expired PAT, invalid private key) rather than failing at gateway time.
	// Follows the same pattern as validateSource which creates a temp driver
	// to test source connections at creation time.
	// Skipped for local sources where MintCredential just echoes config values.
	// Skip credential verification in test mode (when SkipSpecVerification is true)
	if !skipVerification && !s.config.SkipSpecVerification && s.core.credentialDriverRegistry != nil && source.Type != credential.SourceTypeLocal {
		factory, err := s.core.credentialDriverRegistry.GetFactory(source.Type)
		if err == nil {
			driver, err := factory.Create(source.Config, s.logger)
			if err == nil {
				defer driver.Cleanup(ctx)
				testSpec := &credential.CredSpec{
					Name:   "_validation",
					Type:   spec.Type,
					Source: spec.Source,
					Config: spec.Config,
				}

				// Skip the test-mint for a connect-gated spec (e.g. OAuth2
				// authorization_code) that isn't connected yet — it cannot mint
				// until `cred spec connect` seals a token.
				runTestMint := true
				if cg, ok := credType.(credential.ConnectGated); ok &&
					cg.RequiresConnect(spec.Config) && !cg.IsConnected(spec.Config) {
					runTestMint = false
				}

				// A token-exchange spec has no caller subject token at creation
				// time, so it cannot be test-minted here — it mints only on a live
				// request that carries the exchange inputs.
				if credential.SpecRequestsExchange(spec.Config) {
					runTestMint = false
				}

				// A chained spec (secret_spec) fetches its secret material from a
				// referenced spec at request time as the caller, so it cannot be
				// test-minted at create. Its consuming driver must also be able to
				// mint from that material — reject at create rather than at first use.
				if chainedRef != "" {
					if _, ok := driver.(credential.ChainedSecretMinter); !ok {
						return logical.ErrBadRequestf("source type %q does not support secret_spec chaining", source.Type)
					}
					runTestMint = false
				}

				if runTestMint {
					if _, _, _, _, err := driver.MintCredential(ctx, testSpec); err != nil {
						return logical.ErrBadRequestf("credential test failed for spec type '%s': %s", spec.Type, err.Error())
					}

					// Run additional verification if the driver supports it.
					// This catches cases where MintCredential doesn't call the upstream
					// API (e.g., GitHub PAT mode just returns the token).
					if verifier, ok := driver.(credential.SpecVerifier); ok {
						if err := verifier.VerifySpec(ctx, testSpec); err != nil {
							return logical.ErrBadRequestf("credential verification failed for spec type '%s': %s", spec.Type, err.Error())
						}
					}
				}
			}
		}
	}

	// Validate spec rotation_period is within configured bounds
	if spec.RotationPeriod > 0 {
		minPeriod, maxPeriod := s.core.CredSpecRotationPeriodBounds()
		if spec.RotationPeriod < minPeriod {
			return logical.ErrBadRequestf("rotation_period %s is below the minimum allowed %s (configured via min_cred_spec_rotation_period)",
				spec.RotationPeriod, minPeriod)
		}
		if spec.RotationPeriod > maxPeriod {
			return logical.ErrBadRequestf("rotation_period %s exceeds the maximum allowed %s (configured via max_cred_spec_rotation_period)",
				spec.RotationPeriod, maxPeriod)
		}
	}

	return nil
}

// ValidateSource validates a source before creation/update
func (s *CredentialConfigStore) ValidateSource(ctx context.Context, source *credential.CredSource) error {
	return s.validateSource(ctx, source, false)
}

// validateSource validates a source with optional connection test skip.
// skipConnectionTest is used during rotation where credentials are known-good
// but may not yet be propagated at the provider (e.g., AWS IAM key propagation delay).
func (s *CredentialConfigStore) validateSource(ctx context.Context, source *credential.CredSource, skipConnectionTest bool) error {
	if source.Name == "" {
		return logical.ErrBadRequest("source name cannot be empty")
	}

	if source.Type == "" {
		return logical.ErrBadRequest("source type cannot be empty")
	}

	// Credential chaining: a source-level secret_spec makes every spec on this
	// source draw its secret from the referenced spec. Validate that reference.
	if ref := source.Config[credential.ConfigSecretSpec]; ref != "" {
		if err := s.validateSecretSpecRef(ctx, ref); err != nil {
			return err
		}
	}

	// Validate rotation_period is set for source types that require it. A keyless
	// hvault federation source (auth_method=oidc_federation) holds no secret_id to
	// rotate, so rotation_period does not apply — only the rotatable approle/token
	// path requires it.
	if source.Type == credential.SourceTypeVault && source.RotationPeriod <= 0 &&
		credential.GetString(source.Config, "auth_method", "") != "oidc_federation" {
		return logical.ErrBadRequest("rotation_period is required for hvault credential sources (except keyless auth_method=oidc_federation)")
	}

	// Validate rotation_period is within configured bounds
	if source.RotationPeriod > 0 {
		minPeriod, maxPeriod := s.core.CredSourceRotationPeriodBounds()
		if source.RotationPeriod < minPeriod {
			return logical.ErrBadRequestf("rotation_period %s is below the minimum allowed %s (configured via min_cred_source_rotation_period)",
				source.RotationPeriod, minPeriod)
		}
		if source.RotationPeriod > maxPeriod {
			return logical.ErrBadRequestf("rotation_period %s exceeds the maximum allowed %s (configured via max_cred_source_rotation_period)",
				source.RotationPeriod, maxPeriod)
		}
	}

	// Validate driver factory exists
	if s.core.credentialDriverRegistry != nil {
		if !s.core.credentialDriverRegistry.HasFactory(source.Type) {
			return logical.ErrBadRequestf("unknown source type: %s (available types: %v)",
				source.Type,
				s.core.credentialDriverRegistry.ListFactories())
		}

		// Validate config using the driver factory's validation
		factory, err := s.core.credentialDriverRegistry.GetFactory(source.Type)
		if err == nil {
			if err := factory.ValidateConfig(source.Config); err != nil {
				return logical.ErrBadRequestf("invalid config for source type '%s': %s", source.Type, err.Error())
			}

			// Test connection by creating a temporary driver instance
			// This validates credentials and connectivity (e.g., Vault authentication)
			// Skipped during rotation where new credentials may not yet be propagated
			if !skipConnectionTest {
				driver, err := factory.Create(source.Config, s.logger)
				if err != nil {
					return logical.ErrBadRequestf("connection test failed for source type '%s': %s", source.Type, err.Error())
				}
				// Clean up the test driver
				if driver != nil {
					driver.Cleanup(ctx)
				}
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
		if spec.Source == sourceName {
			refs = append(refs, spec)
		}
	}

	return refs, nil
}

// CheckSpecReferences returns the names of sources and specs that reference the
// given spec as their credential-chaining secret source (secret_spec). It scans
// both sources (source-level secret_spec) and specs (spec-level secret_spec) so a
// referenced secret-spec cannot be deleted while any consumer still points at it.
func (s *CredentialConfigStore) CheckSpecReferences(ctx context.Context, specName string) ([]string, error) {
	sources, err := s.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	specs, err := s.ListSpecs(ctx)
	if err != nil {
		return nil, err
	}

	var refs []string
	for _, src := range sources {
		if src.Config[credential.ConfigSecretSpec] == specName {
			refs = append(refs, "source/"+src.Name)
		}
	}
	for _, spec := range specs {
		if spec.Name == specName {
			continue // a spec never references itself
		}
		if spec.Config[credential.ConfigSecretSpec] == specName {
			refs = append(refs, "spec/"+spec.Name)
		}
	}

	return refs, nil
}

// validateSecretSpecRef validates a credential-chaining reference: the named
// secret-spec must exist, must not itself chain (one hop only), and must be minted
// as the caller (subject_token_source set) so it federates per request rather than
// degrading to the non-exchange path and failing late with an opaque backend error.
//
// It deliberately does NOT assert the referenced spec is leaseless here: that would
// need per-type mint-method introspection this layer lacks, and the authoritative
// guard is at mint time — issueChained revokes and fails closed if a referenced spec
// ever returns a lease (including after a config-drift edit this check couldn't see).
func (s *CredentialConfigStore) validateSecretSpecRef(ctx context.Context, ref string) error {
	refSpec, err := s.GetSpec(ctx, ref)
	if err != nil {
		if errors.Is(err, ErrSpecNotFound) {
			return logical.ErrBadRequestf("secret_spec %q not found (create the secret-yielding spec first)", ref)
		}
		return fmt.Errorf("failed to validate secret_spec %q: %w", ref, err)
	}

	if refSpec.Config[credential.ConfigSecretSpec] != "" {
		return logical.ErrBadRequestf("secret_spec %q must not itself set secret_spec (chaining is limited to one hop)", ref)
	}
	refSource, err := s.GetSource(ctx, refSpec.Source)
	if err != nil {
		return fmt.Errorf("secret_spec %q: failed to load its source %q: %w", ref, refSpec.Source, err)
	}
	if refSource.Config[credential.ConfigSecretSpec] != "" {
		return logical.ErrBadRequestf("secret_spec %q's source must not set secret_spec (chaining is limited to one hop)", ref)
	}

	// The referenced secret-spec must be minted as the requesting caller with a
	// SESSION-PINNED subject: warden_identity (Warden mints an assertion for the
	// session's principal) or agent_identity (the caller's own inbound JWT). A
	// user_identity subject is a per-request, per-user token that is NOT tied to the
	// session token — and a chained consumer's outer cache key carries no exchange
	// fingerprint (the exchange happens on this referenced spec, not the consumer),
	// so under a shared session token two principals would collide on that key and
	// one could be served the other's chained credential. Reject anything else
	// (including an unset/"none" subject, which would otherwise degrade to the
	// non-exchange path and fail late with an opaque backend error).
	switch refSpec.Config[credential.ConfigSubjectTokenSource] {
	case credential.SourceWardenIdentity, credential.SourceAgentIdentity:
		// session-pinned — safe
	default:
		return logical.ErrBadRequestf("secret_spec %q must set subject_token_source=%s or %s (got %q); a chained secret must be minted as the session-pinned caller",
			ref, credential.SourceWardenIdentity, credential.SourceAgentIdentity, refSpec.Config[credential.ConfigSubjectTokenSource])
	}

	return nil
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
	// Create global Manager with CredentialConfigStore as ConfigStoreAccessor
	// Note: Credentials are cache-only (not persisted) - ExpirationEntry handles lease revocation
	manager, err := credential.NewManager(
		c.credentialTypeRegistry,
		c.credentialDriverRegistry,
		c.credConfigStore, // Implements ConfigStoreAccessor interface
		c.logger.WithSystem("credential.manager"),
	)
	if err != nil {
		return fmt.Errorf("failed to create credential manager: %w", err)
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

// Note: Background cleanup is now handled by the ExpirationManager

// SetRotationManager sets the rotation manager for the credential config store.
// This is called during unseal after both the rotation manager and config store are initialized.
func (s *CredentialConfigStore) SetRotationManager(rm *RotationManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotationManager = rm
}
