package credential

import (
	"context"
	"fmt"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
	"golang.org/x/sync/singleflight"
)

// DefaultIssuanceTimeout is the default timeout for credential issuance operations
const DefaultIssuanceTimeout = 30 * time.Second

// Manager manages credential issuance with caching and type safety for all namespaces
// The manager is global and handles credentials across all namespaces using namespace-aware cache keys
type Manager struct {
	log            *logger.GatedLogger
	cache          *ristretto.Cache[string, *Credential] // key: {namespace-uuid}:{tokenID} -> value: Credential
	typeRegistry   *TypeRegistry
	driverRegistry *DriverRegistry
	group          singleflight.Group

	// Configuration store accessor (provides specs and sources)
	configStore ConfigStoreAccessor

	// Optional expiration registrar for timer-based TTL enforcement
	// When set, newly issued credentials are registered for expiration
	expirationRegistrar ExpirationRegistrar

	// IssuanceTimeout is the maximum time allowed for credential issuance
	// If not set, defaults to DefaultIssuanceTimeout (30 seconds)
	issuanceTimeout time.Duration
}

// ConfigStoreAccessor defines the interface for accessing credential configuration
// This allows the Manager to retrieve specs and sources from the CredentialConfigStore
type ConfigStoreAccessor interface {
	GetSpec(ctx context.Context, name string) (*CredSpec, error)
	GetSource(ctx context.Context, name string) (*CredSource, error)
}

// ExpirationRegistrar defines the interface for registering credentials with an expiration manager.
// This abstraction allows the credential package to register credentials for expiration
// without creating a circular dependency on the core package.
type ExpirationRegistrar interface {
	// RegisterCredential registers a credential for timer-based expiration.
	// Called only when a new credential is issued (not on cache hits).
	// Parameters:
	//   - ctx: Context with namespace information
	//   - credentialID: Unique identifier for this credential instance (UUID)
	//   - cacheKey: Cache key for cache lookup/deletion ({namespace}:{tokenID})
	//   - ttl: Time-to-live for the credential
	//   - leaseID: Lease ID for revocation at source (separate from credentialID)
	//   - sourceName, sourceType, specName: Metadata for revocation
	//   - revocable: Whether the credential can be revoked at source
	RegisterCredential(ctx context.Context, credentialID, cacheKey string, ttl time.Duration, leaseID, sourceName, sourceType, specName string, revocable bool) error
}

// NewManager creates a new global credential manager
func NewManager(
	typeRegistry *TypeRegistry,
	driverRegistry *DriverRegistry,
	configStore ConfigStoreAccessor,
	logger *logger.GatedLogger,
) (*Manager, error) {
	m := &Manager{
		log:             logger,
		typeRegistry:    typeRegistry,
		driverRegistry:  driverRegistry,
		configStore:     configStore,
		issuanceTimeout: DefaultIssuanceTimeout,
	}

	// Create Ristretto cache
	cache, err := ristretto.NewCache(&ristretto.Config[string, *Credential]{
		NumCounters: 5_000_000,
		MaxCost:     50 << 20, // 50 MB
		BufferItems: 64,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	m.cache = cache

	return m, nil
}

// IssueCredential issues a credential for the given spec, token, and TTL.
// Credentials are cached in memory but not persisted to storage.
// On cache miss, a new credential is issued from the source.
//
// Parameters:
//   - ctx: Context with namespace information
//   - tokenID: The session token ID to bind the credential to
//   - specName: The name of the credential spec to use
//   - tokenTTL: The TTL of the session token (used for cache duration)
//
// Returns the issued credential or an error
func (m *Manager) IssueCredential(ctx context.Context, tokenID string, specName string, tokenTTL time.Duration) (*Credential, error) {
	// Apply issuance timeout to prevent slow drivers from blocking indefinitely
	ctx, cancel := context.WithTimeout(ctx, m.issuanceTimeout)
	defer cancel()

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace from context: %w", err)
	}

	// Build namespace-aware cache key: {namespace-uuid}:{tokenID}
	cacheKey := fmt.Sprintf("%s:%s", ns.ID, tokenID)

	// Check cache first
	if cred, found := m.cache.Get(cacheKey); found {
		return cred, nil
	}

	// Use singleflight to ensure only one creation per cacheKey
	v, err, _ := m.group.Do(cacheKey, func() (interface{}, error) {
		// Double-check cache in case another goroutine just added it
		if cred, found := m.cache.Get(cacheKey); found {
			return cred, nil
		}

		// Issue new credential from source
		cred, err := m.issueCredential(ctx, specName)
		if err != nil {
			return nil, err
		}

		// Generate unique credential ID (UUID) for this credential instance
		cred.CredentialID = uuid.New().String()

		// Bind credential to token and spec
		cred.TokenID = tokenID
		cred.SpecName = specName

		m.cache.Set(cacheKey, cred, 1)

		// Wait for value to be processed (Ristretto is async)
		m.cache.Wait()

		// Register with expiration manager for timer-based TTL enforcement
		// This is done INSIDE singleflight, so it only happens when a NEW credential is issued
		if m.expirationRegistrar != nil && cred.Revocable {
			if regErr := m.expirationRegistrar.RegisterCredential(
				ctx,               // Context with namespace
				cred.CredentialID, // Unique ID for this credential instance (UUID)
				cacheKey,          // Cache key for cache lookup/deletion
				tokenTTL,
				cred.LeaseID,
				cred.SourceName,
				cred.SourceType,
				cred.SpecName,
				cred.Revocable,
			); regErr != nil {
				m.log.Warn("failed to register credential with expiration manager",
					logger.String("credential_id", cred.CredentialID),
					logger.String("cache_key", cacheKey),
					logger.Err(regErr))
				// Don't fail - credential is still valid, just relies on cache eviction
			}
		}

		return cred, nil
	})

	if err != nil {
		// Don't cache errors - allow next request to retry
		m.group.Forget(cacheKey)
		return nil, err
	}

	return v.(*Credential), nil
}

// issueCredential performs the actual credential issuance from the source
func (m *Manager) issueCredential(ctx context.Context, specName string) (*Credential, error) {
	// Step 1: Lookup credential spec from config store
	spec, err := m.configStore.GetSpec(ctx, specName)
	if err != nil {
		return nil, fmt.Errorf("credential spec '%s' not found: %w", specName, err)
	}

	// Step 2: Get or create source driver
	driver, err := m.GetOrCreateDriver(ctx, spec.Source)
	if err != nil {
		return nil, err
	}

	// Step 3: Mint raw credential data using the driver
	rawData, leaseTTL, leaseID, err := driver.MintCredential(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential: %w", err)
	}

	// Step 4: Get credential type handler
	credType, err := m.typeRegistry.GetByName(spec.Type)
	if err != nil {
		return nil, fmt.Errorf("credential type '%s' not found: %w", spec.Type, err)
	}

	// Step 5: Parse raw data into structured credential
	cred, err := credType.Parse(rawData, leaseTTL, leaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Step 6: Set source information
	cred.SourceName = spec.Source
	cred.SourceType = driver.Type()

	// Step 7: Validate credential
	if err := credType.Validate(cred); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	return cred, nil
}

// SetExpirationRegistrar sets the expiration registrar for timer-based TTL enforcement.
// This is called after manager creation since the expiration manager may be created later.
func (m *Manager) SetExpirationRegistrar(registrar ExpirationRegistrar) {
	m.expirationRegistrar = registrar
}

// SetIssuanceTimeout sets the maximum time allowed for credential issuance.
// If timeout is <= 0, it resets to DefaultIssuanceTimeout.
func (m *Manager) SetIssuanceTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = DefaultIssuanceTimeout
	}
	m.issuanceTimeout = timeout
}

// Stop gracefully shuts down the manager
func (m *Manager) Stop() {
	m.cache.Close()
	m.log.Trace("credential manager cache closed")
}

// RevokeByExpiration revokes a credential by its expiration entry data.
// This is called by the expiration manager when a credential expires.
// It handles both the source revocation (if revocable) and cache cleanup.
//
// Parameters:
//   - credentialID: Unique identifier for the credential instance (UUID)
//   - cacheKey: Cache key for cache lookup/deletion
//   - leaseID: Lease ID for revocation at source
//   - sourceName: Name of the credential source for driver lookup
//   - revocable: Whether the credential can be revoked at source
func (m *Manager) RevokeByExpiration(ctx context.Context, credentialID, cacheKey, leaseID, sourceName string, revocable bool) error {

	// Step 1: Delete from cache first to prevent serving a revoked credential
	// Only delete if this credential is still the active one
	// A newer credential with a different CredentialID may have replaced it
	cached, found := m.cache.Get(cacheKey)
	switch {
	case !found:
		// Already evicted by TTL or not cached - nothing to do
	case cached.CredentialID != credentialID:
		// A newer credential replaced it - don't touch cache
		m.log.Trace("skipping cache delete - newer credential in cache",
			logger.String("expiring_credential_id", credentialID),
			logger.String("cached_credential_id", cached.CredentialID))
	default:
		// This is still the active credential - delete it
		m.cache.Del(cacheKey)
	}

	// Step 2: Revoke the lease at the source if revocable
	if err := m.revokeLeaseAtSource(ctx, revocable, leaseID, sourceName); err != nil {
		return err
	}

	m.log.Debug("credential expired",
		logger.String("credential_id", credentialID),
		logger.String("lease_id", leaseID))

	return nil
}

// revokeLeaseAtSource attempts to revoke a lease at the source if applicable.
// Returns an error only if revocation fails and should be retried.
func (m *Manager) revokeLeaseAtSource(ctx context.Context, revocable bool, leaseID, sourceName string) error {
	if !revocable || leaseID == "" || sourceName == "" {
		return nil
	}

	// Get or create driver - it may not exist after server restart
	driver, err := m.GetOrCreateDriver(ctx, sourceName)
	if err != nil {
		m.log.Warn("failed to get driver for credential revocation",
			logger.String("source_name", sourceName),
			logger.Err(err))
		return err // Return error to trigger retry
	}

	if err := driver.Revoke(ctx, leaseID); err != nil {
		m.log.Warn("failed to revoke credential lease",
			logger.String("lease_id", leaseID),
			logger.Err(err))
		return err // Return error to trigger retry
	}

	return nil
}

// SpecExists checks if a credential spec exists and is valid.
// Returns true if the spec exists and can be retrieved without error.
func (m *Manager) SpecExists(ctx context.Context, specName string) bool {
	if m.configStore == nil {
		return false
	}
	spec, err := m.configStore.GetSpec(ctx, specName)
	return err == nil && spec != nil
}

// GetOrCreateDriver retrieves an existing driver or creates one if it doesn't exist.
// This is needed during revocation after server restart when drivers aren't cached yet.
func (m *Manager) GetOrCreateDriver(ctx context.Context, sourceName string) (SourceDriver, error) {
	// First try to get existing driver
	if driver, ok := m.driverRegistry.GetDriver(ctx, sourceName); ok {
		return driver, nil
	}

	// Driver doesn't exist, fetch source config and create it
	credSource, err := m.configStore.GetSource(ctx, sourceName)
	if err != nil {
		return nil, fmt.Errorf("source '%s' not found: %w", sourceName, err)
	}

	driver, created, err := m.driverRegistry.CreateDriver(ctx, sourceName, credSource)
	if err != nil {
		return nil, fmt.Errorf("failed to create driver for source '%s': %w", sourceName, err)
	}

	// Only log when a new driver was actually created (not when returning existing)
	if created {
		ns, _ := namespace.FromContext(ctx)
		m.log.Debug("credential source driver created",
			logger.String("namespace", ns.ID),
			logger.String("source_name", sourceName),
			logger.String("source_type", credSource.Type))
	}

	return driver, nil
}
