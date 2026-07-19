package credential

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"golang.org/x/sync/singleflight"
)

// DefaultIssuanceTimeout is the default timeout for credential issuance operations
const DefaultIssuanceTimeout = 30 * time.Second

// Manager manages credential issuance with caching and type safety for all namespaces.
// It is the central coordinator between the credential subsystems: when a gateway request
// needs credentials, the core calls IssueCredential which orchestrates the full pipeline:
//
//  1. Look up the CredSpec (via SpecResolver) to determine type, source, and parameters
//  2. Resolve or lazily create the SourceDriver (via DriverCoordinator) for the referenced CredSource
//  3. Call driver.MintCredential to obtain raw credential data from the external backend
//  4. Parse and validate the raw data (via CredentialParser) through the registered credential Type handler
//  5. Cache the result keyed by {namespace-uuid}:{tokenID} using Ristretto
//  6. Optionally register the credential with an ExpirationRegistrar for timer-based revocation
//
// The manager is global (one per Warden process) and uses namespace-aware cache keys so
// credentials from different namespaces never collide. Concurrent requests for the same
// cache key are coalesced via singleflight to avoid redundant minting calls.
//
// Architecture: The Manager delegates to focused components for better testability:
//   - SpecResolver: Handles spec lookup from config store
//   - DriverCoordinator: Handles driver lifecycle (get/create/close)
//   - MintingService: Handles credential minting with automatic cleanup
//   - CredentialParser: Handles credential parsing and validation
type Manager struct {
	log   *logger.GatedLogger
	cache *ristretto.Cache[string, *Credential] // key: {namespace-uuid}:{tokenID} -> value: Credential
	group singleflight.Group

	// Focused components (extracted from Manager for better testability)
	specResolver      *SpecResolver
	driverCoordinator *DriverCoordinator
	mintingService    *MintingService
	credentialParser  *CredentialParser

	// configStore persists rotated refresh tokens back into the spec config.
	configStore ConfigStoreAccessor

	// specLocks serializes spec-config mutations (refresh-token write-back and
	// the /connect seal) per namespace+spec. Key: "{ns.UUID}:{specName}".
	specLocks sync.Map

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
	// PersistRotatedSpec persists a spec without re-running verification, used by
	// the refresh-token write-back (re-minting would consume the rotated token).
	PersistRotatedSpec(ctx context.Context, spec *CredSpec) error
	// ReloadSpec returns the spec read from storage, bypassing the node-local
	// cache, so a refresh token another node rotated and persisted is seen.
	ReloadSpec(ctx context.Context, name string) (*CredSpec, error)
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
	// Create focused components for better testability
	specResolver := NewSpecResolver(configStore, logger.WithSubsystem("spec-resolver"))
	driverCoordinator := NewDriverCoordinator(driverRegistry, configStore, logger.WithSubsystem("driver-coordinator"))
	mintingService := NewMintingService(logger.WithSubsystem("minting-service"))
	credentialParser := NewCredentialParser(typeRegistry, logger.WithSubsystem("credential-parser"))

	m := &Manager{
		log:               logger,
		specResolver:      specResolver,
		driverCoordinator: driverCoordinator,
		mintingService:    mintingService,
		credentialParser:  credentialParser,
		configStore:       configStore,
		issuanceTimeout:   DefaultIssuanceTimeout,
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
//   - inputs: Optional caller-derived token-exchange inputs. When non-nil they
//     are folded into the cache key so distinct exchange inputs cannot share a
//     cached credential.
//
// Returns the issued credential or an error
func (m *Manager) IssueCredential(ctx context.Context, tokenID string, specName string, tokenTTL time.Duration, inputs *ExchangeInputs) (*Credential, error) {
	// Apply issuance timeout to prevent slow drivers from blocking indefinitely
	ctx, cancel := context.WithTimeout(ctx, m.issuanceTimeout)
	defer cancel()

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace from context: %w", err)
	}

	// Build namespace-aware cache key: {namespace-uuid}:{tokenID}:{specName}
	// Including specName allows access backends to mint different specs for the same token.
	cacheKey := fmt.Sprintf("%s:%s:%s", ns.ID, tokenID, specName)

	// When the request carries token-exchange inputs, fold their fingerprint into
	// the key so two callers sharing one session token (e.g. an opaque service
	// token) each supplying a different subject token get distinct cached
	// credentials instead of leaking one caller's credential to the other. The
	// non-exchange path (inputs == nil) keeps the key byte-identical.
	if inputs != nil {
		cacheKey += ":x:" + inputs.Fingerprint()
	}

	// Check cache first. A cached credential that has outlived its lease is
	// treated as a miss and re-minted: the cache carries no read-time expiry of
	// its own, and non-revocable credentials (e.g. exchanged bearer tokens) are
	// not tracked by the expiration manager, so IsExpired is the guard that keeps
	// a stale token from being served past its lifetime.
	if cred, found := m.cache.Get(cacheKey); found && !cred.IsExpired() {
		return cred, nil
	}

	// Use singleflight to ensure only one creation per cacheKey
	v, err, _ := m.group.Do(cacheKey, func() (interface{}, error) {
		// Double-check cache in case another goroutine just added it
		if cred, found := m.cache.Get(cacheKey); found && !cred.IsExpired() {
			return cred, nil
		}

		// Issue new credential from source
		cred, err := m.issueCredential(ctx, specName, inputs)
		if err != nil {
			return nil, err
		}

		// Generate unique credential ID (UUID) for this credential instance
		cred.CredentialID = uuid.New().String()

		// Bind credential to token and spec
		cred.TokenID = tokenID
		cred.SpecName = specName

		// Cache the credential. Bound a dynamic credential's entry by its remaining
		// lifetime (capped by the session TTL) so an expired token is actively
		// evicted rather than lingering; the IsExpired guard on the read path is the
		// correctness backstop, this keeps memory from accumulating stale entries.
		if cred.LeaseTTL > 0 {
			ttl := cred.LeaseTTL
			if tokenTTL > 0 && tokenTTL < ttl {
				ttl = tokenTTL
			}
			m.cache.SetWithTTL(cacheKey, cred, 1, ttl)
		} else {
			m.cache.Set(cacheKey, cred, 1)
		}

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
func (m *Manager) issueCredential(ctx context.Context, specName string, inputs *ExchangeInputs) (*Credential, error) {
	// Step 1: Resolve credential spec using SpecResolver
	spec, err := m.specResolver.ResolveSpec(ctx, specName)
	if err != nil {
		return nil, err
	}

	// Step 2: Get or create source driver using DriverCoordinator
	driver, err := m.driverCoordinator.GetOrCreateDriver(ctx, spec.Source)
	if err != nil {
		return nil, err
	}

	// A spec with a sealed refresh token (OAuth2 authorization_code) mints by
	// exchanging that single-use token: serialize per spec, persist a rotated
	// token, and retry once if the provider rejects it. Other specs use the
	// simple mint path unchanged.
	if needsRefreshTokenWriteBack(spec) {
		return m.issueWithWriteBack(ctx, specName, driver, inputs)
	}

	return m.mintAndParse(ctx, spec, driver, inputs)
}

// mintAndParse mints a credential and parses it, with orphaned-lease cleanup on
// failure. This is the simple path for specs that do not rotate a refresh token.
func (m *Manager) mintAndParse(ctx context.Context, spec *CredSpec, driver SourceDriver, inputs *ExchangeInputs) (*Credential, error) {
	var cred *Credential
	err := m.mintingService.MintWithCleanup(ctx, driver, spec, inputs, func(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) error {
		var parseErr error
		cred, parseErr = m.credentialParser.ParseAndValidate(ctx, spec, rawData, metadata, leaseTTL, leaseID, driver)
		return parseErr
	})
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// issueWithWriteBack mints a refresh-token-backed credential under the per-spec
// lock. It persists a rotated refresh token surfaced by the driver, and on a
// rejection (the sealed token was already used — typically a rotation on
// another node) it reloads the spec straight from storage, bypassing this
// node's cache, and retries exactly once.
func (m *Manager) issueWithWriteBack(ctx context.Context, specName string, driver SourceDriver, inputs *ExchangeInputs) (*Credential, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace from context: %w", err)
	}
	unlock, err := m.LockSpec(ctx, ns.UUID, specName)
	if err != nil {
		return nil, err
	}
	defer unlock()

	var cred *Credential
	// reload bypasses the node-local spec cache so a token another node rotated
	// and persisted to shared storage is actually seen on the retry.
	attempt := func(reload bool) error {
		var spec *CredSpec
		if reload {
			spec, err = m.configStore.ReloadSpec(ctx, specName)
		} else {
			spec, err = m.specResolver.ResolveSpec(ctx, specName)
		}
		if err != nil {
			return err
		}
		cred = nil
		return m.mintingService.MintWithCleanup(ctx, driver, spec, inputs, func(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) error {
			m.consumeRotatedRefreshToken(ctx, spec, rawData)
			var parseErr error
			cred, parseErr = m.credentialParser.ParseAndValidate(ctx, spec, rawData, metadata, leaseTTL, leaseID, driver)
			return parseErr
		})
	}

	err = attempt(false)
	if err != nil && errors.Is(err, ErrRefreshTokenRejected) {
		// The token was rejected as already-used. Reload from storage (another
		// node may have rotated+persisted a fresh token this node hasn't cached)
		// and retry exactly once.
		m.log.Info("oauth2 refresh token rejected; reloading spec from storage and retrying once",
			logger.String("spec", specName))
		err = attempt(true)
	}
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// consumeRotatedRefreshToken strips the reserved rotated-token keys from rawData
// (so they never reach the credential Data map) and persists the new refresh
// token — and its refreshed expiry, when the provider surfaced one — into the
// spec config. Must run before ParseAndValidate.
//
// A persist failure does not fail this issuance — the access token just minted
// is valid and is returned. But it is logged at error level because the old
// refresh token is now dead at the provider: on this node the rotated token is
// lost and future mints will fail with invalid_grant until the spec is
// reconnected (or another node's copy is reloaded from storage).
func (m *Manager) consumeRotatedRefreshToken(ctx context.Context, spec *CredSpec, rawData map[string]interface{}) {
	rotated, ok := rawData[RawRotatedRefreshTokenKey]
	if !ok {
		return
	}
	delete(rawData, RawRotatedRefreshTokenKey)
	// The rotated expiry travels under its own reserved key; strip it unconditionally
	// so it never lands in the credential Data, and apply it below if present.
	rotatedExpiry, hasExpiry := rawData[RawRotatedRefreshTokenExpiresAtKey]
	delete(rawData, RawRotatedRefreshTokenExpiresAtKey)
	newToken, isString := rotated.(string)
	if !isString || newToken == "" {
		// The only producer sets a non-empty string; a different shape means a
		// rotated token would be silently dropped, so make it visible.
		m.log.Warn("ignoring rotated refresh token with unexpected value",
			logger.String("spec", spec.Name))
		return
	}
	// Copy the spec (GetSpec returns a shared cached pointer) before mutating.
	updated := &CredSpec{
		Name:           spec.Name,
		Type:           spec.Type,
		Source:         spec.Source,
		MinTTL:         spec.MinTTL,
		MaxTTL:         spec.MaxTTL,
		RotationPeriod: spec.RotationPeriod,
		Config:         make(map[string]string, len(spec.Config)),
	}
	for k, v := range spec.Config {
		updated.Config[k] = v
	}
	updated.Config["refresh_token"] = newToken
	// Keep refresh_token_expires_at in step with the rotated token when the provider
	// returned a fresh expiry. If it rotated the token without one, leave the prior
	// value untouched rather than assert an expiry we no longer know.
	if exp, isStr := rotatedExpiry.(string); hasExpiry && isStr && exp != "" {
		updated.Config["refresh_token_expires_at"] = exp
	}
	if err := m.configStore.PersistRotatedSpec(ctx, updated); err != nil {
		m.log.Error("failed to persist rotated refresh token; spec must be reconnected if mints start failing",
			logger.String("spec", spec.Name), logger.Err(err))
	}
}

// needsRefreshTokenWriteBack reports whether a spec mints by exchanging a sealed
// refresh token. The rotated-token reserved key can only appear for such specs.
// Gating on the sealed token is robust to where auth_method is set; a spec that
// retains a stale refresh_token after switching to client_credentials takes this
// path harmlessly (the write-back is a no-op since no reserved key is surfaced).
func needsRefreshTokenWriteBack(spec *CredSpec) bool {
	return spec.Config["refresh_token"] != ""
}

// LockSpec serializes spec-config mutations (refresh-token write-back and the
// /connect seal) for one namespace+spec. It is context-aware: a waiter whose
// context is cancelled or times out returns an error rather than blocking past
// its deadline. The key MUST use ns.UUID to match the persistence layer's spec
// keying.
//
// Note: the lock map is not pruned on spec/namespace deletion. Each tiny entry
// (a key string + a buffered channel) persists for the process lifetime; safe
// pruning would require reference counting and is deferred.
func (m *Manager) LockSpec(ctx context.Context, nsUUID, specName string) (unlock func(), err error) {
	key := nsUUID + ":" + specName
	v, _ := m.specLocks.LoadOrStore(key, make(chan struct{}, 1))
	ch := v.(chan struct{})
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
	// Delegate to DriverCoordinator for lifecycle management
	driver, err := m.driverCoordinator.GetOrCreateDriver(ctx, sourceName)
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
	return m.specResolver.SpecExists(ctx, specName)
}

// GetOrCreateDriver retrieves an existing driver or creates one if it doesn't exist.
// This is needed during revocation after server restart when drivers aren't cached yet.
// Delegates to DriverCoordinator for lifecycle management.
func (m *Manager) GetOrCreateDriver(ctx context.Context, sourceName string) (SourceDriver, error) {
	return m.driverCoordinator.GetOrCreateDriver(ctx, sourceName)
}

// CloseDriver closes and removes a driver instance by source name.
// This should be called when a source is deleted or updated to prevent resource leaks.
// Delegates to DriverCoordinator for lifecycle management.
func (m *Manager) CloseDriver(ctx context.Context, sourceName string) error {
	return m.driverCoordinator.CloseDriver(ctx, sourceName)
}

// CloseAllDriversForNamespace closes and removes all driver instances for a given namespace.
// This should be called when a namespace is deleted to prevent resource leaks.
// Delegates to DriverCoordinator for lifecycle management.
func (m *Manager) CloseAllDriversForNamespace(ctx context.Context) (int, error) {
	return m.driverCoordinator.CloseAllForNamespace(ctx)
}
