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

	// typeRegistry is retained for credential-chaining field discovery: resolving a
	// referenced credential's primary field (PrimaryFieldProvider) when no explicit
	// secret_field is set and its payload has more than one key.
	typeRegistry *TypeRegistry

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
		typeRegistry:      typeRegistry,
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

// IssueCredential issues a credential for the given spec on behalf of a caller.
// Credentials are cached in memory but not persisted to storage.
// On cache miss, a new credential is issued from the source.
//
// Parameters:
//   - ctx: Context with namespace information
//   - caller: The requesting principal — its TokenID binds and caches the
//     credential, its TokenTTL bounds the cache duration, and its ResolveInputs is
//     used by credential chaining to mint a referenced secret-spec as this caller.
//   - specName: The name of the credential spec to use
//   - inputs: Optional caller-derived token-exchange inputs. When non-nil they
//     are folded into the cache key so distinct exchange inputs cannot share a
//     cached credential. When inputs.ResolveSubjectToken and/or
//     inputs.ResolveActorToken is set, that token is materialized only on a cache
//     miss (inside the singleflight), so a cache hit incurs no mint cost; the two
//     resolve independently (an eager user_identity subject can pair with a lazy actor).
//
// Returns the issued credential or an error
func (m *Manager) IssueCredential(ctx context.Context, caller Caller, specName string, inputs *ExchangeInputs) (*Credential, error) {
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
	cacheKey := fmt.Sprintf("%s:%s:%s", ns.ID, caller.TokenID, specName)

	// When the request carries token-exchange inputs, fold their fingerprint into
	// the key so two callers sharing one session token (e.g. an opaque service
	// token) each supplying a different subject token get distinct cached
	// credentials instead of leaking one caller's credential to the other. The
	// non-exchange path (inputs == nil) keeps the key byte-identical.
	if inputs != nil {
		cacheKey += ":x:" + inputs.Fingerprint()
	}

	// Scope the entry to the secondary (user) principal when present, mirroring the
	// outer key's use of the AGENT's token id (caller.TokenID): both principals are
	// keyed by token id, not identity, so the entry is bound to the token lifecycle
	// — revoking or re-logging-in the user yields a new token id and thus a fresh
	// mint. This dimension is independent of the exchange fingerprint, so a chained
	// consumer (whose outer key carries no ":x:" fragment) still gets per-user
	// isolation. Byte-identical when caller.User == nil.
	if caller.User != nil {
		cacheKey += ":u:" + caller.User.TokenID
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

		// Materialize a lazily-resolved subject token (e.g. a Warden-minted
		// identity assertion) only now — after both cache checks have confirmed a
		// real miss — so cache hits never pay for the mint. singleflight coalesces
		// concurrent requests for this cacheKey, so a burst of N simultaneous
		// misses runs this once and the other N-1 share the resulting credential;
		// each request has its own inputs, so mutating SubjectToken here is race-free.
		if inputs != nil && inputs.ResolveSubjectToken != nil && inputs.SubjectToken == "" {
			tok, rerr := inputs.ResolveSubjectToken(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("failed to resolve subject token: %w", rerr)
			}
			inputs.SubjectToken = tok
		}

		// Materialize a lazily-resolved actor token the same way and for the same
		// reason as the subject above. It is a separate block because the two slots
		// are independent: a spec can pair an eager user_identity subject with a lazy
		// warden_identity actor, so the actor may need minting even when the subject
		// did not. The Fingerprint keyed this entry via ActorCacheIdentity, so the
		// (not-yet-minted) actor bytes never entered the cache key.
		if inputs != nil && inputs.ResolveActorToken != nil && inputs.ActorToken == "" {
			tok, rerr := inputs.ResolveActorToken(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("failed to resolve actor token: %w", rerr)
			}
			inputs.ActorToken = tok
		}

		// Issue a new credential
		cred, err := m.issueCredential(ctx, caller, specName, inputs)
		if err != nil {
			return nil, err
		}

		// Generate unique credential ID (UUID) for this credential instance
		cred.CredentialID = uuid.New().String()

		// Bind credential to token and spec
		cred.TokenID = caller.TokenID
		cred.SpecName = specName

		// sessionTTL bounds the cached credential's lifetime by the requesting
		// principals' token lifetimes: the agent (caller.TokenTTL) always caps it,
		// and for per-user chaining the user (caller.User.TokenTTL) caps it too, so a
		// cached credential is never served past EITHER principal's expiry. (A
		// principal revoked mid-session drives no new mint regardless — the request
		// presenting it fails auth before the cache is consulted.) Zero means "no
		// session bound" (internal/non-request callers).
		sessionTTL := caller.TokenTTL
		if caller.User != nil && caller.User.TokenTTL > 0 && (sessionTTL <= 0 || caller.User.TokenTTL < sessionTTL) {
			sessionTTL = caller.User.TokenTTL
		}

		// Cache the credential. Bound a dynamic credential's entry by its remaining
		// lifetime (capped by the session TTL) so an expired token is actively
		// evicted rather than lingering; the IsExpired guard on the read path is the
		// correctness backstop, this keeps memory from accumulating stale entries.
		if cred.LeaseTTL > 0 {
			ttl := cred.LeaseTTL
			if sessionTTL > 0 && sessionTTL < ttl {
				ttl = sessionTTL
			}
			m.cache.SetWithTTL(cacheKey, cred, 1, ttl)
		} else if sessionTTL > 0 {
			// A static credential (no lease) is still bound to this session: cap its
			// entry by the session TTL so it self-evicts at session end rather than
			// lingering until cache pressure. This also bounds a chained static
			// credential's staleness — a rotated upstream secret is re-fetched at most
			// one session later. Falls back to an untimed set only when no session TTL
			// is known (internal/non-request callers).
			m.cache.SetWithTTL(cacheKey, cred, 1, sessionTTL)
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
				sessionTTL,
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

// issueCredential performs the actual credential issuance from the source. It runs
// on a real cache miss (or, for a chained secret-spec, on the non-caching path so
// the fetched secret is never cached).
func (m *Manager) issueCredential(ctx context.Context, caller Caller, specName string, inputs *ExchangeInputs) (*Credential, error) {
	// Step 1: Resolve credential spec using SpecResolver
	spec, err := m.specResolver.ResolveSpec(ctx, specName)
	if err != nil {
		return nil, err
	}

	// Credential chaining: when the spec (or its source) references another cred
	// spec as its secret source, mint that referenced spec as the same caller and
	// mint this credential from the fetched material. Spec-level reference wins.
	secretRef, err := m.secretSpecRef(ctx, spec)
	if err != nil {
		return nil, err
	}
	if secretRef != "" {
		return m.issueChained(ctx, caller, spec, secretRef)
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

// secretSpecRef returns the referenced secret-spec name for credential chaining:
// spec-level (ConfigSecretSpec on the spec) wins over source-level (on the source).
// Returns "" when the spec is not chained. A source-read failure is returned rather
// than swallowed, so a transient error can't silently route a chained spec down the
// direct (non-chained) mint path.
func (m *Manager) secretSpecRef(ctx context.Context, spec *CredSpec) (string, error) {
	if ref := spec.Config[ConfigSecretSpec]; ref != "" {
		return ref, nil
	}
	src, err := m.configStore.GetSource(ctx, spec.Source)
	if err != nil {
		return "", fmt.Errorf("failed to resolve source %q for credential chaining: %w", spec.Source, err)
	}
	return src.Config[ConfigSecretSpec], nil
}

// issueChained mints a consuming credential whose secret comes from a referenced
// cred spec. It mints the referenced spec AS the caller (fresh assertion), extracts
// the secret material, and hands it to the consuming driver. The fetched secret is
// never cached: it is minted via the non-caching internal path and discarded after
// material extraction.
func (m *Manager) issueChained(ctx context.Context, caller Caller, spec *CredSpec, secretRef string) (*Credential, error) {
	// Bound the chain to a single hop (a referenced secret-spec may not itself
	// chain). This also breaks any config-drift reference cycle rather than letting
	// it recurse unboundedly.
	depth := chainDepth(ctx)
	if depth+1 > MaxSecretChainDepth {
		return nil, fmt.Errorf("credential chaining for spec %q exceeds max depth %d (referenced secret_spec %q)", spec.Name, MaxSecretChainDepth, secretRef)
	}
	ctx = withChainDepth(ctx, depth+1)

	// Build exchange inputs for the referenced secret-spec, as the caller.
	if caller.ResolveInputs == nil {
		return nil, fmt.Errorf("credential chaining for spec %q requires a request caller context", spec.Name)
	}
	inputsB, err := caller.ResolveInputs(ctx, secretRef)
	if err != nil {
		return nil, fmt.Errorf("secret_spec %q: %w", secretRef, err)
	}

	// Fetch the referenced secret credential (minted as the caller, never cached).
	credB, err := m.fetchChainedSecret(ctx, caller, secretRef, inputsB)
	if err != nil {
		return nil, err
	}

	// Extract the secret material and mint the consuming credential from it.
	field := m.resolveSecretField(ctx, spec, credB)
	material := SecretMaterial{Data: credB.Data, Field: field}

	driver, err := m.driverCoordinator.GetOrCreateDriver(ctx, spec.Source)
	if err != nil {
		return nil, err
	}
	return m.mintFromSecret(ctx, spec, driver, material)
}

// fetchChainedSecret mints the referenced secret-spec AS the caller and returns its
// credential. The caller owns the one-hop depth guard and building inputsB (via
// caller.ResolveInputs); this function materializes any lazily-minted subject/actor
// tokens, mints via the non-caching internal path (so the fetched secret is never
// cached), and enforces that the referenced credential is static/leaseless.
func (m *Manager) fetchChainedSecret(ctx context.Context, caller Caller, secretRef string, inputsB *ExchangeInputs) (*Credential, error) {
	// Materialize any lazily-minted subject/actor tokens here: the referenced spec is
	// minted via the non-caching internal path, which — unlike the caching wrapper —
	// does not run ResolveSubjectToken/ResolveActorToken, so a warden_identity subject
	// or actor would otherwise be forwarded empty (the driver would fail closed on the
	// subject; a delegation actor would be silently dropped).
	if inputsB != nil && inputsB.ResolveSubjectToken != nil && inputsB.SubjectToken == "" {
		tok, rerr := inputsB.ResolveSubjectToken(ctx)
		if rerr != nil {
			return nil, fmt.Errorf("secret_spec %q: failed to resolve subject token: %w", secretRef, rerr)
		}
		inputsB.SubjectToken = tok
	}
	if inputsB != nil && inputsB.ResolveActorToken != nil && inputsB.ActorToken == "" {
		tok, rerr := inputsB.ResolveActorToken(ctx)
		if rerr != nil {
			return nil, fmt.Errorf("secret_spec %q: failed to resolve actor token: %w", secretRef, rerr)
		}
		inputsB.ActorToken = tok
	}

	// Mint the secret AS the caller via the non-caching path — never cached; it
	// lives only for this mint and is discarded after material extraction by the caller.
	credB, err := m.issueCredential(ctx, caller, secretRef, inputsB)
	if err != nil {
		return nil, fmt.Errorf("secret_spec %q: %w", secretRef, err)
	}

	// A referenced secret-spec must be static/leaseless: this path skips expiration
	// registration, so a leased credential would orphan its lease. The create-time
	// guard forbids this; fail closed (best-effort revoke) if config drift produced
	// one anyway.
	if credB.LeaseID != "" || credB.LeaseTTL > 0 {
		if credB.LeaseID != "" {
			// Best-effort revoke on a fresh context (the request ctx may be near its
			// issuance deadline); log rather than drop the outcome.
			revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if drv, derr := m.driverCoordinator.GetOrCreateDriver(ctx, credB.SourceName); derr == nil {
				if rerr := drv.Revoke(revokeCtx, credB.LeaseID); rerr != nil {
					m.log.Warn("failed to revoke orphaned lease from a leased secret_spec",
						logger.String("secret_spec", secretRef),
						logger.String("lease_id", credB.LeaseID),
						logger.Err(rerr))
				}
			}
			cancel()
		}
		return nil, fmt.Errorf("secret_spec %q must reference a static/leaseless credential, but it returned a lease", secretRef)
	}

	return credB, nil
}

// resolveSecretField selects which key of the referenced credential's Data carries
// the single secret: an explicit secret_field (spec-level then source-level), else a
// single-key payload, else the referenced type's primary field. Returns "" when it
// cannot determine one — a multi-secret consumer reads Data directly and ignores it;
// a single-secret consumer surfaces the "set secret_field" error at use.
func (m *Manager) resolveSecretField(ctx context.Context, spec *CredSpec, credB *Credential) string {
	if f := spec.Config[ConfigSecretField]; f != "" {
		return f
	}
	if src, err := m.configStore.GetSource(ctx, spec.Source); err == nil && src != nil {
		if f := src.Config[ConfigSecretField]; f != "" {
			return f
		}
	}
	if len(credB.Data) == 1 {
		for k := range credB.Data {
			return k
		}
	}
	if m.typeRegistry != nil {
		if ct, err := m.typeRegistry.GetByName(credB.Type); err == nil {
			if pfp, ok := ct.(PrimaryFieldProvider); ok {
				if pf := pfp.PrimaryField(); pf != "" {
					return pf
				}
			}
		}
	}
	return ""
}

// mintFromSecret mints the consuming credential from fetched secret material, with
// orphaned-lease cleanup on failure. Mirrors mintAndParse for the chaining path.
func (m *Manager) mintFromSecret(ctx context.Context, spec *CredSpec, driver SourceDriver, material SecretMaterial) (*Credential, error) {
	var cred *Credential
	err := m.mintingService.MintFromSecretWithCleanup(ctx, driver, spec, material, func(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) error {
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
