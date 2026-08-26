package credential

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
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
	// secretCache holds referenced secret-spec material for credential chaining,
	// opt-in per consumer via ConfigSecretCacheTTL. It is a separate instance from the
	// credential cache: its entries are keyed by (namespace, secret_spec, agent
	// identity [, user]) and TTL'd by secret_cache_ttl, not by the credential cache's
	// per-token/session lifetime. Fetched secrets are held in memory only, never
	// persisted.
	secretCache *ristretto.Cache[string, chainedSecret]
	group       singleflight.Group

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

// chainedSecret is the cached payload of a referenced secret-spec: the minted
// credential's Data plus its Type. Type is retained because resolveSecretField uses it
// for the PrimaryFieldProvider fallback, so a cache hit resolves the secret_field
// identically to a fresh fetch. It never contains a lease (the referenced spec is
// static/leaseless) and is held in memory only, never persisted.
type chainedSecret struct {
	Data map[string]string
	Type string
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

	// Separate cache for credential-chaining secret material (opt-in via
	// ConfigSecretCacheTTL). Entries are (namespace, secret_spec, agent identity [,
	// user]) tuples — far fewer than issued credentials. Each entry has cost 1, so
	// MaxCost bounds the entry COUNT; NumCounters is ~10x that for TinyLFU admission.
	secretCache, err := ristretto.NewCache(&ristretto.Config[string, chainedSecret]{
		NumCounters: 100_000,
		MaxCost:     10_000,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secret cache: %w", err)
	}
	m.secretCache = secretCache

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
	// mint. This dimension is independent of the exchange fingerprint, so it applies
	// whether or not the consumer requested exchange: a plain chained consumer (no
	// ":x:" fragment) and a chained token-exchange consumer (which does carry ":x:")
	// both get per-user isolation. Byte-identical when caller.User == nil.
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
		// When the chained consumer is ITSELF an exchange spec (it requested exchange, so
		// inputs != nil), it needs both its own subject/actor inputs AND a fetched
		// client-auth secret — route to the exchange-aware chaining path. Otherwise the
		// plain chaining path (mint directly from the fetched material) applies.
		if inputs != nil {
			return m.issueChainedExchange(ctx, caller, spec, secretRef, inputs)
		}
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
// the secret material, and hands it to the consuming driver. By default the fetched
// secret is not cached (re-minted on every consuming-credential miss); a consumer may
// opt into source-scoped caching via secret_cache_ttl (see resolveChainedSecretData).
func (m *Manager) issueChained(ctx context.Context, caller Caller, spec *CredSpec, secretRef string) (*Credential, error) {
	ctx, inputsB, err := m.chainPreamble(ctx, caller, spec, secretRef)
	if err != nil {
		return nil, err
	}

	return m.resolveAndMintChained(ctx, caller, spec, secretRef, inputsB,
		func(ctx context.Context, spec *CredSpec, material SecretMaterial) (*Credential, error) {
			driver, err := m.driverCoordinator.GetOrCreateDriver(ctx, spec.Source)
			if err != nil {
				return nil, err
			}
			return m.mintFromSecret(ctx, spec, driver, material)
		})
}

// issueChainedExchange mints a consuming credential that is ITSELF a token-exchange spec
// AND sources its client-auth secret via chaining. It resolves the referenced secret
// (cached per secret_cache_ttl) and performs the exchange using the consuming spec's own
// exchange inputs plus the fetched material. Reuses resolveAndMintChained, so caching,
// per-agent/per-user isolation, and evict-and-retry are inherited from the generic path.
func (m *Manager) issueChainedExchange(ctx context.Context, caller Caller, spec *CredSpec, secretRef string, inputs *ExchangeInputs) (*Credential, error) {
	ctx, inputsB, err := m.chainPreamble(ctx, caller, spec, secretRef)
	if err != nil {
		return nil, err
	}

	return m.resolveAndMintChained(ctx, caller, spec, secretRef, inputsB,
		func(ctx context.Context, spec *CredSpec, material SecretMaterial) (*Credential, error) {
			driver, err := m.driverCoordinator.GetOrCreateDriver(ctx, spec.Source)
			if err != nil {
				return nil, err
			}
			return m.mintFromSecretWithExchange(ctx, spec, driver, inputs, material)
		})
}

// chainPreamble enforces the one-hop depth guard and builds the referenced secret-spec's
// exchange inputs as the caller. It returns a context carrying the incremented chain
// depth (used by the recursive referenced mint), shared by both the plain and
// exchange-aware chaining paths.
func (m *Manager) chainPreamble(ctx context.Context, caller Caller, spec *CredSpec, secretRef string) (context.Context, *ExchangeInputs, error) {
	// Bound the chain to a single hop (a referenced secret-spec may not itself chain).
	// This also breaks any config-drift reference cycle rather than recursing unboundedly.
	depth := chainDepth(ctx)
	if depth+1 > MaxSecretChainDepth {
		return nil, nil, fmt.Errorf("credential chaining for spec %q exceeds max depth %d (referenced secret_spec %q)", spec.Name, MaxSecretChainDepth, secretRef)
	}
	ctx = withChainDepth(ctx, depth+1)

	// Build exchange inputs for the referenced secret-spec, as the caller.
	if caller.ResolveInputs == nil {
		return nil, nil, fmt.Errorf("credential chaining for spec %q requires a request caller context", spec.Name)
	}
	inputsB, err := caller.ResolveInputs(ctx, secretRef)
	if err != nil {
		return nil, nil, fmt.Errorf("secret_spec %q: %w", secretRef, err)
	}
	return ctx, inputsB, nil
}

// resolveAndMintChained resolves the referenced secret material (through the opt-in
// source-scoped cache) and mints the consuming credential via mintFn. When the material
// came from the cache and the downstream rejects it (ErrChainedSecretRejected or the
// pre-existing ErrRefreshTokenRejected), the cached value may be stale (rotated at the
// source): it evicts the entry and retries once with a fresh fetch. It does not retry a
// freshly fetched secret — that would just re-fetch identical data.
//
// It is shared by issueChained and (with an exchange-aware mintFn) the token_exchange
// chaining path, so caching and rejection-retry cover every ChainedSecretMinter driver.
func (m *Manager) resolveAndMintChained(
	ctx context.Context,
	caller Caller,
	spec *CredSpec,
	secretRef string,
	inputsB *ExchangeInputs,
	mintFn func(ctx context.Context, spec *CredSpec, material SecretMaterial) (*Credential, error),
) (*Credential, error) {
	data, typ, fromCache, key, err := m.resolveChainedSecretData(ctx, caller, spec, secretRef, inputsB)
	if err != nil {
		return nil, err
	}
	material := m.buildSecretMaterial(ctx, spec, data, typ)

	cred, err := mintFn(ctx, spec, material)
	if err != nil && fromCache && (errors.Is(err, ErrChainedSecretRejected) || errors.Is(err, ErrRefreshTokenRejected) || errors.Is(err, ErrChainedSecretIncomplete)) {
		// A cached secret was rejected downstream, or turned out to be missing
		// something the driver needs — evict it and retry once with a fresh fetch, in
		// case it was rotated or completed at the source after we cached it.
		m.invalidateChainedSecret(key)
		data, typ, _, _, rerr := m.resolveChainedSecretData(ctx, caller, spec, secretRef, inputsB)
		if rerr != nil {
			return nil, rerr
		}
		return mintFn(ctx, spec, m.buildSecretMaterial(ctx, spec, data, typ))
	}
	return cred, err
}

// buildSecretMaterial resolves the secret_field for the consuming spec and wraps the
// fetched data as SecretMaterial. The field is resolved per-consumer (not cached),
// using a synthetic Credential so resolveSecretField's type-based fallback still works.
func (m *Manager) buildSecretMaterial(ctx context.Context, spec *CredSpec, data map[string]string, typ string) SecretMaterial {
	field := m.resolveSecretField(ctx, spec, &Credential{Data: data, Type: typ})
	return SecretMaterial{Data: data, Field: field}
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

// resolveChainedSecretData returns the referenced secret-spec's material (Data + Type),
// using the source-scoped secret cache when the consumer opts in via secret_cache_ttl.
// fromCache is true only when the value came from a pre-existing cache entry (so the
// caller retries on a downstream rejection only when a stale cached value could be the
// cause). key is the cache key (empty when caching is disabled), for invalidation on
// retry. A ttl <= 0, or a context without a namespace, disables caching and fetches
// directly — the behaviour-preserving default.
func (m *Manager) resolveChainedSecretData(ctx context.Context, caller Caller, spec *CredSpec, secretRef string, inputsB *ExchangeInputs) (data map[string]string, typ string, fromCache bool, key string, err error) {
	ttl := m.secretCacheTTL(ctx, spec)
	if ttl <= 0 {
		return m.fetchUncached(ctx, caller, secretRef, inputsB)
	}

	ns, nerr := namespace.FromContext(ctx)
	if nerr != nil {
		// No namespace to scope the cache key (internal/non-request path): fall back to
		// a direct, uncached fetch rather than risk a cross-namespace key collision.
		return m.fetchUncached(ctx, caller, secretRef, inputsB)
	}

	// The referenced spec's own config decides which secret is fetched and from where,
	// so it has to key the entry that answers for it — resolve it before keying. Both
	// reads are served from the config store's cache, which this request has already
	// populated (resolveExchangeInputs read the same spec to build inputsB). If either
	// cannot be resolved, decline to cache rather than key on an identity we could not
	// establish; the fetch below reports the real error.
	specB, serr := m.specResolver.ResolveSpec(ctx, secretRef)
	if serr != nil {
		return m.fetchUncached(ctx, caller, secretRef, inputsB)
	}
	srcB, serr := m.configStore.GetSource(ctx, specB.Source)
	if serr != nil {
		return m.fetchUncached(ctx, caller, secretRef, inputsB)
	}

	key = chainedSecretCacheKey(ns.ID, secretRef, chainedSpecFingerprint(specB, srcB), caller, inputsB)
	if key == "" {
		// Caching refused for safety (user-scoped fetch without a user principal): fetch
		// directly, uncached.
		return m.fetchUncached(ctx, caller, secretRef, inputsB)
	}

	if cs, ok := m.secretCache.Get(key); ok {
		return copyStringMap(cs.Data), cs.Type, true, key, nil
	}

	// Miss: coalesce concurrent fetches for this key. A followed (non-leader) request
	// receives the leader's freshly fetched value, so fromCache stays false for the
	// whole group — the value is fresh this round, not a pre-existing cached entry.
	v, ferr, _ := m.group.Do(key, func() (interface{}, error) {
		if cs, ok := m.secretCache.Get(key); ok { // another goroutine populated it
			return cs, nil
		}
		credB, e := m.fetchChainedSecret(ctx, caller, secretRef, inputsB)
		if e != nil {
			return nil, e
		}
		cs := chainedSecret{Data: credB.Data, Type: credB.Type}
		m.secretCache.SetWithTTL(key, cs, 1, ttl)
		m.secretCache.Wait() // Ristretto sets are async; shrink the window vs a concurrent Del.
		return cs, nil
	})
	if ferr != nil {
		return nil, "", false, key, ferr
	}
	cs := v.(chainedSecret)
	return copyStringMap(cs.Data), cs.Type, false, key, nil
}

// fetchUncached performs the referenced fetch without consulting or populating the
// cache, for every path that declines to cache. It reports fromCache=false and an empty
// key, so the caller neither retries on a rejection nor tries to invalidate.
func (m *Manager) fetchUncached(ctx context.Context, caller Caller, secretRef string, inputsB *ExchangeInputs) (map[string]string, string, bool, string, error) {
	credB, err := m.fetchChainedSecret(ctx, caller, secretRef, inputsB)
	if err != nil {
		return nil, "", false, "", err
	}
	return credB.Data, credB.Type, false, "", nil
}

// secretCacheTTL resolves ConfigSecretCacheTTL spec-then-source (matching how
// secret_spec / secret_field resolve). Returns 0 (no caching) when unset. A spec-level
// value is authoritative by PRESENCE, so an explicit spec-level "0" opts out of a
// source-level TTL (e.g. a rotation-sensitive consumer under a source that caches).
func (m *Manager) secretCacheTTL(ctx context.Context, spec *CredSpec) time.Duration {
	if _, ok := spec.Config[ConfigSecretCacheTTL]; ok {
		return GetDuration(spec.Config, ConfigSecretCacheTTL, 0)
	}
	if src, err := m.configStore.GetSource(ctx, spec.Source); err == nil && src != nil {
		return GetDuration(src.Config, ConfigSecretCacheTTL, 0)
	}
	return 0
}

// invalidateChainedSecret evicts a cached secret and forgets any in-flight singleflight
// entry for its key, so an immediate retry re-fetches rather than joining a stale fetch.
func (m *Manager) invalidateChainedSecret(key string) {
	if key == "" {
		return
	}
	m.secretCache.Del(key)
	m.group.Forget(key)
}

// chainedSecretCacheKey scopes a cached secret to (namespace, secret_spec, what that
// spec fetches, agent identity). inputsB.Fingerprint keys on SubjectCacheIdentity — stable across an agent's
// sessions — so the store's per-agent authorization is honoured (agent B is never served
// agent A's fetched secret).
//
// "Agent identity" has to mean everything the store was shown, since sharing a fetch
// across sessions means never asking it again. Where an assertion is minted, that is
// what SubjectCacheIdentity carries: subject, audience, role, resource and the projected
// metadata — every claim a store may bind. Where the agent's own token is forwarded
// instead, the store reads that token and the fingerprint hashes its bytes, so the only
// inputs left to cover are the claims a templated path resolves from, which the agent
// dimension below carries. When the referenced fetch is user-scoped (the referenced
// spec sets assertion_user_claims, so inputsB.UserClaims is populated), the user token id
// and a fingerprint of those claims are folded in — the first so one user's per-user
// secret is never served to another, the second so a user whose claims have changed
// under a stable token id is not served what the old ones fetched; a source-global
// fetch (no user claims) omits both and is shared across users under the agent. A nil
// inputsB (a referenced spec that requests no exchange) uses a fixed sentinel.
//
// refFP is chainedSpecFingerprint over the referenced spec and its source: the spec name
// says which entry to look under, and refFP says what that name resolved to when the
// entry was filled, so an operator repointing the name does not inherit the old answer.
//
// It returns "" — meaning "do not cache" — for a user-scoped fetch that lacks the user
// principal to key on, or a referenced spec that could not be resolved. That combination cannot arise from the current request path, but
// refusing to cache is the safe failure mode: it never shares one user's secret
// namespace-wide.
func chainedSecretCacheKey(nsID, secretRef, refFP string, caller Caller, inputsB *ExchangeInputs) string {
	// No fingerprint means the referenced spec could not be resolved, so there is no
	// identity to key on. Refuse to cache rather than share an entry across whatever
	// the name points at now.
	if refFP == "" {
		return ""
	}

	fp := "noexchange"
	if inputsB != nil {
		fp = inputsB.Fingerprint()
	}

	// The agent's claims can select which secret is fetched — a templated path
	// resolves from them — so they must key the entry that answers for it. The
	// fingerprint alone does not cover them: where the subject is the agent's raw
	// token, it hashes the token bytes, while the claims are derived from those
	// bytes AND the auth role's own mapping (which claim names the principal, which
	// become metadata). One token presented under two roles therefore resolves two
	// sets of claims behind one fingerprint, and editing a role's mapping changes
	// them under a fingerprint that does not move at all.
	agent := ""
	if inputsB != nil && len(inputsB.AgentClaims) > 0 {
		agent = ":a:" + claimsFingerprint(inputsB.AgentClaims)
	}

	// The user's claims select a path the same way the agent's do, so they key the
	// entry the same way. The user token id alone is a proxy, not a cover: it hashes
	// the presented credential, the mount and the role name, but not the role's
	// mapping. Re-authenticating after an operator edits that mapping returns the
	// identical token id carrying different claims, which renders a different path
	// under a key that never moved. The token id stays because it is what binds the
	// entry to a principal's lifecycle; the fingerprint is what tracks what the
	// store was actually shown.
	if inputsB != nil && len(inputsB.UserClaims) > 0 {
		if caller.User == nil {
			return ""
		}
		return "chainsecret:" + nsID + ":" + secretRef + ":s:" + refFP + ":" + fp + agent +
			":u:" + caller.User.TokenID + ":uc:" + claimsFingerprint(inputsB.UserClaims)
	}
	return "chainsecret:" + nsID + ":" + secretRef + ":s:" + refFP + ":" + fp + agent
}

// claimsFingerprint hashes a claim map stably: keys sorted so map order cannot
// change the result, and each field length-prefixed so no two maps can collide by
// running their bytes together differently.
func claimsFingerprint(claims map[string]string) string {
	h := sha256.New()
	hashStringMap(h, claims, nil)
	return hex.EncodeToString(h.Sum(nil))
}

// writeHashField writes s into h length-prefixed, so no two sequences of fields can
// collide by running their bytes together differently.
func writeHashField(h hash.Hash, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	h.Write(lenBuf[:])
	h.Write([]byte(s))
}

// hashStringMap folds a map into h with its keys sorted, so iteration order cannot
// change the result. Keys present in exclude are skipped.
func hashStringMap(h hash.Hash, m map[string]string, exclude map[string]struct{}) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if _, skip := exclude[k]; skip {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		writeHashField(h, k)
		writeHashField(h, m[k])
	}
}

// rotatedProofFields are config keys carrying proof of an identity rather than naming
// what is fetched or where it lives. Each is rewritten by a rotation — source-side by a
// driver's PrepareRotation, spec-side by the refresh-token write-back — while the
// credential goes on reaching the same secret in the same place.
//
// They are excluded from chainedSpecFingerprint for two reasons. Including them would
// dump every secret cached under a source each time that source rotated, buying nothing:
// the Rotatable contract is that a rotation replaces an authenticator, never the identity
// it authenticates. And for a referenced spec whose refresh_token rotates on every use it
// would be worse than churn — the key would move on each fetch, so no entry would ever be
// read once, and caching would be silently dead for exactly the specs that ask for it.
//
// Drift is safe in the direction it drifts: a rotating field missing from this set is
// fingerprinted, which costs cache churn, never a stale secret.
var rotatedProofFields = map[string]struct{}{
	"refresh_token":         {}, // spec-side write-back (persistRotatedRefreshToken)
	"secret_id":             {}, // vault approle, azure client secret id
	"secret_id_accessor":    {}, // vault approle
	"token":                 {}, // vault token auth
	"client_secret":         {}, // azure
	"access_key_id":         {}, // aws, alicloud — rotated in lockstep with its secret
	"secret_access_key":     {}, // aws
	"access_key_secret":     {}, // alicloud
	"api_key":               {}, // elastic, ibm
	"api_key_id":            {}, // elastic
	"service_account_key":   {}, // gcp
	"application_secret":    {}, // gitlab oauth application
	"personal_access_token": {}, // gitlab
	"management_access_key": {}, // scaleway
	"management_secret_key": {}, // scaleway
}

// chainedSpecFingerprint hashes what the referenced spec and its source say about which
// secret is fetched and where it lives: the spec's type, the source it names, and both
// configs minus the proof material above.
//
// The spec NAME alone cannot stand for this. A name is a label an operator can point
// somewhere else — editing secret_path, swapping the mount, repointing the spec at
// another source, or moving the source to a different address all change what a fetch
// returns while the name stays put, and the entry filled before the edit would go on
// answering for it. Deriving the key from the content instead makes every such edit
// self-correcting, on every node, with no invalidation to coordinate — the same standard
// the driver-level token caches are held to.
//
// Config values are only ever hashed, never placed in the key in the clear.
func chainedSpecFingerprint(spec *CredSpec, src *CredSource) string {
	h := sha256.New()
	writeHashField(h, "chained-spec-v1")

	if spec != nil {
		writeHashField(h, "spec")
		writeHashField(h, spec.Type)
		writeHashField(h, spec.Source)
		hashStringMap(h, spec.Config, rotatedProofFields)
	}
	if src != nil {
		writeHashField(h, "src")
		writeHashField(h, src.Type)
		hashStringMap(h, src.Config, rotatedProofFields)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// copyStringMap returns a shallow copy so a cached secret's Data map is never shared
// with (and mutated by) a consumer. Returns nil for a nil input.
func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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

// mintFromSecretWithExchange mints the consuming credential via the exchange-aware
// chained path — both the caller's exchange inputs and the fetched client-auth material
// — with orphaned-lease cleanup on failure. Mirrors mintFromSecret for the
// token-exchange chaining path.
func (m *Manager) mintFromSecretWithExchange(ctx context.Context, spec *CredSpec, driver SourceDriver, inputs *ExchangeInputs, material SecretMaterial) (*Credential, error) {
	var cred *Credential
	err := m.mintingService.MintFromSecretWithExchangeCleanup(ctx, driver, spec, inputs, material, func(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) error {
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
	if m.secretCache != nil {
		m.secretCache.Close()
	}
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
