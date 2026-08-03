package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	aead "github.com/openbao/go-kms-wrapping/v2/aead"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/internal/locking"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	phy "github.com/stephnangue/warden/physical"
	"golang.org/x/sync/singleflight"
)

const (
	// CoreLockPath is the path used to acquire a coordinating lock
	// for a highly-available deploy.
	CoreLockPath = "core/lock"

	// CoreInitLockPath is the path used to acquire a coordinating lock
	// for a highly-available deployment which is undergoing initialization.
	CoreInitLockPath = "core/initialize-lock"

	// DefaultMinCredSourceRotationPeriod is the minimum allowed rotation period
	// for credential sources when not explicitly configured (1 day).
	DefaultMinCredSourceRotationPeriod = 24 * time.Hour

	// DefaultMaxCredSourceRotationPeriod is the maximum allowed rotation period
	// for credential sources when not explicitly configured (30 days).
	DefaultMaxCredSourceRotationPeriod = 720 * time.Hour

	// DefaultMinCredSpecRotationPeriod is the minimum allowed rotation period
	// for credential specs that embed rotatable credentials (1 hour).
	DefaultMinCredSpecRotationPeriod = 1 * time.Hour

	// DefaultMaxCredSpecRotationPeriod is the maximum allowed rotation period
	// for credential specs that embed rotatable credentials (30 days).
	DefaultMaxCredSpecRotationPeriod = 720 * time.Hour
)

var (
	// ErrAlreadyInit is returned if the core is already
	// initialized. This prevents a re-initialization.
	ErrAlreadyInit = errors.New("Warden is already initialized")

	// ErrParallelInit is returned if the core is undergoing
	// initialization on another node. This prevents a re-initialization.
	ErrParallelInit = errors.New("Warden is being initialized on another node")

	// ErrNotInit is returned if a non-initialized barrier
	// is attempted to be unsealed.
	ErrNotInit = errors.New("Warden is not initialized")

	// ErrInternalError is returned when we don't want to leak
	// any information about an internal error
	ErrInternalError = errors.New("internal error")

	// ErrHANotEnabled is returned if the operation only makes sense
	// in an HA setting
	ErrHANotEnabled = errors.New("Warden is not configured for highly-available mode")

	// ErrStandby is returned when a request reaches a node that has
	// transitioned to standby mid-flight. The HTTP layer catches this
	// and issues a 307 redirect to the active node.
	ErrStandby = errors.New("node is standby")

	// errNoMatchingMount is returned if the mount is not found
	errNoMatchingMount = errors.New("no matching mount")
)

// NonFatalError is an error that can be returned during NewCore that should be
// displayed but not cause a program exit
type NonFatalError struct {
	Err error
}

func (e *NonFatalError) WrappedErrors() []error {
	return []error{e.Err}
}

func (e *NonFatalError) Error() string {
	return e.Err.Error()
}

// NewNonFatalError returns a new non-fatal error.
func NewNonFatalError(err error) *NonFatalError {
	return &NonFatalError{Err: err}
}

// IsFatalError returns true if the given error is a fatal error.
func IsFatalError(err error) bool {
	return !errwrap.ContainsType(err, new(NonFatalError))
}

// ErrInvalidKey is returned if there is a user-based error with a provided
// unseal key. This will be shown to the user, so should not contain
// information that is sensitive.
type ErrInvalidKey struct {
	Reason string
}

func (e *ErrInvalidKey) Error() string {
	return fmt.Sprintf("invalid key: %v", e.Reason)
}

type unlockInformation struct {
	Parts [][]byte
	Nonce string
}

type migrationInformation struct {
	// seal to use during a migration operation. It is the
	// seal we're migrating *from*.
	seal Seal

	// unsealKey was the unseal key provided for the migration seal.
	// This will be set as the recovery key when migrating from shamir to auto-seal.
	// We don't need to do anything with it when migrating auto->shamir because
	// we don't store the shamir combined key for shamir seals, nor when
	// migrating auto->auto because then the recovery key doesn't change.
	unsealKey []byte
}

type Core struct {
	// storageType is the storage type set in the storage configuration
	storageType string

	// HABackend may be available depending on the physical backend
	ha physical.HABackend

	// physical backend is the un-trusted backend with durable data
	physical physical.Backend

	// underlyingPhysical will always point to the underlying backend
	// implementation. This is an un-trusted backend with durable data
	underlyingPhysical physical.Backend

	// seal is our seal, for seal configuration information
	seal Seal

	// migrationInfo is used during (and possibly after) a seal migration.
	// This contains information about the seal we are migrating *from*.  Even
	// post seal migration, provided the old seal is still in configuration
	// migrationInfo will be populated, which may be necessary for seal rewrap.
	migrationInfo     *migrationInformation
	sealMigrationDone *uint32

	// barrier is the security barrier wrapping the physical backend
	barrier SecurityBarrier

	// unlockInfo has the keys provided to Unseal until the threshold number of parts is available, as well as the operation nonce
	unlockInfo *unlockInformation

	// systemBarrierView is the barrier view for the system backend
	systemBarrierView BarrierView

	// activeTime is set on active nodes indicating the time at which this node
	// became active.
	activeTime time.Time

	// rawConfig stores the config as-is from the provided server configuration.
	rawConfig *atomic.Value

	logger *logger.GatedLogger

	// tokenStore manages namespace-aware tokens with pluggable types
	tokenStore *TokenStore

	// namespace Store is used to manage namespaces
	namespaceStore *NamespaceStore

	// credConfigStore manages credential specs and sources with namespace isolation
	credConfigStore *CredentialConfigStore

	// skillStore manages the global agent-skill registry (one set, shared
	// across namespaces; root-only mutations are enforced at the HTTP layer).
	skillStore *SkillStore

	// policy store is used to manage named CBP policies
	policyStore *PolicyStore

	// credentialManager handles credentials across all namespaces
	// It uses namespace-aware cache keys and storage paths for isolation
	credentialManager *credential.Manager

	// Global registries shared across all namespaces
	credentialTypeRegistry   *credential.TypeRegistry
	credentialDriverRegistry *credential.DriverRegistry

	// expirationManager provides active TTL enforcement for tokens and credentials
	// Uses timer-based expiration instead of relying on lazy cache eviction
	expirationManager *ExpirationManager

	// rotationManager handles periodic rotation of credential source secrets
	// (e.g., Vault AppRole secret_id rotation)
	rotationManager *RotationManager

	// oidcIssuer, when configured, makes Warden its own OIDC issuer: it mints
	// short-lived identity assertions for Workload Identity Federation. nil (or
	// not-ready) when disabled, so the warden_identity mint path fails closed.
	//
	// oidcMu guards all the oidc* fields below against the concurrent rotation
	// goroutine, config writes (setupOIDCIssuer), and the mint/publish paths.
	oidcMu        sync.RWMutex
	oidcIssuer    *OIDCIssuer
	oidcPublisher JWKSPublisher

	// oidcRotationCancel stops the active node's signing-key rotation loop, and
	// oidcRotationDone is closed when the loop goroutine has exited (so stop can
	// join it). nil when rotation is disabled or the node is a standby.
	oidcRotationCancel context.CancelFunc
	oidcRotationDone   chan struct{}
	// oidcPubRotationCancel/oidcPubRotationDone are the same pair for the active
	// node's publisher-credential rotation loop (see oidc_publisher_rotation.go).
	oidcPubRotationCancel context.CancelFunc
	oidcPubRotationDone   chan struct{}
	// oidcConfigMu serializes the load-modify-save of the issuer config doc so a
	// rotation persist and an operator config write cannot lost-update each other.
	oidcConfigMu sync.Mutex
	// oidcSetupMu serializes setupOIDCIssuer/stopOIDCIssuer so two concurrent config
	// writes (or a write racing seal/promotion) cannot interleave loop start/stop and
	// leak a rotation goroutine that outlives its cancel func. Distinct from oidcConfigMu
	// (which the config-write handler releases before calling setupOIDCIssuer) to avoid a
	// deadlock against the rotation loop's own oidcConfigMu acquisition.
	oidcSetupMu sync.Mutex
	// oidcJWKSCacheTTL / oidcRetiredKeyGrace are the rotation timings from config.
	// oidcJWKSCacheTTL is the published JWKS Cache-Control max-age, which also
	// floors how long a fresh next key is pre-published before it may sign.
	// oidcRetiredKeyGrace is the margin beyond assertion TTL a retired key is kept.
	oidcJWKSCacheTTL    time.Duration
	oidcRetiredKeyGrace time.Duration

	// shutdownHooks are process-level cleanup functions registered by backends
	// (e.g., transport shutdown). Keyed by name for idempotency.
	shutdownHooks   map[string]func()
	shutdownHooksMu sync.Mutex

	auditDevices map[string]audit.Factory

	// auditConfigDeclarations holds the HCL-declared audit devices passed
	// in via CoreConfig.DeclarativeAuditDevices. loadAudits reconciles
	// these against persisted entries on every unseal.
	auditConfigDeclarations []*MountEntry

	authMethods map[string]logical.Factory

	providers map[string]logical.Factory

	// providerSkills maps provider type → agent-facing markdown.
	// Populated from CoreConfig.ProviderSkills; consumed by the mount
	// handler to seed the skill registry on first mount of each type.
	providerSkills map[string]string

	auditManager audit.AuditManager

	audit *MountTable

	// auditLock is used to ensure that the audit table does not
	// change underneath a calling function
	auditLock sync.RWMutex

	router *Router

	// LOCK ORDERING: when a code path needs more than one mount-table lock,
	// acquire them in this order: mountsLock → authLock → auditLock.
	// The reverse is forbidden and will deadlock under contention.

	mounts *MountTable

	// mountsLock guards the provider + system mount table (c.mounts).
	mountsLock locking.DeadlockRWMutex

	// auth holds the auth-method mount table. Separate from c.mounts so
	// callers that only need one class never block on the other, and so
	// missed class checks become impossible (a provider entry physically
	// cannot live in c.auth and vice versa).
	auth *MountTable

	// authLock guards the auth-method mount table (c.auth).
	authLock locking.DeadlockRWMutex

	// initialized tracks whether warden init has been called
	initialized bool
	initLock    sync.RWMutex

	// cachingDisabled indicates whether caches are disabled
	cachingDisabled bool
	// Cache stores the actual cache; we always have this but may bypass it if
	// disabled
	physicalCache physical.ToggleablePurgemonster

	// This can be used to trigger operations to stop running when Warden is
	// going to be shut down, stepped down, or sealed
	activeContext           context.Context
	activeContextCancelFunc *atomic.Value

	// unsealwithStoredKeysLock is a mutex that prevents multiple processes from
	// unsealing with stored keys are the same time.
	unsealWithStoredKeysLock sync.Mutex

	// Stores any funcs that should be run on successful postUnseal
	postUnsealFuncs []func()

	// secureRandomReader is the reader used for CSP operations
	secureRandomReader io.Reader

	// KeyRotateGracePeriod is how long we allow an upgrade path
	// for standby instances before we delete the upgrade keys
	keyRotateGracePeriod *int64

	// Config value for "detect_deadlocks".
	detectDeadlocks []string

	standby          atomic.Bool
	standbyDoneCh    chan struct{}
	standbyStopCh    *atomic.Value
	manualStepDownCh chan struct{}
	standbyRestartCh chan struct{}
	heldHALockMu     sync.Mutex
	heldHALock       physical.Lock

	// leaderParams caches the leader's advertisement info for
	// efficient lookups from standby nodes.
	leaderParams atomic.Value // stores *clusterLeaderParams

	// shutdownDoneCh is used to notify when core.Shutdown() completes.
	// core.Shutdown() is typically issued in a goroutine to allow Warden to
	// release the stateLock. This channel is marked atomic to prevent race
	// conditions.
	shutdownDoneCh *atomic.Value

	// redirectAddr is the address we advertise as leader if held
	redirectAddr string

	// clusterAddr is the address we use for clustering
	clusterAddr *atomic.Value

	// Cluster TLS identity — generated by active node, loaded by standbys
	// from the leader advertisement in barrier storage. All nodes in the
	// cluster share the same cert/key pair for mTLS on the cluster listener.
	localClusterCert       atomic.Pointer[[]byte]           // DER-encoded self-signed cert
	localClusterParsedCert atomic.Pointer[x509.Certificate] // parsed form of the above
	localClusterPrivateKey atomic.Pointer[ecdsa.PrivateKey] // P-521 ECDSA key

	// stateLock protects mutable state
	stateLock locking.RWMutex
	sealed    *uint32

	// systemBackend is the backend which is used to manage internal operations
	systemBackend *SystemBackend

	// transparentAuthGroup ensures only one implicit auth per JWT to prevent
	// duplicate token creation when concurrent requests arrive with the same JWT
	transparentAuthGroup singleflight.Group

	// clusterConfig holds tunable HA cluster parameters (timeouts, intervals).
	clusterConfig ClusterConfig
}

type CoreConfig struct {
	RawConfig *config.Config

	AuditDevices map[string]audit.Factory

	// DeclarativeAuditDevices is the set of audit devices declared in the
	// HCL server config (audit "TYPE" "PATH" { ... } blocks). Translated
	// from config.AuditBlock by the cmd/server wiring. These are
	// reconciled in loadAudits on every unseal; the operator updates them
	// by editing HCL and restarting.
	DeclarativeAuditDevices []*MountEntry

	AuthMethods map[string]logical.Factory

	Providers map[string]logical.Factory

	// ProviderSkills maps provider type → agent-facing skill markdown.
	// Entries are populated by the server wiring (cmd/server) for every
	// provider package that ships a skill.md. On first mount of each
	// type, the markdown is parsed and seeded into the SkillStore via
	// SeedProviderSkill. Types absent from this map simply don't appear
	// in the agent skill catalog until an operator creates one manually.
	ProviderSkills map[string]string

	// TokenStore has been moved to core package and is created internally
	// Deprecated: Remove this field, TokenStore is now created in NewCore
	// TokenStore   token.TokenStore

	Physical physical.Backend

	Logger *logger.GatedLogger

	StorageType string

	// May be nil, which disables HA operations
	HAPhysical physical.HABackend

	// Seal is the configured seal, or if none is configured explicitly, a
	// shamir seal.  In migration scenarios this is the new seal.
	Seal Seal

	// Unwrap seal is the optional seal marked "disabled"; this is the old
	// seal in migration scenarios.
	UnwrapSeal Seal

	SecureRandomReader io.Reader

	// Disables the LRU cache on the physical storage
	DisableCache bool

	// Custom cache size for the LRU cache on the physical storage, or zero for default
	CacheSize int

	DisableKeyEncodingChecks bool

	// Set as the leader address for HA
	RedirectAddr string

	// Set as the cluster address for HA
	ClusterAddr string

	// Use the deadlocks library to detect deadlocks
	DetectDeadlocks string
}

func (c *Core) Shutdown() error {
	c.logger.Info("shutting down the core")

	// If HA is enabled, signal the standby loop to stop and wait for it
	if c.ha != nil {
		if stopCh := c.standbyStopCh.Load(); stopCh != nil {
			ch := stopCh.(chan struct{})
			select {
			case <-ch:
				// Already closed (e.g., Shutdown called twice)
			default:
				close(ch)
			}
		}

		if c.standbyDoneCh != nil {
			select {
			case <-c.standbyDoneCh:
				c.logger.Info("standby loop exited")
			case <-time.After(30 * time.Second):
				c.logger.Warn("timed out waiting for standby loop to exit")
			}
		}

		// Release the HA lock if still held (guarded to prevent double-unlock
		// race with the standby loop on the 30s timeout path).
		c.unlockHeldHALock()
	}

	// Seal the core, which triggers the full preSeal teardown sequence
	if err := c.Seal(); err != nil {
		c.logger.Error("error during seal on shutdown", logger.Err(err))
		return err
	}

	c.logger.Info("core shutdown successfully")

	return nil
}

// CreateCore conducts static validations on the Core Config
// and returns an uninitialized core.
func CreateCore(conf *CoreConfig) (*Core, error) {
	if conf.HAPhysical != nil && conf.HAPhysical.HAEnabled() {
		if conf.RedirectAddr == "" {
			return nil, errors.New("missing API address, please set in configuration or via environment")
		}
	}

	// Validate the advertise addr if its given to us
	if conf.RedirectAddr != "" {
		u, err := url.Parse(conf.RedirectAddr)
		if err != nil {
			return nil, fmt.Errorf("redirect address is not valid url: %w", err)
		}

		if u.Scheme == "" {
			return nil, errors.New("redirect address must include scheme (ex. 'http')")
		}
	}

	// Make a default logger if not provided
	if conf.Logger == nil {
		conf.Logger, _ = logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	}

	// Instantiate a non-nil raw config if none is provided
	if conf.RawConfig == nil {
		conf.RawConfig = new(config.Config)
	}

	// secureRandomReader cannot be nil
	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var detectDeadlocks []string
	if conf.DetectDeadlocks != "" {
		detectDeadlocks = strings.Split(conf.DetectDeadlocks, ",")
		for k, v := range detectDeadlocks {
			detectDeadlocks[k] = strings.ToLower(strings.TrimSpace(v))
		}
	}

	// Use imported logging deadlock if requested
	var stateLock locking.RWMutex
	stateLock = &locking.SyncRWMutex{}

	for _, v := range detectDeadlocks {
		if v == "statelock" {
			stateLock = &locking.DeadlockRWMutex{}
		}
	}

	// Setup the core
	c := &Core{
		physical:                conf.Physical,
		underlyingPhysical:      conf.Physical,
		storageType:             conf.StorageType,
		redirectAddr:            conf.RedirectAddr,
		clusterAddr:             new(atomic.Value),
		seal:                    conf.Seal,
		stateLock:               stateLock,
		rawConfig:               new(atomic.Value),
		logger:                  conf.Logger,
		auditManager:            audit.NewAuditManager(conf.Logger.WithSystem("audit")),
		router:                  NewRouter(conf.Logger.WithSystem("router")),
		mounts:                  NewMountTable(),
		auth:                    NewMountTable(),
		audit:                   NewMountTable(),
		sealed:                  new(uint32),
		standbyStopCh:           new(atomic.Value),
		cachingDisabled:         conf.DisableCache,
		shutdownDoneCh:          new(atomic.Value),
		activeContextCancelFunc: new(atomic.Value),
		secureRandomReader:      conf.SecureRandomReader,
		keyRotateGracePeriod:    new(int64),
		detectDeadlocks:         detectDeadlocks,
	}

	if conf.ClusterAddr != "" {
		c.clusterAddr.Store(conf.ClusterAddr)
	}

	c.standby.Store(true)
	c.standbyStopCh.Store(make(chan struct{}, 1))
	atomic.StoreUint32(c.sealed, 1)

	c.shutdownDoneCh.Store(make(chan struct{}))

	c.SetConfig(conf.RawConfig)
	c.clusterConfig = parseClusterConfig(conf.RawConfig)

	// Load seal information.
	if c.seal == nil {
		wrapper := aead.NewWrapper()
		wrapper.SetConfig(context.Background())

		c.seal = NewDefaultSeal(seal.NewAccess(wrapper))
	}
	c.seal.SetCore(c)

	return c, nil
}

func coreInit(c *Core, conf *CoreConfig) error {
	phys := conf.Physical
	// Wrap the physical storage in a cache layer if enabled
	cacheLogger := c.logger.WithSystem("storage.cache")
	c.physical = phy.NewCache(phys, conf.CacheSize, cacheLogger, nil)
	c.physicalCache = c.physical.(physical.ToggleablePurgemonster)

	// Wrap in encoding checks
	if !conf.DisableKeyEncodingChecks {
		c.physical = physical.NewStorageEncoding(c.physical)
	}

	// if c.StandbyReadsEnabled() {
	// 	c.underlyingPhysical.(physical.CacheInvalidationBackend).HookInvalidate(c.Invalidate)
	// }

	return nil
}

// NewCore creates, initializes and configures a Warden node (core).
func NewCore(conf *CoreConfig) (*Core, error) {
	c, err := CreateCore(conf)
	if err != nil {
		return nil, err
	}

	err = coreInit(c, conf)
	if err != nil {
		return nil, err
	}

	// Construct a new AES-GCM barrier
	c.barrier, err = NewAESGCMBarrier(c.physical)
	if err != nil {
		return nil, fmt.Errorf("barrier setup failed: %w", err)
	}

	// Create TokenStore after barrier is initialized
	// This ensures the barrier is available for storage view creation
	tokenStoreConfig := DefaultTokenStoreConfig()
	// Apply ip_binding_policy from config if set
	if rawConf, ok := c.rawConfig.Load().(*config.Config); ok && rawConf != nil && rawConf.IPBindingPolicy != "" {
		tokenStoreConfig.IPBindingPolicy = IPBindingPolicy(rawConf.IPBindingPolicy)
	}
	tokenStore, err := NewTokenStore(c, tokenStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create token store: %w", err)
	}
	c.tokenStore = tokenStore

	// Create CredentialConfigStore after barrier is initialized
	credConfigStore, err := NewCredentialConfigStore(c, DefaultCredConfigStoreConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create credential config store: %w", err)
	}
	c.credConfigStore = credConfigStore

	// Create SkillStore (storage view is wired up at unseal time).
	c.skillStore = NewSkillStore(c)

	// Initialize global credential type and driver registries
	c.credentialTypeRegistry = credential.NewTypeRegistry()
	c.credentialDriverRegistry = credential.NewDriverRegistry(c.logger.WithSystem("credential.driver"))

	// Register builtin credential types and drivers
	if err := types.RegisterBuiltinTypes(c.credentialTypeRegistry); err != nil {
		return nil, fmt.Errorf("failed to register builtin credential types: %w", err)
	}
	if err := drivers.RegisterBuiltinDrivers(c.credentialDriverRegistry); err != nil {
		return nil, fmt.Errorf("failed to register builtin credential drivers: %w", err)
	}

	if conf.HAPhysical != nil && conf.HAPhysical.HAEnabled() {
		c.ha = conf.HAPhysical
	}

	// Provider backends
	c.configureProvider(conf.Providers)
	c.configureProviderSkills(conf.ProviderSkills)

	// Auth backends
	c.configureAuthMethods(conf.AuthMethods)

	// Audit backends
	c.configureAuditDevices(conf.AuditDevices)
	c.auditConfigDeclarations = conf.DeclarativeAuditDevices

	err = c.adjustForSealMigration(conf.UnwrapSeal)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Core) GetTokenStore() *TokenStore {
	return c.tokenStore
}

func (c *Core) configureProvider(backends map[string]logical.Factory) {
	providers := make(map[string]logical.Factory, len(backends))
	maps.Copy(providers, backends)
	c.providers = providers
}

func (c *Core) configureProviderSkills(skills map[string]string) {
	out := make(map[string]string, len(skills))
	maps.Copy(out, skills)
	c.providerSkills = out
}

func (c *Core) configureAuthMethods(backends map[string]logical.Factory) {
	auths := make(map[string]logical.Factory, len(backends))
	maps.Copy(auths, backends)
	c.authMethods = auths
}

func (c *Core) configureAuditDevices(backends map[string]audit.Factory) {
	audits := make(map[string]audit.Factory, len(backends))
	maps.Copy(audits, backends)
	c.auditDevices = audits
}

func (c *Core) CredentialTypeRegistry() *credential.TypeRegistry {
	return c.credentialTypeRegistry
}

func (c *Core) CredentialDriverRegistry() *credential.DriverRegistry {
	return c.credentialDriverRegistry
}

// IsInitialized returns whether warden init has been called
func (c *Core) IsInitialized() bool {
	c.initLock.RLock()
	defer c.initLock.RUnlock()
	return c.initialized
}

// MarkInitialized marks warden as initialized
func (c *Core) MarkInitialized() {
	c.initLock.Lock()
	defer c.initLock.Unlock()
	c.initialized = true
}

// loadTokensFromStorage loads all persisted tokens from storage into the token store cache.
// This is called during post-unseal to restore tokens after a restart.
func (c *Core) loadTokensFromStorage(ctx context.Context) error {
	if c.tokenStore == nil {
		return fmt.Errorf("token store not initialized")
	}

	return c.tokenStore.LoadFromStorage(ctx)
}

// setupExpirationManager creates and initializes the expiration manager for timer-based TTL enforcement.
// This provides guaranteed expiration of tokens and credentials regardless of cache activity.
func (c *Core) setupExpirationManager(ctx context.Context) error {
	c.logger.Info("setting up expiration manager")

	// Create storage view for expiration data
	expirationStorage := NewBarrierView(c.barrier, expirationStoragePath)

	// Create expiration manager with Core reference for namespace lookup and revocation
	c.expirationManager = NewExpirationManager(
		c,
		c.logger.WithSubsystem("expiration"),
		expirationStorage,
	)

	// Restore persisted expiration entries from storage
	if err := c.expirationManager.Restore(ctx); err != nil {
		c.logger.Warn("failed to restore expiration entries", logger.Err(err))
		// Don't fail startup for restoration errors
	}

	c.logger.Info("expiration manager setup complete")

	return nil
}

// revokeTokenByExpiration is called by the expiration manager when a token expires
func (c *Core) revokeTokenByExpiration(ctx context.Context, entry *ExpirationEntry) error {
	if c.tokenStore == nil {
		return fmt.Errorf("token store not initialized")
	}

	// Delegate to token store which handles cache and storage cleanup
	return c.tokenStore.RevokeByExpiration(entry.ID)
}

// revokeCredentialByExpiration is called by the expiration manager when a credential expires.
// This handles both cache-only (implicit auth) and persisted credentials.
// The credential manager compares CredentialID to decide whether to delete from cache.
func (c *Core) revokeCredentialByExpiration(ctx context.Context, entry *ExpirationEntry) error {
	if c.credentialManager == nil {
		return fmt.Errorf("credential manager not initialized")
	}
	// Delegate to credential manager which handles both revocation and cache cleanup
	// entry.ID is the CredentialID (UUID), entry.CacheKey is for cache lookup
	return c.credentialManager.RevokeByExpiration(ctx, entry.ID, entry.CacheKey, entry.LeaseID, entry.SourceName, entry.Revocable)
}

// stopExpirationManager stops the expiration manager during seal
func (c *Core) stopExpirationManager() error {
	if c.expirationManager != nil {
		c.expirationManager.Stop()
		c.expirationManager = nil
	}
	return nil
}

// GetExpirationManager returns the expiration manager (for subsystem integration)
func (c *Core) GetExpirationManager() *ExpirationManager {
	return c.expirationManager
}

// setupRotationManager creates and initializes the rotation manager for periodic
// credential source secret rotation (e.g., Vault AppRole secret_id).
func (c *Core) setupRotationManager(ctx context.Context) error {
	c.logger.Info("setting up rotation manager")

	// Create storage view for rotation data
	rotationStorage := NewBarrierView(c.barrier, rotationStoragePath)

	// Create rotation manager with Core reference for credential config access
	c.rotationManager = NewRotationManager(
		c,
		c.logger.WithSubsystem("rotation"),
		rotationStorage,
	)
	c.rotationManager.Start()

	// Restore persisted rotation entries from storage
	if err := c.rotationManager.Restore(ctx); err != nil {
		c.logger.Warn("failed to restore rotation entries", logger.Err(err))
		// Don't fail startup for restoration errors
	}

	c.logger.Info("rotation manager setup complete")

	return nil
}

// stopRotationManager stops the rotation manager during seal
func (c *Core) stopRotationManager() error {
	if c.rotationManager != nil {
		c.rotationManager.Stop()
		c.rotationManager = nil
	}
	return nil
}

// GetRotationManager returns the rotation manager (for subsystem integration)
func (c *Core) GetRotationManager() *RotationManager {
	return c.rotationManager
}

// setupOIDCIssuer constructs the OIDC issuer from its stored config during
// unseal. It is disabled by default: with no config (or Enabled=false) the
// issuer is left nil and the warden_identity mint path fails closed.
//
// When enabled, it loads the signing key from storage. If none exists yet, the
// active node generates and persists one; a standby leaves the issuer not-ready
// (it cannot write) and will activate on promotion, when unseal runs again as
// active. Key generation and persistence therefore happen only on the active node.
func (c *Core) setupOIDCIssuer(ctx context.Context, standby bool) error {
	// Serialize issuer setup/teardown so concurrent config writes (or a write racing
	// seal/promotion) cannot interleave rotation-loop start/stop and leak a goroutine.
	c.oidcSetupMu.Lock()
	defer c.oidcSetupMu.Unlock()

	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)

	// Stop the publisher-credential rotation loop BEFORE reading config and rebuilding
	// the publisher: joining it here guarantees no in-flight rotation can commit+delete
	// a key after we have already rebuilt the live publisher from a pre-rotation config
	// snapshot (which would leave the publisher holding a deleted key). It is restarted
	// at the end from the fresh config.
	c.stopPublisherCredRotation()

	cfg, err := loadIssuerConfig(ctx, storage)
	if err != nil {
		return err
	}
	if cfg == nil || !cfg.Enabled {
		c.stopOIDCKeyRotation() // never leak the loop when disabling
		// Drop any publisher-rotation schedule anchor so re-enabling the issuer later
		// starts a fresh period rather than firing off a stale timestamp (active only —
		// the active node owns this shared state).
		if !standby {
			if derr := clearPublisherRotationState(ctx, storage); derr != nil {
				c.logger.Warn("oidc issuer: publisher-credential rotation: clearing schedule anchor failed", logger.Err(derr))
			}
		}
		c.oidcMu.Lock()
		c.oidcIssuer = nil
		c.oidcPublisher = nil
		c.oidcMu.Unlock()
		return nil
	}

	// The Cache-Control for the published/served JWKS is derived from the JWKS
	// cache TTL so a cached copy never outlives the window in which a newly
	// published key must be fetched before it starts signing.
	cacheControl := oidcCacheControl(cfg.jwksCacheTTL())

	// A bad publisher config must NOT fail unseal — the built-in endpoint still
	// serves. It is validated up front on the config-write path instead, so a
	// persisted-but-invalid publisher (e.g. a directory that later disappears)
	// degrades to endpoint-only rather than bricking the node.
	publisher, perr := newJWKSPublisher(cfg.Publisher, cacheControl)
	if perr != nil {
		c.logger.Warn("oidc issuer: publisher config invalid; serving from the built-in endpoint only", logger.Err(perr))
		publisher = nil
	}

	issuer := NewOIDCIssuer(cfg.IssuerURL)
	issuer.SetAssertionTTL(cfg.assertionTTL())
	issuer.SetCacheControl(cfg.jwksCacheTTL())

	keysets, err := loadKeySet(ctx, storage)
	if err != nil {
		return err
	}
	if keysets == nil {
		keysets = make(map[string]*algKeyset)
	}
	// A keyset is complete only with both an active and a pre-published next key.
	incomplete := func(alg string) bool {
		ks := keysets[alg]
		return ks == nil || ks.active == nil || ks.next == nil
	}
	needsKeys := false
	for _, alg := range oidcSupportedAlgs {
		if incomplete(alg) {
			needsKeys = true
			break
		}
	}
	if needsKeys {
		if standby {
			// A standby cannot generate keys. Install whatever it loaded (which may
			// be a complete keyset for some algorithms and none for others) so those
			// keys still verify in-flight assertions; it stays not-ready until
			// promotion fills the gaps.
			c.logger.Warn("oidc issuer enabled but some signing keys are missing; standby stays not-ready until promotion")
			c.stopOIDCKeyRotation()
			issuer.RestoreKeys(keysets)
			c.oidcMu.Lock()
			c.oidcIssuer = issuer
			c.oidcPublisher = publisher
			c.oidcMu.Unlock()
			return nil
		}
		// Active node: generate the active key AND its pre-published successor for
		// every supported algorithm still missing one, so each next key is in the
		// JWKS from the first publish, a full rotation period before it ever signs.
		// (Also self-heals a keyset added after an algorithm becomes supported.)
		for _, alg := range oidcSupportedAlgs {
			if !incomplete(alg) {
				continue
			}
			active, err := generateSigningKey(alg)
			if err != nil {
				return err
			}
			next, err := generateSigningKey(alg)
			if err != nil {
				return err
			}
			keysets[alg] = &algKeyset{active: active, next: next}
			c.logger.Info("oidc issuer generated signing keys",
				logger.String("alg", alg), logger.String("active_kid", active.kid), logger.String("next_kid", next.kid))
		}
		if err := persistKeySet(ctx, storage, keysets); err != nil {
			return err
		}
	}
	issuer.RestoreKeys(keysets)

	c.oidcMu.Lock()
	c.oidcIssuer = issuer
	c.oidcPublisher = publisher
	c.oidcJWKSCacheTTL = cfg.jwksCacheTTL()
	c.oidcRetiredKeyGrace = cfg.retiredKeyGrace()
	c.oidcMu.Unlock()
	c.logger.Info("oidc issuer setup complete", logger.String("issuer", cfg.IssuerURL))

	// Push the current documents to the external surface on the active node.
	// Best-effort here: a publish failure must not fail unseal (the built-in
	// endpoint still serves), but the config-write path surfaces it explicitly.
	if !standby {
		if err := c.publishOIDCFor(ctx, issuer, publisher); err != nil {
			c.logger.Warn("oidc issuer: initial publish failed", logger.Err(err))
		}
	}

	// Signing-key rotation runs only on the active node. Restart it on every
	// (re)setup so a config change or promotion picks up the current settings.
	period := cfg.keyRotationPeriod()
	firstTick := oidcRotationFirstTick(keysets, period)
	c.startOIDCKeyRotation(standby, period, firstTick, issuer, publisher, cfg.jwksCacheTTL(), cfg.retiredKeyGrace())

	// Publisher-credential rotation (active node, credential-bearing publishers only).
	c.startPublisherCredRotation(standby, cfg.Publisher.rotationPeriod(), publisher)
	return nil
}

// publishOIDC pushes the current discovery + JWKS documents to the configured
// publisher, reading the current issuer/publisher under the lock.
func (c *Core) publishOIDC(ctx context.Context) error {
	c.oidcMu.RLock()
	issuer, publisher := c.oidcIssuer, c.oidcPublisher
	c.oidcMu.RUnlock()
	return c.publishOIDCFor(ctx, issuer, publisher)
}

// publishOIDCFor publishes a specific issuer's documents. It is a no-op when no
// publisher is configured or the issuer is not ready. Taking explicit arguments
// lets the rotation loop publish the issuer it was started with, never a
// concurrently-swapped one.
func (c *Core) publishOIDCFor(ctx context.Context, issuer *OIDCIssuer, publisher JWKSPublisher) error {
	if publisher == nil || issuer == nil || !issuer.Ready() {
		return nil
	}
	discovery, err := issuer.DiscoveryDocument(issuer.IssuerURL() + "/" + oidcJWKSObjectPath)
	if err != nil {
		return err
	}
	jwks, err := issuer.JWKS()
	if err != nil {
		return err
	}
	return publisher.Publish(ctx, discovery, jwks)
}

// startOIDCKeyRotation (re)starts the signing-key rotation loop. It runs only on
// the active node and only when a positive period is configured; any existing
// loop is stopped (and joined) first. The loop operates on the issuer/publisher
// it is handed, so a later config swap never affects an in-flight rotation. The
// context is parented on the active context so leadership loss cancels it.
func (c *Core) startOIDCKeyRotation(standby bool, period, firstTick time.Duration, issuer *OIDCIssuer, publisher JWKSPublisher, cacheTTL, grace time.Duration) {
	c.stopOIDCKeyRotation()
	if standby || issuer == nil {
		// A standby must not touch the active-node-owned status anchor.
		return
	}
	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	if period <= 0 {
		// Rotation disabled by config: drop any stale status anchor so a later re-enable
		// reseeds from the current key age instead of reporting a stale last_rotated_at.
		if err := clearOIDCKeyRotationState(c.activeContext, storage); err != nil {
			c.logger.Warn("oidc issuer: key rotation: clearing status anchor failed", logger.Err(err))
		}
		return
	}
	// Seed the status anchor (display only) if absent, from the loop's real schedule anchor
	// (earliest next-key createdAt), so next_rotation matches the loop's first tick.
	if err := c.seedOIDCKeyRotationState(c.activeContext, storage, issuer); err != nil {
		c.logger.Warn("oidc issuer: key rotation: seeding status anchor failed", logger.Err(err))
	}
	if firstTick < 0 {
		firstTick = 0
	}
	ctx, cancel := context.WithCancel(c.activeContext)
	done := make(chan struct{})
	c.oidcMu.Lock()
	c.oidcRotationCancel = cancel
	c.oidcRotationDone = done
	c.oidcMu.Unlock()
	go c.oidcKeyRotationLoop(ctx, done, period, firstTick, issuer, publisher, cacheTTL, grace)
	c.logger.Info("oidc issuer: signing-key rotation enabled", logger.String("period", period.String()))
}

// oidcRotationFirstTick returns the delay until the first rotation should fire.
//
// It anchors on the NEXT key's age, not the active key's: the next key was created
// exactly one rotation cycle before it should be promoted, so next.createdAt+period
// IS the correct next-rotation time — and it is stable across restarts. Anchoring
// on the active key would be wrong, because the active key was minted a full period
// earlier (as the previous cycle's next), so active.createdAt+period is already in
// the past and the loop would rotate immediately on every unseal/restart/promotion.
// The active key's age is only a fallback for the (setup-guaranteed impossible)
// case of an active node with no next key.
func oidcRotationFirstTick(keysets map[string]*algKeyset, period time.Duration) time.Duration {
	// Anchor on the EARLIEST next-key age across algorithms so no keyset rotates
	// late. Keysets are generated together at enable, so their ages are identical
	// in practice; the earliest is only distinct after a later self-heal.
	var anchor time.Time
	for _, ks := range keysets {
		age := ks.next
		if age == nil {
			age = ks.active
		}
		if age == nil {
			continue
		}
		if anchor.IsZero() || age.createdAt.Before(anchor) {
			anchor = age.createdAt
		}
	}
	if anchor.IsZero() {
		return 0
	}
	return time.Until(anchor.Add(period))
}

// stopOIDCKeyRotation cancels the rotation loop and waits for it to exit, so a
// demoted/sealing node never keeps rotating and clobbering the new active's keys.
func (c *Core) stopOIDCKeyRotation() {
	c.oidcMu.Lock()
	cancel := c.oidcRotationCancel
	done := c.oidcRotationDone
	c.oidcRotationCancel = nil
	c.oidcRotationDone = nil
	c.oidcMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (c *Core) oidcKeyRotationLoop(ctx context.Context, done chan struct{}, period, firstTick time.Duration, issuer *OIDCIssuer, publisher JWKSPublisher, cacheTTL, grace time.Duration) {
	defer close(done)
	timer := time.NewTimer(firstTick)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rotErr := c.rotateOIDCKey(ctx, issuer, publisher, cacheTTL, grace)
			// Record the outcome (skip if the loop is tearing down — ctx cancellation is
			// not a rotation failure worth persisting, and the state write would fail).
			if ctx.Err() == nil {
				c.recordOIDCKeyRotationOutcome(ctx, rotErr)
			}
			if rotErr != nil {
				c.logger.Warn("oidc issuer: key rotation failed", logger.Err(rotErr))
			}
			timer.Reset(period)
		}
	}
}

// rotateOIDCKey performs one signing-key rotation on the given issuer by promoting
// its pre-published next key. The next key has already been in the JWKS for a full
// rotation period, so promotion is an instant flip — no propagation wait in the
// steady state. The steps: (optionally) wait out the propagation floor if the next
// key is younger than the JWKS cache TTL, generate a fresh next key, PERSIST the
// post-rotation keyset BEFORE flipping in memory, flip, then publish once. The
// promoted key was persisted as `next` by the previous rotation and the fresh next
// is persisted here before it can ever be promoted, so Warden never signs with a
// key absent from storage.
func (c *Core) rotateOIDCKey(ctx context.Context, issuer *OIDCIssuer, publisher JWKSPublisher, cacheTTL, grace time.Duration) error {
	if issuer == nil || !issuer.Ready() {
		return nil
	}

	keysets := issuer.Keys()
	if len(keysets) == 0 {
		// Setup guarantees keys on the active node; this is a defensive guard.
		return fmt.Errorf("oidc issuer: cannot rotate with no keys")
	}

	// Propagation floor: a fresh next key must be published at least cacheTTL before
	// it signs, so any CDN cache and verifier have refreshed the JWKS. Wait out the
	// youngest next key across algorithms (same-age in practice, so usually a single
	// wait). In steady state each next is ~one rotation period old, so the remainder
	// is <= 0 and there is no wait; the floor only bites on cold start / a shrunk
	// period. Skipped when there is no external publisher (the endpoint serves live).
	// Only the supported algorithms are rotated (each is generatable). Iterating the
	// supported set rather than whatever storage held means a stray/unknown held alg
	// can never break rotation of the healthy ones; it is left untouched in the map.
	if publisher != nil && cacheTTL > 0 {
		var wait time.Duration
		for _, alg := range oidcSupportedAlgs {
			ks := keysets[alg]
			if ks == nil || ks.next == nil {
				return fmt.Errorf("oidc issuer: cannot rotate without a next %s key", alg)
			}
			if rem := cacheTTL - time.Since(ks.next.createdAt); rem > wait {
				wait = rem
			}
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				// Nothing to roll back — the next keys are durable and stay published.
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	// Bail if leadership was lost during the wait — a demoted node must not
	// persist/flip and race the new active.
	if err := ctx.Err(); err != nil {
		return err
	}

	if grace <= 0 {
		grace = defaultRetiredKeyGrace
	}
	cutoff := time.Now().Add(-(issuer.AssertionTTL() + grace))

	// Compute each supported algorithm's post-rotation keyset (promoted active, fresh
	// next, pruned retired) WITHOUT mutating the issuer, then persist the whole map
	// BEFORE flipping in memory. On failure nothing has mutated in memory and the
	// current keyset is still in storage, so a retry next tick is safe.
	newNextByAlg := make(map[string]*signingKey, len(oidcSupportedAlgs))
	for _, alg := range oidcSupportedAlgs {
		if keysets[alg] == nil {
			// Ready() guarantees every supported alg is present; defensive.
			return fmt.Errorf("oidc issuer: missing %s keyset", alg)
		}
		newNext, err := generateSigningKey(alg)
		if err != nil {
			return err
		}
		newNextByAlg[alg] = newNext
		pendingActive, pendingRetired, err := issuer.PendingRotation(alg, cutoff)
		if err != nil {
			return err
		}
		keysets[alg] = &algKeyset{active: pendingActive, next: newNext, retired: pendingRetired}
	}

	storage := NewBarrierView(c.barrier, oidcIssuerStorePrefix)
	if err := persistKeySet(ctx, storage, keysets); err != nil {
		return fmt.Errorf("persist rotated keyset: %w", err)
	}

	for alg, newNext := range newNextByAlg {
		if err := issuer.Rotate(alg, newNext, cutoff); err != nil {
			return err
		}
	}
	if err := c.publishOIDCFor(ctx, issuer, publisher); err != nil {
		c.logger.Warn("oidc issuer: republish after rotation failed", logger.Err(err))
	}
	c.logger.Info("oidc issuer rotated signing keys", logger.Int("algorithms", len(keysets)))
	return nil
}

// stopOIDCIssuer tears down the issuer during seal.
func (c *Core) stopOIDCIssuer() error {
	c.oidcSetupMu.Lock()
	defer c.oidcSetupMu.Unlock()
	c.stopOIDCKeyRotation()
	c.stopPublisherCredRotation()
	c.oidcMu.Lock()
	c.oidcIssuer = nil
	c.oidcPublisher = nil
	c.oidcMu.Unlock()
	return nil
}

// OIDCIssuer returns the configured OIDC issuer, or nil when it is disabled.
func (c *Core) OIDCIssuer() *OIDCIssuer {
	c.oidcMu.RLock()
	defer c.oidcMu.RUnlock()
	return c.oidcIssuer
}

// RegisterShutdownHook registers a named shutdown hook to run during preSeal.
// The key ensures idempotency — the same key overwrites the previous hook.
func (c *Core) RegisterShutdownHook(key string, fn func()) {
	c.shutdownHooksMu.Lock()
	defer c.shutdownHooksMu.Unlock()
	if c.shutdownHooks == nil {
		c.shutdownHooks = make(map[string]func())
	}
	c.shutdownHooks[key] = fn
}

// runShutdownHooks runs all registered shutdown hooks and clears the registry.
func (c *Core) runShutdownHooks() {
	c.shutdownHooksMu.Lock()
	hooks := c.shutdownHooks
	c.shutdownHooks = nil
	c.shutdownHooksMu.Unlock()

	for key, fn := range hooks {
		c.logger.Debug("running shutdown hook", logger.String("key", key))
		fn()
	}
}

// SetConfig sets core's config object to the newly provided config.
func (c *Core) SetConfig(conf *config.Config) {
	c.rawConfig.Store(conf)
}

// ClusterConfig returns the resolved cluster configuration.
func (c *Core) ClusterConfig() ClusterConfig {
	return c.clusterConfig
}

// parseClusterConfig builds a ClusterConfig from the raw Config, falling back
// to defaults for any field not explicitly set.
func parseClusterConfig(conf *config.Config) ClusterConfig {
	cc := DefaultClusterConfig()
	if conf == nil {
		return cc
	}

	applyDuration := func(src string, dst *time.Duration) {
		if src == "" {
			return
		}
		if d, err := time.ParseDuration(src); err == nil {
			*dst = d
		}
	}

	applyDuration(conf.GoroutineShutdownTimeout, &cc.GoroutineShutdownTimeout)
	applyDuration(conf.LockAcquisitionTimeout, &cc.LockAcquisitionTimeout)
	applyDuration(conf.LeaderCleanupInterval, &cc.LeaderCleanupInterval)
	applyDuration(conf.StepDownStateLockTimeout, &cc.StepDownStateLockTimeout)
	applyDuration(conf.LeaderLookupTimeout, &cc.LeaderLookupTimeout)
	applyDuration(conf.ClockSkewGrace, &cc.ClockSkewGrace)
	applyDuration(conf.ClusterListenerReadTimeout, &cc.ClusterListenerReadTimeout)
	applyDuration(conf.ClusterListenerWriteTimeout, &cc.ClusterListenerWriteTimeout)
	applyDuration(conf.ForwardingTimeout, &cc.ForwardingTimeout)

	return cc
}

// CredSourceRotationPeriodBounds returns the configured min and max rotation
// period bounds for credential sources. Falls back to defaults if not set.
func (c *Core) CredSourceRotationPeriodBounds() (min, max time.Duration) {
	min = DefaultMinCredSourceRotationPeriod
	max = DefaultMaxCredSourceRotationPeriod

	conf, ok := c.rawConfig.Load().(*config.Config)
	if !ok || conf == nil {
		return
	}

	if conf.MinCredSourceRotationPeriod != "" {
		if parsed, err := time.ParseDuration(conf.MinCredSourceRotationPeriod); err == nil {
			min = parsed
		}
	}
	if conf.MaxCredSourceRotationPeriod != "" {
		if parsed, err := time.ParseDuration(conf.MaxCredSourceRotationPeriod); err == nil {
			max = parsed
		}
	}

	return
}

// CredSpecRotationPeriodBounds returns the configured min and max rotation
// period bounds for credential specs. Falls back to defaults if not set.
func (c *Core) CredSpecRotationPeriodBounds() (min, max time.Duration) {
	min = DefaultMinCredSpecRotationPeriod
	max = DefaultMaxCredSpecRotationPeriod

	conf, ok := c.rawConfig.Load().(*config.Config)
	if !ok || conf == nil {
		return
	}

	if conf.MinCredSpecRotationPeriod != "" {
		if parsed, err := time.ParseDuration(conf.MinCredSpecRotationPeriod); err == nil {
			min = parsed
		}
	}
	if conf.MaxCredSpecRotationPeriod != "" {
		if parsed, err := time.ParseDuration(conf.MaxCredSpecRotationPeriod); err == nil {
			max = parsed
		}
	}

	return
}

func (c *Core) PhysicalSealConfigs(ctx context.Context) (*SealConfig, *SealConfig, error) {
	pe, err := c.physical.Get(ctx, barrierSealConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch barrier seal configuration at migration check time: %w", err)
	}
	if pe == nil {
		return nil, nil, nil
	}

	barrierConf := new(SealConfig)

	if err := jsonutil.DecodeJSON(pe.Value, barrierConf); err != nil {
		return nil, nil, fmt.Errorf("failed to decode barrier seal configuration at migration check time: %w", err)
	}
	err = barrierConf.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate barrier seal configuration at migration check time: %w", err)
	}
	// In older versions of warden the default seal would not store a type. This
	// is here to offer backwards compatibility for older seal configs.
	if barrierConf.Type == "" {
		barrierConf.Type = seal.WrapperTypeShamir.String()
	}

	var recoveryConf *SealConfig
	pe, err = c.physical.Get(ctx, recoverySealConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch seal configuration at migration check time: %w", err)
	}
	if pe != nil {
		recoveryConf = &SealConfig{}
		if err := jsonutil.DecodeJSON(pe.Value, recoveryConf); err != nil {
			return nil, nil, fmt.Errorf("failed to decode seal configuration at migration check time: %w", err)
		}
		err = recoveryConf.ValidateRecovery()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to validate seal configuration at migration check time: %w", err)
		}
		// In older versions of warden the default seal would not store a type. This
		// is here to offer backwards compatibility for older seal configs.
		if recoveryConf.Type == "" {
			recoveryConf.Type = seal.WrapperTypeShamir.String()
		}
	}

	return barrierConf, recoveryConf, nil
}

// adjustForSealMigration takes the unwrapSeal, which is nil if (a) we're not
// configured for seal migration or (b) we might be doing a seal migration away
// from shamir.  It will only be non-nil if there is a configured seal with
// the config key disabled=true, which implies a migration away from autoseal.
//
// For case (a), the common case, we expect that the stored barrier
// config matches the seal type, in which case we simply return nil.  If they
// don't match, and the stored seal config is of type Shamir but the configured
// seal is not Shamir, that is case (b) and we make an unwrapSeal of type Shamir.
// Any other unwrapSeal=nil scenario is treated as an error.
//
// Given a non-nil unwrapSeal or case (b), we setup c.migrationInfo to prepare
// for a migration upon receiving a valid migration unseal request.  We cannot
// check at this time for already performed (or incomplete) migrations because
// we haven't yet been unsealed, so we have no way of checking whether a
// shamir seal works to read stored seal-encrypted data.
//
// The assumption throughout is that the very last step of seal migration is
// to write the new barrier/recovery stored seal config.
func (c *Core) adjustForSealMigration(unwrapSeal Seal) error {
	ctx := context.Background()
	existBarrierSealConfig, existRecoverySealConfig, err := c.PhysicalSealConfigs(ctx)
	if err != nil {
		return fmt.Errorf("Error checking for existing seal: %s", err)
	}

	// If we don't have an existing config skip out
	if existBarrierSealConfig == nil {
		return nil
	}

	if unwrapSeal == nil {
		// With unwrapSeal==nil, either we're not migrating, or we're migrating
		// from shamir.

		switch {
		case existBarrierSealConfig.Type == c.seal.BarrierType().String():
			// We have the same barrier type and the unwrap seal is nil so we're not
			// migrating from same to same, IOW we assume it's not a migration.
			return nil
		case c.seal.BarrierType() == seal.WrapperTypeShamir:
			// The stored barrier config is not shamir, there is no disabled seal
			// in config, and either no configured seal (which equates to Shamir)
			// or an explicitly configured Shamir seal.
			return fmt.Errorf("cannot seal migrate from %q to Shamir, no disabled seal in configuration",
				existBarrierSealConfig.Type)
		case existBarrierSealConfig.Type == seal.WrapperTypeShamir.String():
			// The configured seal is not Shamir, the stored seal config is Shamir.
			// This is a migration away from Shamir.
			unwrapSeal = NewDefaultSeal(seal.NewAccess(aead.NewWrapper()))
		default:
			// We know at this point that there is a configured non-Shamir seal,
			// that it does not match the stored non-Shamir seal config, and that
			// there is no explicit disabled seal stanza.
			return fmt.Errorf("cannot seal migrate from %q to %q, no disabled seal in configuration",
				existBarrierSealConfig.Type, c.seal.BarrierType())
		}
	} else {
		// If we're not coming from Shamir we expect the previous seal to be
		// in the config and disabled.

		if unwrapSeal.BarrierType() == seal.WrapperTypeShamir {
			//nolint:staticcheck // Shamir is a proper noun
			return errors.New("Shamir seals cannot be set disabled (they should simply not be set)")
		}
	}

	// If we've reached this point it's a migration attempt and we should have both
	// c.migrationInfo.seal (old seal) and c.seal (new seal) populated.
	unwrapSeal.SetCore(c)

	if existBarrierSealConfig.Type != seal.WrapperTypeShamir.String() && existRecoverySealConfig == nil {
		return errors.New("recovery seal configuration not found for existing seal")
	}

	c.migrationInfo = &migrationInformation{
		seal: unwrapSeal,
	}
	if existBarrierSealConfig.Type != c.seal.BarrierType().String() {
		// It's unnecessary to call this when doing an auto->auto
		// same-seal-type migration, since they'll have the same configs before
		// and after migration.
		c.adjustSealConfigDuringMigration(existBarrierSealConfig, existRecoverySealConfig)
	}
	c.logger.Warn("entering seal migration mode; Warden will not automatically unseal even if using an autoseal",
		logger.Any("from_barrier_type", c.migrationInfo.seal.BarrierType()),
		logger.Any("to_barrier_type", c.seal.BarrierType()),
	)

	return nil
}

func (c *Core) adjustSealConfigDuringMigration(existBarrierSealConfig, existRecoverySealConfig *SealConfig) {
	switch {
	case c.migrationInfo.seal.RecoveryKeySupported() && existRecoverySealConfig != nil:
		// Migrating from auto->shamir, clone auto's recovery config and set
		// stored keys to 1.  Unless the recover config doesn't exist, in which
		// case the migration is assumed to already have been performed.
		newSealConfig := existRecoverySealConfig.Clone()
		newSealConfig.StoredShares = 1
		c.seal.SetCachedBarrierConfig(newSealConfig)
	case !c.migrationInfo.seal.RecoveryKeySupported() && c.seal.RecoveryKeySupported():
		// Migrating from shamir->auto, set a new barrier config and set
		// recovery config to a clone of shamir's barrier config with stored
		// keys set to 0.
		newBarrierSealConfig := &SealConfig{
			Type:            c.seal.BarrierType().String(),
			SecretShares:    1,
			SecretThreshold: 1,
			StoredShares:    1,
		}
		c.seal.SetCachedBarrierConfig(newBarrierSealConfig)

		newRecoveryConfig := existBarrierSealConfig.Clone()
		newRecoveryConfig.StoredShares = 0
		c.seal.SetCachedRecoveryConfig(newRecoveryConfig)
	}
}

func (c *Core) SealAccess() *SealAccess {
	return NewSealAccess(c.seal)
}

// Sealed checks if Warden is current sealed
func (c *Core) Sealed() bool {
	return atomic.LoadUint32(c.sealed) == 1
}

// Seal seals the Core, preventing further operations until unsealed
func (c *Core) Seal() error {
	c.stateLock.Lock()
	defer c.stateLock.Unlock()

	if c.Sealed() {
		return nil
	}

	c.logger.Info("sealing core")

	// Run pre-seal teardown
	if err := c.preSeal(); err != nil {
		c.logger.Error("error during pre-seal teardown", logger.Err(err))
	}

	// Seal the barrier
	if err := c.barrier.Seal(); err != nil {
		c.logger.Error("error sealing barrier", logger.Err(err))
		return err
	}

	// Mark as sealed
	atomic.StoreUint32(c.sealed, 1)

	c.logger.Info("core sealed")
	return nil
}

// unsealInternal takes in the root key and attempts to unseal the barrier.
// N.B.: This must be called with the state write lock held.
func (c *Core) unsealInternal(ctx context.Context, rootKey []byte) error {
	// Attempt to unlock
	if err := c.barrier.Unseal(ctx, rootKey); err != nil {
		return err
	}

	// Do post-unseal setup if HA is not enabled
	if c.ha == nil {
		ctx, ctxCancel := context.WithCancel(namespace.RootContext(context.TODO()))
		if err := c.postUnseal(ctx, ctxCancel, standardUnsealStrategy{}); err != nil {
			c.logger.Error("post-unseal setup failed", logger.Err(err))
			c.barrier.Seal()
			c.logger.Warn("warden is sealed")
			return err
		}

		// Force a cache bust here, which will also run migration code
		if c.seal.RecoveryKeySupported() {
			c.seal.SetRecoveryConfig(ctx, nil)
		}

		c.standby.Store(false)
	} else {
		// Go to standby mode, wait until we are active to unseal
		c.standbyDoneCh = make(chan struct{})
		c.manualStepDownCh = make(chan struct{}, 1)
		c.standbyRestartCh = make(chan struct{}, 1)
		c.standbyStopCh.Store(make(chan struct{}, 1))
		go c.runStandby(c.standbyDoneCh, c.manualStepDownCh, c.standbyStopCh.Load().(chan struct{}))
	}

	// Success!
	atomic.StoreUint32(c.sealed, 0)
	//c.metricSink.SetGaugeWithLabels([]string{"core", "unsealed"}, 1, nil)

	c.logger.Info("warden is unsealed")

	return nil
}

func (c *Core) Logger() *logger.GatedLogger {
	return c.logger
}

// postUnseal is invoked on the active node, and performance standby nodes,
// after the barrier is unsealed, but before
// allowing any user operations. This allows us to setup any state that
// requires Warden to be unsealed such as mount tables
func (c *Core) postUnseal(ctx context.Context, ctxCancelFunc context.CancelFunc, unsealer UnsealStrategy) (retErr error) {
	// metrics.MeasureSince([]string{"core", "post_unseal"}, time.Now())

	// Clear any out
	c.postUnsealFuncs = nil

	// Create a new request context
	c.activeContext = ctx
	c.activeContextCancelFunc.Store(ctxCancelFunc)

	defer func() {
		if retErr != nil {
			ctxCancelFunc()
			_ = c.preSeal()
		}
	}()
	c.logger.Info("post-unseal setup starting")

	// Enable the cache
	c.physicalCache.Purge(ctx)
	if !c.cachingDisabled {
		c.physicalCache.SetEnabled(true)
	}

	// Purge these for safety in case of a rotation
	_ = c.seal.SetBarrierConfig(ctx, nil)
	if c.seal.RecoveryKeySupported() {
		_ = c.seal.SetRecoveryConfig(ctx, nil)
	}

	if err := unsealer.unseal(ctx, c.logger, c); err != nil {
		return err
	}

	// Automatically re-encrypt the keys used for auto unsealing when the
	// seal's encryption key changes. The regular rotation of cryptographic
	// keys is a NIST recommendation. Access to prior keys for decryption
	// is normally supported for a configurable time period. Re-encrypting
	// the keys used for auto unsealing ensures Warden and its data will
	// continue to be accessible even after prior seal keys are destroyed.
	if seal, ok := c.seal.(*autoSeal); ok {
		if err := seal.UpgradeKeys(c.activeContext); err != nil {
			c.logger.Warn("post-unseal upgrade seal keys failed",
				logger.Err(err),
			)
		}

		// Start a periodic but infrequent heartbeat to detect auto-seal backend outages at runtime rather than being
		// surprised by this at the next need to unseal.
		seal.StartHealthCheck()
	}

	// This is intentionally the last block in this function. We want to allow
	// writes just before allowing client requests, to ensure everything has
	// been set up properly before any writes can have happened.
	//
	// Use a small temporary worker pool to run postUnsealFuncs in parallel
	postUnsealFuncConcurrency := runtime.NumCPU() * 2
	if v := api.ReadWardenVariable("WARDEN_POSTUNSEAL_FUNC_CONCURRENCY"); v != "" {
		pv, err := strconv.Atoi(v)
		if err != nil || pv < 1 {
			c.logger.Warn("invalid value for WARDEN_POSTUNSEAL_FUNC_CONCURRENCY, must be a positive integer",
				logger.Err(err),
				logger.Any("value", pv),
			)
		} else {
			postUnsealFuncConcurrency = pv
		}
	}
	if postUnsealFuncConcurrency <= 1 {
		// Out of paranoia, keep the old logic for parallism=1
		for _, v := range c.postUnsealFuncs {
			v()
		}
	} else {
		jobs := make(chan func())
		var wg sync.WaitGroup
		for i := 0; i < postUnsealFuncConcurrency; i++ {
			go func() {
				for v := range jobs {
					func() {
						defer func() {
							if r := recover(); r != nil {
								c.logger.Error("panic in postUnseal func", logger.Any("panic", r))
							}
							wg.Done()
						}()
						v()
					}()
				}
			}()
		}
		for _, v := range c.postUnsealFuncs {
			wg.Add(1)
			jobs <- v
		}
		wg.Wait()
		close(jobs)
	}

	c.logger.Info("post-unseal setup complete")
	return nil
}

// preSeal is invoked before the barrier is sealed, allowing
// for any state teardown required.
func (c *Core) preSeal() error {
	//defer metrics.MeasureSince([]string{"core", "pre_seal"}, time.Now())
	c.logger.Info("pre-seal teardown starting")

	if seal, ok := c.seal.(*autoSeal); ok {
		seal.StopHealthCheck()
	}
	// Clear any pending funcs
	c.postUnsealFuncs = nil
	c.activeTime = time.Time{}

	var result error

	if err := c.teardownAudits(context.Background()); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down audits: %w", err))
	}
	if err := c.stopExpirationManager(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error stopping expiration manager: %w", err))
	}
	if err := c.stopRotationManager(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error stopping rotation manager: %w", err))
	}
	if err := c.stopOIDCIssuer(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error stopping oidc issuer: %w", err))
	}

	if err := c.teardownPolicyStore(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down policy store: %w", err))
	}

	// Unload auth BEFORE mounts: c.unloadMounts resets the router and clears
	// c.systemBarrierView (shared global state), and auth backends need to
	// run their Cleanup() against a still-populated router.
	if err := c.unloadAuth(context.Background()); err != nil {
		c.logger.Error("error unloading auth methods", logger.Err(err))
		return fmt.Errorf("error unloading auth methods: %w", err)
	}

	if err := c.unloadMounts(context.Background()); err != nil {
		c.logger.Error("error unloading mounts", logger.Err(err))
		return fmt.Errorf("error unloading mounts: %w", err)
	}

	// Run process-level shutdown hooks (e.g., transport cleanup) after all
	// mounts are unloaded so no in-flight requests use the resources.
	c.runShutdownHooks()

	if err := c.teardownNamespaceStore(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down namespace store: %w", err))
		return result
	}

	// Unload tokens from cache (they remain in storage for next unseal)
	if c.tokenStore != nil {
		c.tokenStore.UnloadFromCache()
	}

	// Unload credential configs from cache (they remain in storage for next unseal)
	if err := c.teardownCredentialConfigStore(); err != nil {
		c.logger.Warn("error tearing down credential config store", logger.Err(err))
	}

	// Unload skill store caches (records remain in storage for next unseal).
	if err := c.teardownSkillStore(); err != nil {
		c.logger.Warn("error tearing down skill store", logger.Err(err))
	}

	// Stop all credential managers
	if err := c.teardownCredentialManager(); err != nil {
		c.logger.Warn("error tearing down credential managers", logger.Err(err))
	}

	// Clear cluster TLS identity so it's regenerated on next activation.
	c.clearClusterTLS()

	c.physicalCache.SetEnabled(false)
	c.physicalCache.Purge(context.Background())

	c.logger.Info("pre-seal teardown complete")
	return nil
}

type UnsealStrategy interface {
	unseal(context.Context, *logger.GatedLogger, *Core) error
}

type standardUnsealStrategy struct {
	// Inherit read-only unseal methods
	readonlyUnsealStrategy
}

func (s standardUnsealStrategy) unseal(ctx context.Context, logger *logger.GatedLogger, c *Core) error {
	c.logger.Debug("standard unseal starting")

	c.activeTime = time.Now().UTC()

	if err := s.unsealShared(ctx, logger, c, false /* active */); err != nil {
		return err
	}

	return nil
}

// readonlyUnsealStrategy is called directly on standby nodes and indirectly
// (via standardUnsealStrategy) on active nodes to handle the core shared
// unseal work: startup of various internal subsystems, mounts, &c.
type readonlyUnsealStrategy struct{}

func (s readonlyUnsealStrategy) unseal(ctx context.Context, logger *logger.GatedLogger, c *Core) error {
	c.logger.Debug("read-only unseal starting")
	return s.unsealShared(ctx, logger, c, true /* standby */)
}

func (readonlyUnsealStrategy) unsealShared(ctx context.Context, log *logger.GatedLogger, c *Core, standby bool) error {

	if err := c.setupNamespaceStore(ctx); err != nil {
		return err
	}
	if err := c.setupPolicyStore(ctx); err != nil {
		return err
	}
	if err := c.setupCredentialConfigStore(ctx); err != nil {
		return err
	}
	if err := c.setupCredentialManager(ctx); err != nil {
		return err
	}
	if err := c.setupSkillStore(ctx); err != nil {
		return err
	}

	// Setup expiration manager for timer-based token/credential expiration
	// Note: ExpirationManager handles all background cleanup (no separate cleanup goroutine)
	if err := c.setupExpirationManager(ctx); err != nil {
		return err
	}

	// Wire up credential manager to expiration manager for timer-based TTL enforcement
	// This allows credential manager to register newly issued credentials for expiration
	c.credentialManager.SetExpirationRegistrar(c.expirationManager)

	// Setup rotation manager for periodic credential source secret rotation
	// (e.g., Vault AppRole secret_id rotation)
	if err := c.setupRotationManager(ctx); err != nil {
		return err
	}

	// Wire up credential config store to rotation manager for source rotation registration
	c.credConfigStore.SetRotationManager(c.rotationManager)

	// Setup the OIDC issuer (Workload Identity Federation). Disabled by default;
	// generates/persists a signing key only on the active node.
	if err := c.setupOIDCIssuer(ctx, standby); err != nil {
		return err
	}

	if err := c.loadMounts(ctx); err != nil {
		return err
	}
	if err := c.setupMounts(ctx); err != nil {
		return err
	}

	// Auth methods are loaded after the provider/system mounts so the router
	// and system backend are live before any auth backend's Initialize()
	// runs. Mirrors OpenBao's postUnseal ordering.
	if err := c.loadAuth(ctx); err != nil {
		return err
	}
	if err := c.setupAuth(ctx); err != nil {
		return err
	}

	if err := c.loadTokensFromStorage(ctx); err != nil {
		c.logger.Warn("failed to load tokens from storage", logger.Err(err))
	}

	err := c.loadAudits(ctx)
	if err != nil {
		return err
	}

	return nil
}
