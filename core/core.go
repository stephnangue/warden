package core

import (
	"context"
	"crypto/rand"
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
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/locking"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/credential/types"
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

	// ForwardSSCTokenToActive is the value that must be set in the
	// forwardToActive to trigger forwarding if a perf standby encounters
	// an SSC Token that it does not have the WAL state for.
	ForwardSSCTokenToActive = "new_token"
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

	auditDevices map[string]audit.Factory

	authMethods map[string]logical.Factory

	providers map[string]logical.Factory

	auditManager audit.AuditManager

	audit *MountTable

	// auditLock is used to ensure that the audit table does not
	// change underneath a calling function
	auditLock sync.RWMutex

	router *Router

	mounts *MountTable

	// mountsLock is used to ensure that the mounts table does not
	// change underneath a calling function
	mountsLock locking.DeadlockRWMutex

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

	standby              atomic.Bool
	standbyDoneCh        chan struct{}
	standbyStopCh        *atomic.Value
	standbyRestartCh     *atomic.Value
	manualStepDownCh     chan struct{}
	keepHALockOnStepDown *uint32
	heldHALock           physical.Lock

	// shutdownDoneCh is used to notify when core.Shutdown() completes.
	// core.Shutdown() is typically issued in a goroutine to allow Warden to
	// release the stateLock. This channel is marked atomic to prevent race
	// conditions.
	shutdownDoneCh *atomic.Value

	// redirectAddr is the address we advertise as leader if held
	redirectAddr string

	// clusterAddr is the address we use for clustering
	clusterAddr *atomic.Value

	// stateLock protects mutable state
	stateLock locking.RWMutex
	sealed    *uint32

	// systemBackend is the backend which is used to manage internal operations
	systemBackend *SystemBackend

	// transparentAuthGroup ensures only one implicit auth per JWT to prevent
	// duplicate token creation when concurrent requests arrive with the same JWT
	transparentAuthGroup singleflight.Group
}

type CoreConfig struct {
	RawConfig *config.Config

	AuditDevices map[string]audit.Factory

	AuthMethods map[string]logical.Factory

	Providers map[string]logical.Factory

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
	c.logger.Info("Shutting down the core")

	// Stop expiration manager first to prevent new expirations during shutdown
	if c.expirationManager != nil {
		c.expirationManager.Stop()
	}

	c.tokenStore.Close()

	c.logger.Info("Core shutdown successfully")

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
		audit:                   NewMountTable(),
		sealed:                  new(uint32),
		standbyStopCh:           new(atomic.Value),
		standbyRestartCh:        new(atomic.Value),
		cachingDisabled:         conf.DisableCache,
		shutdownDoneCh:          new(atomic.Value),
		keepHALockOnStepDown:    new(uint32),
		activeContextCancelFunc: new(atomic.Value),
		secureRandomReader:      conf.SecureRandomReader,
		keyRotateGracePeriod:    new(int64),
		detectDeadlocks:         detectDeadlocks,
	}

	c.standby.Store(true)
	c.standbyStopCh.Store(make(chan struct{}, 1))
	c.standbyRestartCh.Store(make(chan struct{}, 1))
	atomic.StoreUint32(c.sealed, 1)

	c.shutdownDoneCh.Store(make(chan struct{}))

	c.SetConfig(conf.RawConfig)

	// Load seal information.
	if c.seal == nil {
		wrapper := aeadwrapper.NewShamirWrapper()
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
	tokenStore, err := NewTokenStore(c, DefaultTokenStoreConfig())
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

	// Initialize global credential type and driver registries
	c.credentialTypeRegistry = credential.NewTypeRegistry()
	c.credentialDriverRegistry = credential.NewDriverRegistry()

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

	// Auth backends
	c.configureAuthMethods(conf.AuthMethods)

	// Audit backends
	c.configureAuditDevices(conf.AuditDevices)

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
// This handles both cache-only (transparent mode) and persisted credentials.
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

// SetConfig sets core's config object to the newly provided config.
func (c *Core) SetConfig(conf *config.Config) {
	c.rawConfig.Store(conf)
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
		barrierConf.Type = wrapping.WrapperTypeShamir.String()
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
			recoveryConf.Type = wrapping.WrapperTypeShamir.String()
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
		case c.seal.BarrierType() == wrapping.WrapperTypeShamir:
			// The stored barrier config is not shamir, there is no disabled seal
			// in config, and either no configured seal (which equates to Shamir)
			// or an explicitly configured Shamir seal.
			return fmt.Errorf("cannot seal migrate from %q to Shamir, no disabled seal in configuration",
				existBarrierSealConfig.Type)
		case existBarrierSealConfig.Type == wrapping.WrapperTypeShamir.String():
			// The configured seal is not Shamir, the stored seal config is Shamir.
			// This is a migration away from Shamir.
			unwrapSeal = NewDefaultSeal(seal.NewAccess(aeadwrapper.NewShamirWrapper()))
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

		if unwrapSeal.BarrierType() == wrapping.WrapperTypeShamir {
			//nolint:staticcheck // Shamir is a proper noun
			return errors.New("Shamir seals cannot be set disabled (they should simply not be set)")
		}
	}

	// If we've reached this point it's a migration attempt and we should have both
	// c.migrationInfo.seal (old seal) and c.seal (new seal) populated.
	unwrapSeal.SetCore(c)

	if existBarrierSealConfig.Type != wrapping.WrapperTypeShamir.String() && existRecoverySealConfig == nil {
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

	// if err := c.startClusterListener(ctx); err != nil {
	// 	return err
	// }

	// Do post-unseal setup if HA is not enabled
	if c.ha == nil {
		// We still need to set up cluster info even if it's not part of a
		// cluster right now. This also populates the cached cluster object.
		// if err := c.setupCluster(ctx); err != nil {
		// 	c.logger.Error("cluster setup failed", logger.Err(err),)
		// 	c.barrier.Seal()
		// 	c.logger.Warn("warden is sealed")
		// 	return err
		// }

		// if err := c.migrateSeal(ctx); err != nil {
		// 	c.logger.Error("seal migration error", logger.Err(err))
		// 	c.barrier.Seal()
		// 	c.logger.Warn("warden is sealed")
		// 	return err
		// }

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
		c.standbyStopCh.Store(make(chan struct{}, 1))
		c.standbyRestartCh.Store(make(chan struct{}, 1))
		//go c.runStandby(c.standbyDoneCh, c.manualStepDownCh, c.standbyStopCh.Load().(chan struct{}), c.standbyRestartCh.Load().(chan struct{}))
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
					v()
					wg.Done()
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

	// // Clear any rotation progress
	// c.rootRotationConfig = nil
	// c.recoveryRotationConfig = nil

	// if c.metricsCh != nil {
	// 	close(c.metricsCh)
	// 	c.metricsCh = nil
	// }
	var result error

	// c.stopForwarding()
	// c.stopRaftActiveNode()
	// c.cancelNamespaceDeletion()

	// if err := c.invalidations.Stop(); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error tearing down invalidations: %w", err))
	// }
	if err := c.teardownAudits(context.Background()); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down audits: %w", err))
	}
	if err := c.stopExpirationManager(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error stopping expiration manager: %w", err))
	}
	// if err := c.teardownCredentials(context.Background()); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error tearing down credentials: %w", err))
	// }
	if err := c.teardownPolicyStore(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down policy store: %w", err))
	}
	// if err := c.stopRollback(); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error stopping rollback: %w", err))
	// }
	if err := c.unloadMounts(context.Background()); err != nil {
		c.logger.Error("error unloading mounts", logger.Err(err))
		return fmt.Errorf("error unloading mounts: %w", err)
	}
	// if err := c.teardownLoginMFA(); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error tearing down login MFA: %w", err))
	// }
	if err := c.teardownNamespaceStore(); err != nil {
		result = multierror.Append(result, fmt.Errorf("error tearing down namespace store: %w", err))
		return result
	}

	// if c.autoRotateCancel != nil {
	// 	c.autoRotateCancel()
	// 	c.autoRotateCancel = nil
	// }

	// if c.updateLockedUserEntriesCancel != nil {
	// 	c.updateLockedUserEntriesCancel()
	// 	c.updateLockedUserEntriesCancel = nil
	// }

	// Unload tokens from cache (they remain in storage for next unseal)
	if c.tokenStore != nil {
		c.tokenStore.UnloadFromCache()
	}

	// Unload credential configs from cache (they remain in storage for next unseal)
	if err := c.teardownCredentialConfigStore(); err != nil {
		c.logger.Warn("error tearing down credential config store", logger.Err(err))
	}

	// Stop all credential managers
	if err := c.teardownCredentialManager(); err != nil {
		c.logger.Warn("error tearing down credential managers", logger.Err(err))
	}

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
	c.logger.Trace("standard unseal starting")

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
	c.logger.Trace("read-only unseal starting")
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

	// Setup expiration manager for timer-based token/credential expiration
	// Note: ExpirationManager handles all background cleanup (no separate cleanup goroutine)
	if err := c.setupExpirationManager(ctx); err != nil {
		return err
	}

	// Wire up credential manager to expiration manager for timer-based TTL enforcement
	// This allows credential manager to register newly issued credentials for expiration
	c.credentialManager.SetExpirationRegistrar(c.expirationManager)

	if err := c.loadMounts(ctx); err != nil {
		return err
	}
	if err := c.setupMounts(ctx); err != nil {
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
