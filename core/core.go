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
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/logger"
	phy "github.com/stephnangue/warden/physical"
	"github.com/stephnangue/warden/provider"
	"github.com/stephnangue/warden/target"
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

	// credentialManager is a global manager that handles credentials across all namespaces
	// It uses namespace-aware cache keys and storage paths for isolation
	credentialManager *credential.Manager

	// Global registries shared across all namespaces
	credentialTypeRegistry   *credential.TypeRegistry
	credentialDriverRegistry *credential.DriverRegistry

	accessControl *authorize.AccessControl

	roles *authorize.RoleRegistry

	credSources *cred.CredSourceRegistry

	targets *target.TargetRegistry

	auditDevices map[string]audit.Factory

	authMethods map[string]auth.Factory

	providers map[string]provider.Factory

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

	// preInitHandler handles initialization requests before system backend is available
	preInitHandler *PreInitHandler

	// systemBackend is the backend which is used to manage internal operations
	systemBackend *SystemBackend
}

type CoreConfig struct {
	RawConfig *config.Config

	AuditDevices map[string]audit.Factory

	AuthMethods map[string]auth.Factory

	Providers map[string]provider.Factory

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

	// Initialize pre-init handler (handles /sys/init before system backend is mounted)
	c.preInitHandler = NewPreInitHandler(c, c.logger.WithSystem("preinit"))

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

func (c *Core) configureProvider(backends map[string]provider.Factory) {
	providers := make(map[string]provider.Factory, len(backends))
	maps.Copy(providers, backends)
	c.providers = providers
}

func (c *Core) configureAuthMethods(backends map[string]auth.Factory) {
	auths := make(map[string]auth.Factory, len(backends))
	maps.Copy(auths, backends)
	c.authMethods = auths
}

func (c *Core) configureAuditDevices(backends map[string]audit.Factory) {
	audits := make(map[string]audit.Factory, len(backends))
	maps.Copy(audits, backends)
	c.auditDevices = audits
}

func (c *Core) Roles() *authorize.RoleRegistry {
	return c.roles
}

func (c *Core) CredSources() *cred.CredSourceRegistry {
	return c.credSources
}

func (c *Core) Targets() *target.TargetRegistry {
	return c.targets
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

func (c *Core) LoadRoles(ctx context.Context) {
	// load the roles from the storage
	c.logger.Info("loading roles from storage")

	roleRegistry := authorize.NewRoleRegistry()
	roleRegistry.Register(authorize.Role{
		Name: "system_admin",
		Type: "system",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "market_reader",
		Type:           "static_database_userpass",
		CredSourceName: "default",
		CredConfig: map[string]string{
			"database": "myapp",
			"username": "vaultadmin",
			"password": "vaultpassword",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "sales_admin",
		Type:           "static_database_userpass",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"kv2_mount":   "kv_static_secret",
			"secret_path": "database/mysql/prod",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "ondemand_role",
		Type:           "dynamic_database_userpass",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"database":       "myapp",
			"database_mount": "database",
			"role_name":      "my-role",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_dev_account_local",
		Type:           "static_aws_access_keys",
		CredSourceName: "default",
		CredConfig: map[string]string{
			"access_key_id":     "myapp",
			"secret_access_key": "database",
		},
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_dev_account_vault",
		Type:           "static_aws_access_keys",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"kv2_mount":   "kv_static_secret",
			"secret_path": "aws/prod",
		},
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_prod_account_vault",
		Type:           "dynamic_aws_access_keys",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"aws_mount":         "aws",
			"role_name":         "terraform",
			"ttl":               "900s",
			"role_session_name": "test",
			"role_arn":          "arn:aws:iam::905418489750:role/terraform-role-warden",
		},
	})
	c.roles = roleRegistry
}

func (c *Core) LoadCredSources(ctx context.Context) {
	// load the cred sources from the storage
	c.logger.Info("loading cred sources from storage")

	credSources := cred.NewCredSourceRegistry()
	credSources.Register(cred.CredSource{
		Name: "default",
		Type: "local",
	})
	credSources.Register(cred.CredSource{
		Name: "vault_docker",
		Type: "vault",
		Config: map[string]string{
			"vault_address":   "http://vault:8200",
			"vault_namespace": "root",
			"auth_method":     "approle",
			"approle_mount":   "warden_approle",
			"role_id":         "c0ae884e-b55e-1736-3710-bb1d88d76182",
			"secret_id":       "e0b8f9b8-6b32-5478-9a73-196e50734c2f",
		},
	})
	c.credSources = credSources
}

func (c *Core) InitAccessControl(ctx context.Context) {
	// load the role assignments
	c.logger.Info("loading role assignments from storage")

	accessControl := authorize.NewAccessControl()

	// Root principal always has system_admin role
	accessControl.AssignRole("root", "system_admin")

	accessControl.AssignRole("service-client-1", "market_reader")
	accessControl.AssignRole("service-client-1", "ondemand_role")
	accessControl.AssignRole("service-client-1", "aws_dev_account_local")
	accessControl.AssignRole("service-client-1", "aws_dev_account_vault")
	accessControl.AssignRole("service-client-1", "aws_prod_account_vault")
	accessControl.AssignRole("service-client-2", "sales_admin")

	// System admin role assignments
	accessControl.AssignRole("service-client-1", "system_admin") // For testing
	accessControl.AssignRole("admin-user", "system_admin")

	c.accessControl = accessControl
}

func (c *Core) LoadTargets(ctx context.Context) {
	// load the targets from the storage
	targets := target.NewTargetRegistry()
	targets.Register(&target.MysqlTarget{
		Name:        "mysql_backend",
		Hostname:    "mysql-server",
		Port:        "3306",
		MtlsEnabled: true,
		CACert: `-----BEGIN CERTIFICATE-----
MIIFizCCA3OgAwIBAgIUKV0KFYH8n+NMn4RIID/08RaE2hYwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjUx
MDE2MTYxODI2WhcNMjYxMDE2MTYxODI2WjBVMQswCQYDVQQGEwJVUzEOMAwGA1UE
CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEQ
MA4GA1UEAwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AM61xrG8DUPJchhxisMMYGLpw+dfiITkVRSxMkT/Nkzzk8uJ+GZOvJ0+jhJYbF19
ZNVxoTjrc8j0Ojvb8ATQdSkeAKMIdykP7yHOAmboN73bHP+Opde1ZMxGFQYXLTYj
DPWhIqn8dR58LKwkSj6taRKqekMEbP663faGEC+IZkCEMWOZYGkMHFn0C2NUynVP
TX2pnrC+h3XOCsR56FNFbX6EZktBLy+8I5ofpfCkQW/PfNp59mtyhp2/Cyod/FcN
+qZNPKVpiCUqkV2YhMwWudGpdjtZl6BtM0QG4WQwwEfmP1vKO19QrOLLWIvu/tnD
az+awxZLN/+wtAETl6bAaVrmyKeTrUZXRjTyHqZSmnargTc+9ATmFO0TihzVmshP
bk5KdyJ8Ixhbc6DZIDY24GXCGH8dcZaq95OYiBLwxUPHrQi28MeTRKfHMEjtW+ma
BLPfIVTC/qRkZGbE+4lMzCCFaLFeNchLfSavMA7yv7nzALAn80E1D60UBunIH9+K
w55hV6n6Waa9zvHlLWQnuo4NKZkIofiaVwQM2P+Ffgwad4HXCxZ7ebVK1Ur8nnwP
fApZ2StyK1R8cnERFP6ppBwx0+RT3MsPrrSFYnxyiIsRgHPdzuxG4R5PnbQk9+Uw
CJ5z6ihEy4+il+yMjiPoTHcNR7VFwhdRwbIerxnMkz0HAgMBAAGjUzBRMB0GA1Ud
DgQWBBTeN9HrqBjmEhk8hUu94RDsZQA/ETAfBgNVHSMEGDAWgBTeN9HrqBjmEhk8
hUu94RDsZQA/ETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCh
emFkwLedcePho6iDtzbZEjJoWl9YbqYICZuRRnN1cABAPvMNYJVppYTKxrklnXev
BqoG7BIcixmxQAiX7ifuI83t2IDBI78wvBmXRGkzoXjIxy73fUhorVxN+7A0RD9C
aWpnycbpuvziHTyKGPwtfxcECq6xmHidXKojcEdO/v6CYP4bBLBL+NMfXYDRIb13
8/OH94bJOhMrRsA9G7/TLLDEODZI+U9Nuwlovbp1QL+wKEDd/HKlxN9ET0Dg9Hd9
Xb/3oHV+OPEbcEWOWdudU5Rf6NaAeDKEZJeTygsBdx3vdKhMMrvPIZUSOWugN0Ls
H/uoSUMQQsa4Dt2rDHvYLXnQ3EcG8u4jVCxvrnQeuUSu7TFA5pmDWjdzB4ZvDVt1
hiWZlHsTCxDPSi9eiM5YGTXlBU9F9iCOX3y/lGB1oJtwXRdu7j4bf/0T/643m4qH
0bn+dXYlL4yV0NP/09xvzpjJGu+UMjAquv63OGOMRpgJ5W6/QNIXkQ/9iGVlICYA
+Co87WfQEDYTGfORMMwyvqJtbiXka94rH4CP+Ahm8T2IxA16rQ2DPZsp4FE7UDRW
rl3XB7qdvv6khQliu2+vKmkcjMdqeKGVuTtDByAL9opm+IP6Z9ldBHAANDJQjNJe
cpliwKYo8WlwstvVBdrDzDbfbv4vzSeOpem3VvXRSQ==
-----END CERTIFICATE-----
`,
		ClientCert: `-----BEGIN CERTIFICATE-----
MIIFlDCCA3ygAwIBAgIUfnupTqlwijm9GSB3zYBKYtokQ2gwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjUx
MDE2MTYxODI5WhcNMjYxMDE2MTYxODI5WjBaMQswCQYDVQQGEwJVUzEOMAwGA1UE
CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEV
MBMGA1UEAwwMbXlzcWwtY2xpZW50MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAvGxjQwUWd5Sd0S1c6/UYWCymTIQaBhYu1Jgxp0Xdz8emrB03veh/ck8R
YjtSUtTYijO1oIjAvfqeCNic7DZHjfIHmHeU7Hu8JJJ4rn/7Y/MClp1G+97Nc7Ul
XxU51ph8vFBxOillFA9MiAQRzWNEAuNpGjmmOLr+DxTp3MfyXWmbm9W2ohRpc6sb
WEk46CPA8ddLlKej9RZEsepTV2MGfJZRjTl/8zXsNMXno5d5dsTl6vyP9qBBfMYP
Goxxe6lAgu/ZyHNdCvYAhipKEuivJ6LwBeW1aQz2jl6j/FDeCtWOXtsFYGbeCURv
Vi5hPS3X1HIykmYYpJJNOK01OiDdqHUNWcPzob31yGHy9qvxfJrowt2gTzLtoSOC
VTDYQU80gK13k9j5U8duUiY60sr7Uq9OoP4cOXK0jjq8GT92JbgAmHu3V15QyQ+q
EQtlCj9JzwdxxNtW9VWOp0qx7NmeYOGnd2onAHsVV6a+tldQt9QucRa9+Gnyp0tF
pBwvPMHzUn12MFXNgTcTTajmAGnsG7Yt1oO3wPY5tjO/nrFshKA4AAeFrAD7LpVE
N8g8sI2/YeglwAg+sa7mrlZZdf/zMTSU0DqTOYANqiCQThFQxWpMfbwINOwIAZsF
T2Xfmy/Xod3Zsbuam/5C3hxCTYMwPobGGukIVMUA3Itb2uBUlDMCAwEAAaNXMFUw
EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFBo2P4yTtFLonfK2lJreTZhE
dPvgMB8GA1UdIwQYMBaAFN430euoGOYSGTyFS73hEOxlAD8RMA0GCSqGSIb3DQEB
CwUAA4ICAQCjcrZbsiRAmw8demgAMos+222AdV0BZqk2xescGFPJSMtrHetIMByo
BMHmIQWtW2jbt68mQunrk+SkYPPHBdLSkNWqTsNcO/+OzVmYr3nOrYjt24ZyAqOq
wxP7gfQkFEryxgsFDEE1d1a9ueUO3CKhPRkA7hGSmPSPkWbVNc4euUyWd5rGEzXu
REHRb1opnUjDampupDZk+8pKrcJlAP9HlAxDq+O94r13dq17D2+wWf9usmwu9o2l
sQKqp3w5YqCfBN0mcWd5SU5ez1j9nZnEkV+aYqLoZXUbRRZcaQZJJdyF3srDf2wB
qPkhuFwHQVIEfy+SL+EeDdLQT88pCB5CH+dFcDCtJxFXqQyfiUN/E5Fbzp9SLZQB
qpKqF0NiTgogRfmrdGsH6dw4N71BFrSCjv8IqBAu9cBDcmjj7SFa/4ZDoqxH42I+
GyBA05dSsRVOUJMSbBk/cofbUUG3FpUpW3Vb+ciJ1wryvYFikr9c8mCg+OWrQO1d
oRICNKZf3/Mv/eDgju20j3EWFT+NsEP3YVv1+c1Za91mz7UTmaJkBeIBGyE5JKQM
ilKqT8ZCxnXeXce0SyBBtWB3C+XC8xZkdD5h2G84oqyIFAfBf7eeFOleVOnstCRA
9FB8O35VocuRpL3S2+BoqyoNuDhJKZ3yoTrWNrZFggdY4J2FgV3v/w==
-----END CERTIFICATE-----
`,
		ClientKey: `-----BEGIN PRIVATE KEY-----
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
cVs1CNZyx2Epxma3FYINYJdklZNKn5I=
-----END PRIVATE KEY-----
`,
	})
	c.targets = targets
}

// loadTokensFromStorage loads all persisted tokens from storage into the token store cache.
// This is called during post-unseal to restore tokens after a restart.
func (c *Core) loadTokensFromStorage(ctx context.Context) error {
	if c.tokenStore == nil {
		return fmt.Errorf("token store not initialized")
	}

	return c.tokenStore.LoadFromStorage(ctx)
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
	// if err := c.stopExpiration(); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error stopping expiration: %w", err))
	// }
	// if err := c.teardownCredentials(context.Background()); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error tearing down credentials: %w", err))
	// }
	// if err := c.teardownPolicyStore(); err != nil {
	// 	result = multierror.Append(result, fmt.Errorf("error tearing down policy store: %w", err))
	// }
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
	if err := c.setupCredentialConfigStore(ctx); err != nil {
		return err
	}
	if err := c.setupCredentialManager(ctx); err != nil {
		return err
	}

	// Start background cleanup for expired credentials (every 5 minutes)
	c.startCredentialBackgroundCleanup(ctx, 5*time.Minute)

	if err := c.loadMounts(ctx); err != nil {
		return err
	}
	if err := c.setupMounts(ctx); err != nil {
		return err
	}

	if err := c.loadTokensFromStorage(ctx); err != nil {
		c.logger.Warn("failed to load tokens from storage", logger.Err(err))
	}

	c.LoadRoles(ctx)

	c.LoadCredSources(ctx)

	c.InitAccessControl(ctx)

	c.LoadTargets(ctx)

	err := c.loadAudits(ctx)
	if err != nil {
		return err
	}

	return nil
}
