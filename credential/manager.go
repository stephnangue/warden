package credential

import (
	"context"
	"fmt"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"golang.org/x/sync/singleflight"
)

// Storage path constant for issued credentials
const (
	StoragePath = "core/credentials/" // Base path for issued credentials in barrier storage
)

// Manager manages credential issuance with caching and type safety for all namespaces
// The manager is global and handles credentials across all namespaces using namespace-aware cache keys
type Manager struct {
	log            *logger.GatedLogger
	cache          *ristretto.Cache[string, *Credential] // key: {namespace-uuid}:{tokenID} -> value: Credential
	typeRegistry   *TypeRegistry
	driverRegistry *DriverRegistry
	group          singleflight.Group

	// Persistence layer
	storage sdklogical.Storage // Root barrier view at "core/credentials/"

	// Configuration store accessor (provides specs and sources)
	configStore ConfigStoreAccessor
}

// ConfigStoreAccessor defines the interface for accessing credential configuration
// This allows the Manager to retrieve specs and sources from the CredentialConfigStore
type ConfigStoreAccessor interface {
	GetSpec(ctx context.Context, name string) (*CredSpec, error)
	GetSource(ctx context.Context, name string) (*CredSource, error)
}

// NewManager creates a new global credential manager
func NewManager(
	typeRegistry *TypeRegistry,
	driverRegistry *DriverRegistry,
	storage sdklogical.Storage,
	configStore ConfigStoreAccessor,
	logger *logger.GatedLogger,
) (*Manager, error) {
	m := &Manager{
		log:            logger,
		typeRegistry:   typeRegistry,
		driverRegistry: driverRegistry,
		storage:        storage,
		configStore:    configStore,
	}

	// Create Ristretto cache
	cache, err := ristretto.NewCache(&ristretto.Config[string, *Credential]{
		NumCounters: 100000,
		MaxCost:     1_000_000,
		BufferItems: 64,
		OnEvict:     m.onEvict,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	m.cache = cache

	return m, nil
}

// IssueCredential issues a credential for the given spec, token, and TTL
// This is the main entry point for credential issuance
//
// Parameters:
//   - ctx: Context with namespace information
//   - tokenID: The session token ID to bind the credential to
//   - specName: The name of the credential spec to use
//   - tokenTTL: The TTL of the session token (used for cache duration)
//
// Returns the issued credential or an error
func (m *Manager) IssueCredential(ctx context.Context, tokenID string, specName string, tokenTTL time.Duration) (*Credential, error) {
	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace from context: %w", err)
	}

	// Build namespace-aware cache key: {namespace-uuid}:{tokenID}
	cacheKey := fmt.Sprintf("%s:%s", ns.ID, tokenID)

	// Check cache first
	if cred, found := m.cache.Get(cacheKey); found {
		m.log.Debug("using cached credential",
			logger.String("namespace", ns.ID),
			logger.String("token_id", tokenID),
			logger.String("spec", specName),
		)
		return cred, nil
	}

	// Use singleflight to ensure only one creation per cacheKey
	v, err, _ := m.group.Do(cacheKey, func() (interface{}, error) {
		// Double-check cache in case another goroutine just added it
		if cred, found := m.cache.Get(cacheKey); found {
			return cred, nil
		}

		// Check storage (might have been persisted but evicted from cache)
		if m.storage != nil {
			if cred, err := m.loadCredentialFromStorage(ctx, ns.ID, tokenID); err == nil {
				m.log.Debug("loaded credential from storage",
					logger.String("namespace", ns.ID),
					logger.String("token_id", tokenID),
					logger.String("spec", specName),
				)
				// Restore to cache
				cacheTTL := tokenTTL
				if cred.LeaseTTL > 0 {
					remaining := cred.RemainingTTL()
					if remaining > 0 {
						cacheTTL = min(tokenTTL, remaining)
					}
				}
				m.cache.SetWithTTL(cacheKey, cred, 1, cacheTTL)
				m.cache.Wait()
				return cred, nil
			}
		}

		// Cache miss and storage miss - issue new credential
		m.log.Debug("cache miss, issuing new credential",
			logger.String("namespace", ns.ID),
			logger.String("token_id", tokenID),
			logger.String("spec", specName),
		)

		cred, err := m.issueCredential(ctx, specName)
		if err != nil {
			return nil, err
		}

		// Bind credential to token and spec
		cred.TokenID = tokenID
		cred.SpecName = specName

		// Persist to storage FIRST (durability)
		if m.storage != nil {
			if err := m.persistCredential(ctx, ns.ID, cred); err != nil {
				return nil, fmt.Errorf("failed to persist credential: %w", err)
			}
		}

		// Calculate cache TTL: min(tokenTTL, 80% of credential lease TTL)
		cacheTTL := tokenTTL
		if cred.LeaseTTL > 0 {
			cacheTTL = min(tokenTTL, cred.LeaseTTL*4/5)
		}

		// Then cache
		m.cache.SetWithTTL(cacheKey, cred, 1, cacheTTL)

		// Wait for value to be processed (Ristretto is async)
		m.cache.Wait()

		m.log.Debug("cached credential",
			logger.String("namespace", ns.ID),
			logger.String("token_id", tokenID),
			logger.String("spec", specName),
			logger.String("type", cred.Type),
			logger.String("cache_ttl", cacheTTL.String()),
		)

		return cred, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(*Credential), nil
}

// issueCredential performs the actual credential issuance
func (m *Manager) issueCredential(ctx context.Context, specName string) (*Credential, error) {
	// Step 1: Lookup credential spec from config store
	spec, err := m.configStore.GetSpec(ctx, specName)
	if err != nil {
		return nil, fmt.Errorf("credential spec '%s' not found: %w", specName, err)
	}

	// Step 2: Get credential source from config store
	credSource, err := m.configStore.GetSource(ctx, spec.SourceName)
	if err != nil {
		return nil, fmt.Errorf("credential source '%s' not found: %w", spec.SourceName, err)
	}

	// Step 3: Get or create source driver
	driver, err := m.driverRegistry.CreateDriver(spec.SourceName, credSource)
	if err != nil {
		return nil, fmt.Errorf("failed to create driver for source '%s': %w", spec.SourceName, err)
	}

	// Step 4: Mint raw credential data using the driver
	rawData, leaseTTL, leaseID, err := driver.MintCredential(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential: %w", err)
	}

	// Step 5: Get credential type handler
	credType, err := m.typeRegistry.GetByName(spec.Type)
	if err != nil {
		return nil, fmt.Errorf("credential type '%s' not found: %w", spec.Type, err)
	}

	// Step 6: Parse raw data into structured credential
	cred, err := credType.Parse(rawData, leaseTTL, leaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Step 7: Set source type
	cred.SourceType = driver.Type()

	// Step 8: Validate credential
	if err := credType.Validate(cred); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	m.log.Debug("issued credential",
		logger.String("spec", specName),
		logger.String("type", cred.Type),
		logger.String("source", cred.SourceType),
		logger.Bool("revocable", cred.Revocable),
	)

	return cred, nil
}

// onEvict is called when a credential is evicted from the cache
func (m *Manager) onEvict(item *ristretto.Item[*Credential]) {
	if item.Value == nil {
		return
	}

	cred := item.Value

	m.log.Debug("credential evicted from cache",
		logger.String("token_id", cred.TokenID),
		logger.String("type", cred.Type),
		logger.String("reason", "ttl_expired_or_capacity"),
	)

	// NOTE: We do NOT delete from storage or revoke on eviction
	// Storage persists until token expires
	// This allows cache misses to reload from storage
	// Revocation is handled separately during token cleanup
}

// Stop gracefully shuts down the manager
func (m *Manager) Stop() {
	m.cache.Close()
	m.log.Debug("credential manager cache closed")
}
