package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

// Token type constants for backward compatibility
const (
	TypeUserPass      = "user_pass"
	TypeAWSAccessKeys = "aws_access_keys"
	TypeWardenToken   = "warden_token"
)

// Storage path constants for token store organization
const (
	tokenStorePath      = "core/token/"  // Base path for all token-related storage
	tokenIDPrefix       = "id/"          // Prefix for token ID storage (full token data)
	tokenAccessorPrefix = "accessor/"    // Prefix for accessor → ID mappings
)

var (
	// ErrUnsupportedTokenType is returned when an unknown token type is requested
	ErrUnsupportedTokenType = errors.New("unsupported token type")

	// ErrTokenNotFound is returned when a token cannot be found
	ErrTokenNotFound = errors.New("token not found")

	// ErrAuthDeadlineViolated is returned when auth deadline has passed
	ErrAuthDeadlineViolated = errors.New("authentication deadline violated")

	// ErrTokenExpired is returned when token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrOriginViolation is returned when same-origin policy is violated
	ErrOriginViolation = errors.New("same origin policy violated")

	// ErrStoreClosed is returned when operating on a closed store
	ErrStoreClosed = errors.New("token store is closed")

	// ErrTokenNamespaceMismatch is returned when token namespace doesn't match request namespace
	ErrTokenNamespaceMismatch = errors.New("token namespace mismatch")

	// ErrAccessorNotFound is returned when accessor is not found
	ErrAccessorNotFound = errors.New("accessor not found")
)

// TokenStoreConfig holds configuration for the token store
type TokenStoreConfig struct {
	// CacheMaxCost is the maximum cost of cache (in bytes, roughly)
	CacheMaxCost int64

	// CacheNumCounters is the number of keys to track frequency
	CacheNumCounters int64

	// EnableMetrics enables collection of operational metrics
	EnableMetrics bool
}

// DefaultTokenStoreConfig returns a production-ready default configuration
func DefaultTokenStoreConfig() *TokenStoreConfig {
	return &TokenStoreConfig{
		CacheMaxCost:     100 << 20, // 100 MB
		CacheNumCounters: 1e7,       // 10 million
		EnableMetrics:    true,
	}
}

// TokenMetrics tracks operational statistics
type TokenMetrics struct {
	mu                  sync.RWMutex
	TokensGenerated     int64
	TokensResolved      int64
	TokensExpired       int64
	OriginViolations    int64
	DeadlineViolations  int64
	NamespaceMismatches int64
	CacheHits           int64
	CacheMisses         int64
}

func (m *TokenMetrics) IncrementTokensGenerated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensGenerated++
}

func (m *TokenMetrics) IncrementTokensResolved() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensResolved++
}

func (m *TokenMetrics) IncrementTokensExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensExpired++
}

func (m *TokenMetrics) IncrementOriginViolations() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OriginViolations++
}

func (m *TokenMetrics) IncrementDeadlineViolations() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeadlineViolations++
}

func (m *TokenMetrics) IncrementNamespaceMismatches() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NamespaceMismatches++
}

func (m *TokenMetrics) IncrementCacheHits() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

func (m *TokenMetrics) IncrementCacheMisses() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

func (m *TokenMetrics) GetSnapshot() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]int64{
		"tokens_generated":     m.TokensGenerated,
		"tokens_resolved":      m.TokensResolved,
		"tokens_expired":       m.TokensExpired,
		"origin_violations":    m.OriginViolations,
		"deadline_violations":  m.DeadlineViolations,
		"namespace_mismatches": m.NamespaceMismatches,
		"cache_hits":           m.CacheHits,
		"cache_misses":         m.CacheMisses,
	}
}

// TokenStore manages tokens with namespace awareness and pluggable token types
type TokenStore struct {
	core     *Core              // Reference to Core
	registry *TokenTypeRegistry // Token type registry

	// Two-tier indexing with salt-based storage paths
	// Tier 1: Primary index (fast in-memory lookup)
	byID *ristretto.Cache[string, *TokenEntry] // ID → TokenEntry

	// Tier 2: Secondary index (accessor-based lookup)
	byAccessor *ristretto.Cache[string, string] // Accessor → ID

	// Persistent storage backend (uses salt in storage paths for distribution)
	storage BarrierView // For write-through to disk

	// Root token management
	rootTokenManager *RootTokenManager

	// Configuration
	config  *TokenStoreConfig
	logger  *logger.GatedLogger
	metrics *TokenMetrics

	mu     sync.RWMutex
	closed bool
}

// NewTokenStore creates a new token store
func NewTokenStore(core *Core, config *TokenStoreConfig) (*TokenStore, error) {
	if config == nil {
		config = DefaultTokenStoreConfig()
	}

	store := &TokenStore{
		core:             core,
		registry:         NewTokenTypeRegistry(),
		config:           config,
		logger:           core.logger,
		metrics:          &TokenMetrics{},
		closed:           false,
		rootTokenManager: NewRootTokenManager(),
	}

	// Initialize primary cache (by ID)
	cacheByID, err := ristretto.NewCache(&ristretto.Config[string, *TokenEntry]{
		NumCounters: config.CacheNumCounters,
		MaxCost:     config.CacheMaxCost,
		BufferItems: 64,
		OnEvict:     store.onEvictID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ID cache: %w", err)
	}
	store.byID = cacheByID

	// Initialize accessor cache (Tier 2)
	cacheByAccessor, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: config.CacheNumCounters / 10, // Smaller for accessor mappings
		MaxCost:     config.CacheMaxCost / 10,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize accessor cache: %w", err)
	}
	store.byAccessor = cacheByAccessor

	// Initialize persistent storage view
	store.storage = NewBarrierView(core.barrier, tokenStorePath)

	// Register built-in token types
	if err := store.registerBuiltinTypes(); err != nil {
		return nil, fmt.Errorf("failed to register built-in token types: %w", err)
	}

	// Token loading from storage is deferred to post-unseal via LoadFromStorage()
	// This ensures the barrier is unsealed and storage is accessible before loading tokens

	store.logger.Info("token store initialized",
		logger.Bool("metrics_enabled", config.EnableMetrics),
		logger.Int("registered_types", len(store.registry.ListTypes())))

	return store, nil
}

// LoadFromStorage loads all persisted tokens from storage into the cache.
// This should be called during post-unseal to restore tokens after a restart.
func (s *TokenStore) LoadFromStorage(ctx context.Context) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrStoreClosed
	}
	s.mu.RUnlock()

	// Check if storage is available (may not be during first initialization)
	if s.storage == nil {
		s.logger.Debug("storage not available, skipping token load")
		return nil
	}

	loadedCount, err := s.loadAllTokensFromStorage(ctx)
	if err != nil {
		s.logger.Warn("failed to load persisted tokens from storage",
			logger.String("error", err.Error()))
		return err
	}

	s.logger.Info("persisted tokens loaded from storage",
		logger.Int("count", loadedCount))

	return nil
}

// UnloadFromCache clears all tokens from the in-memory cache.
// This should be called during pre-seal to free memory when sealing the vault.
// Tokens remain in persistent storage and will be reloaded on next unseal.
func (s *TokenStore) UnloadFromCache() {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	// Clear both cache tiers
	s.byID.Clear()
	s.byAccessor.Clear()

	// Wait for cache operations to complete
	s.byID.Wait()
	s.byAccessor.Wait()

	s.logger.Info("all tokens unloaded from cache (preserved in storage)")
}

// registerBuiltinTypes registers the built-in token types
func (s *TokenStore) registerBuiltinTypes() error {
	builtinTypes := []TokenType{
		&UserPassTokenType{},
		&AWSAccessKeysTokenType{},
		&WardenTokenType{},
	}

	for _, tokenType := range builtinTypes {
		if err := s.registry.Register(tokenType); err != nil {
			return err
		}
	}

	return nil
}

// onEvictID is called when a token is evicted from the ID cache
// Asynchronously cleans up the accessor index and persistent storage if the token expired
func (s *TokenStore) onEvictID(item *ristretto.Item[*TokenEntry]) {
	entry := item.Value

	// Check if eviction is due to expiration (not capacity)
	// Ristretto evicts due to TTL expiration or capacity pressure
	isExpired := !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt)

	s.logger.Debug("token evicted from cache",
		logger.String("token_id", entry.ID),
		logger.String("accessor", entry.Accessor),
		logger.Bool("expired", isExpired))

	// Only delete from storage if token actually expired
	// If evicted due to capacity, keep in storage for cache miss recovery
	if isExpired {
		// Asynchronously clean up accessor cache and persistent storage
		go func() {
			// Delete from accessor cache
			s.byAccessor.Del(entry.Accessor)

			// Delete from persistent storage
			if err := s.deleteToken(entry); err != nil {
				s.logger.Warn("failed to delete expired token from storage",
					logger.String("token_id", entry.ID),
					logger.String("accessor", entry.Accessor),
					logger.String("error", err.Error()))
			} else {
				s.logger.Debug("expired token cleaned up from storage",
					logger.String("token_id", entry.ID),
					logger.String("accessor", entry.Accessor))
			}
		}()
	} else {
		// Token evicted due to capacity, not expiration
		// Keep in storage but remove from accessor cache to free memory
		s.byAccessor.Del(entry.Accessor)

		s.logger.Debug("token evicted from cache (capacity), kept in storage",
			logger.String("token_id", entry.ID),
			logger.String("accessor", entry.Accessor))
	}
}

// GenerateToken creates a new namespace-aware token
func (s *TokenStore) GenerateToken(ctx context.Context, tokenTypeName string, authData *AuthData) (*TokenEntry, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStoreClosed
	}
	s.mu.Unlock()

	if authData == nil {
		return nil, errors.New("authData cannot be nil")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return nil, errors.New("namespace not found in context")
	}

	// Get token type from registry
	tokenType, err := s.registry.GetByName(tokenTypeName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTokenType, tokenTypeName)
	}

	// Generate token with collision detection
	entry, err := s.generateWithCollisionDetection(ctx, tokenType, authData, ns)
	if err != nil {
		return nil, err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensGenerated()
	}

	return entry, nil
}

// generateWithCollisionDetection generates a token with retry logic for collisions
func (s *TokenStore) generateWithCollisionDetection(
	ctx context.Context,
	tokenType TokenType,
	authData *AuthData,
	ns *namespace.Namespace,
) (*TokenEntry, error) {
	ttl := time.Until(authData.ExpireAt)
	if ttl <= 0 && !authData.ExpireAt.IsZero() {
		return nil, errors.New("token already expired")
	}

	meta := tokenType.Metadata()
	maxRetries := 10

	for i := 0; i < maxRetries; i++ {
		// Create token entry with namespace fields
		entry := &TokenEntry{
			Type:           meta.Name,
			NamespaceID:    ns.UUID,
			NamespacePath:  ns.Path,
			CreatedAt:      time.Now(),
			CreatedByIP:    authData.RequestContext["client_ip"],
			CreatedByReqID: authData.RequestContext["request_id"],
			PrincipalID:    authData.PrincipalID,
			RoleName:       authData.RoleName,
			AuthDeadline:   authData.AuthDeadline,
			ExpireAt:       authData.ExpireAt,
			Data:           make(map[string]string),
		}

		// Generate accessor (Tier 2)
		entry.Accessor = generateAccessor()

		// Let the token type generate its values
		clientData, err := tokenType.Generate(authData, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %w", err)
		}

		// Extract lookup value and compute ID using the deterministic lookup key
		lookupKey := tokenType.LookupKey()
		lookupValue := tokenType.ExtractValue(clientData[lookupKey])
		entry.ID = tokenType.ComputeID(lookupValue)

		// Check for collision
		if _, found := s.byID.Get(entry.ID); !found {
			// No collision, store the token in all three tiers

			// Tier 1: Store in primary cache (byID)
			cost := int64(200)
			if authData.ExpireAt.IsZero() {
				// No expiration
				s.byID.Set(entry.ID, entry, cost)
			} else {
				s.byID.SetWithTTL(entry.ID, entry, cost, ttl)
			}

			// Tier 2: Store accessor mapping
			s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, ttl)

			// Wait for all cache writes to complete
			s.byID.Wait()
			s.byAccessor.Wait()

			// Persist to storage backend (write-through)
			if err := s.persistToken(entry); err != nil {
				s.logger.Error("failed to persist token to storage",
					logger.String("token_id", entry.ID),
					logger.String("error", err.Error()))
				// Don't fail the operation, token is in cache
			}

			s.logger.Debug("token created",
				logger.String("token_id", entry.ID),
				logger.String("accessor", entry.Accessor),
				logger.String("type", meta.Name),
				logger.String("namespace", ns.Path),
				logger.Time("expires_at", authData.ExpireAt))

			return entry, nil
		}

		s.logger.Warn("token ID collision detected, regenerating",
			logger.String("token_id", entry.ID),
			logger.String("type", meta.Name),
			logger.Int("attempt", i+1))

		if i == maxRetries-1 {
			return nil, errors.New("failed to generate unique token after retries")
		}
	}

	return nil, errors.New("failed to generate unique token")
}

// ResolveToken validates and resolves a token with namespace checking
func (s *TokenStore) ResolveToken(ctx context.Context, tokenValue string) (string, string, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", "", ErrStoreClosed
	}
	s.mu.RUnlock()

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return "", "", errors.New("namespace not found in context")
	}

	// Detect token type
	tokenType, err := s.registry.DetectType(tokenValue)
	if err != nil {
		return "", "", fmt.Errorf("failed to detect token type: %w", err)
	}

	// Compute token ID
	lookupValue := tokenType.ExtractValue(tokenValue)
	tokenID := tokenType.ComputeID(lookupValue)

	// Lookup token in cache
	entry, found := s.byID.Get(tokenID)
	if !found {
		// Cache miss: try loading from persistent storage
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}

		s.logger.Debug("token cache miss, loading from storage",
			logger.String("token_id", tokenID))

		loadedEntry, err := s.loadToken(tokenID)
		if err != nil {
			if err == ErrTokenNotFound {
				return "", "", ErrTokenNotFound
			}
			s.logger.Warn("failed to load token from storage on cache miss",
				logger.String("token_id", tokenID),
				logger.String("error", err.Error()))
			return "", "", ErrTokenNotFound
		}

		// Restore to cache with remaining TTL
		entry = loadedEntry
		if err := s.restoreTokenToCache(entry, "ResolveToken"); err != nil {
			return "", "", err
		}
	} else {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheHits()
		}
	}

	// Validate namespace binding with hierarchical access
	// Tokens from a parent namespace can access all child namespaces
	// Get the token's namespace to check if it's a parent of the request namespace
	tokenNs, err := s.core.namespaceStore.GetNamespace(ctx, entry.NamespaceID)
	if err != nil || tokenNs == nil {
		s.logger.Warn("token namespace not found",
			logger.String("token_id", tokenID),
			logger.String("token_namespace_id", entry.NamespaceID))
		return "", "", ErrTokenNamespaceMismatch
	}

	// Check if token's namespace is a parent of (or same as) the request namespace
	// This allows hierarchical access: parent tokens work in all child namespaces
	// ns.HasParent(tokenNs) returns true if tokenNs is a parent of ns
	isValidNamespace := ns.UUID == tokenNs.UUID || ns.HasParent(tokenNs)
	if !isValidNamespace {
		if s.config.EnableMetrics {
			s.metrics.IncrementNamespaceMismatches()
		}
		s.logger.Warn("token namespace mismatch",
			logger.String("token_id", tokenID),
			logger.String("token_namespace", tokenNs.Path),
			logger.String("request_namespace", ns.Path))
		return "", "", ErrTokenNamespaceMismatch
	}

	// Validate token value matches (defense against hash collisions)
	// Use the token type's LookupKey to get the correct value deterministically
	lookupKey := tokenType.LookupKey()
	expectedValue, ok := entry.Data[lookupKey]
	if !ok || expectedValue != tokenValue {
		s.logger.Error("token value mismatch - possible hash collision",
			logger.String("token_id", tokenID),
			logger.String("lookup_key", lookupKey))
		return "", "", ErrTokenNotFound
	}

	// Validate auth deadline
	if !entry.AuthDeadline.IsZero() && time.Now().After(entry.AuthDeadline) {
		if s.config.EnableMetrics {
			s.metrics.IncrementDeadlineViolations()
		}
		return "", "", ErrAuthDeadlineViolated
	}

	// Validate expiration
	if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
		if s.config.EnableMetrics {
			s.metrics.IncrementTokensExpired()
		}
		return "", "", ErrTokenExpired
	}

	// Validate same-origin policy (IP binding)
	if clientIP, ok := ctx.Value("client_ip").(string); ok && entry.CreatedByIP != "" {
		if clientIP != entry.CreatedByIP {
			if s.config.EnableMetrics {
				s.metrics.IncrementOriginViolations()
			}
			s.logger.Warn("same origin policy violation",
				logger.String("token_id", tokenID),
				logger.String("created_ip", entry.CreatedByIP),
				logger.String("request_ip", clientIP))
			return "", "", ErrOriginViolation
		}
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}

	return entry.PrincipalID, entry.RoleName, nil
}

// GetToken retrieves a token by its value (for backward compatibility)
func (s *TokenStore) GetToken(tokenValue string) *TokenEntry {
	// Detect token type
	tokenType, err := s.registry.DetectType(tokenValue)
	if err != nil {
		return nil
	}

	// Compute token ID
	lookupValue := tokenType.ExtractValue(tokenValue)
	tokenID := tokenType.ComputeID(lookupValue)

	// Lookup token in cache
	entry, found := s.byID.Get(tokenID)
	if !found {
		// Cache miss: try loading from persistent storage
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}

		s.logger.Debug("token cache miss, loading from storage",
			logger.String("token_id", tokenID))

		loadedEntry, err := s.loadToken(tokenID)
		if err != nil {
			if err == ErrTokenNotFound {
				return nil
			}
			s.logger.Warn("failed to load token from storage on cache miss",
				logger.String("token_id", tokenID),
				logger.String("error", err.Error()))
			return nil
		}

		// Restore to cache with remaining TTL
		entry = loadedEntry
		if err := s.restoreTokenToCache(entry, "GetToken"); err != nil {
			return nil
		}
	} else {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheHits()
		}
	}

	return entry
}

// LookupByAccessor looks up a token by its accessor
func (s *TokenStore) LookupByAccessor(accessor string) (*TokenEntry, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrStoreClosed
	}
	s.mu.RUnlock()

	// Lookup ID from accessor cache
	tokenID, found := s.byAccessor.Get(accessor)
	if !found {
		// Cache miss: try loading from persistent storage
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}

		s.logger.Debug("accessor cache miss, loading from storage",
			logger.String("accessor", accessor))

		loadedEntry, err := s.loadTokenByAccessor(accessor)
		if err != nil {
			if err == ErrAccessorNotFound {
				return nil, ErrAccessorNotFound
			}
			s.logger.Warn("failed to load token by accessor from storage on cache miss",
				logger.String("accessor", accessor),
				logger.String("error", err.Error()))
			return nil, ErrAccessorNotFound
		}

		// Restore to cache with remaining TTL
		entry := loadedEntry
		if err := s.restoreTokenToCache(entry, "LookupByAccessor"); err != nil {
			return nil, err
		}

		// Return a copy to prevent external modification
		entryCopy := *entry
		return &entryCopy, nil
	}

	// Retrieve full entry from ID cache
	entry, found := s.byID.Get(tokenID)
	if !found {
		// Accessor points to a token that's not in ID cache
		// This shouldn't happen in normal operation, but handle it gracefully
		s.logger.Warn("accessor found but token ID not in cache, loading from storage",
			logger.String("accessor", accessor),
			logger.String("token_id", tokenID))

		loadedEntry, err := s.loadToken(tokenID)
		if err != nil {
			// Clean up orphaned accessor mapping
			s.byAccessor.Del(accessor)
			return nil, ErrTokenNotFound
		}

		// Restore to cache with remaining TTL
		entry = loadedEntry
		if err := s.restoreTokenToCache(entry, "LookupByAccessor-orphaned"); err != nil {
			// Token expired, clean up accessor
			s.byAccessor.Del(accessor)
			return nil, err
		}
	} else {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheHits()
		}
	}

	// Return a copy to prevent external modification
	entryCopy := *entry
	return &entryCopy, nil
}

// RevokeByAccessor revokes a token by its accessor
func (s *TokenStore) RevokeByAccessor(ctx context.Context, accessor string) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrStoreClosed
	}
	s.mu.RUnlock()

	// Lookup token entry first to get salt for storage deletion
	entry, err := s.LookupByAccessor(accessor)
	if err != nil {
		return err
	}

	// Delete from both cache tiers
	s.byID.Del(entry.ID)
	s.byAccessor.Del(accessor)

	// Delete from persistent storage
	if err := s.deleteToken(entry); err != nil {
		s.logger.Error("failed to delete token from storage",
			logger.String("token_id", entry.ID),
			logger.String("error", err.Error()))
		// Don't fail the operation, token is removed from cache
	}

	s.logger.Info("token revoked by accessor",
		logger.String("accessor", accessor),
		logger.String("token_id", entry.ID))

	return nil
}

// GetMetrics returns a snapshot of current metrics
func (s *TokenStore) GetMetrics() map[string]int64 {
	return s.metrics.GetSnapshot()
}

// Close closes the token store
func (s *TokenStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.byID.Close()
	s.byAccessor.Close()
	s.closed = true

	s.logger.Info("token store closed")
}

// RegisterTokenType registers a new token type (for extensibility)
func (s *TokenStore) RegisterTokenType(tokenType TokenType) error {
	return s.registry.Register(tokenType)
}

// ListTokenTypes returns all registered token type names
func (s *TokenStore) ListTokenTypes() []string {
	return s.registry.ListTypes()
}

// GenerateRootToken generates a new root token
func (s *TokenStore) GenerateRootToken() (string, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", ErrStoreClosed
	}
	s.mu.Unlock()

	// Revoke existing root token if present
	if s.rootTokenManager.HasRootToken() {
		oldTokenID := s.rootTokenManager.GetCurrentRootTokenID()
		s.byID.Del(oldTokenID)
		s.rootTokenManager.ClearRootToken()

		s.logger.Info("existing root token revoked before generating new one",
			logger.String("old_token_id", oldTokenID))
	}

	// Get Warden token type
	tokenType, err := s.registry.GetByName("warden_token")
	if err != nil {
		return "", fmt.Errorf("warden token type not found: %w", err)
	}

	// Create AuthData with infinite TTL (for root namespace)
	authData := &AuthData{
		PrincipalID:    "root",
		RoleName:       "system_admin",
		AuthDeadline:   time.Time{}, // No auth deadline
		ExpireAt:       time.Time{}, // No expiration
		NamespaceID:    namespace.RootNamespace.UUID,
		NamespacePath:  namespace.RootNamespace.Path,
		RequestContext: map[string]string{},
	}

	// Generate token using standard mechanism
	entry, err := s.generateWithCollisionDetection(
		namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace),
		tokenType,
		authData,
		namespace.RootNamespace,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate root token: %w", err)
	}

	tokenValue := entry.Data["token"]
	s.rootTokenManager.SetRootToken(tokenValue, entry.ID)

	s.logger.Info("root token generated",
		logger.String("token_id", entry.ID),
		logger.String("accessor", entry.Accessor))

	return tokenValue, nil
}

// RevokeRootToken revokes the current root token
func (s *TokenStore) RevokeRootToken() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStoreClosed
	}
	s.mu.Unlock()

	if !s.rootTokenManager.HasRootToken() {
		return errors.New("no root token exists")
	}

	tokenID := s.rootTokenManager.GetCurrentRootTokenID()

	// Get the full token entry first
	entry, found := s.byID.Get(tokenID)
	if !found {
		// Try loading from storage
		var err error
		entry, err = s.loadToken(tokenID)
		if err != nil {
			s.logger.Warn("root token not found in cache or storage during revocation",
				logger.String("token_id", tokenID))
			s.rootTokenManager.ClearRootToken()
			return nil
		}
	}

	// Delete from cache
	s.byID.Del(tokenID)
	s.byAccessor.Del(entry.Accessor)

	// Delete from storage
	if err := s.deleteToken(entry); err != nil {
		s.logger.Error("failed to delete root token from storage",
			logger.String("token_id", tokenID),
			logger.String("error", err.Error()))
	}

	s.rootTokenManager.ClearRootToken()

	s.logger.Info("root token revoked",
		logger.String("token_id", tokenID))

	return nil
}

// persistToken writes a token to persistent storage using two-tier indexing
// Uses a transaction to ensure atomicity: both token and accessor are stored together
// or neither is stored if any operation fails
func (s *TokenStore) persistToken(entry *TokenEntry) error {
	if s.storage == nil {
		return errors.New("storage backend not initialized")
	}

	ctx := context.Background()

	// Serialize token entry to JSON
	data, err := encodeTokenEntry(entry)
	if err != nil {
		return fmt.Errorf("failed to encode token entry: %w", err)
	}

	// Prepare storage entries
	idPath := tokenIDPrefix + entry.ID
	accessorPath := tokenAccessorPrefix + entry.Accessor
	accessorData := []byte(entry.ID)

	// Check if storage supports transactions
	txnBarrier, supportsTxn := s.storage.(sdklogical.TransactionalStorage)

	if supportsTxn {
		// Use transaction for atomicity
		txn, err := txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer txn.Rollback(ctx) // Safe to call even after commit

		// Tier 1: Store by ID (primary path)
		if err := txn.Put(ctx, &sdklogical.StorageEntry{
			Key:   idPath,
			Value: data,
		}); err != nil {
			return fmt.Errorf("failed to store token by ID: %w", err)
		}

		// Tier 2: Store accessor → ID mapping
		if err := txn.Put(ctx, &sdklogical.StorageEntry{
			Key:   accessorPath,
			Value: accessorData,
		}); err != nil {
			return fmt.Errorf("failed to store accessor mapping: %w", err)
		}

		// Commit the transaction
		if err := txn.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit token persist transaction: %w", err)
		}
	} else {
		// Fallback: non-transactional storage (best effort)
		// Write in order: accessor first (lightweight), then full token data
		// This order minimizes impact if the second write fails

		if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
			Key:   accessorPath,
			Value: accessorData,
		}); err != nil {
			return fmt.Errorf("failed to store accessor mapping: %w", err)
		}

		if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
			Key:   idPath,
			Value: data,
		}); err != nil {
			// Attempt cleanup: delete accessor since token write failed
			_ = s.storage.Delete(ctx, accessorPath)
			return fmt.Errorf("failed to store token by ID: %w", err)
		}
	}

	return nil
}

// loadToken reads a token from persistent storage by ID
func (s *TokenStore) loadToken(tokenID string) (*TokenEntry, error) {
	if s.storage == nil {
		return nil, errors.New("storage backend not initialized")
	}

	// Try to load from primary ID path
	idPath := tokenIDPrefix + tokenID
	storageEntry, err := s.storage.Get(context.Background(), idPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token from storage: %w", err)
	}

	if storageEntry == nil {
		return nil, ErrTokenNotFound
	}

	// Deserialize token entry
	entry, err := decodeTokenEntry(storageEntry.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token entry: %w", err)
	}

	return entry, nil
}

// restoreTokenToCache restores a loaded token to both cache tiers with appropriate TTL
// Returns the entry if successfully restored, or an error if the token is expired
func (s *TokenStore) restoreTokenToCache(entry *TokenEntry, context string) error {
	cost := int64(200)

	if !entry.ExpireAt.IsZero() {
		ttl := time.Until(entry.ExpireAt)
		if ttl > 0 {
			s.byID.SetWithTTL(entry.ID, entry, cost, ttl)
			s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, ttl)
			s.byID.Wait()
			s.byAccessor.Wait()

			s.logger.Debug("token restored to cache from storage",
				logger.String("context", context),
				logger.String("token_id", entry.ID),
				logger.Duration("remaining_ttl", ttl))
			return nil
		} else {
			// Token expired while in storage
			s.logger.Debug("token expired in storage, not restoring to cache",
				logger.String("context", context),
				logger.String("token_id", entry.ID))
			return ErrTokenExpired
		}
	} else {
		// No expiration
		s.byID.Set(entry.ID, entry, cost)
		s.byAccessor.Set(entry.Accessor, entry.ID, 10)
		s.byID.Wait()
		s.byAccessor.Wait()

		s.logger.Debug("token restored to cache from storage (no expiration)",
			logger.String("context", context),
			logger.String("token_id", entry.ID))
		return nil
	}
}

// loadAllTokensFromStorage loads all tokens from persistent storage into cache
// This is called during token store initialization to restore tokens from storage
func (s *TokenStore) loadAllTokensFromStorage(ctx context.Context) (int, error) {
	loadedCount := 0
	expiredCount := 0
	failedCount := 0

	// List all token IDs from storage
	tokenKeys, err := s.storage.List(ctx, tokenIDPrefix)
	if err != nil {
		// If storage isn't ready (e.g., during first init), just return gracefully
		s.logger.Debug("storage not ready for token loading", logger.String("error", err.Error()))
		return 0, nil
	}

	for _, key := range tokenKeys {
		// Extract token ID from the key (remove prefix)
		tokenID := key
		if tokenID == "" {
			continue
		}

		// Load token entry
		entry, err := s.loadToken(tokenID)
		if err != nil {
			s.logger.Warn("failed to load token during initialization",
				logger.String("token_id", tokenID),
				logger.String("error", err.Error()))
			failedCount++
			continue
		}

		// Check if token has expired
		if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
			s.logger.Debug("skipping expired token during initialization",
				logger.String("token_id", entry.ID),
				logger.Time("expired_at", entry.ExpireAt))
			expiredCount++

			// Delete expired token from storage asynchronously
			go func(e *TokenEntry) {
				if err := s.deleteToken(e); err != nil {
					s.logger.Warn("failed to delete expired token during initialization",
						logger.String("token_id", e.ID),
						logger.String("error", err.Error()))
				}
			}(entry)
			continue
		}

		// Restore to cache with remaining TTL
		cost := int64(200)
		if !entry.ExpireAt.IsZero() {
			ttl := time.Until(entry.ExpireAt)
			s.byID.SetWithTTL(entry.ID, entry, cost, ttl)
			s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, ttl)
		} else {
			s.byID.Set(entry.ID, entry, cost)
			s.byAccessor.Set(entry.Accessor, entry.ID, 10)
		}

		// Check if this is the root token
		if entry.Type == TypeWardenToken && entry.PrincipalID == "root" {
			if tokenValue, ok := entry.Data["token"]; ok {
				s.rootTokenManager.SetRootToken(tokenValue, entry.ID)
			}
		}

		loadedCount++
	}

	// Log summary inside the transaction
	if loadedCount > 0 || expiredCount > 0 || failedCount > 0 {
		s.logger.Info("token loading summary",
			logger.Int("loaded", loadedCount),
			logger.Int("expired", expiredCount),
			logger.Int("failed", failedCount),
			logger.Int("total_keys", len(tokenKeys)))
	}


	// Wait for all cache writes to complete
	s.byID.Wait()
	s.byAccessor.Wait()

	return loadedCount, nil
}

// loadTokenByAccessor reads a token from persistent storage by accessor
func (s *TokenStore) loadTokenByAccessor(accessor string) (*TokenEntry, error) {
	if s.storage == nil {
		return nil, errors.New("storage backend not initialized")
	}

	// First, get the token ID from accessor mapping
	accessorPath := tokenAccessorPrefix + accessor
	storageEntry, err := s.storage.Get(context.Background(), accessorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read accessor mapping: %w", err)
	}

	if storageEntry == nil {
		return nil, ErrAccessorNotFound
	}

	tokenID := string(storageEntry.Value)

	// Now load the full token entry by ID
	return s.loadToken(tokenID)
}

// deleteToken removes a token from all storage tiers
// Uses a transaction to ensure atomicity: both token and accessor are deleted together
// or neither is deleted if any operation fails
func (s *TokenStore) deleteToken(entry *TokenEntry) error {
	if s.storage == nil {
		return errors.New("storage backend not initialized")
	}

	ctx := context.Background()
	idPath := tokenIDPrefix + entry.ID
	accessorPath := tokenAccessorPrefix + entry.Accessor

	// Check if storage supports transactions
	txnBarrier, supportsTxn := s.storage.(sdklogical.TransactionalStorage)

	if supportsTxn {
		// Use transaction for atomicity
		txn, err := txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer txn.Rollback(ctx) // Safe to call even after commit

		// Delete from Tier 1 (by ID)
		if err := txn.Delete(ctx, idPath); err != nil {
			return fmt.Errorf("failed to delete token by ID: %w", err)
		}

		// Delete from Tier 2 (accessor mapping)
		if err := txn.Delete(ctx, accessorPath); err != nil {
			return fmt.Errorf("failed to delete accessor mapping: %w", err)
		}

		// Commit the transaction
		if err := txn.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit token delete transaction: %w", err)
		}
	} else {
		// Fallback: non-transactional storage (best effort)
		// Delete in reverse order: token first, then accessor
		// This order minimizes impact if deletion fails
		var errs []error

		if err := s.storage.Delete(ctx, idPath); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete by ID: %w", err))
		}

		if err := s.storage.Delete(ctx, accessorPath); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete accessor: %w", err))
		}

		if len(errs) > 0 {
			return fmt.Errorf("failed to delete token from storage: %v", errs)
		}
	}

	return nil
}

// Helper functions

// generateAccessor generates a cryptographically secure accessor
func generateAccessor() string {
	// Generate 24 random bytes (will be 32 characters in base64)
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based (should never happen)
		return fmt.Sprintf("acc_%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// encodeTokenEntry serializes a TokenEntry to JSON
func encodeTokenEntry(entry *TokenEntry) ([]byte, error) {
	if entry == nil {
		return nil, errors.New("cannot encode nil token entry")
	}
	return json.Marshal(entry)
}

// decodeTokenEntry deserializes a TokenEntry from JSON
func decodeTokenEntry(data []byte) (*TokenEntry, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot decode empty data")
	}
	var entry TokenEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}
