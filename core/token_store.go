package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	TypeUserPass      = "user_pass"
	TypeAWSAccessKeys = "aws_access_keys"
	TypeWardenToken   = "warden_token"
	TypeJWTRole       = "jwt_role"
)

// Storage path constants for token store organization
const (
	tokenStorePath      = "core/token/" // Base path for all token-related storage
	tokenIDPrefix       = "id/"         // Prefix for token ID storage (full token data)
	tokenAccessorPrefix = "accessor/"   // Prefix for accessor → ID mappings
)

var (
	// ErrUnsupportedTokenType is returned when an unknown token type is requested
	ErrUnsupportedTokenType = errors.New("unsupported token type")

	// ErrTokenNotFound is returned when a token cannot be found
	ErrTokenNotFound = errors.New("token not found")

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

// IPBindingPolicy controls how IP binding is enforced for tokens
type IPBindingPolicy string

const (
	// IPBindingDisabled disables IP binding checks entirely
	IPBindingDisabled IPBindingPolicy = "disabled"
	// IPBindingOptional checks IP only if both creation IP and request IP are present (default)
	IPBindingOptional IPBindingPolicy = "optional"
	// IPBindingRequired rejects tokens that don't have IP binding or requests without client IP
	IPBindingRequired IPBindingPolicy = "required"
)

// TokenStoreConfig holds configuration for the token store
type TokenStoreConfig struct {
	// CacheMaxCost is the maximum cost of cache (in bytes, roughly)
	CacheMaxCost int64

	// CacheNumCounters is the number of keys to track frequency
	CacheNumCounters int64

	// EnableMetrics enables collection of operational metrics
	EnableMetrics bool

	// IPBindingPolicy controls how IP binding is enforced
	// "disabled" - no IP binding checks
	// "optional" - check only if both IPs present (default)
	// "required" - reject tokens without IP binding or requests without client IP
	IPBindingPolicy IPBindingPolicy

	// CacheMinRetention is the minimum time to retain tokens in cache
	// regardless of cost-based eviction. This prevents high token volume
	// from evicting valid tokens prematurely. Defaults to 5 minutes.
	CacheMinRetention time.Duration
}

// DefaultTokenStoreConfig returns a production-ready default configuration
func DefaultTokenStoreConfig() *TokenStoreConfig {
	return &TokenStoreConfig{
		CacheMaxCost:      100 << 20, // 100 MB
		CacheNumCounters:  1e7,       // 10 million
		EnableMetrics:     true,
		IPBindingPolicy:   IPBindingOptional,
		CacheMinRetention: 5 * time.Minute,
	}
}

// TokenMetrics tracks operational statistics
type TokenMetrics struct {
	mu                  sync.RWMutex
	TokensGenerated     int64
	TokensResolved      int64
	TokensExpired       int64
	OriginViolations    int64
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
		&JWTRoleTokenType{},
	}

	for _, tokenType := range builtinTypes {
		if err := s.registry.Register(tokenType); err != nil {
			return err
		}
	}

	return nil
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
			NamespaceID:    ns.ID,
			NamespacePath:  ns.Path,
			CreatedAt:      time.Now(),
			PrincipalID:    authData.PrincipalID,
			RoleName:       authData.RoleName,
			ExpireAt:       authData.ExpireAt,
			Data:           make(map[string]string),
			Policies:       authData.Policies,
			CredentialSpec: authData.CredentialSpec,
			CreatedByIP:    authData.ClientIP,
		}

		// Generate accessor (Tier 2)
		accessor, err := generateAccessor()
		if err != nil {
			return nil, fmt.Errorf("failed to generate accessor: %w", err)
		}
		entry.Accessor = accessor

		// Let the token type generate its values
		clientData, err := tokenType.Generate(authData, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %w", err)
		}

		// Compute ID using the deterministic lookup key
		lookupKey := tokenType.LookupKey()
		entry.ID = tokenType.ComputeID(clientData[lookupKey])

		// Check for existing token with same ID
		if existingEntry, found := s.byID.Get(entry.ID); found {
			// For JWT tokens, the ID is deterministic (based on jwt:role hash).
			// Finding an existing token means this JWT+role already has a valid token.
			// Return the existing token instead of treating it as a collision.
			if meta.Name == TypeJWTRole {
				return existingEntry, nil
			}

			// For other token types, this is a true collision - retry with new random values
			s.logger.Error("token ID collision detected, regenerating",
				logger.String("token_id", entry.ID),
				logger.String("type", meta.Name),
				logger.Int("attempt", i+1))

			if i == maxRetries-1 {
				return nil, errors.New("failed to generate unique token after retries")
			}
			continue
		}

		// No existing token, store the new one in all three tiers

		// Tier 1: Store in primary cache (byID) with TTL
		// TTL is computed as max(remaining token lifetime, minimum retention)
		// This prevents high token volume from evicting valid tokens prematurely
		cost := int64(200)
		cacheTTL := s.computeCacheTTL(entry)
		s.byID.SetWithTTL(entry.ID, entry, cost, cacheTTL)

		// Tier 2: Store accessor mapping with same TTL
		s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, cacheTTL)

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

		// Register token with expiration manager for timer-based TTL enforcement
		// JWT role tokens are cache-only, so don't persist their expiration entries
		if expMgr := s.core.GetExpirationManager(); expMgr != nil && ttl > 0 {
			persist := entry.Type != TypeJWTRole
			if err := expMgr.RegisterToken(ctx, entry.ID, ttl, persist); err != nil {
				s.logger.Warn("failed to register token with expiration manager",
					logger.String("token_id", entry.ID),
					logger.Err(err))
				// Don't fail - token is still valid, just relies on cache eviction
			}
		}

		s.logger.Trace("token created",
			logger.String("token_id", entry.ID),
			logger.String("accessor", entry.Accessor),
			logger.String("type", meta.Name),
			logger.String("namespace", ns.Path),
			logger.Time("expires_at", authData.ExpireAt))

		return entry, nil
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
	var tokenID string
	if err != nil {
		// Fallback for dev-mode custom tokens without standard prefix.
		// Compute what the ID would be if this were a Warden token.
		wt := &WardenTokenType{}
		candidateID := wt.ComputeID(tokenValue)
		if _, found := s.byID.Get(candidateID); found {
			tokenType = wt
			tokenID = candidateID
		} else if loaded, loadErr := s.loadToken(candidateID); loadErr == nil && loaded != nil {
			tokenType = wt
			tokenID = candidateID
			_ = s.restoreTokenToCache(ctx, loaded, "ResolveToken-devFallback")
		} else {
			return "", "", fmt.Errorf("failed to detect token type: %w", err)
		}
	} else {
		tokenID = tokenType.ComputeID(tokenValue)
	}

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
		if err := s.restoreTokenToCache(ctx, entry, "ResolveToken"); err != nil {
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
	tokenNs, err := s.core.namespaceStore.GetNamespaceByAccessor(ctx, entry.NamespaceID)
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
	// Use constant-time comparison to prevent timing attacks
	lookupKey := tokenType.LookupKey()
	expectedValue, ok := entry.Data[lookupKey]
	if !ok || subtle.ConstantTimeCompare([]byte(expectedValue), []byte(tokenValue)) != 1 {
		s.logger.Error("token value mismatch - possible hash collision",
			logger.String("token_id", tokenID),
			logger.String("lookup_key", lookupKey))
		return "", "", ErrTokenNotFound
	}

	// Validate expiration
	if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
		if s.config.EnableMetrics {
			s.metrics.IncrementTokensExpired()
		}
		return "", "", ErrTokenExpired
	}

	// Validate same-origin policy (IP binding)
	if err := s.validateIPBinding(ctx, tokenID, entry); err != nil {
		return "", "", err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}

	return entry.PrincipalID, entry.RoleName, nil
}

// LookupByAccessor looks up a token by its accessor
func (s *TokenStore) LookupByAccessor(ctx context.Context, accessor string) (*TokenEntry, error) {
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
		if err := s.restoreTokenToCache(ctx, entry, "LookupByAccessor"); err != nil {
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
		if err := s.restoreTokenToCache(ctx, entry, "LookupByAccessor-orphaned"); err != nil {
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
	entry, err := s.LookupByAccessor(ctx, accessor)
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

// RevokeByExpiration revokes a token by its ID, removing it from caches and storage.
// This is called by the expiration manager when a token expires.
func (s *TokenStore) RevokeByExpiration(tokenID string) error {
	// Lookup the token entry to get accessor for cleanup
	te, found := s.byID.Get(tokenID)
	if !found {
		// Token already gone (perhaps deleted manually), nothing to do
		s.logger.Debug("token not found during expiration revocation",
			logger.String("token_id", tokenID))
		return nil
	}

	// Delete from caches
	s.byID.Del(tokenID)
	s.byAccessor.Del(te.Accessor)

	// Delete from persistent storage
	if err := s.deleteToken(te); err != nil {
		s.logger.Warn("failed to delete expired token from storage",
			logger.String("token_id", tokenID),
			logger.Err(err))
		// Don't fail the revocation for storage errors
	}

	s.logger.Trace("token expired",
		logger.String("token_id", tokenID),
		logger.String("accessor", te.Accessor))

	return nil
}

// RevokeByNamespace removes all tokens belonging to the given namespace.
// namespaceID is the namespace accessor (ns.ID), matching entry.NamespaceID.
// This is called during namespace deletion to remove all auth tokens for the namespace.
func (s *TokenStore) RevokeByNamespace(namespaceID string) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrStoreClosed
	}
	s.mu.RUnlock()

	if s.storage == nil {
		return nil
	}

	// List all token IDs from storage
	tokenKeys, err := s.storage.List(context.Background(), tokenIDPrefix)
	if err != nil {
		return fmt.Errorf("failed to list tokens: %w", err)
	}

	var removed int
	for _, tokenID := range tokenKeys {
		if tokenID == "" {
			continue
		}

		entry, err := s.loadToken(tokenID)
		if err != nil {
			continue
		}

		if entry.NamespaceID != namespaceID {
			continue
		}

		// Delete from caches
		s.byID.Del(entry.ID)
		s.byAccessor.Del(entry.Accessor)

		// Delete from storage
		if err := s.deleteToken(entry); err != nil {
			s.logger.Warn("failed to delete token during namespace cleanup",
				logger.String("token_id", entry.ID),
				logger.Err(err))
		}

		removed++
	}

	if removed > 0 {
		s.logger.Info("revoked all tokens for namespace",
			logger.String("namespace", namespaceID),
			logger.Int("removed", removed))
	}

	return nil
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
		PrincipalID: namespace.RootNamespaceUUID,
		ExpireAt:    time.Time{}, // No expiration
		Policies:    []string{"root"},
	}

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Generate token using standard mechanism
	entry, err := s.generateWithCollisionDetection(
		namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
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

// ReplaceRootTokenValue replaces the current root token value with a custom one.
// This is used in dev mode to support --dev-root-token with arbitrary strings.
func (s *TokenStore) ReplaceRootTokenValue(customToken string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStoreClosed
	}
	s.mu.Unlock()

	if !s.rootTokenManager.HasRootToken() {
		return errors.New("no root token exists to replace")
	}

	// Get the old root token entry
	oldTokenID := s.rootTokenManager.GetCurrentRootTokenID()
	oldEntry, found := s.byID.Get(oldTokenID)
	if !found {
		var err error
		oldEntry, err = s.loadToken(oldTokenID)
		if err != nil {
			return fmt.Errorf("root token entry not found: %w", err)
		}
	}

	// Create new entry with custom token value (copy all fields from old entry)
	newEntry := &TokenEntry{
		Type:           oldEntry.Type,
		NamespaceID:    oldEntry.NamespaceID,
		NamespacePath:  oldEntry.NamespacePath,
		CreatedAt:      oldEntry.CreatedAt,
		PrincipalID:    oldEntry.PrincipalID,
		RoleName:       oldEntry.RoleName,
		ExpireAt:       oldEntry.ExpireAt,
		Accessor:       oldEntry.Accessor,
		Policies:       oldEntry.Policies,
		CredentialSpec: oldEntry.CredentialSpec,
		CreatedByIP:    oldEntry.CreatedByIP,
		Data:           map[string]string{"token": customToken},
	}

	// Compute new ID from custom token value
	wardenType := &WardenTokenType{}
	newEntry.ID = wardenType.ComputeID(customToken)

	// Remove old entry from cache
	s.byID.Del(oldTokenID)

	// Store new entry in cache (no TTL for root token)
	s.byID.SetWithTTL(newEntry.ID, newEntry, 200, 0)
	s.byAccessor.SetWithTTL(newEntry.Accessor, newEntry.ID, 10, 0)
	s.byID.Wait()
	s.byAccessor.Wait()

	// Persist new entry and delete old one from storage
	if err := s.persistToken(newEntry); err != nil {
		s.logger.Error("failed to persist custom root token",
			logger.String("error", err.Error()))
	}
	if err := s.deleteToken(oldEntry); err != nil {
		s.logger.Error("failed to delete old root token from storage",
			logger.String("error", err.Error()))
	}

	// Update root token manager
	s.rootTokenManager.SetRootToken(customToken, newEntry.ID)

	s.logger.Info("root token replaced with custom value",
		logger.String("new_token_id", newEntry.ID))

	return nil
}

// persistToken writes a token to persistent storage using two-tier indexing
// Uses a transaction to ensure atomicity: both token and accessor are stored together
// or neither is stored if any operation fails
func (s *TokenStore) persistToken(entry *TokenEntry) error {
	// Skip persistence for jwt_role tokens - they are cache-only
	if entry.Type == TypeJWTRole {
		return nil
	}

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
func (s *TokenStore) restoreTokenToCache(ctx context.Context, entry *TokenEntry, caller string) error {
	cost := int64(200)

	// Check if token is already expired
	if !entry.ExpireAt.IsZero() {
		ttl := time.Until(entry.ExpireAt)
		if ttl <= 0 {
			// Token expired while in storage
			s.logger.Debug("token expired in storage, not restoring to cache",
				logger.String("caller", caller),
				logger.String("token_id", entry.ID))
			return ErrTokenExpired
		}

		// Store in cache with TTL computed from remaining lifetime and minimum retention
		cacheTTL := s.computeCacheTTL(entry)
		s.byID.SetWithTTL(entry.ID, entry, cost, cacheTTL)
		s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, cacheTTL)
		s.byID.Wait()
		s.byAccessor.Wait()

		// Register with expiration manager for timer-based TTL enforcement
		// Tokens restored from storage are always persisted (JWT role tokens are not stored)
		if expMgr := s.core.GetExpirationManager(); expMgr != nil {
			if err := expMgr.RegisterToken(ctx, entry.ID, ttl, true); err != nil {
				s.logger.Warn("failed to register restored token with expiration manager",
					logger.String("token_id", entry.ID),
					logger.Err(err))
			}
		}

		s.logger.Debug("token restored to cache from storage",
			logger.String("caller", caller),
			logger.String("token_id", entry.ID),
			logger.String("remaining_ttl", ttl.String()))
		return nil
	} else {
		// No expiration (non-expiring token) - use minimum retention for cache TTL
		cacheTTL := s.computeCacheTTL(entry)
		s.byID.SetWithTTL(entry.ID, entry, cost, cacheTTL)
		s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, cacheTTL)
		s.byID.Wait()
		s.byAccessor.Wait()

		// Register non-expiring token with expiration manager (TTL=0)
		// Tokens restored from storage are always persisted (JWT role tokens are not stored)
		if expMgr := s.core.GetExpirationManager(); expMgr != nil {
			if err := expMgr.RegisterToken(ctx, entry.ID, 0, true); err != nil {
				s.logger.Warn("failed to register restored non-expiring token with expiration manager",
					logger.String("token_id", entry.ID),
					logger.Err(err))
			}
		}

		s.logger.Debug("token restored to cache from storage (no expiration)",
			logger.String("caller", caller),
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

		// Skip expired tokens - ExpirationManager will handle cleanup
		if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
			s.logger.Debug("skipping expired token during initialization",
				logger.String("token_id", entry.ID),
				logger.Time("expired_at", entry.ExpireAt))
			expiredCount++
			continue
		}

		// Restore to cache with TTL computed from remaining lifetime and minimum retention
		cost := int64(200)
		cacheTTL := s.computeCacheTTL(entry)
		s.byID.SetWithTTL(entry.ID, entry, cost, cacheTTL)
		s.byAccessor.SetWithTTL(entry.Accessor, entry.ID, 10, cacheTTL)

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
			logger.Int("expired_skipped", expiredCount),
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
	// Skip storage operations for jwt_role tokens - they are cache-only
	if entry.Type == TypeJWTRole {
		return nil
	}

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

func (c *Core) LookupToken(ctx context.Context, tokenValue string) (*TokenEntry, error) {
	if c.Sealed() {
		return nil, fmt.Errorf("the core is sealed")
	}

	// Many tests don't have a token store running
	if c.tokenStore == nil {
		return nil, nil
	}

	s := c.tokenStore

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrStoreClosed
	}
	s.mu.RUnlock()

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return nil, errors.New("namespace not found in context")
	}

	// Detect token type
	tokenType, err := s.registry.DetectType(tokenValue)
	if err != nil {
		return nil, fmt.Errorf("failed to detect token type: %w", err)
	}

	// Compute token ID
	tokenID := tokenType.ComputeID(tokenValue)

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
				return nil, ErrTokenNotFound
			}
			s.logger.Warn("failed to load token from storage on cache miss",
				logger.String("token_id", tokenID),
				logger.String("error", err.Error()))
			return nil, ErrTokenNotFound
		}

		// Restore to cache with remaining TTL
		entry = loadedEntry
		if err := s.restoreTokenToCache(ctx, entry, "LookupToken"); err != nil {
			return nil, err
		}
	} else {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheHits()
		}
	}

	// Validate namespace binding with hierarchical access
	// Tokens from a parent namespace can access all child namespaces
	tokenNs, err := c.namespaceStore.GetNamespaceByAccessor(ctx, entry.NamespaceID)
	if err != nil || tokenNs == nil {
		s.logger.Warn("token namespace not found",
			logger.String("token_id", tokenID),
			logger.String("token_namespace_id", entry.NamespaceID))
		return nil, ErrTokenNamespaceMismatch
	}

	// Check if token's namespace is a parent of (or same as) the request namespace
	isValidNamespace := ns.UUID == tokenNs.UUID || ns.HasParent(tokenNs)
	if !isValidNamespace {
		if s.config.EnableMetrics {
			s.metrics.IncrementNamespaceMismatches()
		}
		s.logger.Warn("token namespace mismatch",
			logger.String("token_id", tokenID),
			logger.String("token_namespace", tokenNs.Path),
			logger.String("request_namespace", ns.Path))
		return nil, ErrTokenNamespaceMismatch
	}

	// Validate token value matches (defense against hash collisions)
	// Use constant-time comparison to prevent timing attacks
	lookupKey := tokenType.LookupKey()
	expectedValue, ok := entry.Data[lookupKey]
	if !ok || subtle.ConstantTimeCompare([]byte(expectedValue), []byte(tokenValue)) != 1 {
		s.logger.Error("token value mismatch - possible hash collision",
			logger.String("token_id", tokenID),
			logger.String("lookup_key", lookupKey))
		return nil, ErrTokenNotFound
	}

	// Validate expiration
	if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
		if s.config.EnableMetrics {
			s.metrics.IncrementTokensExpired()
		}
		return nil, ErrTokenExpired
	}

	// Validate same-origin policy (IP binding)
	if err := s.validateIPBinding(ctx, tokenID, entry); err != nil {
		return nil, err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}

	// Return a copy to prevent external modification
	entryCopy := *entry
	return &entryCopy, nil
}

// LookupJWTTokenWithRole looks up a JWT token using both the JWT and role.
// This is used for transparent mode where the same JWT with different roles
// should produce different tokens. The composite "jwt:role" value is used
// for ID computation and validation.
func (c *Core) LookupJWTTokenWithRole(ctx context.Context, jwt string, role string) (*TokenEntry, error) {
	if c.Sealed() {
		return nil, fmt.Errorf("the core is sealed")
	}

	if c.tokenStore == nil {
		return nil, nil
	}

	s := c.tokenStore

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrStoreClosed
	}
	s.mu.RUnlock()

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return nil, errors.New("namespace not found in context")
	}

	// Get JWT token type
	jwtType := &JWTRoleTokenType{}

	// Compute hash of "jwt:role" - this matches what's stored in entry.Data["jwt"]
	jwtHash := jwtType.ComputeData(jwt, role)
	// Token ID is computed from the hash
	tokenID := jwtType.ComputeID(jwtHash)

	// Lookup token in cache only - JWT tokens are not persisted to storage
	// On cache miss, the caller should perform implicit auth to create a new token
	entry, found := s.byID.Get(tokenID)
	if !found {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}
		return nil, ErrTokenNotFound
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementCacheHits()
	}

	// Validate namespace binding
	tokenNs, err := c.namespaceStore.GetNamespaceByAccessor(ctx, entry.NamespaceID)
	if err != nil || tokenNs == nil {
		s.logger.Warn("JWT token namespace not found",
			logger.String("token_id", tokenID),
			logger.String("token_namespace_id", entry.NamespaceID))
		return nil, ErrTokenNamespaceMismatch
	}

	isValidNamespace := ns.UUID == tokenNs.UUID || ns.HasParent(tokenNs)
	if !isValidNamespace {
		if s.config.EnableMetrics {
			s.metrics.IncrementNamespaceMismatches()
		}
		s.logger.Warn("JWT token namespace mismatch",
			logger.String("token_id", tokenID),
			logger.String("token_namespace", tokenNs.Path),
			logger.String("request_namespace", ns.Path))
		return nil, ErrTokenNamespaceMismatch
	}

	// Validate token value matches (comparing hashes, not raw JWT)
	// entry.Data["jwt"] stores the SHA-256 hash of the composite "jwt:role" value
	lookupKey := jwtType.LookupKey()
	expectedHash, ok := entry.Data[lookupKey]
	if !ok {
		s.logger.Error("JWT token lookup key not found",
			logger.String("token_id", tokenID),
			logger.String("lookup_key", lookupKey))
		return nil, ErrTokenNotFound
	}
	// Compare stored hash with computed hash using constant-time comparison
	// to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(jwtHash)) != 1 {
		s.logger.Error("JWT token value mismatch",
			logger.String("token_id", tokenID),
			logger.String("lookup_key", lookupKey))
		return nil, ErrTokenNotFound
	}

	// Validate expiration
	if !entry.ExpireAt.IsZero() && time.Now().After(entry.ExpireAt) {
		if s.config.EnableMetrics {
			s.metrics.IncrementTokensExpired()
		}
		return nil, ErrTokenExpired
	}

	// Validate same-origin policy (IP binding)
	if err := s.validateIPBinding(ctx, tokenID, entry); err != nil {
		return nil, err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}

	entryCopy := *entry
	return &entryCopy, nil
}

// Helper functions

// generateAccessor generates a cryptographically secure accessor.
// Returns an error if secure random generation fails - never falls back to weak entropy.
func generateAccessor() (string, error) {
	// Generate 24 random bytes (will be 32 characters in base64)
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure accessor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
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

// isLoopback returns true if the IP is a loopback address (127.0.0.1 or ::1).
func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// ipsMatch returns true if two IPs are equal, treating all loopback addresses
// (127.0.0.1 and ::1) as equivalent so that localhost vs 127.0.0.1 doesn't
// cause spurious origin violations.
func ipsMatch(a, b string) bool {
	if a == b {
		return true
	}
	return isLoopback(a) && isLoopback(b)
}

// validateIPBinding checks IP binding based on the configured policy.
// Returns nil if validation passes, or ErrOriginViolation if it fails.
func (s *TokenStore) validateIPBinding(ctx context.Context, tokenID string, entry *TokenEntry) error {
	policy := s.config.IPBindingPolicy

	// Disabled: skip all IP binding checks
	if policy == IPBindingDisabled {
		return nil
	}

	clientIP, hasClientIP := ctx.Value(logical.ClientIPKey).(string)
	hasCreationIP := entry.CreatedByIP != ""

	switch policy {
	case IPBindingRequired:
		// Required: both creation IP and request IP must be present and match
		if !hasCreationIP {
			if s.config.EnableMetrics {
				s.metrics.IncrementOriginViolations()
			}
			s.logger.Warn("IP binding required but token has no creation IP",
				logger.String("token_id", tokenID))
			return ErrOriginViolation
		}
		if !hasClientIP || clientIP == "" {
			if s.config.EnableMetrics {
				s.metrics.IncrementOriginViolations()
			}
			s.logger.Warn("IP binding required but request has no client IP",
				logger.String("token_id", tokenID))
			return ErrOriginViolation
		}
		if !ipsMatch(clientIP, entry.CreatedByIP) {
			if s.config.EnableMetrics {
				s.metrics.IncrementOriginViolations()
			}
			s.logger.Warn("same origin policy violation",
				logger.String("token_id", tokenID),
				logger.String("created_ip", entry.CreatedByIP),
				logger.String("request_ip", clientIP))
			return ErrOriginViolation
		}

	case IPBindingOptional:
		fallthrough
	default:
		// Optional: only check if both IPs are present
		if hasClientIP && hasCreationIP {
			if !ipsMatch(clientIP, entry.CreatedByIP) {
				if s.config.EnableMetrics {
					s.metrics.IncrementOriginViolations()
				}
				s.logger.Warn("same origin policy violation",
					logger.String("token_id", tokenID),
					logger.String("created_ip", entry.CreatedByIP),
					logger.String("request_ip", clientIP))
				return ErrOriginViolation
			}
		}
	}

	return nil
}

// computeCacheTTL calculates the cache TTL for a token entry.
// Uses the maximum of remaining token lifetime and minimum retention period.
func (s *TokenStore) computeCacheTTL(entry *TokenEntry) time.Duration {
	minRetention := s.config.CacheMinRetention

	// For non-expiring tokens (e.g., root token), cache indefinitely (TTL=0)
	if entry.ExpireAt.IsZero() {
		return 0
	}

	remaining := time.Until(entry.ExpireAt)
	if remaining <= 0 {
		return 0 // Token expired
	}

	// Use the maximum of remaining time and minimum retention
	if remaining > minRetention {
		return remaining
	}
	return minRetention
}
