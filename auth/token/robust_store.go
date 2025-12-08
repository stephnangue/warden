package token

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/logger"
)

var (
	ErrUnsupportedTokenType = errors.New("unsupported token type")
	ErrTokenNotFound        = errors.New("token not found")
	ErrAuthDeadlineViolated = errors.New("authentication deadline violated")
	ErrTokenExpired         = errors.New("token has expired")
	ErrOriginViolation      = errors.New("same origin policy violated")
	ErrStoreClosed          = errors.New("token store is closed")
)

type TokenAccess interface {
	ResolveToken(ctx context.Context, tokenID string, reqContext map[string]string) (string, string, error)
	GetToken(tokenID string) *Token
}

// StoreConfig holds configuration for the token store
type StoreConfig struct {
	// CacheMaxCost is the maximum cost of cache (in bytes, roughly)
	CacheMaxCost int64

	// CacheNumCounters is the number of keys to track frequency
	CacheNumCounters int64

	// EnableMetrics enables collection of operational metrics
	EnableMetrics bool
}

// DefaultConfig returns a production-ready default configuration
func DefaultConfig() *StoreConfig {
	return &StoreConfig{
		CacheMaxCost:     100 << 20, // 100 MB
		CacheNumCounters: 1e7,       // 10 million
		EnableMetrics:    true,
	}
}

// Metrics tracks operational statistics
type Metrics struct {
	mu                 sync.RWMutex
	TokensGenerated    int64
	TokensResolved     int64
	TokensExpired      int64
	OriginViolations   int64
	DeadlineViolations int64
	CacheHits          int64
	CacheMisses        int64
}

func (m *Metrics) IncrementTokensGenerated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensGenerated++
}

func (m *Metrics) IncrementTokensResolved() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensResolved++
}

func (m *Metrics) IncrementTokensExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensExpired++
}

func (m *Metrics) IncrementOriginViolations() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OriginViolations++
}

func (m *Metrics) IncrementDeadlineViolations() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeadlineViolations++
}

func (m *Metrics) IncrementCacheHits() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

func (m *Metrics) IncrementCacheMisses() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

func (m *Metrics) GetSnapshot() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]int64{
		"tokens_generated":    m.TokensGenerated,
		"tokens_resolved":     m.TokensResolved,
		"tokens_expired":      m.TokensExpired,
		"origin_violations":   m.OriginViolations,
		"deadline_violations": m.DeadlineViolations,
		"cache_hits":          m.CacheHits,
		"cache_misses":        m.CacheMisses,
	}
}

type RobustStore struct {
	mu               sync.RWMutex
	cache            *ristretto.Cache[string, *AuthData]
	config           *StoreConfig
	logger           logger.Logger
	metrics          *Metrics
	closed           bool
	rootTokenManager *RootTokenManager
}

func NewRobustStore(log logger.Logger, config *StoreConfig) (*RobustStore, error) {
	if config == nil {
		config = DefaultConfig()
	}

	store := &RobustStore{
		config:           config,
		logger:           log,
		metrics:          &Metrics{},
		closed:           false,
		rootTokenManager: NewRootTokenManager(),
	}

	cache, err := ristretto.NewCache(&ristretto.Config[string, *AuthData]{
		NumCounters: config.CacheNumCounters,
		MaxCost:     config.CacheMaxCost,
		BufferItems: 64,
		OnEvict:     store.onEvict,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	store.cache = cache

	log.Info("token store initialized",
		logger.Bool("metrics_enabled", config.EnableMetrics))

	return store, nil
}

// onEvict is called when a credential is evicted from the cache
func (cp *RobustStore) onEvict(item *ristretto.Item[*AuthData]) {
	cp.logger.Debug("token evicted from cache",
		logger.String("token_id", item.Value.token.ID),
		logger.String("reason", "ttl_expired_or_capacity"),
	)
}

// GenerateToken creates a new token based on the specified type
func (s *RobustStore) GenerateToken(tokenType string, authData *AuthData) (*Token, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStoreClosed
	}
	s.mu.Unlock()

	if authData == nil {
		return nil, errors.New("authData cannot be nil")
	}

	var token *Token
	var err error

	switch tokenType {
	case USER_PASS:
		token, err = s.generateUserPassToken(authData)
	case AWS_ACCESS_KEYS:
		token, err = s.generateAwsAccessKeysToken(authData)
	case WARDEN_TOKEN:
		token, err = s.generateWardenToken(authData)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTokenType, tokenType)
	}

	if err != nil {
		return nil, err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensGenerated()
	}

	return token, nil
}

// ResolveToken validates and resolves a token to its principal and role
func (s *RobustStore) ResolveToken(ctx context.Context, tokenValue string, reqContext map[string]string) (string, string, error) {
	// Detect token type from value format
	tokenType := DetectTokenType(tokenValue)

	// Compute hash-based ID for cache lookup
	tokenID := ComputeTokenID(tokenType, tokenValue)

	s.logger.Trace("resolving token",
		logger.String("token_id", tokenID),  // Safe to log (hash)
		logger.String("request_id", middleware.GetReqID(ctx)),
	)

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", "", ErrStoreClosed
	}
	s.mu.RUnlock()

	// Get from cache using computed hash
	authData, found := s.cache.Get(tokenID)
	if !found {
		s.logger.Warn("token not found",
			logger.String("token_id", tokenID),  // Safe to log (hash)
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}
		return "", "", ErrTokenNotFound
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementCacheHits()
	}

	token := authData.GetToken()
	if token == nil {
		s.logger.Warn("token is nil",
			logger.String("token_id", tokenID),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		return "", "", ErrTokenNotFound
	}

	// Verify the token value matches (defense in depth against hash collisions)
	var expectedValue string
	switch token.Type {
	case WARDEN_TOKEN:
		expectedValue = token.Data["token"]
	case AWS_ACCESS_KEYS:
		expectedValue = token.Data["access_key_id"]
	case USER_PASS:
		expectedValue = token.Data["username"]
	}

	if expectedValue != tokenValue {
		s.logger.Error("token value mismatch - possible hash collision",
			logger.String("token_id", tokenID),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		return "", "", ErrTokenNotFound
	}

	now := time.Now()

	// Check auth deadline (skip if zero time = infinite)
	if !authData.AuthDeadline.IsZero() && now.After(authData.AuthDeadline) && !token.HasBeenUsed() {
		s.logger.Warn("auth deadline policy violated",
			logger.String("token_id", tokenID),
			logger.Time("deadline", authData.AuthDeadline),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		if s.config.EnableMetrics {
			s.metrics.IncrementDeadlineViolations()
		}
		// Remove from cache
		s.cache.Del(tokenID)
		return "", "", ErrAuthDeadlineViolated
	}

	// Check expiration (skip if zero time = infinite)
	if !authData.ExpireAt.IsZero() && now.After(authData.ExpireAt) {
		s.logger.Warn("token expired",
			logger.String("token_id", tokenID),
			logger.Time("expired_at", authData.ExpireAt),
			logger.String("request_id", middleware.GetReqID(ctx)),
		)
		if s.config.EnableMetrics {
			s.metrics.IncrementTokensExpired()
		}
		// Remove from cache
		s.cache.Del(tokenID)
		return "", "", ErrTokenExpired
	}

	// Enforce same-origin policy
	if clientIP, exists := reqContext["client_ip"]; exists {
		if expectedIP, hasIP := authData.RequestContext["client_ip"]; hasIP {
			if clientIP != expectedIP {
				s.logger.Warn("same origin policy violated",
					logger.String("token_id", tokenID),
					logger.String("expected_ip", expectedIP),
					logger.String("actual_ip", clientIP),
					logger.String("request_id", middleware.GetReqID(ctx)),
				)
				if s.config.EnableMetrics {
					s.metrics.IncrementOriginViolations()
				}
				return "", "", ErrOriginViolation
			}
		}
	}

	// Mark token as used
	if !token.HasBeenUsed() {
		token.SetUsed()
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}

	return authData.PrincipalID, authData.RoleName, nil
}

// GetToken retrieves a token by value without validation
func (s *RobustStore) GetToken(tokenValue string) *Token {
	// Detect token type from value format
	tokenType := DetectTokenType(tokenValue)

	// Compute hash-based ID for cache lookup
	tokenID := ComputeTokenID(tokenType, tokenValue)

	authData, found := s.cache.Get(tokenID)
	if !found {
		return nil
	}

	return authData.GetToken()
}

// GetMetrics returns a snapshot of current metrics
func (s *RobustStore) GetMetrics() map[string]int64 {
	if !s.config.EnableMetrics {
		return nil
	}
	return s.metrics.GetSnapshot()
}

// generateAwsAccessKeysToken creates an AWS-style access key token
func (s *RobustStore) generateAwsAccessKeysToken(authData *AuthData) (*Token, error) {
	ttl := time.Until(authData.ExpireAt)
	if ttl <= 0 {
		return nil, errors.New("token already expired")
	}

	var token *Token
	var tokenID string
	var accessKeyID string
	var secretAccessKey string

	// Generate token with collision detection (infinite retry loop)
	for {
		accessKeyID = helper.GenerateAWSAccessKeyID()
		secretAccessKey = helper.GenerateAWSSecretAccessKey()

		tokenID = ComputeTokenID(AWS_ACCESS_KEYS, accessKeyID)

		if _, found := s.cache.Get(tokenID); !found {
			break
		}

		s.logger.Warn("token ID collision detected, regenerating",
			logger.String("token_id", tokenID))
	}

	token = &Token{
		Type: AWS_ACCESS_KEYS,
		ID:   tokenID,
		Data: map[string]string{
			"access_key_id":     accessKeyID,
			"secret_access_key": secretAccessKey,
		},
		ExpireAt: authData.ExpireAt,
	}
	authData.SetToken(token)

	// Store in cache with TTL using hash as key
	cost := int64(200) // Approximate bytes for AuthData + Token
	s.cache.SetWithTTL(tokenID, authData, cost, ttl)

	s.cache.Wait()

	s.logger.Debug("AWS access keys token created",
		logger.String("token_id", tokenID), 
		logger.Time("expires_at", authData.ExpireAt))

	return token, nil
}

// generateUserPassToken creates a username/password token
func (s *RobustStore) generateUserPassToken(authData *AuthData) (*Token, error) {
	ttl := time.Until(authData.ExpireAt)
	if ttl <= 0 {
		return nil, errors.New("token already expired")
	}

	var token *Token
	var tokenID string
	var username string
	var password string

	// Generate token with collision detection
	for {
		username = "usr-" + helper.GenerateRandomString(26)
		password = helper.GenerateRandomString(40)

		tokenID = ComputeTokenID(USER_PASS, username)

		if _, found := s.cache.Get(tokenID); !found {
			break
		}

		s.logger.Warn("token ID collision detected, regenerating",
			logger.String("token_id", tokenID))
	}

	token = &Token{
		Type: USER_PASS,
		ID:   tokenID,
		Data: map[string]string{
			"username": username,
			"password": password,
		},
		ExpireAt: authData.ExpireAt,
	}
	authData.SetToken(token)

	// Store in cache with TTL using hash as key
	cost := int64(200) // Approximate bytes for AuthData + Token
	s.cache.SetWithTTL(tokenID, authData, cost, ttl)

	s.cache.Wait()

	s.logger.Debug("userpass token created",
		logger.String("token_id", tokenID), 
		logger.Time("expires_at", authData.ExpireAt))

	return token, nil
}

func (s *RobustStore) generateWardenToken(authData *AuthData) (*Token, error) {
	ttl := time.Until(authData.ExpireAt)
	if ttl <= 0 {
		return nil, errors.New("token already expired")
	}

	var token *Token
	var tokenID string
	var tokenValue string

	// Generate token with collision detection
	for {
		tokenValue = "cws." + helper.GenerateRandomString(64)

		tokenID = ComputeTokenID(WARDEN_TOKEN, tokenValue)

		if _, found := s.cache.Get(tokenID); !found {
			break
		}

		s.logger.Warn("token ID collision detected, regenerating",
			logger.String("token_id", tokenID))
	}

	token = &Token{
		Type: WARDEN_TOKEN,
		ID:   tokenID, 
		Data: map[string]string{
			"token": tokenValue, 
		},
		ExpireAt: authData.ExpireAt,
	}
	authData.SetToken(token)

	// Store in cache with TTL using hash as key
	cost := int64(200) // Approximate bytes for AuthData + Token
	s.cache.SetWithTTL(tokenID, authData, cost, ttl)

	s.cache.Wait()

	s.logger.Debug("warden token created",
		logger.String("token_id", tokenID),
		logger.Time("expires_at", authData.ExpireAt))

	return token, nil
}

// GenerateRootToken creates a new root token with infinite lifetime.
// Only one root token can exist at a time; generating a new one revokes the old.
func (s *RobustStore) GenerateRootToken() (string, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", ErrStoreClosed
	}
	s.mu.Unlock()

	// Revoke existing root token if any
	if s.rootTokenManager.HasRootToken() {
		s.logger.Info("revoking existing root token before generating new one")
		if err := s.RevokeRootToken(); err != nil {
			s.logger.Warn("failed to revoke existing root token",
				logger.Err(err))
			// Continue anyway - we'll overwrite it
		}
	}

	var tokenValue string
	var tokenID string

	// Generate token with collision detection (infinite retry loop)
	for {
		tokenValue = "cws." + helper.GenerateRandomString(64)
		tokenID = ComputeTokenID(WARDEN_TOKEN, tokenValue)

		if _, found := s.cache.Get(tokenID); !found {
			break
		}

		s.logger.Warn("token ID collision detected during root token generation, regenerating",
			logger.String("token_id", tokenID))
	}

	// Create AuthData with infinite TTL (zero time values)
	authData := &AuthData{
		PrincipalID:    "root",
		RoleName:       "system_admin",
		AuthDeadline:   time.Time{}, // Zero = no deadline
		ExpireAt:       time.Time{}, // Zero = never expires
		RequestContext: map[string]string{}, // No origin restrictions
	}

	token := &Token{
		Type:     WARDEN_TOKEN,
		ID:       tokenID,
		Data:     map[string]string{"token": tokenValue},
		ExpireAt: time.Time{}, // Never expires
	}
	authData.SetToken(token)

	// Store with no TTL (permanent until revoked)
	cost := int64(200)
	s.cache.Set(tokenID, authData, cost)
	s.cache.Wait()

	// Track in root token manager
	s.rootTokenManager.SetRootToken(tokenValue, tokenID)

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensGenerated()
	}

	s.logger.Info("root token generated",
		logger.String("token_id", tokenID),
		logger.String("principal_id", "root"))

	return tokenValue, nil
}

// RevokeRootToken revokes the current root token.
func (s *RobustStore) RevokeRootToken() error {
	tokenValue := s.rootTokenManager.GetCurrentRootToken()
	if tokenValue == "" {
		return errors.New("no root token to revoke")
	}

	tokenID := ComputeTokenID(WARDEN_TOKEN, tokenValue)
	s.cache.Del(tokenID)

	s.rootTokenManager.ClearRootToken()

	s.logger.Info("root token revoked",
		logger.String("token_id", tokenID))

	return nil
}

// Close gracefully shuts down the token store
func (s *RobustStore) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	s.logger.Info("closing token store")

	// Clear and close cache
	s.cache.Clear()
	s.cache.Close()

	s.logger.Info("token store closed")
}
