package vault

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/logger"

	"github.com/hashicorp/vault/api"
)

// AppRoleConfig holds AppRole authentication configuration
type AppRoleConfig struct {
	RoleID   string
	SecretID string
	MountPath string // defaults to "approle"
	Namespace string
}

// TokenManager handles Vault token caching and renewal
type TokenManager struct {
	client       *api.Client
	appRole      *AppRoleConfig
	token        string
	mutex        sync.RWMutex
	stopCh       chan struct{}
	renewable    bool
	ttl          time.Duration
	lastRenewal  time.Time
	renewalCount int
	maxRetries   int
	logger       logger.Logger
}

// NewTokenManager creates a new token manager with AppRole authentication
func NewTokenManager(client *api.Client, appRole *AppRoleConfig, logger logger.Logger) *TokenManager {
	if appRole.MountPath == "" {
		appRole.MountPath = "approle"
	}

	return &TokenManager{
		client:      client,
		appRole:     appRole,
		stopCh:      make(chan struct{}),
		maxRetries:  5,
		logger:      logger,
	}
}

// Start performs initial AppRole authentication and begins token management
func (tm *TokenManager) Start(ctx context.Context) error {
	// Perform initial AppRole authentication
	if err := tm.authenticateWithAppRole(ctx); err != nil {
		return fmt.Errorf("failed to authenticate with AppRole: %w", err)
	}
	tm.logger.Info("successfully authenticated with AppRole", 
		logger.String("mount_point", tm.appRole.MountPath), 
		logger.String("vault_addr", tm.client.Address()), 
		logger.String("namespace", tm.appRole.Namespace))

	// Get token info after authentication
	if err := tm.refreshTokenInfo(); err != nil {
		return fmt.Errorf("failed to get token info after authentication: %w", err)
	}

	// Start renewal if token is renewable
	if tm.renewable {
		tm.logger.Info("admin token is renewable, starting renewal loop")
		go tm.renewalLoop(ctx)
	} else {
		// For non-renewable tokens, periodically re-authenticate before expiry
		tm.logger.Info("admin token is not renewable, starting reauth loop")
		go tm.reauthLoop(ctx)
	}

	return nil
}

// authenticateWithAppRole performs AppRole authentication
func (tm *TokenManager) authenticateWithAppRole(ctx context.Context) error {
	data := map[string]interface{}{
		"role_id":   tm.appRole.RoleID,
		"secret_id": tm.appRole.SecretID,
	}

	secret, err := tm.client.WithNamespace(tm.appRole.Namespace).Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/login", tm.appRole.MountPath), data)
	if err != nil {
		return fmt.Errorf("AppRole authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no auth info returned from AppRole login")
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tm.token = secret.Auth.ClientToken
	tm.client.SetToken(tm.token)
	tm.renewable = secret.Auth.Renewable
	tm.ttl = time.Duration(secret.Auth.LeaseDuration) * time.Second
	tm.lastRenewal = time.Now()
	tm.renewalCount = 0

	return nil
}

// GetToken returns the current cached token (thread-safe)
func (tm *TokenManager) GetToken() string {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	return tm.token
}

// GetTokenInfo returns current token information
func (tm *TokenManager) GetTokenInfo() (ttl time.Duration, renewable bool, lastRenewal time.Time) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	return tm.ttl, tm.renewable, tm.lastRenewal
}

// refreshTokenInfo gets current token information from Vault
func (tm *TokenManager) refreshTokenInfo() error {
	secret, err := tm.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if token is renewable
	if renewable, ok := secret.Data["renewable"].(bool); ok {
		tm.renewable = renewable
	}

	// Get TTL
	if ttlRaw, ok := secret.Data["ttl"]; ok {
		if ttlFloat, ok := ttlRaw.(float64); ok {
			tm.ttl = time.Duration(ttlFloat) * time.Second
		}
	}

	return nil
}

// renewalLoop handles periodic token renewal with exponential backoff
func (tm *TokenManager) renewalLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			tm.logger.Warn("the admin token renewal stopped due to context cancellation")
			return
		case <-tm.stopCh:
			tm.logger.Warn("the admin token renewal stopped")
			return
		default:
			// Calculate next renewal time
			renewalTime := tm.calculateNextRenewal()
			timer := time.NewTimer(renewalTime)
			futureTime := time.Now().Add(renewalTime)
			tm.logger.Info("next scheduled renewal for the admin token", logger.String("next_renewal_time", futureTime.Format("2006-01-02 15:04:05")))

			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-tm.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				if err := tm.renewTokenWithBackoff(ctx); err != nil {
					tm.logger.Error("schedule renewal for the admin token failed after retries", logger.Err(err))

					tm.logger.Info("failing back to re-authentication")
					// Fall back to re-authentication
					if authErr := tm.authenticateWithAppRole(ctx); authErr != nil {
						tm.logger.Error("fallback re-authentication failed", logger.Err(authErr))
					}
				}
			}
		}
	}
}

// reauthLoop handles periodic re-authentication for non-renewable tokens
func (tm *TokenManager) reauthLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			tm.logger.Info("re-authentication loop stopped due to context cancellation")
			return
		case <-tm.stopCh:
			tm.logger.Info("re-authentication loop stopped")
			return
		default:
			// Re-authenticate at 80% of TTL
			tm.mutex.RLock()
			reauthTime := tm.ttl * 4 / 5
			tm.mutex.RUnlock()

			if reauthTime < time.Minute {
				reauthTime = time.Minute
			}

			timer := time.NewTimer(reauthTime)
			futureTime := time.Now().Add(reauthTime)
			tm.logger.Info("next reauth scheduled for the admin token", logger.String("next_reauth_time", futureTime.Format("2006-01-02 15:04:05")))

			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-tm.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				if err := tm.authenticateWithAppRole(ctx); err != nil {
					tm.logger.Error("scheduled re-authentication failed", logger.Err(err))
				} else {
					tm.logger.Info("scheduled re-authentication successful")
				}
			}
		}
	}
}

// calculateNextRenewal determines when to next renew the token
func (tm *TokenManager) calculateNextRenewal() time.Duration {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	// Renew at 2/3 of TTL, with minimum of 1 minute
	renewalInterval := tm.ttl * 2 / 3
	if renewalInterval < time.Minute {
		renewalInterval = time.Minute
	}

	// Add jitter to prevent thundering herd
	jitter := time.Duration(float64(renewalInterval) * 0.1) // 10% jitter
	randomFactor := rand.Float64()*2 - 1 // Random value between -1 and 1
	renewalInterval += time.Duration(float64(jitter) * randomFactor)


	return renewalInterval
}

// renewTokenWithBackoff performs token renewal with exponential backoff
func (tm *TokenManager) renewTokenWithBackoff(ctx context.Context) error {
	var lastErr error

	for attempt := 0; attempt < tm.maxRetries; attempt++ {
		if attempt > 0 {
			// Calculate exponential backoff delay
			backoffDelay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			maxDelay := 60 * time.Second
			if backoffDelay > maxDelay {
				backoffDelay = maxDelay
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDelay):
				// Continue to next attempt
			}
		}

		if err := tm.renewToken(); err != nil {
			lastErr = err

			continue
		}

		// Success
		tm.logger.Info("admin token renewed successfully", logger.Int("attemt_num", attempt+1) )
		return nil
	}

	return fmt.Errorf("failed to renew token after %d attempts, last error: %w", tm.maxRetries, lastErr)
}

// renewToken performs the actual token renewal
func (tm *TokenManager) renewToken() error {
	secret, err := tm.client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("failed to renew the admin token: %w", err)
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Update TTL from renewal response
	if auth := secret.Auth; auth != nil {
		tm.ttl = time.Duration(auth.LeaseDuration) * time.Second
		tm.lastRenewal = time.Now()
		tm.renewalCount++
		tm.logger.Info("the admin token was renewed", logger.String("new_ttl", helper.FormatTTL(int64(tm.ttl))), logger.Int("renewal_count", tm.renewalCount))
	}

	return nil
}

// Stop gracefully stops the token renewal process
func (tm *TokenManager) Stop() {
	close(tm.stopCh)
}
