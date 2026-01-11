package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

// StoredCredential is the versioned storage format for issued credentials
type StoredCredential struct {
	Version     int               `json:"version"`      // Schema version: 1
	NamespaceID string            `json:"namespace_id"` // Namespace UUID
	TokenID     string            `json:"token_id"`     // Token identifier
	Type        string            `json:"type"`         // Credential type
	Category    string            `json:"category"`     // Credential category

	// Lifecycle
	LeaseTTL  string    `json:"lease_ttl"`  // Duration as string
	LeaseID   string    `json:"lease_id"`   // For revocation
	IssuedAt  time.Time `json:"issued_at"`  // When issued
	ExpiresAt time.Time `json:"expires_at"` // IssuedAt + LeaseTTL

	// Data (encrypted by barrier)
	Data map[string]string `json:"data"`

	// Metadata
	SourceType string `json:"source_type"` // Driver type
	Revocable  bool   `json:"revocable"`   // Can be revoked
	SpecName   string `json:"spec_name"`   // Which spec created this
}

// ============================================================================
// Storage Persistence Methods
// ============================================================================

// persistCredential writes credential to storage with namespace-scoped path
func (m *Manager) persistCredential(ctx context.Context, namespaceID string, cred *Credential) error {
	if m.storage == nil {
		// Storage not configured - skip persistence (backward compatibility)
		return nil
	}

	stored := &StoredCredential{
		Version:     1,
		NamespaceID: namespaceID,
		TokenID:     cred.TokenID,
		Type:        cred.Type,
		Category:    cred.Category,
		LeaseTTL:    cred.LeaseTTL.String(),
		LeaseID:     cred.LeaseID,
		IssuedAt:    cred.IssuedAt,
		ExpiresAt:   cred.IssuedAt.Add(cred.LeaseTTL),
		Data:        cred.Data,
		SourceType:  cred.SourceType,
		Revocable:   cred.Revocable,
		SpecName:    cred.SpecName,
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Build namespace-scoped storage path: {namespace-uuid}/{tokenID}
	storagePath := fmt.Sprintf("%s/%s", namespaceID, cred.TokenID)

	entry := &sdklogical.StorageEntry{
		Key:   storagePath,
		Value: data,
	}

	if err := m.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write credential to storage: %w", err)
	}

	return nil
}

// loadCredentialFromStorage reads credential from storage with namespace-scoped path
func (m *Manager) loadCredentialFromStorage(ctx context.Context, namespaceID string, tokenID string) (*Credential, error) {
	if m.storage == nil {
		// Storage not configured
		return nil, ErrCredentialNotFound
	}

	// Build namespace-scoped storage path: {namespace-uuid}/{tokenID}
	storagePath := fmt.Sprintf("%s/%s", namespaceID, tokenID)

	entry, err := m.storage.Get(ctx, storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read from storage: %w", err)
	}
	if entry == nil {
		return nil, ErrCredentialNotFound
	}

	var stored StoredCredential
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	leaseTTL, _ := time.ParseDuration(stored.LeaseTTL)

	cred := &Credential{
		Type:       stored.Type,
		Category:   stored.Category,
		LeaseTTL:   leaseTTL,
		LeaseID:    stored.LeaseID,
		TokenID:    stored.TokenID,
		IssuedAt:   stored.IssuedAt,
		Data:       stored.Data,
		SourceType: stored.SourceType,
		Revocable:  stored.Revocable,
		SpecName:   stored.SpecName,
	}

	return cred, nil
}

// deleteCredentialFromStorage removes credential from storage with namespace-scoped path
func (m *Manager) deleteCredentialFromStorage(ctx context.Context, namespaceID string, tokenID string) error {
	if m.storage == nil {
		// Storage not configured
		return nil
	}

	// Build namespace-scoped storage path: {namespace-uuid}/{tokenID}
	storagePath := fmt.Sprintf("%s/%s", namespaceID, tokenID)

	if err := m.storage.Delete(ctx, storagePath); err != nil {
		return fmt.Errorf("failed to delete credential from storage: %w", err)
	}

	return nil
}

// LoadFromStorage loads all persisted credentials from storage across all namespaces
func (m *Manager) LoadFromStorage(ctx context.Context) error {
	if m.storage == nil {
		// Storage not configured - skip loading
		m.log.Debug("storage not configured, skipping credential loading")
		return nil
	}

	// List all namespace directories in storage
	namespaces, err := m.storage.List(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	totalLoaded := 0
	totalExpired := 0

	// For each namespace, load its credentials
	for _, nsPath := range namespaces {
		// nsPath is like "namespace-uuid/"
		namespaceID := nsPath[:len(nsPath)-1] // Remove trailing slash

		// List credentials in this namespace
		credKeys, err := m.storage.List(ctx, nsPath)
		if err != nil {
			m.log.Warn("failed to list credentials for namespace",
				logger.String("namespace", namespaceID),
				logger.Err(err),
			)
			continue
		}

		for _, credPath := range credKeys {
			// credPath is like "namespace-uuid/tokenID"
			// Extract tokenID from path
			parts := []rune(credPath)
			tokenID := string(parts[len(nsPath):])

			cred, err := m.loadCredentialFromStorage(ctx, namespaceID, tokenID)
			if err != nil {
				m.log.Warn("failed to load credential from storage",
					logger.String("namespace", namespaceID),
					logger.String("token_id", tokenID),
					logger.Err(err),
				)
				continue
			}

			// Check if credential is expired
			if cred.IsExpired() {
				// Attempt revocation and cleanup
				m.revokeAndDelete(ctx, namespaceID, cred)
				totalExpired++
				continue
			}

			// Build namespace-aware cache key
			cacheKey := fmt.Sprintf("%s:%s", namespaceID, tokenID)

			// Restore to cache with remaining TTL
			remaining := cred.RemainingTTL()
			if remaining > 0 {
				m.cache.SetWithTTL(cacheKey, cred, 1, remaining)
			} else {
				// Static credential or no TTL
				m.cache.Set(cacheKey, cred, 1)
			}
			totalLoaded++
		}
	}

	m.cache.Wait()

	m.log.Debug("loaded credentials from storage",
		logger.Int("loaded", totalLoaded),
		logger.Int("expired", totalExpired),
	)

	return nil
}

// ============================================================================
// Credential Lifecycle Methods
// ============================================================================

// GetCredential retrieves a credential by namespace and tokenID from cache or storage
func (m *Manager) GetCredential(ctx context.Context, namespaceID string, tokenID string) (*Credential, error) {
	// Build namespace-aware cache key
	cacheKey := fmt.Sprintf("%s:%s", namespaceID, tokenID)

	// Check cache first
	if cred, found := m.cache.Get(cacheKey); found {
		return cred, nil
	}

	// Try loading from storage
	cred, err := m.loadCredentialFromStorage(ctx, namespaceID, tokenID)
	if err != nil {
		return nil, err
	}

	// Check if expired
	if cred.IsExpired() {
		return nil, ErrCredentialNotFound
	}

	// Restore to cache
	remaining := cred.RemainingTTL()
	if remaining > 0 {
		m.cache.SetWithTTL(cacheKey, cred, 1, remaining)
	} else {
		m.cache.Set(cacheKey, cred, 1)
	}
	m.cache.Wait()

	return cred, nil
}

// RevokeAndDeleteCredential revokes and deletes a credential for a given namespace and tokenID
func (m *Manager) RevokeAndDeleteCredential(ctx context.Context, namespaceID string, tokenID string) error {
	// Get credential (from cache or storage)
	cred, err := m.GetCredential(ctx, namespaceID, tokenID)
	if err != nil {
		// Already deleted or never existed
		return nil
	}

	// Revoke if needed
	if cred.Revocable && cred.LeaseID != "" {
		if err := m.revokeCredential(ctx, cred); err != nil {
			m.log.Warn("failed to revoke credential during cleanup",
				logger.String("namespace", namespaceID),
				logger.String("token_id", tokenID),
				logger.Err(err),
			)
		}
	}

	// Build namespace-aware cache key and remove from cache
	cacheKey := fmt.Sprintf("%s:%s", namespaceID, tokenID)
	m.cache.Del(cacheKey)

	// Delete from storage
	if err := m.deleteCredentialFromStorage(ctx, namespaceID, tokenID); err != nil {
		return fmt.Errorf("failed to delete credential from storage: %w", err)
	}

	m.log.Debug("cleaned up credential for token",
		logger.String("namespace", namespaceID),
		logger.String("token_id", tokenID),
	)

	return nil
}

// revokeAndDelete is a helper to revoke and delete a credential
func (m *Manager) revokeAndDelete(ctx context.Context, namespaceID string, cred *Credential) error {
	return m.RevokeAndDeleteCredential(ctx, namespaceID, cred.TokenID)
}

// revokeCredential attempts to revoke a credential via its type handler
func (m *Manager) revokeCredential(ctx context.Context, cred *Credential) error {
	// Get credential type for revocation
	credType, err := m.typeRegistry.GetByName(cred.Type)
	if err != nil {
		return fmt.Errorf("credential type not found: %w", err)
	}

	// Get driver for revocation
	driver, ok := m.driverRegistry.GetDriver(cred.SourceType)
	if !ok {
		return fmt.Errorf("driver not found for revocation: %s", cred.SourceType)
	}

	// Revoke via type handler
	if err := credType.Revoke(ctx, cred, driver); err != nil {
		return fmt.Errorf("revocation failed: %w", err)
	}

	return nil
}

// ============================================================================
// Background Cleanup
// ============================================================================

// StartBackgroundCleanup starts a background goroutine to clean up expired credentials
func (m *Manager) StartBackgroundCleanup(ctx context.Context, interval time.Duration) {
	if m.storage == nil {
		// Storage not configured - skip background cleanup
		return
	}

	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				m.cleanupExpiredCredentials(ctx)
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	m.log.Debug("started background credential cleanup",
		logger.String("interval", interval.String()),
	)
}

// cleanupExpiredCredentials scans storage and removes expired credentials across all namespaces
func (m *Manager) cleanupExpiredCredentials(ctx context.Context) {
	if m.storage == nil {
		return
	}

	// List all namespace directories
	namespaces, err := m.storage.List(ctx, "")
	if err != nil {
		m.log.Warn("failed to list namespaces for cleanup", logger.Err(err))
		return
	}

	totalCleaned := 0

	// For each namespace, scan its credentials
	for _, nsPath := range namespaces {
		// nsPath is like "namespace-uuid/"
		namespaceID := nsPath[:len(nsPath)-1] // Remove trailing slash

		// List credentials in this namespace
		credKeys, err := m.storage.List(ctx, nsPath)
		if err != nil {
			m.log.Warn("failed to list credentials for cleanup",
				logger.String("namespace", namespaceID),
				logger.Err(err),
			)
			continue
		}

		for _, credPath := range credKeys {
			// credPath is like "namespace-uuid/tokenID"
			// Extract tokenID from path
			parts := []rune(credPath)
			tokenID := string(parts[len(nsPath):])

			cred, err := m.loadCredentialFromStorage(ctx, namespaceID, tokenID)
			if err != nil {
				continue
			}

			if cred.IsExpired() {
				if err := m.revokeAndDelete(ctx, namespaceID, cred); err != nil {
					m.log.Warn("failed to cleanup expired credential",
						logger.String("namespace", namespaceID),
						logger.String("token_id", tokenID),
						logger.Err(err),
					)
					continue
				}
				totalCleaned++
			}
		}
	}

	if totalCleaned > 0 {
		m.log.Debug("cleaned up expired credentials",
			logger.Int("count", totalCleaned),
		)
	}
}
