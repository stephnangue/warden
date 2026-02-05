// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openbao/openbao/helper/fairshare"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

// ExpirationType identifies what kind of entry is expiring
type ExpirationType string

const (
	ExpirationTypeToken      ExpirationType = "token"
	ExpirationTypeCredential ExpirationType = "credential"
)

// Storage paths for expiration data
const (
	expirationStoragePath     = "core/expiration/"
	expirationPendingPath     = expirationStoragePath + "pending/"
	expirationIrrevocablePath = expirationStoragePath + "irrevocable/"
)

// Configuration constants
const (
	// DefaultWorkerCount is the number of workers in the revocation job pool
	DefaultWorkerCount = 50

	// MaxRevokeAttempts is the maximum number of revocation attempts before marking entry as irrevocable
	MaxRevokeAttempts = 6

	// IrrevocableRetryPeriod is how often the daily irrevocable retry loop runs
	IrrevocableRetryPeriod = 24 * time.Hour

	// IrrevocableMinAge is the minimum time since expiration before an irrevocable entry is retried
	IrrevocableMinAge = 1 * time.Hour

	// RevocationTimeout is the context timeout for each revocation attempt
	RevocationTimeout = 30 * time.Second

	// MaxRevocationBackoff is the maximum backoff duration between retry attempts
	MaxRevocationBackoff = 5 * time.Minute

	// restoreWorkerCount is the number of parallel workers for restoring entries from storage
	restoreWorkerCount = 32
)

// ExpirationEntry is the persisted representation of an expiration
type ExpirationEntry struct {
	ID        string         `json:"id"` // For credentials: CredentialID (UUID); for tokens: tokenID
	EntryType ExpirationType `json:"type"`
	ExpiresAt time.Time      `json:"expires_at"`
	IssuedAt  time.Time      `json:"issued_at"`
	Namespace string         `json:"namespace"`

	// For credentials - needed for revocation and cache management
	CacheKey   string `json:"cache_key,omitempty"` // Cache key for cache lookup/deletion ({namespace}:{tokenID})
	LeaseID    string `json:"lease_id,omitempty"`  // Lease ID for revocation at source (separate from ID)
	SourceName string `json:"source_name,omitempty"`
	SourceType string `json:"source_type,omitempty"`
	SpecName   string `json:"spec_name,omitempty"`
	Revocable  bool   `json:"revocable,omitempty"`

	// For irrevocable entries
	RevokeErr      string `json:"revoke_err,omitempty"`
	RevokeAttempts int    `json:"revoke_attempts,omitempty"`
}

// pendingInfo holds in-memory state for a pending expiration
type pendingInfo struct {
	entry          *ExpirationEntry
	timer          *time.Timer
	revokeAttempts int32 // atomic counter
}

// ExpirationManager provides active TTL enforcement for tokens and credentials.
// Features:
// - Individual timer per entry for exact TTL enforcement
// - Worker pool for concurrent revocation processing
// - Multiple storage tiers: pending, nonexpiring, irrevocable
// - Persistence for surviving server restarts
// - Automatic retry of irrevocable entries
type ExpirationManager struct {
	core    *Core // Reference to Core for namespace lookup and revocation
	log     *logger.GatedLogger
	storage sdklogical.Storage

	// Three storage tiers (sync.Map for thread-safety)
	pending     sync.Map // key: "{type}:{id}" → *pendingInfo (active with TTL)
	nonexpiring sync.Map // key: "{type}:{id}" → *pendingInfo (zero TTL, e.g., root tokens)
	irrevocable sync.Map // key: "{type}:{id}" → *ExpirationEntry (failed revocation)

	// Worker pool for revocation jobs (uses OpenBao's fairshare package)
	jobManager *fairshare.JobManager

	// Metrics (atomic) - total counts
	pendingCount     int64
	nonexpiringCount int64
	irrevocableCount int64

	// Metrics (atomic) - per-type counts for detailed reporting
	pendingTokenCount          int64
	pendingCredentialCount     int64
	irrevocableTokenCount      int64
	irrevocableCredentialCount int64

	// Lifecycle
	quitCtx    context.Context
	quitCancel context.CancelFunc

	// Irrevocable retry ticker
	irrevocableRetryTicker *time.Ticker

	// Channel for testing - signals when a revocation completes
	revocationDoneCh chan struct{}
}

// NewExpirationManager creates a new global expiration manager.
// The core parameter provides access to namespace lookup for context reconstruction during revocation.
// It can be nil for testing purposes (namespace lookup will be skipped).
func NewExpirationManager(core *Core, log *logger.GatedLogger, storage sdklogical.Storage) *ExpirationManager {
	ctx, cancel := context.WithCancel(context.Background())

	workerCount := DefaultWorkerCount

	// Create hclog adapter for fairshare (it uses hashicorp's go-hclog)
	hclogLogger := logger.NewHCLogAdapter(log.WithSubsystem("manager"))

	// Use OpenBao's battle-tested fairshare.JobManager
	// nil for metricSink as we don't have ClusterMetricSink
	jobManager := fairshare.NewJobManager("expiration", workerCount, hclogLogger, nil)

	m := &ExpirationManager{
		core:             core,
		log:              log,
		storage:          storage,
		jobManager:       jobManager,
		quitCtx:          ctx,
		quitCancel:       cancel,
		revocationDoneCh: make(chan struct{}, 100),
	}

	// Start the job manager
	jobManager.Start()

	// Start irrevocable retry ticker (daily)
	m.irrevocableRetryTicker = time.NewTicker(IrrevocableRetryPeriod)
	go m.irrevocableRetryLoop()

	log.Info("expiration manager started",
		logger.Int("workers", workerCount))

	return m
}

// Stop gracefully shuts down the expiration manager
func (m *ExpirationManager) Stop() {
	m.quitCancel()

	// Stop irrevocable retry ticker
	if m.irrevocableRetryTicker != nil {
		m.irrevocableRetryTicker.Stop()
	}

	// Stop all pending timers
	count := 0
	m.pending.Range(func(key, value any) bool {
		pi := value.(*pendingInfo)
		pi.timer.Stop()
		m.pending.Delete(key)
		count++
		return true
	})

	// Stop job manager
	m.jobManager.Stop()

	m.log.Info("expiration manager stopped",
		logger.Int("pending_cancelled", count))
}

// ============================================================================
// Registration Methods
// ============================================================================

// RegisterToken registers a token for expiration.
// If persist is false, the entry is only tracked in memory (for cache-only tokens like JWT role tokens).
func (m *ExpirationManager) RegisterToken(ctx context.Context, tokenID string, ttl time.Duration, persist bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	entry := &ExpirationEntry{
		ID:        tokenID,
		EntryType: ExpirationTypeToken,
		ExpiresAt: time.Now().Add(ttl),
		IssuedAt:  time.Now(),
		Namespace: ns.ID,
	}
	return m.register(entry, ttl, persist)
}

// RegisterCredential registers a credential for expiration.
// Credentials are always persisted for durability (needed for lease revocation at source).
// Parameters:
//   - ctx: Context with namespace information
//   - credentialID: Unique identifier for this credential instance (UUID)
//   - cacheKey: Cache key for cache lookup/deletion ({namespace}:{tokenID})
//   - ttl: Time-to-live for the credential
//   - leaseID: Lease ID for revocation at source (separate from credentialID)
//   - sourceName, sourceType, specName: Metadata for revocation
//   - revocable: Whether the credential can be revoked at source
func (m *ExpirationManager) RegisterCredential(ctx context.Context, credentialID, cacheKey string, ttl time.Duration, leaseID, sourceName, sourceType, specName string, revocable bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	entry := &ExpirationEntry{
		ID:         credentialID, // UUID - unique per credential instance
		EntryType:  ExpirationTypeCredential,
		ExpiresAt:  time.Now().Add(ttl),
		IssuedAt:   time.Now(),
		Namespace:  ns.ID,
		CacheKey:   cacheKey, // For cache lookup/deletion
		LeaseID:    leaseID,  // For source revocation (separate from ID)
		SourceName: sourceName,
		SourceType: sourceType,
		SpecName:   specName,
		Revocable:  revocable,
	}
	return m.register(entry, ttl, true) // Always persist credentials
}

// register is the internal registration method.
// If persist is false, the entry is only tracked in memory (no storage durability).
func (m *ExpirationManager) register(entry *ExpirationEntry, ttl time.Duration, persist bool) error {
	key := buildKey(entry.EntryType, entry.ID)

	// Handle zero TTL (nonexpiring)
	if ttl <= 0 {
		pi := &pendingInfo{entry: entry}
		m.nonexpiring.Store(key, pi)
		atomic.AddInt64(&m.nonexpiringCount, 1)
		m.log.Debug("registered nonexpiring entry",
			logger.String("type", string(entry.EntryType)),
			logger.String("id", entry.ID))
		return nil
	}

	// Persist entry to storage FIRST (durability) - only if persist=true
	if persist && m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			return fmt.Errorf("failed to persist expiration entry: %w", err)
		}
	}

	// Create timer callback
	pi := &pendingInfo{entry: entry}
	pi.timer = time.AfterFunc(ttl, func() {
		m.onExpire(key, pi)
	})

	// Cancel existing timer if present (for tokens which may be re-registered with same ID)
	// For credentials, each has a unique UUID so this rarely happens
	if existing, loaded := m.pending.LoadAndDelete(key); loaded {
		existingPI := existing.(*pendingInfo)
		existingPI.timer.Stop()
		atomic.AddInt64(&m.pendingCount, -1)
		m.decrementPendingTypeCount(existingPI.entry.EntryType)

		m.log.Info("replaced existing expiration entry",
			logger.String("type", string(entry.EntryType)),
			logger.String("id", entry.ID))
	}

	m.pending.Store(key, pi)
	atomic.AddInt64(&m.pendingCount, 1)
	m.incrementPendingTypeCount(entry.EntryType)

	m.log.Debug("registered for expiration",
		logger.String("type", string(entry.EntryType)),
		logger.String("id", entry.ID),
		logger.Duration("ttl", ttl),
		logger.Time("expires_at", entry.ExpiresAt))

	return nil
}

// Unregister removes an entry from expiration tracking (e.g., on explicit revocation)
func (m *ExpirationManager) Unregister(entryType ExpirationType, id string) {
	key := buildKey(entryType, id)

	// Try pending first
	if existing, loaded := m.pending.LoadAndDelete(key); loaded {
		pi := existing.(*pendingInfo)
		pi.timer.Stop()
		atomic.AddInt64(&m.pendingCount, -1)
		m.decrementPendingTypeCount(entryType)

		// Delete from storage
		if m.storage != nil {
			m.deletePersistedEntry(pi.entry)
		}
		return
	}

	// Try nonexpiring
	if _, loaded := m.nonexpiring.LoadAndDelete(key); loaded {
		atomic.AddInt64(&m.nonexpiringCount, -1)
		return
	}

	// Try irrevocable
	if _, loaded := m.irrevocable.LoadAndDelete(key); loaded {
		atomic.AddInt64(&m.irrevocableCount, -1)
		m.decrementIrrevocableTypeCount(entryType)

		// Delete from irrevocable storage
		if m.storage != nil {
			path := expirationIrrevocablePath + string(entryType) + "/" + id
			m.storage.Delete(context.Background(), path)
		}
	}
}

// ============================================================================
// Persistence Methods
// ============================================================================

// persistEntry saves an expiration entry to storage
func (m *ExpirationManager) persistEntry(entry *ExpirationEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	path := expirationPendingPath + string(entry.EntryType) + "/" + entry.ID
	return m.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	})
}

// deletePersistedEntry removes an entry from storage
func (m *ExpirationManager) deletePersistedEntry(entry *ExpirationEntry) error {
	path := expirationPendingPath + string(entry.EntryType) + "/" + entry.ID
	return m.storage.Delete(context.Background(), path)
}

// persistIrrevocableEntry saves an irrevocable entry to storage
func (m *ExpirationManager) persistIrrevocableEntry(entry *ExpirationEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	path := expirationIrrevocablePath + string(entry.EntryType) + "/" + entry.ID
	return m.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	})
}

// ============================================================================
// Expiration Handling
// ============================================================================

// onExpire is called when an entry's timer fires
func (m *ExpirationManager) onExpire(key string, pi *pendingInfo) {
	// Check if shutting down
	select {
	case <-m.quitCtx.Done():
		return
	default:
	}

	entry := pi.entry

	// Queue revocation job to worker pool using OpenBao's fairshare.JobManager
	// Queue ID for fairshare: namespace:type (ensures fair distribution across namespaces)
	queueID := entry.Namespace + ":" + string(entry.EntryType)
	job := &revocationJob{
		manager: m,
		entry:   entry,
		key:     key,
		pending: pi,
	}
	m.jobManager.AddJob(job, queueID)
}

// revokeEntry performs the actual revocation by calling Core methods directly.
// It reconstructs namespace context from the entry before invoking revocation.
func (m *ExpirationManager) revokeEntry(entry *ExpirationEntry) error {
	// Create timeout context
	ctx, cancel := context.WithTimeout(m.quitCtx, RevocationTimeout)
	defer cancel()

	// Look up namespace and add to context
	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	// Perform type-specific revocation via Core
	if m.core != nil {
		switch entry.EntryType {
		case ExpirationTypeToken:
			if err := m.core.revokeTokenByExpiration(ctx, entry); err != nil {
				return err
			}
		case ExpirationTypeCredential:
			if err := m.core.revokeCredentialByExpiration(ctx, entry); err != nil {
				return err
			}
		default:
			m.log.Error("unknown entry type for revocation",
				logger.String("type", string(entry.EntryType)))
		}
	}

	// Success - clean up
	key := buildKey(entry.EntryType, entry.ID)
	m.pending.Delete(key)
	atomic.AddInt64(&m.pendingCount, -1)
	m.decrementPendingTypeCount(entry.EntryType)

	// Delete from persistent storage
	if m.storage != nil {
		if err := m.deletePersistedEntry(entry); err != nil {
			m.log.Warn("failed to delete persisted entry",
				logger.String("id", entry.ID),
				logger.Err(err))
		}
	}

	// Signal completion for testing
	select {
	case m.revocationDoneCh <- struct{}{}:
	default:
	}

	return nil
}

// ============================================================================
// Failure Handling
// ============================================================================

// handleRevocationFailure handles a failed revocation attempt
func (m *ExpirationManager) handleRevocationFailure(key string, entry *ExpirationEntry, pi *pendingInfo, err error) {
	attempts := atomic.AddInt32(&pi.revokeAttempts, 1)

	m.log.Error("revocation failed",
		logger.String("type", string(entry.EntryType)),
		logger.String("id", entry.ID),
		logger.Int("attempt", int(attempts)),
		logger.Err(err))

	// Check if max attempts reached
	if int(attempts) >= MaxRevokeAttempts {
		m.markIrrevocable(key, entry, err)
		return
	}

	// Exponential backoff retry: 10s, 20s, 40s, 80s, 160s, 320s
	backoff := time.Duration(10<<(attempts-1)) * time.Second
	if backoff > MaxRevocationBackoff {
		backoff = MaxRevocationBackoff
	}

	// Schedule retry
	pi.timer = time.AfterFunc(backoff, func() {
		m.onExpire(key, pi)
	})

	m.log.Debug("scheduled retry",
		logger.String("id", entry.ID),
		logger.Duration("backoff", backoff))
}

// markIrrevocable moves an entry to the irrevocable tier
func (m *ExpirationManager) markIrrevocable(key string, entry *ExpirationEntry, err error) {
	// Update entry with error
	entry.RevokeErr = truncateError(err, 240)
	entry.RevokeAttempts = MaxRevokeAttempts

	// Move from pending to irrevocable
	m.pending.Delete(key)
	atomic.AddInt64(&m.pendingCount, -1)
	m.decrementPendingTypeCount(entry.EntryType)

	m.irrevocable.Store(key, entry)
	atomic.AddInt64(&m.irrevocableCount, 1)
	m.incrementIrrevocableTypeCount(entry.EntryType)

	// Persist irrevocable entry
	if m.storage != nil {
		m.persistIrrevocableEntry(entry)

		// Delete from pending storage
		m.deletePersistedEntry(entry)
	}

	m.log.Error("entry marked irrevocable",
		logger.String("type", string(entry.EntryType)),
		logger.String("id", entry.ID),
		logger.String("error", entry.RevokeErr))
}

// ============================================================================
// Irrevocable Retry
// ============================================================================

// irrevocableRetryLoop periodically retries irrevocable entries
func (m *ExpirationManager) irrevocableRetryLoop() {
	for {
		select {
		case <-m.quitCtx.Done():
			return
		case <-m.irrevocableRetryTicker.C:
			m.attemptIrrevocableRetry()
		}
	}
}

// attemptIrrevocableRetry attempts to revoke all irrevocable entries
func (m *ExpirationManager) attemptIrrevocableRetry() {
	m.log.Info("starting daily irrevocable retry")

	var retried, succeeded, failed int

	m.irrevocable.Range(func(key, value any) bool {
		entry := value.(*ExpirationEntry)

		// Only retry if at least 1 hour has passed since expiration
		if time.Since(entry.ExpiresAt) < IrrevocableMinAge {
			return true
		}

		retried++

		// Attempt revocation
		if err := m.revokeEntry(entry); err != nil {
			failed++
			m.log.Warn("irrevocable retry failed",
				logger.String("id", entry.ID),
				logger.Err(err))

			// Rate limit on failure
			time.Sleep(10 * time.Millisecond)
		} else {
			succeeded++

			// Remove from irrevocable tier
			m.irrevocable.Delete(key)
			atomic.AddInt64(&m.irrevocableCount, -1)
			m.decrementIrrevocableTypeCount(entry.EntryType)

			// Delete from irrevocable storage
			if m.storage != nil {
				path := expirationIrrevocablePath + string(entry.EntryType) + "/" + entry.ID
				m.storage.Delete(context.Background(), path)
			}
		}

		return true
	})

	m.log.Info("daily irrevocable retry completed",
		logger.Int("retried", retried),
		logger.Int("succeeded", succeeded),
		logger.Int("failed", failed))
}

// ============================================================================
// Restore on Startup
// ============================================================================

// Restore loads all persisted expiration entries on startup
func (m *ExpirationManager) Restore(ctx context.Context) error {
	if m.storage == nil {
		m.log.Warn("no storage configured, skipping expiration restore")
		return nil
	}

	m.log.Info("restoring expiration entries from storage")

	// Collect all entry IDs
	pendingIDs, err := m.collectEntryIDs(ctx, expirationPendingPath)
	if err != nil {
		return fmt.Errorf("failed to collect pending entries: %w", err)
	}

	irrevocableIDs, err := m.collectEntryIDs(ctx, expirationIrrevocablePath)
	if err != nil {
		return fmt.Errorf("failed to collect irrevocable entries: %w", err)
	}

	// Restore pending entries in parallel
	if len(pendingIDs) > 0 {
		if err := m.restoreEntriesParallel(ctx, pendingIDs, false); err != nil {
			return err
		}
	}

	// Restore irrevocable entries in parallel
	if len(irrevocableIDs) > 0 {
		if err := m.restoreEntriesParallel(ctx, irrevocableIDs, true); err != nil {
			return err
		}
	}

	m.log.Info("expiration restore completed",
		logger.Int64("pending_tokens", atomic.LoadInt64(&m.pendingTokenCount)),
		logger.Int64("pending_credentials", atomic.LoadInt64(&m.pendingCredentialCount)),
		logger.Int64("irrevocable_tokens", atomic.LoadInt64(&m.irrevocableTokenCount)),
		logger.Int64("irrevocable_credentials", atomic.LoadInt64(&m.irrevocableCredentialCount)))

	return nil
}

// collectEntryIDs collects all entry paths from storage
func (m *ExpirationManager) collectEntryIDs(ctx context.Context, basePath string) ([]string, error) {
	var ids []string

	// List entry types (token/, credential/)
	types, err := m.storage.List(ctx, basePath)
	if err != nil {
		// If path doesn't exist yet, return empty
		return ids, nil
	}

	for _, entryType := range types {
		// List entries for this type
		entries, err := m.storage.List(ctx, basePath+entryType)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			ids = append(ids, basePath+entryType+entry)
		}
	}

	return ids, nil
}

// restoreEntriesParallel restores entries using a worker pool
func (m *ExpirationManager) restoreEntriesParallel(ctx context.Context, paths []string, isIrrevocable bool) error {
	// Create worker pool
	pathCh := make(chan string, len(paths))
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	// Start workers
	workerCount := restoreWorkerCount
	if len(paths) < workerCount {
		workerCount = len(paths)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				if err := m.restoreEntry(ctx, path, isIrrevocable); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}

	// Send paths to workers
	for _, path := range paths {
		pathCh <- path
	}
	close(pathCh)

	// Wait for completion
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// restoreEntry restores a single entry from storage
func (m *ExpirationManager) restoreEntry(ctx context.Context, path string, isIrrevocable bool) error {
	// Load from storage
	raw, err := m.storage.Get(ctx, path)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
	}

	var entry ExpirationEntry
	if err := json.Unmarshal(raw.Value, &entry); err != nil {
		return err
	}

	key := buildKey(entry.EntryType, entry.ID)

	if isIrrevocable {
		// Restore to irrevocable tier
		m.irrevocable.Store(key, &entry)
		atomic.AddInt64(&m.irrevocableCount, 1)
		m.incrementIrrevocableTypeCount(entry.EntryType)
	} else {
		// Calculate remaining TTL
		remaining := time.Until(entry.ExpiresAt)
		if remaining <= 0 {
			// Already expired - queue for immediate revocation
			remaining = time.Millisecond
		}

		// Create pending entry with timer
		pi := &pendingInfo{entry: &entry}
		pi.timer = time.AfterFunc(remaining, func() {
			m.onExpire(key, pi)
		})

		m.pending.Store(key, pi)
		atomic.AddInt64(&m.pendingCount, 1)
		m.incrementPendingTypeCount(entry.EntryType)
	}

	return nil
}

// ============================================================================
// Metrics
// ============================================================================

// GetPendingCount returns the number of pending expirations
func (m *ExpirationManager) GetPendingCount() int64 {
	return atomic.LoadInt64(&m.pendingCount)
}

// GetNonexpiringCount returns the number of non-expiring entries
func (m *ExpirationManager) GetNonexpiringCount() int64 {
	return atomic.LoadInt64(&m.nonexpiringCount)
}

// GetIrrevocableCount returns the number of irrevocable entries
func (m *ExpirationManager) GetIrrevocableCount() int64 {
	return atomic.LoadInt64(&m.irrevocableCount)
}

// GetPendingTokenCount returns the number of pending token expirations
func (m *ExpirationManager) GetPendingTokenCount() int64 {
	return atomic.LoadInt64(&m.pendingTokenCount)
}

// GetPendingCredentialCount returns the number of pending credential expirations
func (m *ExpirationManager) GetPendingCredentialCount() int64 {
	return atomic.LoadInt64(&m.pendingCredentialCount)
}

// GetIrrevocableTokenCount returns the number of irrevocable token entries
func (m *ExpirationManager) GetIrrevocableTokenCount() int64 {
	return atomic.LoadInt64(&m.irrevocableTokenCount)
}

// GetIrrevocableCredentialCount returns the number of irrevocable credential entries
func (m *ExpirationManager) GetIrrevocableCredentialCount() int64 {
	return atomic.LoadInt64(&m.irrevocableCredentialCount)
}

// ============================================================================
// Helpers
// ============================================================================

// incrementPendingTypeCount increments the per-type pending counter
func (m *ExpirationManager) incrementPendingTypeCount(entryType ExpirationType) {
	switch entryType {
	case ExpirationTypeToken:
		atomic.AddInt64(&m.pendingTokenCount, 1)
	case ExpirationTypeCredential:
		atomic.AddInt64(&m.pendingCredentialCount, 1)
	}
}

// decrementPendingTypeCount decrements the per-type pending counter
func (m *ExpirationManager) decrementPendingTypeCount(entryType ExpirationType) {
	switch entryType {
	case ExpirationTypeToken:
		atomic.AddInt64(&m.pendingTokenCount, -1)
	case ExpirationTypeCredential:
		atomic.AddInt64(&m.pendingCredentialCount, -1)
	}
}

// incrementIrrevocableTypeCount increments the per-type irrevocable counter
func (m *ExpirationManager) incrementIrrevocableTypeCount(entryType ExpirationType) {
	switch entryType {
	case ExpirationTypeToken:
		atomic.AddInt64(&m.irrevocableTokenCount, 1)
	case ExpirationTypeCredential:
		atomic.AddInt64(&m.irrevocableCredentialCount, 1)
	}
}

// decrementIrrevocableTypeCount decrements the per-type irrevocable counter
func (m *ExpirationManager) decrementIrrevocableTypeCount(entryType ExpirationType) {
	switch entryType {
	case ExpirationTypeToken:
		atomic.AddInt64(&m.irrevocableTokenCount, -1)
	case ExpirationTypeCredential:
		atomic.AddInt64(&m.irrevocableCredentialCount, -1)
	}
}

// buildKey creates a storage key from type and ID
func buildKey(entryType ExpirationType, id string) string {
	return string(entryType) + ":" + id
}

// truncateError truncates an error message to a maximum length
func truncateError(err error, maxLen int) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// getNamespaceFromEntry retrieves the namespace for an expiration entry.
// This is used to reconstruct the namespace context during revocation.
// Returns the namespace or an error if the namespace cannot be found.
func (m *ExpirationManager) getNamespaceFromEntry(ctx context.Context, entry *ExpirationEntry) (*namespace.Namespace, error) {
	// If no namespace stored, use root namespace
	if entry.Namespace == "" {
		return namespace.RootNamespace, nil
	}

	// If no core reference (testing), return root namespace
	// Revocation won't happen anyway when Core is nil
	if m.core == nil || m.core.namespaceStore == nil {
		return namespace.RootNamespace, nil
	}

	ns, err := m.core.NamespaceByID(ctx, entry.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup namespace %s: %w", entry.Namespace, err)
	}
	if ns == nil {
		return nil, fmt.Errorf("namespace %s not found", entry.Namespace)
	}

	return ns, nil
}
