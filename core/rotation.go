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
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// Storage paths for rotation data
const (
	rotationStoragePath = "core/rotation/"
	rotationPendingPath = rotationStoragePath + "pending/"
	rotationFailedPath  = rotationStoragePath + "failed/"
	rotationCleanupPath = rotationStoragePath + "cleanup/"
)

// Configuration constants for rotation
const (
	// RotationWorkerCount is the number of workers in the rotation job pool
	RotationWorkerCount = 10

	// MaxRotateAttempts is the maximum number of rotation attempts before marking entry as failed
	MaxRotateAttempts = 6

	// FailedRetryPeriod is how often the daily failed retry loop runs
	FailedRetryPeriod = 24 * time.Hour

	// FailedMinAge is the minimum time since last attempt before a failed entry is retried
	FailedMinAge = 1 * time.Hour

	// RotationTimeout is the context timeout for each rotation attempt
	RotationTimeout = 60 * time.Second

	// MaxRotationBackoff is the maximum backoff duration between retry attempts
	MaxRotationBackoff = 5 * time.Minute

	// rotationRestoreWorkerCount is the number of parallel workers for restoring entries from storage
	rotationRestoreWorkerCount = 16
)

// PendingCleanup represents a cleanup that needs to be retried
type PendingCleanup struct {
	SourceName    string            `json:"source_name"`
	SourceType    string            `json:"source_type"`
	Namespace     string            `json:"namespace"`
	CleanupConfig map[string]string `json:"cleanup_config"`
	Attempts      int               `json:"attempts"`
	CreatedAt     time.Time         `json:"created_at"`
	LastAttempt   time.Time         `json:"last_attempt"`
}

// RotationEntry is the persisted representation of a rotation schedule
type RotationEntry struct {
	SourceName     string        `json:"source_name"`
	SourceType     string        `json:"source_type"`
	Namespace      string        `json:"namespace"`
	RotationPeriod time.Duration `json:"rotation_period"`
	NextRotation   time.Time     `json:"next_rotation"`
	LastRotation   time.Time     `json:"last_rotation"`
	LastError      string        `json:"last_error,omitempty"`
	RotateAttempts int           `json:"rotate_attempts,omitempty"`
}

// pendingRotation holds in-memory state for a pending rotation
type pendingRotation struct {
	entry          *RotationEntry
	timer          *time.Timer
	rotateAttempts int32 // atomic counter
}

// RotationManager provides periodic credential rotation for sources.
// Features:
// - Individual timer per source for scheduled rotation
// - Worker pool for concurrent rotation processing
// - Two storage tiers: pending, failed
// - Persistence for surviving server restarts
// - Automatic retry of failed rotations
type RotationManager struct {
	core    *Core // Reference to Core for credential config store access
	log     *logger.GatedLogger
	storage sdklogical.Storage

	// Two storage tiers (sync.Map for thread-safety)
	pending sync.Map // key: "{namespace}:{sourceName}" → *pendingRotation
	failed  sync.Map // key: "{namespace}:{sourceName}" → *RotationEntry

	// Worker pool for rotation jobs
	jobManager *fairshare.JobManager

	// Metrics (atomic)
	pendingCount int64
	failedCount  int64

	// Lifecycle
	quitCtx    context.Context
	quitCancel context.CancelFunc

	// Failed retry ticker
	failedRetryTicker *time.Ticker

	// Channel for testing - signals when a rotation completes
	rotationDoneCh chan struct{}
}

// NewRotationManager creates a new rotation manager.
// The core parameter provides access to credential config store for updating source configs.
func NewRotationManager(core *Core, log *logger.GatedLogger, storage sdklogical.Storage) *RotationManager {
	ctx, cancel := context.WithCancel(context.Background())

	workerCount := RotationWorkerCount

	// Create hclog adapter for fairshare (it uses hashicorp's go-hclog)
	hclogLogger := logger.NewHCLogAdapter(log.WithSubsystem("manager"))

	// Use OpenBao's battle-tested fairshare.JobManager
	jobManager := fairshare.NewJobManager("rotation", workerCount, hclogLogger, nil)

	m := &RotationManager{
		core:           core,
		log:            log,
		storage:        storage,
		jobManager:     jobManager,
		quitCtx:        ctx,
		quitCancel:     cancel,
		rotationDoneCh: make(chan struct{}, 100),
	}

	// Start the job manager
	jobManager.Start()

	// Start failed retry ticker (daily)
	m.failedRetryTicker = time.NewTicker(FailedRetryPeriod)
	go m.failedRetryLoop()

	log.Info("rotation manager started",
		logger.Int("workers", workerCount))

	return m
}

// Stop gracefully shuts down the rotation manager
func (m *RotationManager) Stop() {
	m.quitCancel()

	// Stop failed retry ticker
	if m.failedRetryTicker != nil {
		m.failedRetryTicker.Stop()
	}

	// Stop all pending timers
	count := 0
	m.pending.Range(func(key, value any) bool {
		pr := value.(*pendingRotation)
		pr.timer.Stop()
		m.pending.Delete(key)
		count++
		return true
	})

	// Stop job manager
	m.jobManager.Stop()

	m.log.Info("rotation manager stopped",
		logger.Int("pending_cancelled", count))
}

// ============================================================================
// Registration Methods
// ============================================================================

// RegisterSource registers a credential source for periodic rotation.
// The source must support rotation (implement credential.Rotatable interface).
func (m *RotationManager) RegisterSource(ctx context.Context, sourceName, sourceType string, period time.Duration) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	entry := &RotationEntry{
		SourceName:     sourceName,
		SourceType:     sourceType,
		Namespace:      ns.UUID,
		RotationPeriod: period,
		NextRotation:   time.Now().Add(period),
		LastRotation:   time.Time{}, // Never rotated yet
	}

	return m.register(entry, period)
}

// register is the internal registration method.
func (m *RotationManager) register(entry *RotationEntry, ttl time.Duration) error {
	key := buildRotationKey(entry.Namespace, entry.SourceName)

	// Persist entry to storage FIRST (durability)
	if m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			return fmt.Errorf("failed to persist rotation entry: %w", err)
		}
	}

	// Create timer callback
	pr := &pendingRotation{entry: entry}
	pr.timer = time.AfterFunc(ttl, func() {
		m.onRotate(key, pr)
	})

	// Cancel existing timer if present (source re-registered with new period)
	if existing, loaded := m.pending.LoadAndDelete(key); loaded {
		existingPR := existing.(*pendingRotation)
		existingPR.timer.Stop()
		atomic.AddInt64(&m.pendingCount, -1)

		m.log.Debug("replaced existing rotation entry",
			logger.String("source", entry.SourceName))
	}

	m.pending.Store(key, pr)
	atomic.AddInt64(&m.pendingCount, 1)

	m.log.Info("registered source for rotation",
		logger.String("source", entry.SourceName),
		logger.String("type", entry.SourceType),
		logger.Duration("period", entry.RotationPeriod),
		logger.Time("next_rotation", entry.NextRotation))

	return nil
}

// UnregisterSource removes a source from rotation tracking
func (m *RotationManager) UnregisterSource(ctx context.Context, sourceName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	key := buildRotationKey(ns.UUID, sourceName)

	// Try pending first
	if existing, loaded := m.pending.LoadAndDelete(key); loaded {
		pr := existing.(*pendingRotation)
		pr.timer.Stop()
		atomic.AddInt64(&m.pendingCount, -1)

		// Delete from storage
		if m.storage != nil {
			m.deletePersistedEntry(pr.entry)
		}

		m.log.Debug("unregistered source from rotation",
			logger.String("source", sourceName))
		return nil
	}

	// Try failed
	if entry, loaded := m.failed.LoadAndDelete(key); loaded {
		atomic.AddInt64(&m.failedCount, -1)

		// Delete from failed storage
		if m.storage != nil {
			e := entry.(*RotationEntry)
			path := rotationFailedPath + e.Namespace + "/" + e.SourceName
			m.storage.Delete(context.Background(), path)
		}

		m.log.Debug("unregistered failed source from rotation",
			logger.String("source", sourceName))
	}

	return nil
}

// UpdateRotationPeriod updates the rotation period for a source
func (m *RotationManager) UpdateRotationPeriod(ctx context.Context, sourceName string, newPeriod time.Duration) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	key := buildRotationKey(ns.UUID, sourceName)

	// Get existing entry
	existing, loaded := m.pending.Load(key)
	if !loaded {
		return fmt.Errorf("source %s is not registered for rotation", sourceName)
	}

	pr := existing.(*pendingRotation)

	// Update period and reschedule
	pr.entry.RotationPeriod = newPeriod
	pr.entry.NextRotation = time.Now().Add(newPeriod)

	// Stop old timer
	pr.timer.Stop()

	// Persist updated entry
	if m.storage != nil {
		if err := m.persistEntry(pr.entry); err != nil {
			return fmt.Errorf("failed to persist updated rotation entry: %w", err)
		}
	}

	// Create new timer
	pr.timer = time.AfterFunc(newPeriod, func() {
		m.onRotate(key, pr)
	})

	m.log.Info("updated rotation period",
		logger.String("source", sourceName),
		logger.Duration("new_period", newPeriod),
		logger.Time("next_rotation", pr.entry.NextRotation))

	return nil
}

// ============================================================================
// Persistence Methods
// ============================================================================

// persistEntry saves a rotation entry to storage
func (m *RotationManager) persistEntry(entry *RotationEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	path := rotationPendingPath + entry.Namespace + "/" + entry.SourceName
	return m.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	})
}

// deletePersistedEntry removes an entry from storage
func (m *RotationManager) deletePersistedEntry(entry *RotationEntry) error {
	path := rotationPendingPath + entry.Namespace + "/" + entry.SourceName
	return m.storage.Delete(context.Background(), path)
}

// persistFailedEntry saves a failed entry to storage
func (m *RotationManager) persistFailedEntry(entry *RotationEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	path := rotationFailedPath + entry.Namespace + "/" + entry.SourceName
	return m.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	})
}

// ============================================================================
// Rotation Handling
// ============================================================================

// onRotate is called when an entry's timer fires
func (m *RotationManager) onRotate(key string, pr *pendingRotation) {
	// Check if shutting down
	select {
	case <-m.quitCtx.Done():
		return
	default:
	}

	entry := pr.entry

	// Queue rotation job to worker pool using OpenBao's fairshare.JobManager
	// Queue ID for fairshare: namespace (ensures fair distribution across namespaces)
	queueID := entry.Namespace
	job := &rotationJob{
		manager: m,
		entry:   entry,
		key:     key,
		pending: pr,
	}
	m.jobManager.AddJob(job, queueID)
}

// rotateSource performs the actual rotation using the three-phase approach:
// Phase 1: PREPARE - Generate new credentials (old still valid)
// Phase 2: PERSIST + COMMIT - Save new config, then activate in driver
// Phase 3: CLEANUP - Destroy old credentials (best-effort with retry)
func (m *RotationManager) rotateSource(entry *RotationEntry) error {
	// Create timeout context
	ctx, cancel := context.WithTimeout(m.quitCtx, RotationTimeout)
	defer cancel()

	// Look up namespace and add to context
	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	// Get the credential source from config store
	if m.core == nil || m.core.credConfigStore == nil {
		return fmt.Errorf("credential config store not available")
	}

	source, err := m.core.credConfigStore.GetSource(ctx, entry.SourceName)
	if err != nil {
		return fmt.Errorf("failed to get source %s: %w", entry.SourceName, err)
	}

	// Get the driver from the registry
	if m.core.credentialManager == nil {
		return fmt.Errorf("credential manager not available")
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	// Check if driver supports rotation
	rotatable, ok := driver.(credential.Rotatable)
	if !ok {
		return fmt.Errorf("driver for source %s does not support rotation", entry.SourceName)
	}

	if !rotatable.SupportsRotation() {
		return fmt.Errorf("source %s configuration does not support rotation", entry.SourceName)
	}

	// Phase 1: PREPARE - Generate new credentials (old still valid)
	newConfig, cleanupConfig, err := rotatable.PrepareRotation(ctx)
	if err != nil {
		return fmt.Errorf("prepare rotation failed for source %s: %w", entry.SourceName, err)
	}

	// Phase 2a: PERSIST - Save new config BEFORE committing or destroying
	source.Config = newConfig
	if err := m.core.credConfigStore.UpdateSource(ctx, source, UpdateSourceOptions{SkipConnectionTest: true}); err != nil {
		// New credentials orphaned but will auto-expire, safe to fail
		return fmt.Errorf("failed to persist rotated config for source %s: %w", entry.SourceName, err)
	}

	// Phase 2b: COMMIT - Activate new credentials in driver
	if err := rotatable.CommitRotation(ctx, newConfig); err != nil {
		// Config persisted, driver will recover on restart
		return fmt.Errorf("commit rotation failed for source %s: %w", entry.SourceName, err)
	}

	// Phase 3: CLEANUP - Destroy old credentials with retry (non-fatal)
	m.performCleanupWithRetry(ctx, entry, rotatable, cleanupConfig)

	m.log.Info("successfully rotated credentials",
		logger.String("source", entry.SourceName),
		logger.String("namespace", entry.Namespace))

	return nil
}

// performCleanupWithRetry attempts cleanup with immediate retries, then persists for daily retry.
func (m *RotationManager) performCleanupWithRetry(ctx context.Context, entry *RotationEntry,
	rotatable credential.Rotatable, cleanupConfig map[string]string) {

	if len(cleanupConfig) == 0 {
		return // Nothing to clean up
	}

	// Immediate retry with backoff (3 attempts: 0s, 1s, 2s)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		err = rotatable.CleanupRotation(ctx, cleanupConfig)
		if err == nil {
			return // Success
		}

		m.log.Warn("cleanup attempt failed",
			logger.String("source", entry.SourceName),
			logger.Int("attempt", attempt+1),
			logger.Err(err))
	}

	// All immediate retries failed - persist for daily retry
	m.persistFailedCleanup(entry, cleanupConfig)
}

// persistFailedCleanup stores a failed cleanup to storage for daily retry
func (m *RotationManager) persistFailedCleanup(entry *RotationEntry, cleanupConfig map[string]string) {
	pending := &PendingCleanup{
		SourceName:    entry.SourceName,
		SourceType:    entry.SourceType,
		Namespace:     entry.Namespace,
		CleanupConfig: cleanupConfig,
		Attempts:      3, // Already tried 3 times
		CreatedAt:     time.Now(),
		LastAttempt:   time.Now(),
	}

	// Persist to storage (will be retried daily)
	if m.storage != nil {
		path := rotationCleanupPath + entry.Namespace + "/" + entry.SourceName
		data, err := json.Marshal(pending)
		if err != nil {
			m.log.Error("failed to marshal pending cleanup",
				logger.String("source", entry.SourceName),
				logger.Err(err))
			return
		}
		if err := m.storage.Put(context.Background(), &sdklogical.StorageEntry{
			Key:   path,
			Value: data,
		}); err != nil {
			m.log.Error("failed to persist pending cleanup",
				logger.String("source", entry.SourceName),
				logger.Err(err))
			return
		}
	}

	m.log.Warn("cleanup persisted for daily retry",
		logger.String("source", entry.SourceName))
}

// retryFailedCleanups is called daily to retry persisted failed cleanups.
func (m *RotationManager) retryFailedCleanups() {
	if m.storage == nil || m.core == nil {
		return
	}

	// List all pending cleanup namespaces
	namespaces, err := m.storage.List(context.Background(), rotationCleanupPath)
	if err != nil {
		return
	}

	var retried, succeeded, abandoned int

	for _, ns := range namespaces {
		entries, err := m.storage.List(context.Background(), rotationCleanupPath+ns)
		if err != nil {
			continue
		}

		for _, entryName := range entries {
			path := rotationCleanupPath + ns + entryName
			raw, err := m.storage.Get(context.Background(), path)
			if err != nil || raw == nil {
				continue
			}

			var pending PendingCleanup
			if err := json.Unmarshal(raw.Value, &pending); err != nil {
				continue
			}

			// Check if cleanup is too old (> 7 days) - abandon it
			if time.Since(pending.CreatedAt) > 7*24*time.Hour {
				m.storage.Delete(context.Background(), path)
				abandoned++
				m.log.Error("cleanup abandoned after 7 days",
					logger.String("source", pending.SourceName),
					logger.Int("attempts", pending.Attempts))
				continue
			}

			retried++

			// Get driver and attempt cleanup
			ctx := context.Background()
			nsObj := &namespace.Namespace{UUID: pending.Namespace}
			ctx = namespace.ContextWithNamespace(ctx, nsObj)

			driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, pending.SourceName)
			if err != nil {
				continue // Skip, try again tomorrow
			}

			rotatable, ok := driver.(credential.Rotatable)
			if !ok {
				m.storage.Delete(context.Background(), path) // Remove, driver changed
				continue
			}

			pending.Attempts++
			pending.LastAttempt = time.Now()

			if err := rotatable.CleanupRotation(ctx, pending.CleanupConfig); err == nil {
				// Success - remove from storage
				m.storage.Delete(context.Background(), path)
				succeeded++
				m.log.Info("pending cleanup succeeded",
					logger.String("source", pending.SourceName),
					logger.Int("attempts", pending.Attempts))
			} else {
				// Update attempts count in storage
				data, _ := json.Marshal(pending)
				m.storage.Put(context.Background(), &sdklogical.StorageEntry{
					Key:   path,
					Value: data,
				})
				m.log.Warn("cleanup retry failed",
					logger.String("source", pending.SourceName),
					logger.Int("attempts", pending.Attempts),
					logger.Err(err))
			}
		}
	}

	if retried > 0 {
		m.log.Info("daily cleanup retry completed",
			logger.Int("retried", retried),
			logger.Int("succeeded", succeeded),
			logger.Int("abandoned", abandoned))
	}
}

// handleRotationSuccess handles a successful rotation
func (m *RotationManager) handleRotationSuccess(key string, entry *RotationEntry, pr *pendingRotation) {
	// Update entry times
	entry.LastRotation = time.Now()
	entry.NextRotation = time.Now().Add(entry.RotationPeriod)
	entry.LastError = ""
	entry.RotateAttempts = 0
	atomic.StoreInt32(&pr.rotateAttempts, 0)

	// Persist updated entry
	if m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			m.log.Error("failed to persist rotation entry after success",
				logger.String("source", entry.SourceName),
				logger.Err(err))
		}
	}

	// Schedule next rotation
	pr.timer = time.AfterFunc(entry.RotationPeriod, func() {
		m.onRotate(key, pr)
	})

	// Signal completion for testing
	select {
	case m.rotationDoneCh <- struct{}{}:
	default:
	}

	m.log.Debug("scheduled next rotation",
		logger.String("source", entry.SourceName),
		logger.Time("next_rotation", entry.NextRotation))
}

// ============================================================================
// Failure Handling
// ============================================================================

// handleRotationFailure handles a failed rotation attempt
func (m *RotationManager) handleRotationFailure(key string, entry *RotationEntry, pr *pendingRotation, err error) {
	attempts := atomic.AddInt32(&pr.rotateAttempts, 1)

	m.log.Error("rotation failed",
		logger.String("source", entry.SourceName),
		logger.Int("attempt", int(attempts)),
		logger.Err(err))

	// Check if max attempts reached
	if int(attempts) >= MaxRotateAttempts {
		m.markFailed(key, entry, err)
		return
	}

	// Exponential backoff retry: 10s, 20s, 40s, 80s, 160s, 320s
	backoff := time.Duration(10<<(attempts-1)) * time.Second
	if backoff > MaxRotationBackoff {
		backoff = MaxRotationBackoff
	}

	// Schedule retry
	pr.timer = time.AfterFunc(backoff, func() {
		m.onRotate(key, pr)
	})

	m.log.Debug("scheduled rotation retry",
		logger.String("source", entry.SourceName),
		logger.Duration("backoff", backoff))
}

// markFailed moves an entry to the failed tier
func (m *RotationManager) markFailed(key string, entry *RotationEntry, err error) {
	// Update entry with error
	entry.LastError = truncateError(err, 240)
	entry.RotateAttempts = MaxRotateAttempts

	// Move from pending to failed
	m.pending.Delete(key)
	atomic.AddInt64(&m.pendingCount, -1)

	m.failed.Store(key, entry)
	atomic.AddInt64(&m.failedCount, 1)

	// Persist failed entry
	if m.storage != nil {
		m.persistFailedEntry(entry)

		// Delete from pending storage
		m.deletePersistedEntry(entry)
	}

	m.log.Error("source marked as failed rotation",
		logger.String("source", entry.SourceName),
		logger.String("error", entry.LastError))
}

// ============================================================================
// Failed Retry
// ============================================================================

// failedRetryLoop periodically retries failed entries
func (m *RotationManager) failedRetryLoop() {
	for {
		select {
		case <-m.quitCtx.Done():
			return
		case <-m.failedRetryTicker.C:
			m.attemptFailedRetry()
		}
	}
}

// attemptFailedRetry attempts to rotate all failed entries and retry failed cleanups
func (m *RotationManager) attemptFailedRetry() {
	// Also retry any persisted failed cleanups
	m.retryFailedCleanups()

	m.log.Info("starting daily failed rotation retry")

	var retried, succeeded, failed int

	m.failed.Range(func(key, value any) bool {
		entry := value.(*RotationEntry)

		// Only retry if at least 1 hour has passed since last attempt
		if time.Since(entry.NextRotation) < FailedMinAge {
			return true
		}

		retried++

		// Attempt rotation
		if err := m.rotateSource(entry); err != nil {
			failed++
			m.log.Warn("failed rotation retry failed",
				logger.String("source", entry.SourceName),
				logger.Err(err))

			// Rate limit on failure
			time.Sleep(10 * time.Millisecond)
		} else {
			succeeded++

			// Move back to pending with new schedule
			entry.LastRotation = time.Now()
			entry.NextRotation = time.Now().Add(entry.RotationPeriod)
			entry.LastError = ""
			entry.RotateAttempts = 0

			// Remove from failed tier
			m.failed.Delete(key)
			atomic.AddInt64(&m.failedCount, -1)

			// Delete from failed storage
			if m.storage != nil {
				path := rotationFailedPath + entry.Namespace + "/" + entry.SourceName
				m.storage.Delete(context.Background(), path)
			}

			// Re-register in pending
			m.register(entry, entry.RotationPeriod)
		}

		return true
	})

	m.log.Info("daily failed rotation retry completed",
		logger.Int("retried", retried),
		logger.Int("succeeded", succeeded),
		logger.Int("failed", failed))
}

// ============================================================================
// Restore on Startup
// ============================================================================

// Restore loads all persisted rotation entries on startup
func (m *RotationManager) Restore(ctx context.Context) error {
	if m.storage == nil {
		m.log.Warn("no storage configured, skipping rotation restore")
		return nil
	}

	m.log.Info("restoring rotation entries from storage")

	// Collect all entry paths
	pendingPaths, err := m.collectEntryPaths(ctx, rotationPendingPath)
	if err != nil {
		return fmt.Errorf("failed to collect pending entries: %w", err)
	}

	failedPaths, err := m.collectEntryPaths(ctx, rotationFailedPath)
	if err != nil {
		return fmt.Errorf("failed to collect failed entries: %w", err)
	}

	// Restore pending entries in parallel
	if len(pendingPaths) > 0 {
		if err := m.restoreEntriesParallel(ctx, pendingPaths, false); err != nil {
			return err
		}
	}

	// Restore failed entries in parallel
	if len(failedPaths) > 0 {
		if err := m.restoreEntriesParallel(ctx, failedPaths, true); err != nil {
			return err
		}
	}

	m.log.Info("rotation restore completed",
		logger.Int64("pending", atomic.LoadInt64(&m.pendingCount)),
		logger.Int64("failed", atomic.LoadInt64(&m.failedCount)))

	return nil
}

// collectEntryPaths collects all entry paths from storage
func (m *RotationManager) collectEntryPaths(ctx context.Context, basePath string) ([]string, error) {
	var paths []string

	// List namespaces
	namespaces, err := m.storage.List(ctx, basePath)
	if err != nil {
		// If path doesn't exist yet, return empty
		return paths, nil
	}

	for _, ns := range namespaces {
		// List entries for this namespace
		entries, err := m.storage.List(ctx, basePath+ns)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			paths = append(paths, basePath+ns+entry)
		}
	}

	return paths, nil
}

// restoreEntriesParallel restores entries using a worker pool
func (m *RotationManager) restoreEntriesParallel(ctx context.Context, paths []string, isFailed bool) error {
	// Create worker pool
	pathCh := make(chan string, len(paths))
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	// Start workers
	workerCount := rotationRestoreWorkerCount
	if len(paths) < workerCount {
		workerCount = len(paths)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				if err := m.restoreEntry(ctx, path, isFailed); err != nil {
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
func (m *RotationManager) restoreEntry(ctx context.Context, path string, isFailed bool) error {
	// Load from storage
	raw, err := m.storage.Get(ctx, path)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
	}

	var entry RotationEntry
	if err := json.Unmarshal(raw.Value, &entry); err != nil {
		return err
	}

	key := buildRotationKey(entry.Namespace, entry.SourceName)

	if isFailed {
		// Restore to failed tier
		m.failed.Store(key, &entry)
		atomic.AddInt64(&m.failedCount, 1)
	} else {
		// Calculate remaining time until next rotation
		remaining := time.Until(entry.NextRotation)
		if remaining <= 0 {
			// Already past due - schedule for immediate rotation
			remaining = time.Millisecond
		}

		// Create pending entry with timer
		pr := &pendingRotation{entry: &entry}
		pr.timer = time.AfterFunc(remaining, func() {
			m.onRotate(key, pr)
		})

		m.pending.Store(key, pr)
		atomic.AddInt64(&m.pendingCount, 1)
	}

	return nil
}

// ============================================================================
// Metrics
// ============================================================================

// GetPendingCount returns the number of pending rotations
func (m *RotationManager) GetPendingCount() int64 {
	return atomic.LoadInt64(&m.pendingCount)
}

// GetFailedCount returns the number of failed rotations
func (m *RotationManager) GetFailedCount() int64 {
	return atomic.LoadInt64(&m.failedCount)
}

// GetEntry returns the rotation entry for a given namespace and source name.
// Returns nil if no entry is found (source has no rotation configured).
func (m *RotationManager) GetEntry(namespaceID, sourceName string) *RotationEntry {
	key := buildRotationKey(namespaceID, sourceName)
	if pr, ok := m.pending.Load(key); ok {
		return pr.(*pendingRotation).entry
	}
	if entry, ok := m.failed.Load(key); ok {
		return entry.(*RotationEntry)
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// buildRotationKey creates a storage key from namespace and source name
func buildRotationKey(namespaceID, sourceName string) string {
	return namespaceID + ":" + sourceName
}

// getNamespaceFromEntry retrieves the namespace for a rotation entry.
func (m *RotationManager) getNamespaceFromEntry(ctx context.Context, entry *RotationEntry) (*namespace.Namespace, error) {
	// If no namespace stored, use root namespace
	if entry.Namespace == "" {
		return namespace.RootNamespace, nil
	}

	// If no core reference (testing), return root namespace
	if m.core == nil || m.core.namespaceStore == nil {
		return namespace.RootNamespace, nil
	}

	ns, err := m.core.namespaceStore.GetNamespace(ctx, entry.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup namespace %s: %w", entry.Namespace, err)
	}
	if ns == nil {
		return nil, fmt.Errorf("namespace %s not found", entry.Namespace)
	}

	return ns, nil
}
