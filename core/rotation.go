// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
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
	rotationEntryPath   = rotationStoragePath + "entries/"
	rotationCleanupPath = rotationStoragePath + "cleanup/"
)

// Configuration constants for rotation
const (
	// RotationWorkerCount is the number of workers in the rotation job pool
	RotationWorkerCount = 10

	// MaxRotateAttempts is the maximum number of attempts before marking entry as failed
	MaxRotateAttempts = 6

	// FailedRetryPeriod is how often the failed cleanup retry runs
	FailedRetryPeriod = 24 * time.Hour

	// FailedMinAge is the minimum time since last attempt before a failed entry is retried
	FailedMinAge = 1 * time.Hour

	// StageTimeout is the context timeout for each rotation stage (PREPARE or ACTIVATE).
	// Each stage is fast (milliseconds to seconds) since propagation delays are handled
	// by the tick loop, not by polling. This timeout only guards against hung API calls.
	StageTimeout = 30 * time.Second

	// MaxRotationBackoff is the maximum backoff duration between retry attempts
	MaxRotationBackoff = 5 * time.Minute

	// DefaultTickInterval is the default interval for the rotation tick loop.
	// All rotation scheduling runs through this single loop — no per-entry timers.
	DefaultTickInterval = 5 * time.Second

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

// EntryType constants for rotation entries
const (
	EntryTypeSource = "source" // Rotation of credential source
	EntryTypeSpec   = "spec"   // Rotation of credential spec
)

// EntryState represents the lifecycle state of a rotation entry
type EntryState string

const (
	// StateIdle — entry is waiting for NextAction to trigger a PREPARE job
	StateIdle EntryState = "idle"
	// StateStaged — PREPARE completed, entry is waiting for NextAction to trigger ACTIVATE
	StateStaged EntryState = "staged"
	// StateFailed — exhausted MaxRotateAttempts, waiting for FailedMinAge before retrying
	StateFailed EntryState = "failed"
)

// RotationEntry is the unified representation of a rotation schedule.
// A single entry tracks identity, schedule, state, and staged credentials.
//
// mu protects mutable fields (State, NextAction, Attempts, staged fields, etc.)
// that are read by the tick loop and written by worker goroutines.
type RotationEntry struct {
	mu sync.Mutex `json:"-"` // protects mutable fields below

	// Identity (immutable after creation)
	EntryType  string `json:"entry_type"`            // "source" or "spec"
	SourceName string `json:"source_name"`           // Source name (always set)
	SourceType string `json:"source_type,omitempty"` // Source type (for source entries)
	SpecName   string `json:"spec_name,omitempty"`   // Spec name (for spec entries)
	Namespace  string `json:"namespace"`

	// Schedule
	RotationPeriod time.Duration `json:"rotation_period"`
	NextAction     time.Time     `json:"next_action"` // When to rotate (idle) or activate (staged)
	LastRotation   time.Time     `json:"last_rotation"`

	// State machine
	State    EntryState `json:"state"`
	Attempts int        `json:"attempts"`

	// Staged fields (populated only when State == StateStaged)
	NewConfig       map[string]string `json:"new_config,omitempty"`
	CleanupConfig   map[string]string `json:"cleanup_config,omitempty"`
	ActivationDelay time.Duration     `json:"activation_delay,omitempty"`
	PreparedAt      time.Time         `json:"prepared_at,omitempty"`

	// Failure tracking
	LastError string `json:"last_error,omitempty"`

	// In-flight guard (not persisted) — prevents tick from re-queuing while a job is executing
	inflight int32 // atomic: 0 = available, 1 = job in worker pool
}

// clearStagedFields resets the staged-only fields after activation completes.
// Caller must hold e.mu.
func (e *RotationEntry) clearStagedFields() {
	e.NewConfig = nil
	e.CleanupConfig = nil
	e.ActivationDelay = 0
	e.PreparedAt = time.Time{}
}

// GetState returns the entry's current state in a thread-safe manner.
func (e *RotationEntry) GetState() EntryState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.State
}

// GetAttempts returns the entry's current attempt count in a thread-safe manner.
func (e *RotationEntry) GetAttempts() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Attempts
}

// GetLastError returns the entry's last error in a thread-safe manner.
func (e *RotationEntry) GetLastError() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.LastError
}

// GetNewConfig returns a copy of the entry's staged new config in a thread-safe manner.
func (e *RotationEntry) GetNewConfig() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.NewConfig
}

// GetNextAction returns the entry's next action time in a thread-safe manner.
func (e *RotationEntry) GetNextAction() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.NextAction
}

// GetLastRotation returns the entry's last rotation time in a thread-safe manner.
func (e *RotationEntry) GetLastRotation() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.LastRotation
}

// RotationManager provides periodic credential rotation using a tick loop.
//
// Instead of per-entry timers (which create race conditions between concurrent
// callbacks), a single goroutine ticks every TickInterval and scans all entries.
// Entries whose NextAction has passed are queued as jobs to the fairshare worker pool.
type RotationManager struct {
	core    *Core
	log     *logger.GatedLogger
	storage sdklogical.Storage

	// Single map for all entries regardless of state
	entries sync.Map // key: "{namespace}:source:{sourceName}" or "{namespace}:spec:{specName}" → *RotationEntry

	// Worker pool for rotation jobs
	jobManager *fairshare.JobManager

	// Counts (atomic)
	entryCount  int64
	failedCount int64

	// Lifecycle
	quitCtx    context.Context
	quitCancel context.CancelFunc

	// Tick loop configuration
	tickInterval     time.Duration
	lastCleanupRetry time.Time

	// Channel for testing — signals when a rotation completes
	rotationDoneCh chan struct{}

	// backoffScale scales retry backoff durations (default 1.0, <1.0 for tests)
	backoffScale float64
}

// NewRotationManager creates a new rotation manager.
// Call Start() to begin the tick loop after any configuration (e.g. tickInterval).
func NewRotationManager(core *Core, log *logger.GatedLogger, storage sdklogical.Storage) *RotationManager {
	ctx, cancel := context.WithCancel(context.Background())

	workerCount := RotationWorkerCount
	hclogLogger := logger.NewHCLogAdapter(log.WithSubsystem("manager"))
	jobManager := fairshare.NewJobManager("rotation", workerCount, hclogLogger, nil)

	m := &RotationManager{
		core:           core,
		log:            log,
		storage:        storage,
		jobManager:     jobManager,
		quitCtx:        ctx,
		quitCancel:     cancel,
		tickInterval:   DefaultTickInterval,
		rotationDoneCh: make(chan struct{}, 100),
		backoffScale:   1.0,
	}

	return m
}

// Start launches the worker pool and tick loop. Must be called after any
// configuration changes (e.g. tickInterval for tests).
func (m *RotationManager) Start() {
	m.jobManager.Start()
	go m.tickLoop()

	m.log.Info("rotation manager started",
		logger.Int("workers", RotationWorkerCount),
		logger.String("tick_interval", m.tickInterval.String()))
}

// Stop gracefully shuts down the rotation manager
func (m *RotationManager) Stop() {
	m.quitCancel()
	m.jobManager.Stop()

	count := 0
	m.entries.Range(func(key, value any) bool {
		m.entries.Delete(key)
		count++
		return true
	})

	m.log.Info("rotation manager stopped",
		logger.Int("entries_cleared", count))
}

// ============================================================================
// Tick Loop
// ============================================================================

// tickLoop is the single goroutine that drives all rotation scheduling.
func (m *RotationManager) tickLoop() {
	ticker := time.NewTicker(m.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.quitCtx.Done():
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

// tick scans all entries and queues jobs for those whose NextAction has passed.
func (m *RotationManager) tick() {
	now := time.Now()

	// Periodically retry failed cleanups (daily)
	if time.Since(m.lastCleanupRetry) >= FailedRetryPeriod {
		m.lastCleanupRetry = now
		m.retryFailedCleanups()
	}

	m.entries.Range(func(key, value any) bool {
		entry := value.(*RotationEntry)

		// Skip if a job is already in-flight for this entry
		if atomic.LoadInt32(&entry.inflight) == 1 {
			return true
		}

		entry.mu.Lock()
		// Skip if not yet due
		if now.Before(entry.NextAction) {
			entry.mu.Unlock()
			return true
		}

		switch entry.State {
		case StateIdle:
			atomic.StoreInt32(&entry.inflight, 1)
			entry.mu.Unlock()
			m.queuePrepareJob(key.(string), entry)

		case StateStaged:
			atomic.StoreInt32(&entry.inflight, 1)
			entry.mu.Unlock()
			m.queueActivateJob(key.(string), entry)

		case StateFailed:
			atomic.StoreInt32(&entry.inflight, 1)
			entry.State = StateIdle
			entry.Attempts = 0
			entry.mu.Unlock()
			atomic.AddInt64(&m.failedCount, -1)
			m.queuePrepareJob(key.(string), entry)

		default:
			entry.mu.Unlock()
		}

		return true
	})
}

// queuePrepareJob adds a prepare job to the worker pool.
func (m *RotationManager) queuePrepareJob(key string, entry *RotationEntry) {
	job := &prepareJob{manager: m, entry: entry, key: key}
	m.jobManager.AddJob(job, entry.Namespace)
}

// queueActivateJob adds an activate job to the worker pool.
func (m *RotationManager) queueActivateJob(key string, entry *RotationEntry) {
	job := &activateJob{manager: m, entry: entry, key: key}
	m.jobManager.AddJob(job, entry.Namespace)
}

// ============================================================================
// Registration Methods
// ============================================================================

// RegisterSource registers a credential source for periodic rotation.
func (m *RotationManager) RegisterSource(ctx context.Context, sourceName, sourceType string, period time.Duration) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	entry := &RotationEntry{
		EntryType:      EntryTypeSource,
		SourceName:     sourceName,
		SourceType:     sourceType,
		Namespace:      ns.UUID,
		RotationPeriod: period,
		NextAction:     time.Now().Add(jitterDuration(period, 0.05)),
		State:          StateIdle,
	}

	return m.register(entry)
}

// RegisterSpec registers a credential spec for periodic rotation.
func (m *RotationManager) RegisterSpec(ctx context.Context, specName, sourceName string, period time.Duration) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	entry := &RotationEntry{
		EntryType:      EntryTypeSpec,
		SpecName:       specName,
		SourceName:     sourceName,
		Namespace:      ns.UUID,
		RotationPeriod: period,
		NextAction:     time.Now().Add(jitterDuration(period, 0.05)),
		State:          StateIdle,
	}

	return m.register(entry)
}

// register is the internal registration method.
func (m *RotationManager) register(entry *RotationEntry) error {
	key := m.buildEntryKey(entry)

	// Persist entry to storage FIRST (durability)
	if m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			return fmt.Errorf("failed to persist rotation entry: %w", err)
		}
	}

	// Replace existing entry if present
	if existing, loaded := m.entries.Load(key); loaded {
		old := existing.(*RotationEntry)
		if old.State == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}
		m.entries.Store(key, entry)

		if entry.EntryType == EntryTypeSpec {
			m.log.Debug("replaced existing rotation entry",
				logger.String("spec", entry.SpecName))
		} else {
			m.log.Debug("replaced existing rotation entry",
				logger.String("source", entry.SourceName))
		}
	} else {
		m.entries.Store(key, entry)
		atomic.AddInt64(&m.entryCount, 1)
	}

	if entry.EntryType == EntryTypeSpec {
		m.log.Debug("registered spec for rotation",
			logger.String("spec", entry.SpecName),
			logger.String("source", entry.SourceName),
			logger.String("period", entry.RotationPeriod.String()),
			logger.Time("next_rotation", entry.NextAction))
	} else {
		m.log.Debug("registered source for rotation",
			logger.String("source", entry.SourceName),
			logger.String("type", entry.SourceType),
			logger.String("period", entry.RotationPeriod.String()),
			logger.Time("next_rotation", entry.NextAction))
	}

	return nil
}

// UnregisterSource removes a source from rotation tracking
func (m *RotationManager) UnregisterSource(ctx context.Context, sourceName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	key := buildRotationKey(ns.UUID, sourceName)
	if existing, loaded := m.entries.LoadAndDelete(key); loaded {
		entry := existing.(*RotationEntry)
		atomic.AddInt64(&m.entryCount, -1)
		if entry.State == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}

		if m.storage != nil {
			m.deleteEntry(entry)
		}

		m.log.Debug("unregistered source from rotation manager",
			logger.String("source", sourceName))
	}

	return nil
}

// UnregisterSpec removes a spec from rotation tracking
func (m *RotationManager) UnregisterSpec(ctx context.Context, specName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}

	key := buildSpecKey(ns.UUID, specName)
	if existing, loaded := m.entries.LoadAndDelete(key); loaded {
		entry := existing.(*RotationEntry)
		atomic.AddInt64(&m.entryCount, -1)
		if entry.State == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}

		if m.storage != nil {
			m.deleteEntry(entry)
		}

		m.log.Debug("unregistered spec from rotation",
			logger.String("spec", specName))
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
	existing, loaded := m.entries.Load(key)
	if !loaded {
		return fmt.Errorf("source %s is not registered for rotation", sourceName)
	}

	entry := existing.(*RotationEntry)
	entry.RotationPeriod = newPeriod
	entry.NextAction = time.Now().Add(newPeriod)

	if m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			return fmt.Errorf("failed to persist updated rotation entry: %w", err)
		}
	}

	m.log.Info("updated rotation period",
		logger.String("source", sourceName),
		logger.String("new_period", newPeriod.String()),
		logger.Time("next_rotation", entry.NextAction))

	return nil
}

// ============================================================================
// Persistence
// ============================================================================

// entryStoragePath returns the storage path for an entry.
func (m *RotationManager) entryStoragePath(entry *RotationEntry) string {
	if entry.EntryType == EntryTypeSpec {
		return rotationEntryPath + entry.Namespace + "/spec:" + entry.SpecName
	}
	return rotationEntryPath + entry.Namespace + "/source:" + entry.SourceName
}

// persistEntry saves a rotation entry to storage
func (m *RotationManager) persistEntry(entry *RotationEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return m.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key:   m.entryStoragePath(entry),
		Value: data,
	})
}

// deleteEntry removes an entry from storage
func (m *RotationManager) deleteEntry(entry *RotationEntry) error {
	return m.storage.Delete(context.Background(), m.entryStoragePath(entry))
}

// ============================================================================
// Rotation Business Logic
// ============================================================================

// prepareSource creates new credentials and either activates them immediately (fast path)
// or returns staged data for deferred activation (slow path).
//
// Returns (newConfig, cleanupConfig, activateAfter, error).
// activateAfter == 0 means fast path (already activated inline).
func (m *RotationManager) prepareSource(entry *RotationEntry) (activateAfter time.Duration, err error) {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return 0, fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	if m.core == nil || m.core.credConfigStore == nil {
		return 0, fmt.Errorf("credential config store not available")
	}

	source, err := m.core.credConfigStore.GetSource(ctx, entry.SourceName)
	if err != nil {
		return 0, fmt.Errorf("failed to get source %s: %w", entry.SourceName, err)
	}

	if m.core.credentialManager == nil {
		return 0, fmt.Errorf("credential manager not available")
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return 0, fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	rotatable, ok := driver.(credential.Rotatable)
	if !ok {
		return 0, fmt.Errorf("driver for source %s does not support rotation", entry.SourceName)
	}

	if !rotatable.SupportsRotation() {
		return 0, fmt.Errorf("source %s configuration does not support rotation", entry.SourceName)
	}

	// PREPARE: Generate new credentials (old still valid)
	newConfig, cleanupConfig, delay, err := rotatable.PrepareRotation(ctx)
	if err != nil {
		return 0, fmt.Errorf("prepare rotation failed for source %s: %w", entry.SourceName, err)
	}

	// Fast path: immediate activation
	if delay == 0 {
		if err := m.activateSourceInline(ctx, entry, source, rotatable, newConfig, cleanupConfig); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// Slow path: populate staged fields on the entry
	entry.NewConfig = newConfig
	entry.CleanupConfig = cleanupConfig
	entry.ActivationDelay = delay
	entry.PreparedAt = time.Now()

	m.log.Debug("prepared source rotation, activation scheduled",
		logger.String("source", entry.SourceName),
		logger.String("activate_after", delay.String()))

	return delay, nil
}

// activateSourceInline runs persist + commit + cleanup synchronously (fast path for activateAfter == 0).
func (m *RotationManager) activateSourceInline(ctx context.Context, entry *RotationEntry,
	source *credential.CredSource, rotatable credential.Rotatable,
	newConfig, cleanupConfig map[string]string) error {

	// PERSIST
	source.Config = newConfig
	if err := m.core.credConfigStore.UpdateSource(ctx, source, UpdateSourceOptions{SkipConnectionTest: true}); err != nil {
		return fmt.Errorf("failed to persist rotated config for source %s: %w", entry.SourceName, err)
	}

	// COMMIT
	if err := rotatable.CommitRotation(ctx, newConfig); err != nil {
		return fmt.Errorf("commit rotation failed for source %s: %w", entry.SourceName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performCleanupWithRetry(cleanupCtx, entry, rotatable, cleanupConfig)

	m.log.Debug("successfully rotated credentials",
		logger.String("source", entry.SourceName))

	return nil
}

// activateSource runs the ACTIVATE stage for a staged source rotation.
func (m *RotationManager) activateSource(entry *RotationEntry) error {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to get namespace: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	source, err := m.core.credConfigStore.GetSource(ctx, entry.SourceName)
	if err != nil {
		return fmt.Errorf("failed to get source %s: %w", entry.SourceName, err)
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	rotatable, ok := driver.(credential.Rotatable)
	if !ok {
		return fmt.Errorf("driver for source %s does not support rotation", entry.SourceName)
	}

	// PERSIST
	source.Config = entry.NewConfig
	if err := m.core.credConfigStore.UpdateSource(ctx, source, UpdateSourceOptions{SkipConnectionTest: true}); err != nil {
		return fmt.Errorf("failed to persist rotated config for source %s: %w", entry.SourceName, err)
	}

	// COMMIT
	if err := rotatable.CommitRotation(ctx, entry.NewConfig); err != nil {
		return fmt.Errorf("commit rotation failed for source %s: %w", entry.SourceName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performCleanupWithRetry(cleanupCtx, entry, rotatable, entry.CleanupConfig)

	m.log.Debug("successfully activated rotated credentials",
		logger.String("source", entry.SourceName))

	return nil
}

// prepareSpec creates new spec credentials and either activates immediately or returns staged data.
func (m *RotationManager) prepareSpec(entry *RotationEntry) (activateAfter time.Duration, err error) {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return 0, fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	if m.core == nil || m.core.credConfigStore == nil {
		return 0, fmt.Errorf("credential config store not available")
	}

	spec, err := m.core.credConfigStore.GetSpec(ctx, entry.SpecName)
	if err != nil {
		return 0, fmt.Errorf("failed to get spec %s: %w", entry.SpecName, err)
	}

	if m.core.credentialManager == nil {
		return 0, fmt.Errorf("credential manager not available")
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return 0, fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	specRotatable, ok := driver.(credential.SpecRotatable)
	if !ok {
		return 0, fmt.Errorf("driver for source %s does not support spec rotation", entry.SourceName)
	}

	if !specRotatable.SupportsSpecRotation() {
		return 0, fmt.Errorf("source %s configuration does not support spec rotation", entry.SourceName)
	}

	// PREPARE
	newConfig, cleanupConfig, delay, err := specRotatable.PrepareSpecRotation(ctx, spec)
	if err != nil {
		return 0, fmt.Errorf("prepare spec rotation failed for spec %s: %w", entry.SpecName, err)
	}

	// Fast path
	if delay == 0 {
		if err := m.activateSpecInline(ctx, entry, spec, specRotatable, newConfig, cleanupConfig); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// Slow path: populate staged fields
	entry.NewConfig = newConfig
	entry.CleanupConfig = cleanupConfig
	entry.ActivationDelay = delay
	entry.PreparedAt = time.Now()

	m.log.Info("prepared spec rotation, activation scheduled",
		logger.String("spec", entry.SpecName),
		logger.String("activate_after", delay.String()))

	return delay, nil
}

// activateSpecInline runs persist + commit + cleanup synchronously (fast path).
func (m *RotationManager) activateSpecInline(ctx context.Context, entry *RotationEntry,
	spec *credential.CredSpec, specRotatable credential.SpecRotatable,
	newConfig, cleanupConfig map[string]string) error {

	// PERSIST
	spec.Config = newConfig
	if err := m.core.credConfigStore.UpdateSpec(ctx, spec); err != nil {
		return fmt.Errorf("failed to persist rotated config for spec %s: %w", entry.SpecName, err)
	}

	// COMMIT
	if err := specRotatable.CommitSpecRotation(ctx, spec, newConfig); err != nil {
		return fmt.Errorf("commit spec rotation failed for spec %s: %w", entry.SpecName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performSpecCleanupWithRetry(cleanupCtx, entry, specRotatable, cleanupConfig)

	m.log.Debug("successfully rotated spec credentials (immediate)",
		logger.String("spec", entry.SpecName))

	return nil
}

// activateSpec runs the ACTIVATE stage for a staged spec rotation.
func (m *RotationManager) activateSpec(entry *RotationEntry) error {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to get namespace: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	spec, err := m.core.credConfigStore.GetSpec(ctx, entry.SpecName)
	if err != nil {
		return fmt.Errorf("failed to get spec %s: %w", entry.SpecName, err)
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	specRotatable, ok := driver.(credential.SpecRotatable)
	if !ok {
		return fmt.Errorf("driver for source %s does not support spec rotation", entry.SourceName)
	}

	// PERSIST
	spec.Config = entry.NewConfig
	if err := m.core.credConfigStore.UpdateSpec(ctx, spec); err != nil {
		return fmt.Errorf("failed to persist rotated config for spec %s: %w", entry.SpecName, err)
	}

	// COMMIT
	if err := specRotatable.CommitSpecRotation(ctx, spec, entry.NewConfig); err != nil {
		return fmt.Errorf("commit spec rotation failed for spec %s: %w", entry.SpecName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performSpecCleanupWithRetry(cleanupCtx, entry, specRotatable, entry.CleanupConfig)

	m.log.Debug("successfully activated rotated spec credentials",
		logger.String("spec", entry.SpecName))

	return nil
}

// ============================================================================
// Cleanup With Retry
// ============================================================================

// performCleanupWithRetry attempts source cleanup with immediate retries, then persists for daily retry.
func (m *RotationManager) performCleanupWithRetry(ctx context.Context, entry *RotationEntry,
	rotatable credential.Rotatable, cleanupConfig map[string]string) {

	if len(cleanupConfig) == 0 {
		return
	}

	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				m.persistFailedCleanup(entry, cleanupConfig)
				return
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		err = rotatable.CleanupRotation(ctx, cleanupConfig)
		if err == nil {
			return
		}

		m.log.Warn("cleanup attempt failed",
			logger.String("source", entry.SourceName),
			logger.Int("attempt", attempt+1),
			logger.Err(err))
	}

	m.persistFailedCleanup(entry, cleanupConfig)
}

// performSpecCleanupWithRetry attempts spec cleanup with immediate retries, then persists for daily retry.
func (m *RotationManager) performSpecCleanupWithRetry(ctx context.Context, entry *RotationEntry,
	specRotatable credential.SpecRotatable, cleanupConfig map[string]string) {

	if len(cleanupConfig) == 0 {
		return
	}

	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				m.persistFailedSpecCleanup(entry, cleanupConfig)
				return
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		err = specRotatable.CleanupSpecRotation(ctx, cleanupConfig)
		if err == nil {
			return
		}

		m.log.Warn("spec cleanup attempt failed",
			logger.String("spec", entry.SpecName),
			logger.Int("attempt", attempt+1),
			logger.Err(err))
	}

	m.persistFailedSpecCleanup(entry, cleanupConfig)
}

// persistFailedCleanup stores a failed cleanup to storage for daily retry
func (m *RotationManager) persistFailedCleanup(entry *RotationEntry, cleanupConfig map[string]string) {
	pending := &PendingCleanup{
		SourceName:    entry.SourceName,
		SourceType:    entry.SourceType,
		Namespace:     entry.Namespace,
		CleanupConfig: cleanupConfig,
		Attempts:      3,
		CreatedAt:     time.Now(),
		LastAttempt:   time.Now(),
	}

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

// persistFailedSpecCleanup stores a failed spec cleanup to storage for daily retry
func (m *RotationManager) persistFailedSpecCleanup(entry *RotationEntry, cleanupConfig map[string]string) {
	pending := &PendingCleanup{
		SourceName:    entry.SourceName,
		SourceType:    EntryTypeSpec,
		Namespace:     entry.Namespace,
		CleanupConfig: cleanupConfig,
		Attempts:      3,
		CreatedAt:     time.Now(),
		LastAttempt:   time.Now(),
	}

	if pending.CleanupConfig == nil {
		pending.CleanupConfig = make(map[string]string)
	}
	pending.CleanupConfig["_spec_name"] = entry.SpecName

	if m.storage != nil {
		path := rotationCleanupPath + entry.Namespace + "/spec:" + entry.SpecName
		data, err := json.Marshal(pending)
		if err != nil {
			m.log.Error("failed to marshal pending spec cleanup",
				logger.String("spec", entry.SpecName),
				logger.Err(err))
			return
		}
		if err := m.storage.Put(context.Background(), &sdklogical.StorageEntry{
			Key:   path,
			Value: data,
		}); err != nil {
			m.log.Error("failed to persist pending spec cleanup",
				logger.String("spec", entry.SpecName),
				logger.Err(err))
			return
		}
	}

	m.log.Warn("spec cleanup persisted for daily retry",
		logger.String("spec", entry.SpecName))
}

// retryFailedCleanups is called daily to retry persisted failed cleanups.
func (m *RotationManager) retryFailedCleanups() {
	if m.storage == nil || m.core == nil {
		return
	}

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

			if time.Since(pending.CreatedAt) > 7*24*time.Hour {
				m.storage.Delete(context.Background(), path)
				abandoned++
				m.log.Error("cleanup abandoned after 7 days",
					logger.String("source", pending.SourceName),
					logger.Int("attempts", pending.Attempts))
				continue
			}

			retried++

			select {
			case <-m.quitCtx.Done():
				return
			default:
			}

			ctx := m.quitCtx
			nsObj := &namespace.Namespace{UUID: pending.Namespace}
			ctx = namespace.ContextWithNamespace(ctx, nsObj)

			driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, pending.SourceName)
			if err != nil {
				// Source was deleted — cleanup is no longer possible or needed
				m.storage.Delete(context.Background(), path)
				abandoned++
				m.log.Warn("cleanup abandoned, source no longer exists",
					logger.String("source", pending.SourceName),
					logger.Err(err))
				continue
			}

			rotatable, ok := driver.(credential.Rotatable)
			if !ok {
				m.storage.Delete(context.Background(), path)
				continue
			}

			pending.Attempts++
			pending.LastAttempt = time.Now()

			if err := rotatable.CleanupRotation(ctx, pending.CleanupConfig); err == nil {
				m.storage.Delete(context.Background(), path)
				succeeded++
				m.log.Info("pending cleanup succeeded",
					logger.String("source", pending.SourceName),
					logger.Int("attempts", pending.Attempts))
			} else {
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

// ============================================================================
// Restore on Startup
// ============================================================================

// Restore loads all persisted rotation entries on startup.
// Also migrates entries from legacy storage paths (pending/failed/staged).
func (m *RotationManager) Restore(ctx context.Context) error {
	if m.storage == nil {
		m.log.Warn("no storage configured, skipping rotation restore")
		return nil
	}

	m.log.Info("restoring rotation entries from storage")

	// Restore from new unified path
	entryPaths, err := m.collectEntryPaths(ctx, rotationEntryPath)
	if err != nil {
		return fmt.Errorf("failed to collect entries: %w", err)
	}
	if len(entryPaths) > 0 {
		if err := m.restoreEntriesParallel(ctx, entryPaths); err != nil {
			return err
		}
	}

	var entryCount, failedCount int64
	m.entries.Range(func(key, value any) bool {
		entryCount++
		if value.(*RotationEntry).State == StateFailed {
			failedCount++
		}
		return true
	})
	atomic.StoreInt64(&m.entryCount, entryCount)
	atomic.StoreInt64(&m.failedCount, failedCount)

	m.log.Info("rotation restore completed",
		logger.Int64("entries", entryCount),
		logger.Int64("failed", failedCount))

	return nil
}

// collectEntryPaths collects all entry paths from storage
func (m *RotationManager) collectEntryPaths(ctx context.Context, basePath string) ([]string, error) {
	var paths []string

	namespaces, err := m.storage.List(ctx, basePath)
	if err != nil {
		return paths, nil
	}

	for _, ns := range namespaces {
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
func (m *RotationManager) restoreEntriesParallel(ctx context.Context, paths []string) error {
	pathCh := make(chan string, len(paths))
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	workerCount := rotationRestoreWorkerCount
	if len(paths) < workerCount {
		workerCount = len(paths)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				if err := m.restoreEntry(ctx, path); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}

	for _, path := range paths {
		pathCh <- path
	}
	close(pathCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// restoreEntry restores a single entry from storage
func (m *RotationManager) restoreEntry(ctx context.Context, path string) error {
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

	key := m.buildEntryKey(&entry)
	m.entries.Store(key, &entry)

	return nil
}

// ============================================================================
// Metrics
// ============================================================================

// GetPendingCount returns the number of non-failed entries (idle + staged).
func (m *RotationManager) GetPendingCount() int64 {
	return atomic.LoadInt64(&m.entryCount) - atomic.LoadInt64(&m.failedCount)
}

// GetFailedCount returns the number of failed rotations
func (m *RotationManager) GetFailedCount() int64 {
	return atomic.LoadInt64(&m.failedCount)
}

// GetEntry returns the rotation entry for a given namespace and source name.
func (m *RotationManager) GetEntry(namespaceID, sourceName string) *RotationEntry {
	key := buildRotationKey(namespaceID, sourceName)
	if val, ok := m.entries.Load(key); ok {
		return val.(*RotationEntry)
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// buildRotationKey creates a map key from namespace and source name
func buildRotationKey(namespaceID, sourceName string) string {
	return namespaceID + ":source:" + sourceName
}

// buildSpecKey creates a storage key from namespace and spec name
func buildSpecKey(namespaceID, specName string) string {
	return namespaceID + ":spec:" + specName
}

// buildEntryKey creates a unique key for a rotation entry based on its type
func (m *RotationManager) buildEntryKey(entry *RotationEntry) string {
	if entry.EntryType == EntryTypeSpec {
		return buildSpecKey(entry.Namespace, entry.SpecName)
	}
	return buildRotationKey(entry.Namespace, entry.SourceName)
}

// getNamespaceFromEntry retrieves the namespace for a rotation entry.
func (m *RotationManager) getNamespaceFromEntry(ctx context.Context, entry *RotationEntry) (*namespace.Namespace, error) {
	if entry.Namespace == "" {
		return namespace.RootNamespace, nil
	}

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

// signalDone sends a signal on the rotationDoneCh for testing.
func (m *RotationManager) signalDone() {
	select {
	case m.rotationDoneCh <- struct{}{}:
	default:
	}
}

// calculateBackoff computes exponential backoff for a given attempt count.
func (m *RotationManager) calculateBackoff(attempts int) time.Duration {
	backoff := time.Duration(10<<attempts) * time.Second
	if backoff > MaxRotationBackoff {
		backoff = MaxRotationBackoff
	}
	if m.backoffScale > 0 && m.backoffScale < 1.0 {
		backoff = time.Duration(float64(backoff) * m.backoffScale)
		if backoff < time.Millisecond {
			backoff = time.Millisecond
		}
	}
	return jitterDuration(backoff, 0.20)
}

// jitterDuration adds a random jitter to a duration.
// pct is the maximum jitter as a fraction (e.g., 0.05 = 5%).
func jitterDuration(d time.Duration, pct float64) time.Duration {
	if d <= 0 || pct <= 0 {
		return d
	}
	maxJitter := int64(float64(d) * pct)
	if maxJitter <= 0 {
		return d
	}
	return d + time.Duration(rand.Int63n(maxJitter))
}
