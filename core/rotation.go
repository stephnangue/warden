// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/fairshare"
	"github.com/stephnangue/warden/internal/namespace"
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

	// Kind is cleanupKindCleanup or cleanupKindDiscard. Empty on records
	// written before discards existed, which were all cleanups.
	Kind string `json:"kind,omitempty"`

	// SpecName is set for a spec rotation's cleanup, which is retried through
	// CleanupSpecRotation. Records written before this field carried the name
	// as "_spec_name" inside CleanupConfig.
	SpecName string `json:"spec_name,omitempty"`

	// AuthConfigHash, set for a discard, is the hash of the source config the
	// deleting driver authenticated with. The retry runs only while the source
	// still holds that config; once it changes, the driver that could delete
	// the credential is gone.
	AuthConfigHash string `json:"auth_config_hash,omitempty"`
}

// cleanupStoragePath is where a pending cleanup is persisted: one record per
// credential, keyed by target, kind and a digest of the cleanup config. One
// record per source used to mean a second failure overwrote the first, and the
// credential the first one named was never deleted.
func cleanupStoragePath(namespaceID, target, kind string, cleanupConfig map[string]string) string {
	return rotationCleanupPath + namespaceID + "/" + target + "." + kind + "." + credential.NewConfig(cleanupConfig).Hash()[:16]
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

	// Staged fields (populated only when State == StateStaged, and kept when an
	// activation that exhausted its attempts moves the entry to StateFailed)
	NewConfig       map[string]string `json:"new_config,omitempty"`
	CleanupConfig   map[string]string `json:"cleanup_config,omitempty"`
	ActivationDelay time.Duration     `json:"activation_delay,omitempty"`
	PreparedAt      time.Time         `json:"prepared_at,omitempty"`

	// BaseConfigHash is credential.Config.Hash of the config the prepare ran
	// against. Activation persists NewConfig — a full snapshot of that config
	// with new credentials — only while the stored config still hashes to it,
	// so a snapshot never overwrites an edit made after the prepare. A hash, not
	// a copy, so the entry does not hold a second copy of the old secret.
	BaseConfigHash string `json:"base_config_hash,omitempty"`

	// Failure tracking
	LastError string `json:"last_error,omitempty"`

	// In-flight guard (not persisted) — prevents tick from re-queuing while a job is executing
	inflight int32 // atomic: 0 = available, 1 = job in worker pool

	// removed (not persisted) is set once the entry leaves the registry. A job
	// already holding the entry checks it before writing anything, so an
	// unregistered source or spec is not rotated after the fact.
	removed int32 // atomic

	// discardPending (not persisted, guarded by mu) marks an entry found at
	// restore whose source or spec no longer rotates. The tick loop queues a job
	// that discards its staged credential and drops it, keeping upstream calls
	// off the unseal path.
	discardPending bool
}

// isRemoved reports whether the entry has left the registry.
func (e *RotationEntry) isRemoved() bool {
	return atomic.LoadInt32(&e.removed) == 1
}

// markRemoved records that the entry has left the registry.
func (e *RotationEntry) markRemoved() {
	atomic.StoreInt32(&e.removed, 1)
}

// clearStagedFields resets the staged-only fields after activation completes.
// Caller must hold e.mu.
func (e *RotationEntry) clearStagedFields() {
	e.NewConfig = nil
	e.CleanupConfig = nil
	e.ActivationDelay = 0
	e.PreparedAt = time.Time{}
	e.BaseConfigHash = ""
}

// stagedRotation is the outcome of a slow-path prepare: credentials generated
// upstream and waiting to be activated.
//
// It is returned from the prepare step rather than written straight onto the
// entry so that every write to an entry's staged fields happens under e.mu, in
// the job that owns the transition. Writing them from the prepare step would
// race the tick loop's readers and persistEntry's marshal of the whole struct.
type stagedRotation struct {
	NewConfig       map[string]string
	CleanupConfig   map[string]string
	ActivationDelay time.Duration
	PreparedAt      time.Time
	BaseConfigHash  string
}

// applyStaged copies a completed prepare onto the entry. Caller must hold e.mu.
func (e *RotationEntry) applyStaged(s *stagedRotation) {
	e.NewConfig = s.NewConfig
	e.CleanupConfig = s.CleanupConfig
	e.ActivationDelay = s.ActivationDelay
	e.PreparedAt = s.PreparedAt
	e.BaseConfigHash = s.BaseConfigHash
}

// errEntryRemoved and errNothingStaged tell a job that the work it was queued
// for is gone: the entry left the registry, or an operator's edit discarded the
// staged rotation before the activation ran. The job completes as a no-op.
var (
	errEntryRemoved  = errors.New("rotation entry was removed")
	errNothingStaged = errors.New("rotation entry has no staged rotation")
)

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
//
// It genuinely copies. The lock only made reading the field safe; handing back the
// map itself left the caller free to write into staged credentials that the entry
// still owns and later serializes. maps.Clone(nil) is nil, so a cleared entry still
// reads as nil.
func (e *RotationEntry) GetNewConfig() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return maps.Clone(e.NewConfig)
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
		if entry.discardPending {
			atomic.StoreInt32(&entry.inflight, 1)
			entry.mu.Unlock()
			m.queueDiscardJob(key.(string), entry)
			return true
		}

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
			entry.Attempts = 0
			atomic.AddInt64(&m.failedCount, -1)
			if entry.NewConfig != nil {
				// An activation that ran out of attempts still holds a staged
				// credential. Retry the activation rather than preparing over
				// it: a fresh prepare would overwrite the staged data and leave
				// that credential live upstream with nothing tracking it.
				// Activation resumes, persists or discards as the stored config
				// requires.
				entry.State = StateStaged
				entry.mu.Unlock()
				m.queueActivateJob(key.(string), entry)
				return true
			}
			entry.State = StateIdle
			entry.mu.Unlock()
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

// queueDiscardJob adds a job that discards an orphaned entry's staged
// credential and drops the entry.
func (m *RotationManager) queueDiscardJob(key string, entry *RotationEntry) {
	job := &discardJob{manager: m, entry: entry, key: key}
	m.jobManager.AddJob(job, entry.Namespace)
}

// lockEntryTarget takes the lock that serializes config writes to the entry's
// target: LockSource for a source entry, LockSpec for a spec entry. Every
// writer of that config — the operator's update and delete handlers, and these
// jobs — takes the same lock, so a job's read, prepare and write of a config
// cannot interleave with an operator's.
//
// Acquisition is bounded by StageTimeout. A job that cannot get the lock fails
// and retries with backoff like any other stage failure.
func (m *RotationManager) lockEntryTarget(entry *RotationEntry) (func(), error) {
	if m.core == nil || m.core.credentialManager == nil {
		return func() {}, nil
	}
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace for entry: %w", err)
	}

	var unlock func()
	if entry.EntryType == EntryTypeSpec {
		unlock, err = m.core.credentialManager.LockSpec(ctx, ns.UUID, entry.SpecName)
	} else {
		unlock, err = m.core.credentialManager.LockSource(ctx, ns.UUID, entry.SourceName)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lock rotation target: %w", err)
	}
	return unlock, nil
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

	return m.register(ctx, entry)
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

	return m.register(ctx, entry)
}

// register is the internal registration method.
func (m *RotationManager) register(ctx context.Context, entry *RotationEntry) error {
	key := m.buildEntryKey(entry)

	// Persist entry to storage FIRST (durability)
	if m.storage != nil {
		if err := m.persistEntry(entry); err != nil {
			return fmt.Errorf("failed to persist rotation entry: %w", err)
		}
	}

	// Replace existing entry if present
	if existing, loaded := m.entries.Load(key); loaded {
		// The entry being replaced is live: a worker may be mutating its state
		// right now, so read it through the accessor rather than off the field.
		old := existing.(*RotationEntry)
		if old.GetState() == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}
		m.entries.Store(key, entry)
		old.markRemoved()

		// Replacing an entry drops its staged data, and with it the only record
		// of a credential the prepare already created upstream. Discard it
		// first. A spec re-registers after its own update has persisted, but
		// the discard authenticates through the source's driver, which that
		// update left untouched.
		m.discardEntryStaged(ctx, old)

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
		entry.markRemoved()
		atomic.AddInt64(&m.entryCount, -1)
		if entry.GetState() == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}

		m.discardEntryStaged(ctx, entry)

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
		entry.markRemoved()
		atomic.AddInt64(&m.entryCount, -1)
		if entry.GetState() == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}

		m.discardEntryStaged(ctx, entry)

		if m.storage != nil {
			m.deleteEntry(entry)
		}

		m.log.Debug("unregistered spec from rotation",
			logger.String("spec", specName))
	}

	return nil
}

// UnregisterByNamespace removes all rotation entries for the given namespace UUID.
// This is called during namespace deletion to stop all rotation jobs for the namespace.
// It also deletes any pending cleanup entries from storage.
func (m *RotationManager) UnregisterByNamespace(namespaceID string) error {
	prefix := namespaceID + ":"
	var removed int

	m.entries.Range(func(key, value any) bool {
		keyStr := key.(string)
		if !strings.HasPrefix(keyStr, prefix) {
			return true
		}

		entry := value.(*RotationEntry)
		m.entries.Delete(key)
		entry.markRemoved()
		atomic.AddInt64(&m.entryCount, -1)
		if entry.GetState() == StateFailed {
			atomic.AddInt64(&m.failedCount, -1)
		}

		// Namespace deletion unregisters before it clears the sources, so the
		// driver that prepared a staged credential can still discard it.
		ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
		if ns, err := m.getNamespaceFromEntry(ctx, entry); err == nil {
			m.discardEntryStaged(namespace.ContextWithNamespace(ctx, ns), entry)
		}
		cancel()

		if m.storage != nil {
			m.deleteEntry(entry)
		}

		removed++
		return true
	})

	// Delete cleanup entries from storage (entire namespace directory). The
	// namespace's sources go next, so nothing could ever run these; each names
	// a credential still live upstream, so say which before dropping it.
	if m.storage != nil {
		cleanupPath := rotationCleanupPath + namespaceID + "/"
		entries, err := m.storage.List(context.Background(), cleanupPath)
		if err == nil {
			for _, entryName := range entries {
				if raw, err := m.storage.Get(context.Background(), cleanupPath+entryName); err == nil && raw != nil {
					var pending PendingCleanup
					if json.Unmarshal(raw.Value, &pending) == nil {
						m.log.Error("pending rotation cleanup abandoned with its namespace; delete the credential at the provider",
							logger.String("source", pending.SourceName),
							logger.String("credential", credentialHint(pending.CleanupConfig)))
					}
				}
				m.storage.Delete(context.Background(), cleanupPath+entryName)
			}
		}
	}

	if removed > 0 {
		m.log.Info("unregistered all rotation entries for namespace",
			logger.String("namespace", namespaceID),
			logger.Int("removed", removed))
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

	// Take the entry's lock: the schedule fields are written by worker goroutines
	// too, and persistEntry marshals every field of the struct, so an unlocked
	// update here races both those writes and its own persist.
	entry := existing.(*RotationEntry)
	entry.mu.Lock()
	entry.RotationPeriod = newPeriod
	// A staged entry's NextAction is its activation time, which the period does
	// not govern. Rescheduling it would postpone the activation by a whole
	// period, with both the old and the staged credential live throughout. The
	// same holds for a failed entry still holding staged data: its next action
	// is that activation's retry. The new period takes effect when the
	// activation completes.
	if entry.State != StateStaged && entry.NewConfig == nil {
		entry.NextAction = time.Now().Add(newPeriod)
	}
	nextAction := entry.NextAction

	var persistErr error
	if m.storage != nil {
		persistErr = m.persistEntryIfCurrent(entry)
	}
	entry.mu.Unlock()

	if persistErr != nil {
		return fmt.Errorf("failed to persist updated rotation entry: %w", persistErr)
	}

	m.log.Info("updated rotation period",
		logger.String("source", sourceName),
		logger.String("new_period", newPeriod.String()),
		logger.Time("next_rotation", nextAction))

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

// persistEntryIfCurrent persists entry unless it has been superseded in the
// registry, in which case it does nothing.
//
// register() replaces the map value for a key while a job may still be running
// against the entry it replaced, and both entries map to the same storage path.
// Without this check, the in-flight job's completion would write the superseded
// entry's state over the live one's record — invisible until a restart restored
// the stale copy.
//
// It equally skips an entry that is no longer registered at all. A job still
// running against an unregistered entry would otherwise write it back to
// storage after the unregister deleted it, and the next restore would bring
// back a rotation for a source that left the schedule, or no longer exists.
//
// Only the job paths use it. register() itself persists before storing, by
// design, so its own write must not be filtered out.
func (m *RotationManager) persistEntryIfCurrent(entry *RotationEntry) error {
	key := m.buildEntryKey(entry)
	if current, ok := m.entries.Load(key); !ok || current.(*RotationEntry) != entry {
		m.log.Debug("skipping persist for a superseded or unregistered rotation entry",
			logger.String("key", key))
		return nil
	}
	return m.persistEntry(entry)
}

// dropEntry removes entry from the registry and from storage, provided it is
// still the entry registered under key.
func (m *RotationManager) dropEntry(key string, entry *RotationEntry) {
	if !m.entries.CompareAndDelete(key, entry) {
		return
	}
	entry.markRemoved()
	atomic.AddInt64(&m.entryCount, -1)
	if entry.GetState() == StateFailed {
		atomic.AddInt64(&m.failedCount, -1)
	}
	if m.storage != nil {
		m.deleteEntry(entry)
	}
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
// A nil *stagedRotation means the fast path: activation already happened inline.
// The staged data is returned rather than written onto the entry here, so the
// caller can apply it under the entry's lock — see stagedRotation.
func (m *RotationManager) prepareSource(entry *RotationEntry) (staged *stagedRotation, err error) {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	if m.core == nil || m.core.credConfigStore == nil {
		return nil, fmt.Errorf("credential config store not available")
	}

	source, err := m.core.credConfigStore.GetSource(ctx, entry.SourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get source %s: %w", entry.SourceName, err)
	}

	if m.core.credentialManager == nil {
		return nil, fmt.Errorf("credential manager not available")
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	rotatable, ok := driver.(credential.Rotatable)
	if !ok {
		return nil, fmt.Errorf("driver for source %s does not support rotation", entry.SourceName)
	}

	if !rotatable.SupportsRotation() {
		return nil, fmt.Errorf("source %s configuration does not support rotation", entry.SourceName)
	}

	// The config this prepare runs against. newConfig is a snapshot of it with
	// new credentials, so it may only ever be written over this exact config.
	baseHash := source.Config.Hash()

	// PREPARE: Generate new credentials (old still valid)
	newConfig, cleanupConfig, delay, err := rotatable.PrepareRotation(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare rotation failed for source %s: %w", entry.SourceName, err)
	}

	// Fast path: immediate activation
	if delay == 0 {
		if err := m.activateSourceInline(ctx, entry, source, rotatable, newConfig, cleanupConfig, baseHash); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// The job holds the source lock, so every unregister made through an
	// operator path waits for it. Namespace deletion does not take that lock: if
	// it removed the entry while PrepareRotation ran, the credential just
	// created has no entry left to activate it. Discard it now, while this
	// driver still authenticates with the old credential.
	if entry.isRemoved() {
		m.discardStaged(ctx, entry, driver, newConfig)
		return nil, errEntryRemoved
	}

	// Slow path: hand the staged data back for the caller to apply under the lock.
	m.log.Debug("prepared source rotation, activation scheduled",
		logger.String("source", entry.SourceName),
		logger.String("activate_after", delay.String()))

	return &stagedRotation{
		NewConfig:       newConfig,
		CleanupConfig:   cleanupConfig,
		ActivationDelay: delay,
		PreparedAt:      time.Now(),
		BaseConfigHash:  baseHash,
	}, nil
}

// sourceWithConfig and specWithConfig return a copy carrying the rotated config,
// leaving the original untouched.
//
// The config store hands back the pointer it caches, and every concurrent mint is
// reading through it. Assigning the config field on that shared object is a data
// race against those readers, and it publishes the new credentials before they are
// validated and written: if the persist below then fails, the cache is left serving
// material that never reached storage, which a restart silently reverts.
//
// Publishing a new object instead makes the persist the only thing that changes what
// readers see. NewConfig copies the map as well, which matters because the staged
// map on a rotation entry outlives this call and is serialized with the entry.
func sourceWithConfig(source *credential.CredSource, config map[string]string) *credential.CredSource {
	updated := *source
	updated.Config = credential.NewConfig(config)
	return &updated
}

func specWithConfig(spec *credential.CredSpec, config map[string]string) *credential.CredSpec {
	updated := *spec
	updated.Config = credential.NewConfig(config)
	return &updated
}

// activateSourceInline runs persist + commit + cleanup synchronously (fast path for activateAfter == 0).
func (m *RotationManager) activateSourceInline(ctx context.Context, entry *RotationEntry,
	source *credential.CredSource, rotatable credential.Rotatable,
	newConfig, cleanupConfig map[string]string, baseHash string) error {

	// PERSIST, only over the config the prepare ran against.
	updated := sourceWithConfig(source, newConfig)
	if err := m.core.credConfigStore.UpdateSource(ctx, updated, UpdateSourceOptions{
		SkipConnectionTest: true,
		ExpectedConfigHash: baseHash,
	}); err != nil {
		// Someone else wrote the config since the prepare. Nothing will
		// activate the credential just created, so discard it while this
		// driver still holds the one it was meant to replace.
		if errors.Is(err, ErrConfigChanged) {
			if driver, ok := rotatable.(credential.SourceDriver); ok {
				m.discardStaged(ctx, entry, driver, newConfig)
			}
		}
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

// stagedSnapshot copies the staged fields out under the entry's lock, so an
// activation works from a consistent view while an operator's discard or the
// tick loop may touch the entry.
func (e *RotationEntry) stagedSnapshot() (newConfig, cleanupConfig map[string]string, baseHash string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return maps.Clone(e.NewConfig), maps.Clone(e.CleanupConfig), e.BaseConfigHash
}

// errStagedDiscarded reports that activation found the stored config changed
// since the prepare and discarded the staged credential instead of writing it.
// The job returns the entry to idle and re-prepares against the current config.
var errStagedDiscarded = errors.New("staged rotation discarded: config changed since prepare")

// activateSource runs the ACTIVATE stage for a staged source rotation.
//
// NewConfig is a snapshot of the whole config the prepare ran against, so what
// activation does depends on what is stored now:
//
//   - The stored config equals NewConfig: an earlier attempt persisted it and
//     then failed at commit. The staged credential is already the live one, so
//     resume at commit; discarding it here would delete the key in use.
//   - The stored config is still the one the prepare ran against: persist.
//   - Anything else: someone else changed the config since. Writing the snapshot
//     would undo their change, so discard the staged credential instead.
func (m *RotationManager) activateSource(entry *RotationEntry) error {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	newConfig, cleanupConfig, baseHash := entry.stagedSnapshot()
	if newConfig == nil {
		return errNothingStaged
	}

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

	storedHash := source.Config.Hash()
	switch {
	case source.Config.Equal(credential.NewConfig(newConfig)):
		m.log.Info("resuming a source activation that persisted but did not commit",
			logger.String("source", entry.SourceName))

	// An entry staged before BaseConfigHash existed carries none; it keeps the
	// unconditional write it was prepared under.
	case baseHash == "" || storedHash == baseHash:
		updated := sourceWithConfig(source, newConfig)
		err := m.core.credConfigStore.UpdateSource(ctx, updated, UpdateSourceOptions{
			SkipConnectionTest: true,
			ExpectedConfigHash: storedHash,
		})
		if errors.Is(err, ErrConfigChanged) {
			m.discardStaged(ctx, entry, driver, newConfig)
			return errStagedDiscarded
		}
		if err != nil {
			return fmt.Errorf("failed to persist rotated config for source %s: %w", entry.SourceName, err)
		}

	default:
		m.log.Warn("source config changed since the rotation was prepared; discarding the staged credential",
			logger.String("source", entry.SourceName))
		m.discardStaged(ctx, entry, driver, newConfig)
		return errStagedDiscarded
	}

	// COMMIT
	if err := rotatable.CommitRotation(ctx, newConfig); err != nil {
		return fmt.Errorf("commit rotation failed for source %s: %w", entry.SourceName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performCleanupWithRetry(cleanupCtx, entry, rotatable, cleanupConfig)

	m.log.Debug("successfully activated rotated credentials",
		logger.String("source", entry.SourceName))

	return nil
}

// prepareSpec creates new spec credentials and either activates immediately or returns
// staged data. A nil *stagedRotation means activation already happened inline. As in
// prepareSource, the staged data is returned rather than written onto the entry so the
// caller can apply it under the entry's lock.
func (m *RotationManager) prepareSpec(entry *RotationEntry) (staged *stagedRotation, err error) {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	ns, err := m.getNamespaceFromEntry(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace for entry: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	if m.core == nil || m.core.credConfigStore == nil {
		return nil, fmt.Errorf("credential config store not available")
	}

	spec, err := m.core.credConfigStore.GetSpec(ctx, entry.SpecName)
	if err != nil {
		return nil, fmt.Errorf("failed to get spec %s: %w", entry.SpecName, err)
	}

	if m.core.credentialManager == nil {
		return nil, fmt.Errorf("credential manager not available")
	}

	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver for source %s: %w", entry.SourceName, err)
	}

	specRotatable, ok := driver.(credential.SpecRotatable)
	if !ok {
		return nil, fmt.Errorf("driver for source %s does not support spec rotation", entry.SourceName)
	}

	if !specRotatable.SupportsSpecRotation() {
		return nil, fmt.Errorf("source %s configuration does not support spec rotation", entry.SourceName)
	}

	// The spec config this prepare runs against; see prepareSource.
	baseHash := spec.Config.Hash()

	// PREPARE
	newConfig, cleanupConfig, delay, err := specRotatable.PrepareSpecRotation(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("prepare spec rotation failed for spec %s: %w", entry.SpecName, err)
	}

	// Fast path
	if delay == 0 {
		if err := m.activateSpecInline(ctx, entry, spec, specRotatable, newConfig, cleanupConfig, baseHash); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// See prepareSource: an entry removed while the prepare ran has nothing left
	// to activate the credential it created.
	if entry.isRemoved() {
		m.discardStaged(ctx, entry, driver, newConfig)
		return nil, errEntryRemoved
	}

	// Slow path: hand the staged data back for the caller to apply under the lock.
	m.log.Info("prepared spec rotation, activation scheduled",
		logger.String("spec", entry.SpecName),
		logger.String("activate_after", delay.String()))

	return &stagedRotation{
		NewConfig:       newConfig,
		CleanupConfig:   cleanupConfig,
		ActivationDelay: delay,
		PreparedAt:      time.Now(),
		BaseConfigHash:  baseHash,
	}, nil
}

// activateSpecInline runs persist + commit + cleanup synchronously (fast path).
func (m *RotationManager) activateSpecInline(ctx context.Context, entry *RotationEntry,
	spec *credential.CredSpec, specRotatable credential.SpecRotatable,
	newConfig, cleanupConfig map[string]string, baseHash string) error {

	// PERSIST, only over the config the prepare ran against.
	updated := specWithConfig(spec, newConfig)
	if err := m.core.credConfigStore.UpdateSpec(ctx, updated, UpdateSpecOptions{ExpectedConfigHash: baseHash}); err != nil {
		// See activateSourceInline.
		if errors.Is(err, ErrConfigChanged) {
			if driver, ok := specRotatable.(credential.SourceDriver); ok {
				m.discardStaged(ctx, entry, driver, newConfig)
			}
		}
		return fmt.Errorf("failed to persist rotated config for spec %s: %w", entry.SpecName, err)
	}

	// COMMIT
	if err := specRotatable.CommitSpecRotation(ctx, updated, newConfig); err != nil {
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

// activateSpec runs the ACTIVATE stage for a staged spec rotation. It resolves
// the stored spec config the same three ways activateSource does.
func (m *RotationManager) activateSpec(entry *RotationEntry) error {
	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()

	newConfig, cleanupConfig, baseHash := entry.stagedSnapshot()
	if newConfig == nil {
		return errNothingStaged
	}

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

	updated := specWithConfig(spec, newConfig)
	storedHash := spec.Config.Hash()
	switch {
	case spec.Config.Equal(credential.NewConfig(newConfig)):
		m.log.Info("resuming a spec activation that persisted but did not commit",
			logger.String("spec", entry.SpecName))

	case baseHash == "" || storedHash == baseHash:
		err := m.core.credConfigStore.UpdateSpec(ctx, updated, UpdateSpecOptions{ExpectedConfigHash: storedHash})
		if errors.Is(err, ErrConfigChanged) {
			m.discardStaged(ctx, entry, driver, newConfig)
			return errStagedDiscarded
		}
		if err != nil {
			return fmt.Errorf("failed to persist rotated config for spec %s: %w", entry.SpecName, err)
		}

	default:
		m.log.Warn("spec config changed since the rotation was prepared; discarding the staged credential",
			logger.String("spec", entry.SpecName))
		m.discardStaged(ctx, entry, driver, newConfig)
		return errStagedDiscarded
	}

	// COMMIT
	if err := specRotatable.CommitSpecRotation(ctx, updated, newConfig); err != nil {
		return fmt.Errorf("commit spec rotation failed for spec %s: %w", entry.SpecName, err)
	}

	// CLEANUP (non-fatal)
	cleanupCtx, cleanupCancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cleanupCancel()
	m.performSpecCleanupWithRetry(cleanupCtx, entry, specRotatable, cleanupConfig)

	m.log.Debug("successfully activated rotated spec credentials",
		logger.String("spec", entry.SpecName))

	return nil
}

// ============================================================================
// Cleanup With Retry
// ============================================================================

// Kinds of pending cleanup. A cleanup retires the credential a rotation
// replaced; a discard deletes the credential a staged rotation created and
// never activated.
const (
	cleanupKindCleanup = "cleanup"
	cleanupKindDiscard = "discard"
)

// performCleanupWithRetry attempts source cleanup with immediate retries, then persists for daily retry.
func (m *RotationManager) performCleanupWithRetry(ctx context.Context, entry *RotationEntry,
	rotatable credential.Rotatable, cleanupConfig map[string]string) {
	_ = m.cleanupWithRetry(ctx, entry, cleanupKindCleanup, cleanupConfig, "", rotatable.CleanupRotation)
}

// performSpecCleanupWithRetry attempts spec cleanup with immediate retries, then persists for daily retry.
func (m *RotationManager) performSpecCleanupWithRetry(ctx context.Context, entry *RotationEntry,
	specRotatable credential.SpecRotatable, cleanupConfig map[string]string) {
	_ = m.cleanupWithRetry(ctx, entry, cleanupKindCleanup, cleanupConfig, "", specRotatable.CleanupSpecRotation)
}

// cleanupWithRetry runs cleanup with immediate retries, then persists the
// cleanup for the daily retry. authHash, set for a discard, is the hash of the
// source config the deleting driver authenticated with: the daily retry only
// runs while the source still holds that config. It reports whether the
// cleanup succeeded now, as opposed to being left for the retry.
func (m *RotationManager) cleanupWithRetry(ctx context.Context, entry *RotationEntry, kind string,
	cleanupConfig map[string]string, authHash string, cleanup func(context.Context, map[string]string) error) bool {

	if len(cleanupConfig) == 0 {
		return true
	}

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				m.persistFailedCleanup(entry, kind, cleanupConfig, authHash)
				return false
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		err := cleanup(ctx, cleanupConfig)
		if err == nil {
			return true
		}

		m.log.Warn(kind+" attempt failed",
			logger.String("target", entryLabel(entry)),
			logger.Int("attempt", attempt+1),
			logger.Err(err))
	}

	m.persistFailedCleanup(entry, kind, cleanupConfig, authHash)
	return false
}

// discardStaged deletes the credential a staged prepare created, through a
// driver that must still authenticate with the credential that prepare meant
// to replace. It is best-effort: a failure is retried daily, and a credential
// it cannot identify is logged for manual deletion.
func (m *RotationManager) discardStaged(ctx context.Context, entry *RotationEntry,
	driver credential.SourceDriver, newConfig map[string]string) {

	var target map[string]string
	var cleanup func(context.Context, map[string]string) error
	var err error

	if entry.EntryType == EntryTypeSpec {
		discarder, ok1 := driver.(credential.StagedSpecRotationDiscarder)
		specRotatable, ok2 := driver.(credential.SpecRotatable)
		if !ok1 || !ok2 {
			m.logUndiscarded(entry, newConfig, "the driver cannot discard a staged spec rotation")
			return
		}
		target, err = discarder.StagedSpecCleanupConfig(ctx, newConfig)
		cleanup = specRotatable.CleanupSpecRotation
	} else {
		discarder, ok1 := driver.(credential.StagedRotationDiscarder)
		rotatable, ok2 := driver.(credential.Rotatable)
		if !ok1 || !ok2 {
			m.logUndiscarded(entry, newConfig, "the driver cannot discard a staged rotation")
			return
		}
		target, err = discarder.StagedCleanupConfig(ctx, newConfig)
		cleanup = rotatable.CleanupRotation
	}
	if err != nil {
		m.logUndiscarded(entry, newConfig, err.Error())
		return
	}

	// The daily retry only runs while the source still hashes to this. If the
	// source cannot be read now the hash is left empty, which skips that check
	// and lets the retry simply try.
	authHash, _ := m.sourceConfigHash(ctx, entry.SourceName)
	if m.cleanupWithRetry(ctx, entry, cleanupKindDiscard, target, authHash, cleanup) {
		m.log.Info("discarded staged rotation credential",
			logger.String("target", entryLabel(entry)),
			logger.String("credential", credentialHint(target)))
	}
}

// discardEntryStaged abandons whatever an entry has staged, clearing the staged
// fields. It is called when the entry is leaving the registry, being replaced,
// or being reset by an operator's edit. The caller holds the target's lock,
// except on namespace deletion, which unregisters before it clears anything.
//
// When the stored config already equals the staged one, an activation persisted
// it and then failed at commit: the staged credential is the live one. It is
// kept, and the credential it replaced is retired instead.
func (m *RotationManager) discardEntryStaged(ctx context.Context, entry *RotationEntry) {
	entry.mu.Lock()
	newConfig := maps.Clone(entry.NewConfig)
	cleanupConfig := maps.Clone(entry.CleanupConfig)
	entry.clearStagedFields()
	entry.mu.Unlock()

	if newConfig == nil {
		return
	}
	if m.core == nil || m.core.credConfigStore == nil || m.core.credentialManager == nil {
		m.logUndiscarded(entry, newConfig, "credential subsystem not available")
		return
	}

	stored, err := m.targetConfig(ctx, entry)
	if err != nil {
		m.logUndiscarded(entry, newConfig, err.Error())
		return
	}
	driver, err := m.core.credentialManager.GetOrCreateDriver(ctx, entry.SourceName)
	if err != nil {
		m.logUndiscarded(entry, newConfig, err.Error())
		return
	}

	if stored.Equal(credential.NewConfig(newConfig)) {
		if entry.EntryType == EntryTypeSpec {
			if specRotatable, ok := driver.(credential.SpecRotatable); ok {
				m.performSpecCleanupWithRetry(ctx, entry, specRotatable, cleanupConfig)
			}
		} else if rotatable, ok := driver.(credential.Rotatable); ok {
			m.performCleanupWithRetry(ctx, entry, rotatable, cleanupConfig)
		}
		return
	}

	m.discardStaged(ctx, entry, driver, newConfig)
}

// DiscardStagedSource abandons a source's staged rotation before an operator's
// edit or delete lands. The caller holds the source's lock and has not yet
// written: the driver still authenticates with the credential the staged one
// was to replace, which is the only credential that can delete it. The entry
// goes back to idle and re-prepares against whatever config is then stored.
func (m *RotationManager) DiscardStagedSource(ctx context.Context, sourceName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}
	m.resetStaged(ctx, buildRotationKey(ns.UUID, sourceName))
	return nil
}

// DiscardStagedSpec is DiscardStagedSource for a spec entry. The caller holds
// the spec's lock.
func (m *RotationManager) DiscardStagedSpec(ctx context.Context, specName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get namespace from context: %w", err)
	}
	m.resetStaged(ctx, buildSpecKey(ns.UUID, specName))
	return nil
}

// resetStaged discards the staged rotation of the entry under key, if any, and
// returns the entry to idle, due now.
func (m *RotationManager) resetStaged(ctx context.Context, key string) {
	v, ok := m.entries.Load(key)
	if !ok {
		return
	}
	entry := v.(*RotationEntry)

	entry.mu.Lock()
	staged := entry.NewConfig != nil
	entry.mu.Unlock()
	if !staged {
		return
	}

	m.discardEntryStaged(ctx, entry)

	entry.mu.Lock()
	if entry.State == StateFailed {
		atomic.AddInt64(&m.failedCount, -1)
	}
	entry.State = StateIdle
	entry.Attempts = 0
	entry.LastError = ""
	entry.NextAction = time.Now()
	if m.storage != nil {
		if err := m.persistEntryIfCurrent(entry); err != nil {
			m.log.Error("failed to persist entry after discarding its staged rotation",
				logger.String("key", key), logger.Err(err))
		}
	}
	entry.mu.Unlock()
}

// targetConfig returns the stored config of the entry's target: the spec's for
// a spec entry, the source's otherwise.
func (m *RotationManager) targetConfig(ctx context.Context, entry *RotationEntry) (credential.Config, error) {
	if entry.EntryType == EntryTypeSpec {
		spec, err := m.core.credConfigStore.GetSpec(ctx, entry.SpecName)
		if err != nil {
			return credential.Config{}, fmt.Errorf("failed to get spec %s: %w", entry.SpecName, err)
		}
		return spec.Config, nil
	}
	source, err := m.core.credConfigStore.GetSource(ctx, entry.SourceName)
	if err != nil {
		return credential.Config{}, fmt.Errorf("failed to get source %s: %w", entry.SourceName, err)
	}
	return source.Config, nil
}

// sourceConfigHash returns the hash of a source's stored config.
func (m *RotationManager) sourceConfigHash(ctx context.Context, sourceName string) (string, error) {
	if m.core == nil || m.core.credConfigStore == nil {
		return "", fmt.Errorf("credential config store not available")
	}
	source, err := m.core.credConfigStore.GetSource(ctx, sourceName)
	if err != nil {
		return "", err
	}
	return source.Config.Hash(), nil
}

// logUndiscarded reports a staged credential that could not be discarded. It
// is live upstream with nothing tracking it, so the log carries what an
// operator needs to find it: the target, when it was prepared, and its id.
func (m *RotationManager) logUndiscarded(entry *RotationEntry, newConfig map[string]string, reason string) {
	m.log.Error("staged rotation credential could not be discarded; delete it at the provider",
		logger.String("target", entryLabel(entry)),
		logger.String("credential", credentialHint(newConfig)),
		logger.String("reason", reason))
}

// entryLabel names an entry's target for logs.
func entryLabel(entry *RotationEntry) string {
	if entry.EntryType == EntryTypeSpec {
		return "spec:" + entry.SpecName
	}
	return "source:" + entry.SourceName
}

// credentialHint picks the identifier of a credential out of a config or
// cleanup config, for logs. Only identifier fields are read, never secrets —
// which is why secret_id is not on the list: for some sources it is the secret.
func credentialHint(config map[string]string) string {
	for _, k := range []string{"access_key_id", "api_key_id", "old_secret_id", "management_access_key", "access_key", "old_key_id"} {
		if v := config[k]; v != "" {
			return k + "=" + v
		}
	}
	return "unknown (see the provider for credentials created around the prepare time)"
}

// persistFailedCleanup stores a failed cleanup or discard for the daily retry.
func (m *RotationManager) persistFailedCleanup(entry *RotationEntry, kind string, cleanupConfig map[string]string, authHash string) {
	pending := &PendingCleanup{
		SourceName:     entry.SourceName,
		SourceType:     entry.SourceType,
		Namespace:      entry.Namespace,
		CleanupConfig:  cleanupConfig,
		Attempts:       3,
		CreatedAt:      time.Now(),
		LastAttempt:    time.Now(),
		Kind:           kind,
		AuthConfigHash: authHash,
	}
	target := entry.SourceName
	if entry.EntryType == EntryTypeSpec {
		pending.SourceType = EntryTypeSpec
		pending.SpecName = entry.SpecName
		target = "spec:" + entry.SpecName
	}

	if m.storage != nil {
		data, err := json.Marshal(pending)
		if err != nil {
			m.log.Error("failed to marshal pending cleanup",
				logger.String("target", entryLabel(entry)),
				logger.Err(err))
			return
		}
		if err := m.storage.Put(context.Background(), &sdklogical.StorageEntry{
			Key:   cleanupStoragePath(entry.Namespace, target, kind, cleanupConfig),
			Value: data,
		}); err != nil {
			m.log.Error("failed to persist pending cleanup",
				logger.String("target", entryLabel(entry)),
				logger.Err(err))
			return
		}
	}

	m.log.Warn(kind+" persisted for daily retry",
		logger.String("target", entryLabel(entry)),
		logger.String("credential", credentialHint(cleanupConfig)))
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

			// A discard can only be done by a driver still holding the
			// credential the staged one was to replace. Once the source's
			// config has moved on, no driver can, so hand it to the operator.
			if pending.Kind == cleanupKindDiscard && pending.AuthConfigHash != "" {
				hash, err := m.sourceConfigHash(ctx, pending.SourceName)
				switch {
				case errors.Is(err, ErrSourceNotFound):
					// Handled below, with every other kind.
				case err != nil:
					// A read that failed says nothing about the config; try
					// again at the next retry rather than give up for good.
					continue
				case hash != pending.AuthConfigHash:
					m.storage.Delete(context.Background(), path)
					abandoned++
					m.log.Error("staged rotation credential could not be discarded and the source has changed since; delete it at the provider",
						logger.String("source", pending.SourceName),
						logger.String("credential", credentialHint(pending.CleanupConfig)))
					continue
				}
			}

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

			// Records from before SpecName existed carry the spec in the config.
			if pending.SpecName == "" && pending.SourceType == EntryTypeSpec {
				pending.SpecName = pending.CleanupConfig["_spec_name"]
				delete(pending.CleanupConfig, "_spec_name")
			}

			// A spec's credential is cleaned through the spec method. The source
			// method takes a different config, and for a spec cleanup it would
			// act on the source's own credential.
			var cleanup func(context.Context, map[string]string) error
			if pending.SpecName != "" {
				specRotatable, ok := driver.(credential.SpecRotatable)
				if !ok {
					m.storage.Delete(context.Background(), path)
					continue
				}
				cleanup = specRotatable.CleanupSpecRotation
			} else {
				rotatable, ok := driver.(credential.Rotatable)
				if !ok {
					m.storage.Delete(context.Background(), path)
					continue
				}
				cleanup = rotatable.CleanupRotation
			}

			pending.Attempts++
			pending.LastAttempt = time.Now()

			if err := cleanup(ctx, pending.CleanupConfig); err == nil {
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

	m.reconcileRestoredEntries(ctx)

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

// reconcileRestoredEntries checks every restored entry against the config it
// rotates. An entry is only as current as the last write that reached storage,
// and an unregister and a job's write-back used to race, so a restore could
// bring back rotations for sources and specs that are gone or no longer rotate.
//
//   - Target gone: the entry is dropped. A staged credential cannot be discarded
//     without the driver that created it, so it is logged for manual deletion.
//   - Target no longer eligible: an entry with nothing staged is dropped; one with
//     a staged credential is marked for the tick loop to discard and drop.
//
// Only config-store reads happen here; the upstream calls a discard needs run
// later, from the tick loop, so unseal does no network I/O.
func (m *RotationManager) reconcileRestoredEntries(ctx context.Context) {
	if m.core == nil || m.core.credConfigStore == nil {
		return
	}

	m.entries.Range(func(key, value any) bool {
		entry := value.(*RotationEntry)

		ns, err := m.getNamespaceFromEntry(ctx, entry)
		if err != nil {
			// A transient lookup failure must not drop a live rotation.
			return true
		}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)

		var eligible bool
		if entry.EntryType == EntryTypeSpec {
			spec, err := m.core.credConfigStore.GetSpec(nsCtx, entry.SpecName)
			if errors.Is(err, ErrSpecNotFound) {
				m.dropRestoredEntry(key.(string), entry, "spec no longer exists")
				return true
			}
			if err != nil {
				return true
			}
			eligible = spec.RotationPeriod > 0
		} else {
			source, err := m.core.credConfigStore.GetSource(nsCtx, entry.SourceName)
			if errors.Is(err, ErrSourceNotFound) {
				m.dropRestoredEntry(key.(string), entry, "source no longer exists")
				return true
			}
			if err != nil {
				return true
			}
			eligible = sourceRotationEligible(source)
		}
		if eligible {
			return true
		}

		entry.mu.Lock()
		staged := entry.NewConfig != nil
		if staged {
			entry.discardPending = true
		}
		entry.mu.Unlock()
		if !staged {
			m.dropRestoredEntry(key.(string), entry, "")
		}
		return true
	})
}

// dropRestoredEntry drops a restored entry at unseal, logging any staged
// credential it held since nothing can discard it any more.
func (m *RotationManager) dropRestoredEntry(key string, entry *RotationEntry, reason string) {
	if newConfig := entry.GetNewConfig(); newConfig != nil {
		m.logUndiscarded(entry, newConfig, reason)
	}
	m.entries.Delete(key)
	entry.markRemoved()
	if m.storage != nil {
		m.deleteEntry(entry)
	}
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
