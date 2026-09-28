// Copyright (c) Warden Authors
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
)

// prepareJob implements fairshare.Job for the PREPARE stage of credential rotation.
//
// On success it either:
//   - Fast path (activateAfter == 0): keeps State=idle, sets NextAction = now + period
//   - Slow path (activateAfter > 0): transitions to State=staged, sets NextAction = now + activateAfter
//
// On failure it increments Attempts and applies exponential backoff, or moves to StateFailed.
type prepareJob struct {
	manager *RotationManager
	entry   *RotationEntry
	key     string
}

// Execute implements fairshare.Job.Execute
func (j *prepareJob) Execute() error {
	m := j.manager
	entry := j.entry

	// The target's lock is held for the whole job, the bookkeeping below
	// included, so an operator's edit or delete of the same source or spec
	// either lands before this job reads the config or waits until it is done.
	unlock, err := m.lockEntryTarget(entry)
	if err != nil {
		return err
	}
	defer unlock()

	if entry.isRemoved() {
		atomic.StoreInt32(&entry.inflight, 0)
		return nil
	}

	var staged *stagedRotation

	// Business logic — no entry lock held (these do I/O). They return the staged
	// data rather than writing it onto the entry, so every write below happens
	// under the lock the tick loop and persistEntry read against.
	switch entry.EntryType {
	case EntryTypeSpec:
		staged, err = m.prepareSpec(entry)
	default:
		staged, err = m.prepareSource(entry)
	}

	if errors.Is(err, errEntryRemoved) {
		atomic.StoreInt32(&entry.inflight, 0)
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now()

	entry.mu.Lock()
	if staged == nil {
		// Fast path: activation already done inline by prepareSource/prepareSpec
		entry.State = StateIdle
		entry.LastRotation = now
		entry.NextAction = now.Add(jitterDuration(entry.RotationPeriod, 0.05))
		entry.Attempts = 0
		entry.LastError = ""
		entry.clearStagedFields()
	} else {
		// Slow path: staged for deferred activation
		entry.applyStaged(staged)
		entry.State = StateStaged
		entry.NextAction = now.Add(jitterDuration(staged.ActivationDelay, 0.10))
		entry.Attempts = 0
		entry.LastError = ""
	}

	nextAction := entry.NextAction
	state := entry.State

	if m.storage != nil {
		if err := m.persistEntryIfCurrent(entry); err != nil {
			m.log.Error("failed to persist entry after prepare",
				logger.String("key", j.key),
				logger.Err(err))
		}
	}
	entry.mu.Unlock()

	if state == StateIdle {
		// Fast path: full rotation completed inline
		if entry.EntryType == EntryTypeSpec {
			m.log.Info("rotation completed",
				logger.String("spec", entry.SpecName),
				logger.Time("next_rotation", nextAction))
		} else {
			m.log.Info("rotation completed",
				logger.String("source", entry.SourceName),
				logger.Time("next_rotation", nextAction))
		}
	} else {
		// Slow path: credentials prepared, waiting for activation
		if entry.EntryType == EntryTypeSpec {
			m.log.Info("credentials prepared, waiting for activation",
				logger.String("spec", entry.SpecName),
				logger.Time("activate_at", nextAction))
		} else {
			m.log.Info("credentials prepared, waiting for activation",
				logger.String("source", entry.SourceName),
				logger.Time("activate_at", nextAction))
		}
	}

	atomic.StoreInt32(&entry.inflight, 0)
	m.signalDone()
	return nil
}

// OnFailure implements fairshare.Job.OnFailure
func (j *prepareJob) OnFailure(err error) {
	m := j.manager
	entry := j.entry

	// OnFailure runs after Execute released the target lock, so an unregister
	// may have landed in between. A removed entry is no longer counted; moving
	// it to failed would count it again and leave the counters skewed.
	if entry.isRemoved() {
		atomic.StoreInt32(&entry.inflight, 0)
		return
	}

	entry.mu.Lock()
	entry.Attempts++
	entry.LastError = truncateError(err, 256)

	if entry.EntryType == EntryTypeSpec {
		m.log.Error("spec rotation prepare failed",
			logger.String("spec", entry.SpecName),
			logger.Int("attempt", entry.Attempts),
			logger.Err(err))
	} else {
		m.log.Error("source rotation prepare failed",
			logger.String("source", entry.SourceName),
			logger.Int("attempt", entry.Attempts),
			logger.Err(err))
	}

	if entry.Attempts >= MaxRotateAttempts {
		// Move to failed state
		entry.State = StateFailed
		entry.NextAction = time.Now().Add(FailedMinAge)
		atomic.AddInt64(&m.failedCount, 1)

		if entry.EntryType == EntryTypeSpec {
			m.log.Error("spec rotation exhausted max attempts, moved to failed",
				logger.String("spec", entry.SpecName),
				logger.Int("attempts", entry.Attempts))
		} else {
			m.log.Error("source rotation exhausted max attempts, moved to failed",
				logger.String("source", entry.SourceName),
				logger.Int("attempts", entry.Attempts))
		}
	} else {
		// Exponential backoff
		entry.NextAction = time.Now().Add(m.calculateBackoff(entry.Attempts))
	}

	if m.storage != nil {
		if err := m.persistEntryIfCurrent(entry); err != nil {
			m.log.Error("failed to persist entry after prepare failure",
				logger.String("key", j.key),
				logger.Err(err))
		}
	}
	entry.mu.Unlock()

	atomic.StoreInt32(&entry.inflight, 0)
}

// activateJob implements fairshare.Job for the ACTIVATE stage of a staged rotation.
//
// On success it clears staged fields, transitions to State=idle, and sets NextAction = now + period.
// On failure it increments Attempts with exponential backoff, or moves to StateFailed.
type activateJob struct {
	manager *RotationManager
	entry   *RotationEntry
	key     string
}

// Execute implements fairshare.Job.Execute
func (j *activateJob) Execute() error {
	m := j.manager
	entry := j.entry

	// Held for the whole job; see prepareJob.Execute.
	unlock, err := m.lockEntryTarget(entry)
	if err != nil {
		return err
	}
	defer unlock()

	if entry.isRemoved() {
		atomic.StoreInt32(&entry.inflight, 0)
		return nil
	}

	// Business logic — no entry lock held (these do I/O)
	switch entry.EntryType {
	case EntryTypeSpec:
		err = m.activateSpec(entry)
	default:
		err = m.activateSource(entry)
	}

	switch {
	case errors.Is(err, errNothingStaged):
		// An operator's edit discarded the staged rotation after this job was
		// queued, and reset the entry itself.
		atomic.StoreInt32(&entry.inflight, 0)
		return nil

	case errors.Is(err, errStagedDiscarded):
		// The config changed since the prepare, so the staged credential was
		// discarded rather than written. Re-prepare against the current config.
		entry.mu.Lock()
		entry.clearStagedFields()
		entry.State = StateIdle
		entry.Attempts = 0
		entry.LastError = ""
		entry.NextAction = time.Now()
		if m.storage != nil {
			if err := m.persistEntryIfCurrent(entry); err != nil {
				m.log.Error("failed to persist entry after discarding a stale activation",
					logger.String("key", j.key),
					logger.Err(err))
			}
		}
		entry.mu.Unlock()
		atomic.StoreInt32(&entry.inflight, 0)
		return nil

	case err != nil:
		return err
	}

	now := time.Now()

	entry.mu.Lock()
	entry.clearStagedFields()
	entry.State = StateIdle
	entry.LastRotation = now
	entry.NextAction = now.Add(jitterDuration(entry.RotationPeriod, 0.05))
	entry.Attempts = 0
	entry.LastError = ""

	nextAction := entry.NextAction

	if m.storage != nil {
		if err := m.persistEntryIfCurrent(entry); err != nil {
			m.log.Error("failed to persist entry after activation",
				logger.String("key", j.key),
				logger.Err(err))
		}
	}
	entry.mu.Unlock()

	if entry.EntryType == EntryTypeSpec {
		m.log.Info("rotation completed",
			logger.String("spec", entry.SpecName),
			logger.Time("next_rotation", nextAction))
	} else {
		m.log.Info("rotation completed",
			logger.String("source", entry.SourceName),
			logger.Time("next_rotation", nextAction))
	}

	atomic.StoreInt32(&entry.inflight, 0)
	m.signalDone()
	return nil
}

// OnFailure implements fairshare.Job.OnFailure
func (j *activateJob) OnFailure(err error) {
	m := j.manager
	entry := j.entry

	// See prepareJob.OnFailure.
	if entry.isRemoved() {
		atomic.StoreInt32(&entry.inflight, 0)
		return
	}

	entry.mu.Lock()
	entry.Attempts++
	entry.LastError = truncateError(err, 256)

	if entry.EntryType == EntryTypeSpec {
		m.log.Error("spec rotation activation failed",
			logger.String("spec", entry.SpecName),
			logger.Int("attempt", entry.Attempts),
			logger.Err(err))
	} else {
		m.log.Error("source rotation activation failed",
			logger.String("source", entry.SourceName),
			logger.Int("attempt", entry.Attempts),
			logger.Err(err))
	}

	if entry.Attempts >= MaxRotateAttempts {
		// Move to failed state — staged data is preserved for manual recovery
		entry.State = StateFailed
		entry.NextAction = time.Now().Add(FailedMinAge)
		atomic.AddInt64(&m.failedCount, 1)

		if entry.EntryType == EntryTypeSpec {
			m.log.Error("spec activation exhausted max attempts, moved to failed",
				logger.String("spec", entry.SpecName),
				logger.Int("attempts", entry.Attempts))
		} else {
			m.log.Error("source activation exhausted max attempts, moved to failed",
				logger.String("source", entry.SourceName),
				logger.Int("attempts", entry.Attempts))
		}
	} else {
		// Exponential backoff — keep State=staged so next tick retries activation
		entry.NextAction = time.Now().Add(m.calculateBackoff(entry.Attempts))
	}

	if m.storage != nil {
		if err := m.persistEntryIfCurrent(entry); err != nil {
			m.log.Error("failed to persist entry after activation failure",
				logger.String("key", j.key),
				logger.Err(err))
		}
	}
	entry.mu.Unlock()

	atomic.StoreInt32(&entry.inflight, 0)
}

// discardJob drops an entry found at restore whose source or spec no longer
// rotates, discarding the credential it had staged first. It runs from the tick
// loop rather than from Restore so the upstream call stays off the unseal path.
type discardJob struct {
	manager *RotationManager
	entry   *RotationEntry
	key     string
}

// Execute implements fairshare.Job.Execute
func (j *discardJob) Execute() error {
	m := j.manager
	entry := j.entry

	unlock, err := m.lockEntryTarget(entry)
	if err != nil {
		return err
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(m.quitCtx, StageTimeout)
	defer cancel()
	if ns, err := m.getNamespaceFromEntry(ctx, entry); err == nil {
		m.discardEntryStaged(namespace.ContextWithNamespace(ctx, ns), entry)
	} else {
		m.logUndiscarded(entry, entry.GetNewConfig(), err.Error())
	}

	m.dropEntry(j.key, entry)
	atomic.StoreInt32(&entry.inflight, 0)
	return nil
}

// OnFailure implements fairshare.Job.OnFailure. The entry is dropped either
// way: it no longer describes a rotation, and retrying on every tick a discard
// that cannot get its lock would only repeat the failure.
func (j *discardJob) OnFailure(err error) {
	m := j.manager
	m.logUndiscarded(j.entry, j.entry.GetNewConfig(), err.Error())
	m.dropEntry(j.key, j.entry)
	atomic.StoreInt32(&j.entry.inflight, 0)
}
