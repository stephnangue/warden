package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/logger"
)

// manualStepDownSleepPeriod is how long to sleep after a user-initiated
// step down, to prevent the same node from instantly re-acquiring the lock.
// It's a var (not const) so that tests can override it.
var manualStepDownSleepPeriod = 10 * time.Second

// lockRetryInterval is how long to wait before retrying lock acquisition
// after a failure. It's a var (not const) so that tests can override it.
var lockRetryInterval = 10 * time.Second

// DefaultMaxRequestDuration is the maximum time to wait for in-flight
// requests to complete when stepping down from active.
var DefaultMaxRequestDuration = 90 * time.Second

// runStandby is the main HA loop wrapper. It delegates to runStandbyOnce
// for each iteration and supports restarting via standbyRestartCh.
func (c *Core) runStandby(doneCh chan struct{}, manualStepDownCh chan struct{}, stopCh chan struct{}) {
	defer close(doneCh)
	c.logger.Info("entering standby mode")

	for {
		c.drainPendingRestarts()

		shouldRestart := c.runStandbyOnce(manualStepDownCh, stopCh)
		if !shouldRestart {
			return
		}
		c.logger.Info("standby loop restarting")
	}
}

// runStandbyOnce runs a single iteration of the standby loop.
// Returns true if the loop should restart, false if it should exit.
func (c *Core) runStandbyOnce(manualStepDownCh chan struct{}, stopCh chan struct{}) bool {
	var manualStepDown bool

	for {
		// Check for shutdown, restart, or post-step-down sleep.
		select {
		case <-stopCh:
			c.logger.Debug("stop channel triggered in runStandby")
			return false
		case <-c.standbyRestartCh:
			return true
		default:
			if manualStepDown {
				c.logger.Info("sleeping after manual step-down before re-acquiring lock",
					logger.Duration("duration", manualStepDownSleepPeriod))
				time.Sleep(manualStepDownSleepPeriod)
				manualStepDown = false
			}
		}

		// Guard: a sealed node must not contend for the HA lock.
		// This handles the case where Seal() was called while the standby
		// loop is running (Seal does not close stopCh).
		// Uses barrier.Sealed() instead of c.Sealed() to avoid a startup
		// race: during unsealInternal, the barrier is unsealed before the
		// standby loop starts, but the atomic c.sealed flag is cleared after.
		if sealed, _ := c.barrier.Sealed(); sealed {
			c.logger.Warn("standby loop detected sealed barrier, exiting")
			metrics.IncrCounter([]string{"ha", "standby", "sealed_exit"}, 1)
			return false
		}

		// Generate a UUID for the lock value (used for leader advertisement).
		leaderUUID, err := generateLeaderUUID()
		if err != nil {
			c.logger.Error("failed to generate leader UUID", logger.Err(err))
			select {
			case <-time.After(lockRetryInterval):
				continue
			case <-stopCh:
				return false
			}
		}

		lock, err := c.ha.LockWith(CoreLockPath, leaderUUID)
		if err != nil {
			c.logger.Error("failed to create HA lock", logger.Err(err))
			select {
			case <-time.After(lockRetryInterval):
				continue
			case <-stopCh:
				return false
			}
		}

		// Attempt to acquire the lock. This blocks until the lock is
		// acquired, stopCh is closed, or the acquisition timeout fires.
		lockStopCh := stopCh
		var lockTimer *time.Timer
		if timeout := c.clusterConfig.LockAcquisitionTimeout; timeout > 0 {
			lockStopCh = make(chan struct{})
			lockTimer = time.NewTimer(timeout)
			go func() {
				select {
				case <-stopCh:
					close(lockStopCh)
				case <-lockTimer.C:
					close(lockStopCh)
				}
			}()
		}

		lockAcquireStart := time.Now()
		leaderLostCh, err := lock.Lock(lockStopCh)

		if lockTimer != nil {
			lockTimer.Stop()
		}

		if err != nil {
			c.logger.Error("failed to acquire HA lock", logger.Err(err))
			metrics.IncrCounter([]string{"ha", "lock", "acquire", "error"}, 1)
			select {
			case <-time.After(lockRetryInterval):
				continue
			case <-stopCh:
				return false
			}
		}

		// If Lock returned nil, either stopCh was closed or the
		// acquisition timeout fired. Check stopCh to distinguish.
		if leaderLostCh == nil {
			select {
			case <-stopCh:
				return false
			default:
				// Acquisition timeout — retry after interval.
				c.logger.Warn("HA lock acquisition timed out, retrying",
					logger.Duration("timeout", c.clusterConfig.LockAcquisitionTimeout))
				metrics.IncrCounter([]string{"ha", "lock", "acquire", "timeout"}, 1)
				select {
				case <-time.After(lockRetryInterval):
					continue
				case <-stopCh:
					return false
				}
			}
		}

		// We acquired the lock — become active
		metrics.MeasureSince([]string{"ha", "lock", "acquire", "duration"}, lockAcquireStart)
		c.logger.Info("acquired HA lock, transitioning to active")
		c.setHeldHALock(lock)

		// If the HA backend supports fencing, register the lock so future
		// writes include a fencing token. This prevents split-brain writes.
		if fha, ok := c.ha.(physical.FencingHABackend); ok {
			if err := fha.RegisterActiveNodeLock(lock); err != nil {
				c.logger.Error("failed to register active node lock for fencing", logger.Err(err))
				c.setHeldHALock(nil)
				if err := lock.Unlock(); err != nil {
					c.logger.Error("failed to release lock after fencing registration failure", logger.Err(err))
				}
				select {
				case <-time.After(lockRetryInterval):
					continue
				case <-stopCh:
					return false
				}
			}
		}

		stepDown, err := c.becomeActive(leaderUUID, leaderLostCh, manualStepDownCh, stopCh)

		// No longer active — clean up. Clear heldHALock before Unlock so
		// Shutdown (which may be racing on the 30s timeout) won't double-unlock.
		c.setHeldHALock(nil)

		if err != nil {
			c.logger.Error("error during active operation", logger.Err(err))
		}

		// Release the lock
		if err := lock.Unlock(); err != nil {
			c.logger.Error("failed to release HA lock", logger.Err(err))
		}

		c.logger.Info("released HA lock, returning to standby")

		// Track whether this was a manual step-down so we sleep
		// before re-acquiring the lock on the next iteration.
		manualStepDown = stepDown
	}
}

// becomeActive transitions this node from standby to active. It runs postUnseal
// to start all managers, then waits for a signal to step down (lock loss, manual
// step-down, or shutdown). Returns true if the exit was due to manual step-down.
func (c *Core) becomeActive(leaderUUID string, leaderLostCh <-chan struct{}, manualStepDownCh chan struct{}, stopCh chan struct{}) (bool, error) {
	activeTime := time.Now()

	// Use non-blocking lock acquisition so we can respond to stop signals
	// while waiting for the state lock (which might be held by a seal operation).
	if grabLockOrStop(c.stateLock.Lock, c.stateLock.Unlock, stopCh) {
		return false, nil
	}

	// Guard: if we acquired both the HA lock and stateLock but the node
	// is sealed, release everything and exit. This prevents a sealed node
	// from holding the HA lock and blocking unsealed nodes.
	// Matches OpenBao's pattern in vault/ha.go.
	if c.Sealed() {
		c.logger.Warn("acquired HA lock but node is sealed, releasing")
		metrics.IncrCounter([]string{"ha", "standby", "sealed_after_lock"}, 1)
		metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
		c.stateLock.Unlock()
		return false, fmt.Errorf("node is sealed")
	}

	activeCtx, activeCtxCancel := context.WithCancel(namespace.RootContext(context.TODO()))

	// Generate a new cluster TLS identity for this leadership term.
	// setupCluster atomically overwrites any previous identity, avoiding
	// a nil window that would break concurrent standby forwarding.
	if err := c.setupCluster(activeCtx); err != nil {
		c.logger.Error("cluster TLS setup failed", logger.Err(err))
		c.stateLock.Unlock()
		activeCtxCancel()
		return false, fmt.Errorf("cluster TLS setup failed: %w", err)
	}

	postUnsealStart := time.Now()
	if err := c.postUnseal(activeCtx, activeCtxCancel, standardUnsealStrategy{}); err != nil {
		c.stateLock.Unlock()
		activeCtxCancel()
		c.logger.Error("post-unseal failed during active transition", logger.Err(err))
		metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
		return false, err
	}

	// Write leader advertisement AFTER postUnseal succeeds so standby
	// nodes never discover and forward to a node that isn't fully active.
	// If the advertisement fails, step down — an active node that can't
	// advertise is invisible to standbys and unusable.
	if err := c.advertiseLeader(activeCtx, leaderUUID); err != nil {
		c.logger.Error("failed to write leader advertisement, stepping down", logger.Err(err))
		c.stateLock.Unlock()
		activeCtxCancel()
		return false, fmt.Errorf("leader advertisement failed: %w", err)
	}
	c.leaderParams.Store(&clusterLeaderParams{
		LeaderUUID:   leaderUUID,
		RedirectAddr: c.redirectAddr,
		ClusterAddr:  c.clusterAddrValue(),
	})

	metrics.MeasureSince([]string{"ha", "post_unseal", "duration"}, postUnsealStart)
	metrics.IncrCounter([]string{"ha", "transition", "standby_to_active"}, 1)

	c.standby.Store(false)
	c.activeTime = time.Now().UTC()
	metrics.SetGauge([]string{"core", "active"}, 1)

	c.stateLock.Unlock()

	c.logger.Info("node is now active", logger.String("redirect_addr", c.redirectAddr))

	// Start key upgrade checker for when this node is active.
	keyUpgradeDone := make(chan struct{})
	keyUpgradeStop := make(chan struct{})
	go c.periodicCheckKeyUpgrades(keyUpgradeDone, keyUpgradeStop)

	// Start periodic leader refresh so standby nodes keep leader cache fresh.
	leaderRefreshDone := make(chan struct{})
	leaderRefreshStop := make(chan struct{})
	go c.periodicLeaderRefresh(leaderRefreshDone, leaderRefreshStop)

	// Start leader prefix cleanup goroutine.
	leaderCleanupDone := make(chan struct{})
	leaderCleanupStop := make(chan struct{})
	go c.cleanLeaderPrefix(activeCtx, leaderUUID, leaderCleanupDone, leaderCleanupStop)

	// Wait for step-down signal
	var manualStepDown bool
	select {
	case <-leaderLostCh:
		c.logger.Warn("leadership lost (lock released by another process)")
		metrics.MeasureSince([]string{"core", "leadership_lost"}, activeTime)
		metrics.IncrCounter([]string{"ha", "step_down", "lock_lost"}, 1)
	case <-manualStepDownCh:
		manualStepDown = true
		c.logger.Info("manual step-down requested")
		metrics.IncrCounter([]string{"ha", "step_down", "manual"}, 1)
	case <-stopCh:
		c.logger.Info("shutdown signal received while active")
		metrics.IncrCounter([]string{"ha", "step_down", "shutdown"}, 1)
	}

	// Enforce a timeout on active context cancellation to allow in-flight
	// requests to complete gracefully before forcibly cancelling.
	go func() {
		select {
		case <-activeCtx.Done():
		case <-time.After(DefaultMaxRequestDuration):
			c.logger.Warn("active context cancellation timeout reached, forcing cancel",
				logger.Duration("timeout", DefaultMaxRequestDuration))
			activeCtxCancel()
		}
	}()

	// Stop background goroutines in parallel with a timeout.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); close(keyUpgradeStop); <-keyUpgradeDone }()
		go func() { defer wg.Done(); close(leaderRefreshStop); <-leaderRefreshDone }()
		go func() { defer wg.Done(); close(leaderCleanupStop); <-leaderCleanupDone }()
		wg.Wait()
	}()
	select {
	case <-shutdownDone:
	case <-time.After(c.clusterConfig.GoroutineShutdownTimeout):
		c.logger.Warn("timed out waiting for background goroutines during step-down",
			logger.Duration("timeout", c.clusterConfig.GoroutineShutdownTimeout))
	}

	// Transition back to standby. Use a combined stop channel that fires
	// on either shutdown or a timeout, so we don't block indefinitely if
	// the state lock is held by a long-running seal operation.
	stepDownStop := make(chan struct{})
	stepDownTimer := time.NewTimer(c.clusterConfig.StepDownStateLockTimeout)
	go func() {
		select {
		case <-stopCh:
			close(stepDownStop)
		case <-stepDownTimer.C:
			c.logger.Warn("timed out waiting for state lock during step-down",
				logger.Duration("timeout", c.clusterConfig.StepDownStateLockTimeout))
			close(stepDownStop)
		}
	}()
	if grabLockOrStop(c.stateLock.Lock, c.stateLock.Unlock, stepDownStop) {
		stepDownTimer.Stop()
		// Stopped while acquiring lock for step-down teardown.
		// Still run preSeal to properly shut down subsystems (expiration
		// manager, rotation manager, mounts, etc.) rather than leaving
		// them running without a valid active context.
		c.standby.Store(true)
		metrics.SetGauge([]string{"core", "active"}, 0)
		activeCtxCancel()
		// Clear leader advertisement best-effort
		if err := c.clearLeader(leaderUUID); err != nil {
			c.logger.Warn("failed to clear leader advertisement", logger.Err(err))
		}
		c.leaderParams.Store((*clusterLeaderParams)(nil))
		if err := c.preSeal(); err != nil {
			c.logger.Error("error during pre-seal on forced step-down", logger.Err(err))
		}
		return manualStepDown, nil
	}
	stepDownTimer.Stop()
	defer c.stateLock.Unlock()

	c.standby.Store(true)
	metrics.SetGauge([]string{"core", "active"}, 0)
	activeCtxCancel()

	// Clear leader advertisement
	if err := c.clearLeader(leaderUUID); err != nil {
		c.logger.Warn("failed to clear leader advertisement", logger.Err(err))
	}
	c.leaderParams.Store((*clusterLeaderParams)(nil))

	preSealStart := time.Now()
	if err := c.preSeal(); err != nil {
		c.logger.Error("error during pre-seal on step-down", logger.Err(err))
	}
	metrics.MeasureSince([]string{"ha", "pre_seal", "duration"}, preSealStart)

	c.logger.Info("node has stepped down to standby")
	return manualStepDown, nil
}

// setHeldHALock updates the held HA lock reference under a mutex to prevent
// races with Shutdown's lock release on the 30s timeout path.
func (c *Core) setHeldHALock(lock physical.Lock) {
	c.heldHALockMu.Lock()
	defer c.heldHALockMu.Unlock()
	c.heldHALock = lock
}

// unlockHeldHALock releases the held HA lock if one is set, and clears the
// reference. Returns true if a lock was released.
func (c *Core) unlockHeldHALock() bool {
	c.heldHALockMu.Lock()
	defer c.heldHALockMu.Unlock()
	if c.heldHALock == nil {
		return false
	}
	if err := c.heldHALock.Unlock(); err != nil {
		c.logger.Error("error releasing HA lock", logger.Err(err))
	}
	c.heldHALock = nil
	return true
}

// restart sends a restart signal to the standby loop.
func (c *Core) restart() {
	if c.standbyRestartCh == nil {
		return
	}
	select {
	case c.standbyRestartCh <- struct{}{}:
	default:
	}
}

// drainPendingRestarts drains any buffered restart signals so that
// a restart requested during cleanup does not cause an immediate
// second restart.
func (c *Core) drainPendingRestarts() {
	if c.standbyRestartCh == nil {
		return
	}
	for {
		select {
		case <-c.standbyRestartCh:
		default:
			return
		}
	}
}
