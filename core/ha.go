package core

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/logger"
)

// leaderCheckInterval is how often standby nodes refresh the leader cache.
var leaderCheckInterval = 2500 * time.Millisecond

// StandbyReadsEnabled returns true if standby reads are enabled and supported
// by the physical backend.
func (c *Core) StandbyReadsEnabled() bool {
	if _, ok := c.underlyingPhysical.(physical.CacheInvalidationBackend); !ok {
		return false
	}

	conf := c.rawConfig.Load()
	if conf == nil {
		return false
	}
	return !conf.(*config.Config).DisableStandbyReads
}

// Leader returns information about the current active leader in relation to this node.
// It acquires a read lock on the state lock. Do not call this method if a read lock
// on this Core's state lock is already held, as this will cause a deadlock.
func (c *Core) Leader() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}

	if c.Sealed() {
		return false, "", "", consts.ErrSealed
	}
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	return c.LeaderLocked()
}

// LeaderLocked returns leader information. The caller must hold the state lock.
func (c *Core) LeaderLocked() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}

	// If this node is active, use cached leader params if available.
	if !c.standby.Load() {
		if p := c.leaderParams.Load(); p != nil {
			if params, ok := p.(*clusterLeaderParams); ok && params != nil {
				return true, params.RedirectAddr, params.ClusterAddr, nil
			}
		}
		return true, c.redirectAddr, c.clusterAddrValue(), nil
	}

	// We are standby — query the lock to discover the leader's UUID,
	// then read the advertisement from barrier storage.
	lock, err := c.ha.LockWith(CoreLockPath, "")
	if err != nil {
		return false, "", "", err
	}

	held, leaderUUID, err := lock.Value()
	if err != nil {
		return false, "", "", err
	}
	if !held {
		return false, "", "", nil
	}

	// Read the leader advertisement from barrier storage.
	adv, err := c.readLeaderAdvertisement(context.Background(), leaderUUID)
	if err != nil {
		c.logger.Warn("failed to read leader advertisement from barrier",
			logger.Err(err), logger.String("leader_uuid", leaderUUID))
		return false, "", "", nil
	}
	if adv == nil {
		// Advertisement not yet written (brief race on startup).
		// Fall back to empty — caller will retry.
		return false, "", "", nil
	}

	// Load the cluster TLS identity from the leader advertisement so
	// this standby can authenticate via mTLS when forwarding requests.
	if adv.ClusterCert != nil && adv.ClusterKeyParams != nil {
		if err := c.loadLocalClusterTLS(*adv); err != nil {
			c.logger.Warn("failed to load cluster TLS from leader advertisement",
				logger.Err(err))
		}
	}

	return false, adv.RedirectAddr, adv.ClusterAddr, nil
}

// Standby returns whether this node is in standby mode.
func (c *Core) Standby() bool {
	return c.standby.Load()
}

// ActiveTime returns the time at which this node became active.
func (c *Core) ActiveTime() time.Time {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	return c.activeTime
}

// HAEnabled returns whether HA mode is configured and supported by the backend.
func (c *Core) HAEnabled() bool {
	return c.ha != nil && c.ha.HAEnabled()
}

// StepDown causes the active node to step down from leadership.
// A standby node will then acquire the lock and become active.
func (c *Core) StepDown(r *http.Request) error {
	if c.ha == nil {
		return ErrHANotEnabled
	}

	if c.Sealed() {
		return consts.ErrSealed
	}

	if c.standby.Load() {
		// Already standby, nothing to do
		return nil
	}

	c.logger.Info("step-down requested")
	defer metrics.MeasureSince([]string{"core", "step_down"}, time.Now())

	select {
	case c.manualStepDownCh <- struct{}{}:
	default:
		c.logger.Warn("step-down already in progress")
	}

	return nil
}

func (c *Core) clusterAddrValue() string {
	if v := c.clusterAddr.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// periodicLeaderRefresh periodically calls Leader() to keep the leader
// address cached and fresh. This avoids per-request leader lookups on
// standby nodes when forwarding. Uses an atomic flag to skip if the
// previous check is still running. On the active node, Leader() returns
// cached params immediately so this is a no-op — skip to avoid waste.
func (c *Core) periodicLeaderRefresh(doneCh, stopCh chan struct{}) {
	defer close(doneCh)

	ticker := time.NewTicker(leaderCheckInterval)
	defer ticker.Stop()

	var running int32

	for {
		select {
		case <-ticker.C:
			// Active node returns cached params from Leader(); skip the refresh.
			if !c.standby.Load() {
				continue
			}
			// Skip if a previous check is still running
			if !atomic.CompareAndSwapInt32(&running, 0, 1) {
				continue
			}
			go func() {
				defer atomic.StoreInt32(&running, 0)
				_, _, _, _ = c.Leader()
			}()
		case <-stopCh:
			return
		}
	}
}

// periodicCheckKeyUpgrades checks for key upgrades from the active node
// and applies them on standby. This ensures standby nodes can decrypt
// data after the active node rotates the barrier key.
func (c *Core) periodicCheckKeyUpgrades(doneCh, stopCh chan struct{}) {
	defer close(doneCh)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.checkKeyUpgrades(context.Background()); err != nil {
				c.logger.Debug("key upgrade check failed", logger.Err(err))
			}
		case <-stopCh:
			return
		}
	}
}

// checkKeyUpgrades checks for any key upgrades that the active node has performed.
// It loops until no more upgrades remain, applying all pending upgrades in one pass.
func (c *Core) checkKeyUpgrades(ctx context.Context) error {
	if c.barrier == nil {
		return nil
	}

	for {
		didUpgrade, newTerm, err := c.barrier.CheckUpgrade(ctx)
		if err != nil {
			return err
		}
		if !didUpgrade {
			return nil
		}
		c.logger.Info("barrier key upgraded by active node", logger.Int("new_term", int(newTerm)))
	}
}
