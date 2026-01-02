package core

import (
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/config"
)

// StandbyReadsEnabled returns true if standby read are enabled and supported
// by the physical backend
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

// Leader is used to get information about the current active leader in relation to the current node (core).
// It utilizes a state lock on the Core by attempting to acquire a read lock. Care should be taken not to
// call this method if a read lock on this Core's state lock is currently held, as this can cause deadlock.
// e.g. if called from within request handling.
func (c *Core) Leader() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	// Check if HA enabled. We don't need the lock for this check as it's set
	// on startup and never modified
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}

	// Check if sealed
	if c.Sealed() {
		return false, "", "", consts.ErrSealed
	}
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	return c.LeaderLocked()
}

func (c *Core) LeaderLocked() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	// Check if HA enabled. We don't need the lock for this check as it's set
	// on startup and never modified
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}
	return false, "", "", ErrHANotEnabled
}
