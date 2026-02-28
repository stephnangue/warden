package core

import (
	"context"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

const (
	// leaderPrefix is the barrier storage prefix for leader advertisements.
	leaderPrefix = "core/leader/"

	// leaderCleanupInterval is how often the background cleaner removes
	// stale leader advertisements from barrier storage.
	leaderCleanupInterval = 24 * time.Hour
)

// activeAdvertisement is stored in the barrier under core/leader/{uuid}
// by the active node to advertise its identity to standby nodes.
type activeAdvertisement struct {
	RedirectAddr string `json:"redirect_addr"`
	ClusterAddr  string `json:"cluster_addr,omitempty"`
}

// clusterLeaderParams caches leader information to avoid repeated
// barrier reads on every Leader() call.
type clusterLeaderParams struct {
	LeaderUUID   string
	RedirectAddr string
	ClusterAddr  string
}

// advertiseLeader writes a leader advertisement to barrier storage
// at core/leader/{uuid}.
func (c *Core) advertiseLeader(ctx context.Context, leaderUUID string) error {
	adv := &activeAdvertisement{
		RedirectAddr: c.redirectAddr,
		ClusterAddr:  c.clusterAddrValue(),
	}

	encoded, err := jsonutil.EncodeJSON(adv)
	if err != nil {
		return err
	}

	entry := &logical.StorageEntry{
		Key:   leaderPrefix + leaderUUID,
		Value: encoded,
	}

	if err := c.barrier.Put(ctx, entry); err != nil {
		return err
	}

	c.logger.Info("leader advertisement written",
		logger.String("uuid", leaderUUID),
		logger.String("redirect_addr", c.redirectAddr))

	return nil
}

// clearLeader removes the leader advertisement from barrier storage.
func (c *Core) clearLeader(leaderUUID string) error {
	return c.barrier.Delete(context.Background(), leaderPrefix+leaderUUID)
}

// cleanLeaderPrefix runs as a background goroutine while the node is active.
// It removes stale leader advertisements from barrier storage, keeping only
// the entry matching activeUUID.
func (c *Core) cleanLeaderPrefix(ctx context.Context, activeUUID string, doneCh, stopCh chan struct{}) {
	defer close(doneCh)

	cleanup := func() {
		keys, err := c.barrier.List(ctx, leaderPrefix)
		if err != nil {
			c.logger.Warn("failed to list leader entries for cleanup", logger.Err(err))
			return
		}
		for _, key := range keys {
			if key == activeUUID {
				continue
			}
			if err := c.barrier.Delete(ctx, leaderPrefix+key); err != nil {
				c.logger.Warn("failed to delete stale leader entry",
					logger.String("key", key), logger.Err(err))
			} else {
				c.logger.Debug("cleaned stale leader entry", logger.String("key", key))
			}
		}
	}

	// Run once immediately on startup
	cleanup()

	ticker := time.NewTicker(leaderCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanup()
		case <-stopCh:
			return
		}
	}
}

// readLeaderAdvertisement reads and decodes the leader advertisement
// for the given UUID from barrier storage.
func (c *Core) readLeaderAdvertisement(ctx context.Context, leaderUUID string) (*activeAdvertisement, error) {
	entry, err := c.barrier.Get(ctx, leaderPrefix+leaderUUID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var adv activeAdvertisement
	if err := jsonutil.DecodeJSON(entry.Value, &adv); err != nil {
		return nil, err
	}
	return &adv, nil
}

// generateLeaderUUID generates a new UUID for use as the HA lock value.
func generateLeaderUUID() (string, error) {
	return uuid.GenerateUUID()
}
