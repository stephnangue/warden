package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHA_LeaderAdvertisement(t *testing.T) {
	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	ctx := context.Background()

	// Active node should have a leader advertisement in barrier storage
	keys, err := active.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, keys, "active node should have written a leader advertisement")

	// Read the advertisement and verify it contains the active node's address
	adv, err := active.readLeaderAdvertisement(ctx, keys[0])
	require.NoError(t, err)
	require.NotNil(t, adv)
	assert.Equal(t, active.redirectAddr, adv.RedirectAddr)

	// Standby should discover the active's address via the advertisement
	isLeader, leaderAddr, _, err := standby.Leader()
	require.NoError(t, err)
	assert.False(t, isLeader)
	assert.Equal(t, active.redirectAddr, leaderAddr)
}

func TestHA_LeaderAdvertisement_Cleanup(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	ctx := context.Background()

	// Record the active's advertisement UUID
	keys1, err := active.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, keys1)

	// Step down to cause a leadership transition
	err = active.StepDown(nil)
	require.NoError(t, err)

	// Wait for the standby to become active
	newActive := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, newActive)

	// The new active should have written its own advertisement
	keys2, err := newActive.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, keys2)

	// The old active's advertisement should eventually be cleaned up.
	// The cleanLeaderPrefix goroutine runs immediately on startup, so
	// after a short wait there should only be one entry.
	time.Sleep(200 * time.Millisecond)
	keysAfterCleanup, err := newActive.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	assert.Len(t, keysAfterCleanup, 1, "stale leader advertisement should be cleaned up")
}
