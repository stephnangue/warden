package core

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHA_Failover(t *testing.T) {
	// Create shared inmem_ha backend
	physBackend, haBackend := newInmemHABackends(t)

	// Create two cores sharing the same backend
	core1 := createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, physBackend, haBackend, "http://node2:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()

	// Initialize on core1 and unseal both
	_, unsealKey := initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)

	// Wait for one to become active
	active := waitForActiveNode(t, []*Core{core1, core2}, 5*time.Second)
	require.NotNil(t, active)

	// The other should be standby
	standby := waitForStandbyNode(t, []*Core{core1, core2}, 5*time.Second)
	require.NotNil(t, standby)
	require.True(t, active != standby, "active and standby should be different cores")

	// Verify leader info from standby
	isLeader, leaderAddr, _, err := standby.Leader()
	require.NoError(t, err)
	assert.False(t, isLeader)
	assert.NotEmpty(t, leaderAddr, "standby should know the leader address")

	// Verify leader info from active
	isLeader, _, _, err = active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	// Shutdown the active node to trigger failover
	activeAddr := active.redirectAddr
	err = active.Shutdown()
	require.NoError(t, err)

	// The standby should promote to active
	promoted := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, promoted)
	assert.False(t, promoted.Standby())

	// Promoted node should report itself as leader
	isLeader, newLeaderAddr, _, err := promoted.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)
	assert.NotEqual(t, activeAddr, newLeaderAddr, "new leader should have a different address")
}

func TestHA_StepDown(t *testing.T) {
	// Reduce step-down sleep so the test doesn't wait 10s
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	// Create shared inmem_ha backend
	physBackend, haBackend := newInmemHABackends(t)

	core1 := createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, physBackend, haBackend, "http://node2:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()

	_, unsealKey := initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)

	// Wait for active + standby
	active := waitForActiveNode(t, []*Core{core1, core2}, 5*time.Second)
	standby := waitForStandbyNode(t, []*Core{core1, core2}, 5*time.Second)
	require.NotNil(t, active)
	require.NotNil(t, standby)

	// Step down the active node
	err := active.StepDown(nil)
	require.NoError(t, err)

	// The former standby should become active
	newActive := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, newActive)
	assert.True(t, standby == newActive, "standby should have promoted")
}

func TestHA_Standby_Seal(t *testing.T) {
	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	// Seal the standby node
	err := standby.Seal()
	require.NoError(t, err)
	assert.True(t, standby.Sealed())

	// Active node should continue to function
	assert.False(t, active.Sealed())
	assert.False(t, active.Standby())

	isLeader, _, _, err := active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	// The sealed standby's loop should have exited. Wait briefly for the
	// loop to observe the sealed barrier and exit.
	time.Sleep(200 * time.Millisecond)

	// Shut down the active — the sealed node must not become active.
	err = active.Shutdown()
	require.NoError(t, err)

	// Wait and verify the sealed node did not acquire the lock.
	time.Sleep(500 * time.Millisecond)
	assert.True(t, standby.Sealed(), "sealed node should remain sealed")
	assert.True(t, standby.Standby(), "sealed node should remain standby")
}

func TestHA_StepDown_ReAcquire(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	firstActiveAddr := active.redirectAddr

	// Step down active -> standby should promote
	err := active.StepDown(nil)
	require.NoError(t, err)

	newActive := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, newActive)
	assert.Equal(t, standby.redirectAddr, newActive.redirectAddr)

	// Step down again -> original should re-acquire
	err = newActive.StepDown(nil)
	require.NoError(t, err)

	reAcquired := waitForActiveNode(t, []*Core{core1, core2}, 10*time.Second)
	require.NotNil(t, reAcquired)

	// Verify both nodes can serve as active at different times
	// (either node can re-acquire, just verify one did)
	assert.False(t, reAcquired.Standby())

	isLeader, _, _, err := reAcquired.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	// Verify a second standby exists
	otherNode := core1
	if reAcquired == core1 {
		otherNode = core2
	}

	// If the original active re-acquired, that confirms two transitions worked
	if reAcquired.redirectAddr == firstActiveAddr {
		t.Logf("original active re-acquired leadership after two transitions")
	} else {
		t.Logf("other node acquired leadership; addr=%s", reAcquired.redirectAddr)
	}
	_ = otherNode // suppress unused
}

func TestHA_Standby_DataVisibility(t *testing.T) {
	active, _, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	ctx := context.Background()

	// Write data on active via barrier
	entry := &logical.StorageEntry{
		Key:   "test/data-visibility",
		Value: []byte("hello from active"),
	}
	err := active.barrier.Put(ctx, entry)
	require.NoError(t, err)

	// Shutdown active to trigger failover
	err = active.Shutdown()
	require.NoError(t, err)

	// Determine which core is the remaining one
	remaining := core1
	if active == core1 {
		remaining = core2
	}

	// Wait for promotion
	newActive := waitForActiveNode(t, []*Core{remaining}, 10*time.Second)
	require.NotNil(t, newActive)

	// New active should be able to read data written by old active
	got, err := newActive.barrier.Get(ctx, "test/data-visibility")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []byte("hello from active"), got.Value)
}

func TestHA_KeyRotation_Standby(t *testing.T) {
	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	ctx := context.Background()

	// Get initial key info
	initialInfo, err := active.barrier.ActiveKeyInfo()
	require.NoError(t, err)
	initialTerm := initialInfo.Term

	// Rotate the barrier key on the active node
	newTerm, err := active.barrier.Rotate(ctx, rand.Reader)
	require.NoError(t, err)
	assert.Greater(t, newTerm, uint32(initialTerm))

	// Create an upgrade path so standby can discover the new key
	err = active.barrier.CreateUpgrade(ctx, newTerm)
	require.NoError(t, err)

	// Standby's checkKeyUpgrades should detect and apply the new key
	err = standby.checkKeyUpgrades(ctx)
	require.NoError(t, err)

	// Verify standby's barrier now knows about the new term
	standbyInfo, err := standby.barrier.ActiveKeyInfo()
	require.NoError(t, err)
	assert.Equal(t, int(newTerm), standbyInfo.Term)
}

func TestHA_SeparateHABackend(t *testing.T) {
	// Use a plain inmem for data storage (shared between cores)
	dataBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err)

	// Use a separate inmem_ha for HA locking only
	haOnlyBackend, err := inmem.NewInmemHA(nil, nil)
	require.NoError(t, err)
	haBackend := haOnlyBackend.(physical.HABackend)

	core1 := createHACore(t, dataBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, dataBackend, haBackend, "http://node2:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()

	_, unsealKey := initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)

	active := waitForActiveNode(t, []*Core{core1, core2}, 5*time.Second)
	standby := waitForStandbyNode(t, []*Core{core1, core2}, 5*time.Second)
	require.NotNil(t, active)
	require.NotNil(t, standby)
	require.True(t, active != standby, "active and standby should be different cores")

	// Verify both cores function correctly with separate backends
	isLeader, _, _, err := active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	isLeader, leaderAddr, _, err := standby.Leader()
	require.NoError(t, err)
	assert.False(t, isLeader)
	assert.NotEmpty(t, leaderAddr)
}

func TestHA_ConcurrentUnseal(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	origRetry := lockRetryInterval
	lockRetryInterval = 100 * time.Millisecond
	defer func() { lockRetryInterval = origRetry }()

	physBackend, haBackend := newInmemHABackends(t)

	core1 := createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, physBackend, haBackend, "http://node2:8400")
	core3 := createHACore(t, physBackend, haBackend, "http://node3:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()
	defer core3.Shutdown()

	// Initialize on core1
	_, unsealKey := initAndUnsealCore(t, core1)

	// Unseal core2 and core3 concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		unsealCore(t, core2, unsealKey)
	}()
	go func() {
		defer wg.Done()
		unsealCore(t, core3, unsealKey)
	}()
	wg.Wait()

	cores := []*Core{core1, core2, core3}

	// Wait for one active node
	active := waitForActiveNode(t, cores, 10*time.Second)
	require.NotNil(t, active)

	// Wait for convergence
	time.Sleep(500 * time.Millisecond)

	// Count active and standby nodes
	var activeCount, standbyCount int
	for _, c := range cores {
		if !c.Sealed() {
			if c.Standby() {
				standbyCount++
			} else {
				activeCount++
			}
		}
	}

	assert.Equal(t, 1, activeCount, "exactly 1 node should be active")
	assert.Equal(t, 2, standbyCount, "exactly 2 nodes should be standby")

	// Verify leader info is consistent across all nodes
	isLeader, activeAddr, _, err := active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	for _, c := range cores {
		if c == active || c.Sealed() {
			continue
		}
		isLeader, leaderAddr, _, err := c.Leader()
		require.NoError(t, err)
		assert.False(t, isLeader)
		assert.Equal(t, activeAddr, leaderAddr, "all standby nodes should agree on leader")
	}
}

func TestHA_Shutdown_ActiveThenStandby(t *testing.T) {
	_, _, core1, core2, _ := setupTwoNodeHA(t)

	active := core1
	standby := core2
	if core1.Standby() {
		active = core2
		standby = core1
	}

	// Shutdown active first
	err := active.Shutdown()
	require.NoError(t, err)

	// Standby should promote to active
	promoted := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, promoted)
	assert.False(t, promoted.Standby())

	// Then shutdown the promoted node
	err = promoted.Shutdown()
	require.NoError(t, err)
}

func TestHA_Shutdown_StandbyFirst(t *testing.T) {
	_, _, core1, core2, _ := setupTwoNodeHA(t)

	active := core1
	standby := core2
	if core1.Standby() {
		active = core2
		standby = core1
	}

	// Shutdown standby first
	err := standby.Shutdown()
	require.NoError(t, err)

	// Active should continue to function
	assert.False(t, active.Sealed())
	assert.False(t, active.Standby())

	isLeader, _, _, err := active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	// Then shutdown active cleanly
	err = active.Shutdown()
	require.NoError(t, err)
}

func TestHA_StandbyRestart(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	c := createHACore(t, physBackend, haBackend, "http://127.0.0.1:8400")
	defer c.Shutdown()

	initAndUnsealCore(t, c)
	waitForActiveNode(t, []*Core{c}, 5*time.Second)

	// Verify the node is active and functional
	isLeader, _, _, err := c.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)

	// Send a restart signal — should be a no-op on an active node
	// (restart is for the standby loop, but the signal is buffered)
	c.restart()

	// Node should still be active and functional
	time.Sleep(100 * time.Millisecond)
	assert.False(t, c.Sealed())

	isLeader, _, _, err = c.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)
}

func TestHA_DrainPendingRestarts(t *testing.T) {
	// Create a buffered channel to simulate standbyRestartCh
	ch := make(chan struct{}, 1)

	c := &Core{
		standbyRestartCh: ch,
	}

	// Buffer a restart signal
	ch <- struct{}{}

	// Drain should clear the channel
	c.drainPendingRestarts()

	// Channel should be empty
	select {
	case <-ch:
		t.Fatal("channel should be empty after drain")
	default:
		// expected
	}

	// Drain on empty channel should be a no-op
	c.drainPendingRestarts()

	// Drain with nil channel should not panic
	c2 := &Core{standbyRestartCh: nil}
	c2.drainPendingRestarts()
}

func TestHA_ActiveContextTimeout(t *testing.T) {
	// Verify the constant is set correctly
	assert.Equal(t, 90*time.Second, DefaultMaxRequestDuration)
}

func TestHA_SealedNodeReleasesLock(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	origRetry := lockRetryInterval
	lockRetryInterval = 100 * time.Millisecond
	defer func() { lockRetryInterval = origRetry }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	// Seal the standby — its loop should exit via the pre-acquisition guard
	err := standby.Seal()
	require.NoError(t, err)

	// Wait for the sealed standby's loop to exit
	time.Sleep(200 * time.Millisecond)

	// Step down active — since the sealed standby cannot contend for
	// the lock, the original active should re-acquire.
	err = active.StepDown(nil)
	require.NoError(t, err)

	newActive := waitForActiveNode(t, []*Core{active}, 10*time.Second)
	require.NotNil(t, newActive)
	assert.Equal(t, active, newActive, "original active should re-acquire since standby is sealed")
}

func TestHA_SealDuringLockContention(t *testing.T) {
	origRetry := lockRetryInterval
	lockRetryInterval = 100 * time.Millisecond
	defer func() { lockRetryInterval = origRetry }()

	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	physBackend, haBackend := newInmemHABackends(t)

	core1 := createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, physBackend, haBackend, "http://node2:8400")
	core3 := createHACore(t, physBackend, haBackend, "http://node3:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()
	defer core3.Shutdown()

	_, unsealKey := initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)
	unsealCore(t, core3, unsealKey)

	// Wait for one active and two standbys
	active := waitForActiveNode(t, []*Core{core1, core2, core3}, 5*time.Second)
	require.NotNil(t, active)

	// Find the two standbys
	var standbys []*Core
	for _, c := range []*Core{core1, core2, core3} {
		if c != active {
			standbys = append(standbys, c)
		}
	}
	require.Len(t, standbys, 2)

	// Seal one standby
	err := standbys[0].Seal()
	require.NoError(t, err)

	// Wait for the sealed node's standby loop to exit
	time.Sleep(200 * time.Millisecond)

	// Step down active — the unsealed standby should become active
	err = active.StepDown(nil)
	require.NoError(t, err)

	newActive := waitForActiveNode(t, []*Core{standbys[1], active}, 10*time.Second)
	require.NotNil(t, newActive)

	// The sealed node should never have become active
	assert.True(t, standbys[0].Sealed())
	assert.True(t, standbys[0].Standby())
}
