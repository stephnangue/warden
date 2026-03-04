package core

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHA_SingleNode(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)
	require.True(t, haBackend.HAEnabled())

	// Create core with HA enabled
	c := createHACore(t, physBackend, haBackend, "http://127.0.0.1:8400")
	defer c.Shutdown()

	// Core starts sealed and standby
	assert.True(t, c.Sealed())
	assert.True(t, c.Standby())

	// Initialize and unseal
	initAndUnsealCore(t, c)

	// Wait for the node to become active
	active := waitForActiveNode(t, []*Core{c}, 5*time.Second)
	require.NotNil(t, active)

	// Verify state
	assert.False(t, c.Sealed())
	assert.False(t, c.Standby())
	assert.False(t, c.ActiveTime().IsZero())

	// Verify leader info
	isLeader, leaderAddr, _, err := c.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)
	assert.Equal(t, "http://127.0.0.1:8400", leaderAddr)
}

func TestHA_LeaderEndpoint(t *testing.T) {
	// Create a non-HA core
	c := createTestCore(t)

	// Leader should return ErrHANotEnabled for non-HA cores
	_, _, _, err := c.Leader()
	assert.ErrorIs(t, err, ErrHANotEnabled)

	// HAEnabled should return false
	assert.False(t, c.HAEnabled())
}

func TestHA_StepDown_NoHA(t *testing.T) {
	c := createTestCore(t)

	err := c.StepDown(nil)
	assert.ErrorIs(t, err, ErrHANotEnabled)
}

func TestHA_Standby_Method(t *testing.T) {
	c := createTestCore(t)

	// createTestCore sets standby to false (active)
	assert.False(t, c.Standby())
}

func TestHA_Sealed_Node(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	// Create HA core but don't initialize or unseal
	c := createHACore(t, physBackend, haBackend, "http://127.0.0.1:8400")
	defer c.Shutdown()

	// Sealed node should report sealed and standby
	assert.True(t, c.Sealed())
	assert.True(t, c.Standby())
	assert.True(t, c.HAEnabled())

	// Leader should return ErrSealed for sealed HA nodes
	_, _, _, err := c.Leader()
	assert.ErrorIs(t, err, consts.ErrSealed)
}

func TestHA_StepDown_Sealed(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	c := createHACore(t, physBackend, haBackend, "http://127.0.0.1:8400")
	defer c.Shutdown()

	// StepDown on a sealed node should return ErrSealed
	err := c.StepDown(nil)
	assert.ErrorIs(t, err, consts.ErrSealed)
}

func TestHA_Leader_Standby_Info(t *testing.T) {
	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()

	// Active should report itself as leader with its own address
	isLeader, leaderAddr, _, err := active.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)
	assert.Equal(t, active.redirectAddr, leaderAddr)

	// Standby should report not-leader but know the active's address
	isLeader, leaderAddr, _, err = standby.Leader()
	require.NoError(t, err)
	assert.False(t, isLeader)
	assert.Equal(t, active.redirectAddr, leaderAddr)

	// Shutdown active to trigger failover
	err = active.Shutdown()
	require.NoError(t, err)

	// Determine remaining core
	remaining := core1
	if active == core1 {
		remaining = core2
	}

	// Wait for promotion
	newActive := waitForActiveNode(t, []*Core{remaining}, 10*time.Second)
	require.NotNil(t, newActive)

	// New active should now report itself as leader
	isLeader, leaderAddr, _, err = newActive.Leader()
	require.NoError(t, err)
	assert.True(t, isLeader)
	assert.Equal(t, newActive.redirectAddr, leaderAddr)
}

func TestHA_Health_StatusCodes(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	c := createHACore(t, physBackend, haBackend, "http://127.0.0.1:8400")
	defer c.Shutdown()

	// Before init: sealed=true, standby=true
	assert.True(t, c.Sealed(), "should be sealed before init")
	assert.True(t, c.Standby(), "should be standby before init")

	initialized, err := c.Initialized(context.Background())
	require.NoError(t, err)
	assert.False(t, initialized, "should not be initialized")

	// Initialize and unseal
	initAndUnsealCore(t, c)

	// Wait for active
	waitForActiveNode(t, []*Core{c}, 5*time.Second)

	// Active: sealed=false, standby=false
	assert.False(t, c.Sealed(), "should not be sealed when active")
	assert.False(t, c.Standby(), "should not be standby when active")

	initialized, err = c.Initialized(context.Background())
	require.NoError(t, err)
	assert.True(t, initialized, "should be initialized")
}
