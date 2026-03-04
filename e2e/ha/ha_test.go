//go:build e2e

package ha

import (
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestLeaderSIGKILL verifies new leader elected after SIGKILL (T13).
func TestLeaderSIGKILL(t *testing.T) {
	oldLeader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(oldLeader)

	h.KillNode(t, nodeNum, "KILL")
	time.Sleep(12 * time.Second) // advisory lock timeout

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)
	if newLeader == oldLeader {
		t.Fatalf("leader did not change: still on port %d", oldLeader)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestCascadingFailure verifies cluster survives two successive leader kills (T14).
func TestCascadingFailure(t *testing.T) {
	// Kill first leader
	leader1 := h.GetLeaderPort(t)
	node1 := h.NodeNumberForPort(leader1)
	h.KillNode(t, node1, "TERM")
	time.Sleep(8 * time.Second)

	// Kill second leader
	leader2 := h.WaitForLeader(t, 10, 2*time.Second)
	node2 := h.NodeNumberForPort(leader2)
	h.KillNode(t, node2, "TERM")
	time.Sleep(8 * time.Second)

	// Third leader should exist
	_ = h.WaitForLeader(t, 10, 2*time.Second)

	// Restore cluster
	h.RestartNode(t, node1)
	h.RestartNode(t, node2)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestStandbyLocalEndpoints verifies standby serves health and leader locally (T15).
func TestStandbyLocalEndpoints(t *testing.T) {
	standby := h.GetStandbyPort(t)

	healthStatus, _ := h.DoRequest(t, "GET", h.NodeURL(standby)+"/v1/sys/health", nil, "")
	if healthStatus != 429 {
		t.Fatalf("expected 429 for standby health, got %d", healthStatus)
	}

	leaderStatus, _ := h.DoRequest(t, "GET", h.NodeURL(standby)+"/v1/sys/leader", nil, "")
	if leaderStatus != 200 {
		t.Fatalf("expected 200 for standby /sys/leader, got %d", leaderStatus)
	}
}

// TestDeletionDurability verifies deletion persists after failover (T16).
func TestDeletionDurability(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	// Cleanup stale
	h.APIRequest(t, "DELETE", "sys/providers/e2e-ci-del", leader, "")

	// Create then delete
	h.APIRequest(t, "POST", "sys/providers/e2e-ci-del", leader, `{"type":"vault"}`)
	h.APIRequest(t, "DELETE", "sys/providers/e2e-ci-del", leader, "")

	// Kill leader
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	// Verify deletion persisted on new leader
	newLeader := h.WaitForLeader(t, 10, 2*time.Second)
	readStatus, _ := h.APIRequest(t, "GET", "sys/providers/e2e-ci-del", newLeader, "")
	if readStatus == 200 {
		t.Fatal("expected non-200 (resource should be deleted), got 200")
	}

	// Restore cluster
	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestRapidKillRestartCycle verifies node survives 3 rapid kill/restart cycles (T20).
func TestRapidKillRestartCycle(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	for i := 0; i < 3; i++ {
		h.KillNode(t, nodeNum, "TERM")
		time.Sleep(2 * time.Second)
		h.RestartNode(t, nodeNum)
		time.Sleep(3 * time.Second)
	}

	// Wait for node to stabilize
	for i := 0; i < 15; i++ {
		status, _ := h.TryRequest("GET", h.NodeURL(standby)+"/v1/sys/health", nil, "")
		if status == 429 || status == 200 {
			h.WaitForCluster(t, 15, 2*time.Second)
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("node did not stabilize after rapid kill/restart cycles")
}
