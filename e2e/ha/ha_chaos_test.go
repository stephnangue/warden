//go:build e2e

package ha

import (
	"fmt"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestSimultaneousStandbyKillDuringStepDown verifies the cluster recovers when both
// standbys are killed (SIGKILL) at the same time the leader steps down (T-002).
func TestSimultaneousStandbyKillDuringStepDown(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby1, standby2 := h.GetBothStandbyPorts(t)

	nodeStandby1 := h.NodeNumberForPort(standby1)
	nodeStandby2 := h.NodeNumberForPort(standby2)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		h.KillNode(t, nodeStandby1, "KILL")
	}()
	go func() {
		defer wg.Done()
		h.KillNode(t, nodeStandby2, "KILL")
	}()
	go func() {
		defer wg.Done()
		h.StepDown(t, leader)
	}()

	wg.Wait()
	time.Sleep(5 * time.Second)

	h.RestartNode(t, nodeStandby1)
	h.RestartNode(t, nodeStandby2)

	h.WaitForCluster(t, 20, 3*time.Second)
}

// TestLeaderKillDuringActiveRequest verifies that killing the leader while a request
// is in-flight does not hang or panic, and that the cluster recovers (T-003).
func TestLeaderKillDuringActiveRequest(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	type result struct {
		status int
		body   []byte
	}
	ch := make(chan result, 1)

	go func() {
		status, body := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/sys/health", h.NodeURL(leader)), nil, "")
		ch <- result{status, body}
	}()

	h.KillNode(t, nodeNum, "KILL")

	<-ch

	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	status, _ := h.APIRequest(t, "GET", "sys/health", newLeader, "")
	if status != 200 {
		t.Fatalf("expected 200 from new leader, got %d", status)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestLeaderCrashDuringNamespaceCreation verifies that a namespace creation either
// completes or can be retried after the leader crashes mid-operation (T-006).
func TestLeaderCrashDuringNamespaceCreation(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)

	h.CleanupNamespaces(t, leader, "e2e-crash-test")

	type result struct {
		status int
		body   []byte
	}
	ch := make(chan result, 1)

	go func() {
		status, body := h.TryRequest("POST",
			fmt.Sprintf("%s/v1/sys/namespaces/e2e-crash-test", h.NodeURL(leader)),
			map[string]string{"X-Warden-Token": h.RootToken(t)}, "")
		ch <- result{status, body}
	}()

	time.Sleep(100 * time.Millisecond)
	h.KillNode(t, nodeNum, "KILL")

	<-ch

	time.Sleep(10 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-crash-test", newLeader, "")
	if readStatus != 200 {
		createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-crash-test", newLeader, "")
		if createStatus != 200 && createStatus != 201 && createStatus != 204 {
			t.Fatalf("failed to create namespace after leader crash, got %d", createStatus)
		}
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)

	h.CleanupNamespaces(t, h.GetLeaderPort(t), "e2e-crash-test")
}

// TestAllNodesKilledSimultaneously verifies the cluster reforms after all three
// nodes are killed at once (T-007).
func TestAllNodesKilledSimultaneously(t *testing.T) {
	h.KillNode(t, 1, "TERM")
	h.KillNode(t, 2, "TERM")
	h.KillNode(t, 3, "TERM")

	time.Sleep(5 * time.Second)

	h.RestartNode(t, 1)
	h.RestartNode(t, 2)
	h.RestartNode(t, 3)

	h.WaitForCluster(t, 20, 3*time.Second)

	leader := h.GetLeaderPort(t)
	status, _ := h.APIRequest(t, "GET", "sys/health", leader, "")
	if status != 200 {
		t.Fatalf("expected 200 from leader after full cluster restart, got %d", status)
	}
}

// TestLeaderStepDownDuringStreaming verifies that a step-down during a transparent
// Vault gateway request does not crash the cluster (T-008).
func TestLeaderStepDownDuringStreaming(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	type result struct {
		status int
		body   []byte
	}
	ch := make(chan result, 1)

	go func() {
		status, body := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader)),
			map[string]string{"Authorization": "Bearer " + jwt}, "")
		ch <- result{status, body}
	}()

	h.StepDown(t, leader)

	<-ch

	time.Sleep(5 * time.Second)

	h.WaitForCluster(t, 15, 2*time.Second)

	newLeader := h.GetLeaderPort(t)
	newJWT := h.GetDefaultJWT(t)
	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", newLeader, newJWT)
	if status != 200 {
		t.Fatalf("expected 200 from new leader after step-down, got %d", status)
	}
}

// TestStandbyRestartStaleLeaderCache verifies that a restarted standby node handles
// requests correctly even before its leader cache is refreshed (T-009).
func TestStandbyRestartStaleLeaderCache(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(2 * time.Second)

	h.RestartNode(t, nodeNum)
	time.Sleep(1 * time.Second)

	earlyStatus, _ := h.TryRequest("GET",
		fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if earlyStatus != 200 && earlyStatus != 429 && earlyStatus != 0 {
		t.Fatalf("unexpected early status %d from restarted standby", earlyStatus)
	}

	time.Sleep(5 * time.Second)

	lateStatus, _ := h.TryRequest("GET",
		fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if lateStatus != 200 && lateStatus != 429 {
		t.Fatalf("expected 200 or 429 after standby settled, got %d", lateStatus)
	}

	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestLeaderElectionDuringConcurrentRequests verifies the cluster handles a step-down
// while many concurrent requests are in-flight (T-010).
func TestLeaderElectionDuringConcurrentRequests(t *testing.T) {
	leader := h.GetLeaderPort(t)

	doneCh := make(chan int, 1)

	go func() {
		successes := h.ConcurrentDo(20, func(i int) bool {
			status, _ := h.TryRequest("GET",
				fmt.Sprintf("%s/v1/sys/health", h.NodeURL(leader)), nil, "")
			return status == 200 || status == 429
		})
		doneCh <- successes
	}()

	h.StepDown(t, leader)

	<-doneCh

	time.Sleep(5 * time.Second)

	h.WaitForCluster(t, 15, 2*time.Second)

	newLeader := h.GetLeaderPort(t)
	status, _ := h.APIRequest(t, "GET", "sys/health", newLeader, "")
	if status != 200 {
		t.Fatalf("expected 200 from leader after concurrent step-down, got %d", status)
	}
}

// TestDoubleStepDownRace verifies the cluster handles two simultaneous step-down
// requests to the same leader without crashing (T-011).
func TestDoubleStepDownRace(t *testing.T) {
	leader := h.GetLeaderPort(t)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		h.StepDown(t, leader)
	}()
	go func() {
		defer wg.Done()
		h.StepDown(t, leader)
	}()

	wg.Wait()

	time.Sleep(5 * time.Second)

	_ = h.WaitForLeader(t, 10, 2*time.Second)
	h.WaitForCluster(t, 15, 2*time.Second)

	finalLeader := h.GetLeaderPort(t)
	status, _ := h.APIRequest(t, "GET", "sys/health", finalLeader, "")
	if status != 200 {
		t.Fatalf("expected 200 after double step-down race, got %d", status)
	}
}

// TestKillNodeCreateDataRestartVerify verifies that data created while a node is
// down is available after the node restarts and becomes leader (T-012).
func TestKillNodeCreateDataRestartVerify(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(3 * time.Second)

	leader := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, leader, "e2e-post-kill-ns")
	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-post-kill-ns", leader, "")
	if createStatus != 200 && createStatus != 201 && createStatus != 204 {
		t.Fatalf("expected 200, 201, or 204 on namespace create, got %d", createStatus)
	}

	h.RestartNode(t, nodeNum)
	time.Sleep(5 * time.Second)
	h.WaitForCluster(t, 15, 2*time.Second)

	h.StepDown(t, leader)
	time.Sleep(5 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-post-kill-ns", newLeader, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 reading namespace on new leader, got %d", readStatus)
	}

	h.CleanupNamespaces(t, h.GetLeaderPort(t), "e2e-post-kill-ns")
	h.WaitForCluster(t, 15, 2*time.Second)
}
