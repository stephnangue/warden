//go:build e2e

package seal

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestKillAndRestartStandbyAutoUnseal verifies a standby killed with SIGKILL
// auto-unseals after restart and rejoins the cluster (T-089).
func TestKillAndRestartStandbyAutoUnseal(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	h.KillNode(t, nodeNum, "KILL")
	time.Sleep(3 * time.Second)

	h.RestartNode(t, nodeNum)

	h.WaitForNodeStatus(t, standby, 429, 15, 2*time.Second)

	status, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if status != 429 && status != 200 {
		h.WaitForNodeStatus(t, standby, 200, 5, 2*time.Second)
	}

	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestAutoUnsealAfterSIGKILL verifies a node auto-unseals (not sealed/503)
// after being killed with SIGKILL and restarted (T-091).
func TestAutoUnsealAfterSIGKILL(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	h.KillNode(t, nodeNum, "KILL")
	time.Sleep(3 * time.Second)

	h.RestartNode(t, nodeNum)

	var lastStatus int
	for i := 0; i < 15; i++ {
		status, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
		lastStatus = status
		if status == 200 || status == 429 {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if lastStatus != 200 && lastStatus != 429 {
		t.Fatalf("node on port %d did not auto-unseal after SIGKILL: last health status was %d (503 = sealed)", standby, lastStatus)
	}

	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestFullClusterKillIncrementalRestart verifies the cluster reforms correctly
// after all nodes are killed and restarted one by one (T-092).
func TestFullClusterKillIncrementalRestart(t *testing.T) {
	h.KillNode(t, 1, "TERM")
	h.KillNode(t, 2, "TERM")
	h.KillNode(t, 3, "TERM")
	time.Sleep(5 * time.Second)

	h.RestartNode(t, 1)
	time.Sleep(3 * time.Second)
	h.RestartNode(t, 2)
	time.Sleep(3 * time.Second)
	h.RestartNode(t, 3)

	h.WaitForCluster(t, 20, 3*time.Second)

	leaders := 0
	standbys := 0
	for _, port := range h.NodePorts {
		status, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(port)), nil, "")
		switch status {
		case 200:
			leaders++
		case 429:
			standbys++
		}
	}

	if leaders != 1 {
		t.Fatalf("expected 1 leader, got %d", leaders)
	}
	if standbys != 2 {
		t.Fatalf("expected 2 standbys, got %d", standbys)
	}
}

// TestKilledNodeReturnsNoResponse verifies a killed node returns no response
// (connection refused / status 0) or 503 (T-093).
func TestKilledNodeReturnsNoResponse(t *testing.T) {
	standby := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standby)

	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(3 * time.Second)

	status, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if status != 0 && status != 503 {
		t.Fatalf("expected status 0 (connection refused) or 503 from killed node, got %d", status)
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestHealthStatusAccuracy verifies health endpoints return accurate status
// codes for leader, standby, and killed nodes (T-094).
func TestHealthStatusAccuracy(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)
	standbyNode := h.NodeNumberForPort(standby)

	leaderStatus, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(leader)), nil, "")
	if leaderStatus != 200 {
		t.Fatalf("expected leader health 200, got %d", leaderStatus)
	}

	standbyStatus, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if standbyStatus != 429 {
		t.Fatalf("expected standby health 429, got %d", standbyStatus)
	}

	h.KillNode(t, standbyNode, "TERM")
	time.Sleep(3 * time.Second)

	killedStatus, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
	if killedStatus != 0 {
		t.Fatalf("expected status 0 (down) from killed standby, got %d", killedStatus)
	}

	h.RestartNode(t, standbyNode)

	var finalStatus int
	for i := 0; i < 15; i++ {
		s, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
		if s == 429 || s == 200 {
			finalStatus = s
			break
		}
		time.Sleep(2 * time.Second)
	}

	if finalStatus != 429 && finalStatus != 200 {
		t.Fatalf("expected restarted node to report 429 or 200, got %d", finalStatus)
	}

	h.WaitForCluster(t, 15, 2*time.Second)
}
