//go:build e2e

package cluster

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestSplitBrainCheck verifies exactly 1 node reports is_leader=true (T08).
func TestSplitBrainCheck(t *testing.T) {
	leader := h.GetLeaderPort(t)
	h.StepDown(t, leader)
	time.Sleep(5 * time.Second)
	h.WaitForCluster(t, 15, 2*time.Second)

	leaderCount := 0
	for _, port := range h.NodePorts {
		status, body := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/sys/leader", h.NodeURL(port)), nil, "")
		if status != 200 {
			continue
		}
		data := h.ParseJSON(t, body)
		if isLeader, ok := data["is_leader"].(bool); ok && isLeader {
			leaderCount++
		}
	}

	if leaderCount != 1 {
		t.Fatalf("expected exactly 1 node with is_leader=true, got %d", leaderCount)
	}
}
