//go:build e2e

package cluster

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestSplitBrainCheck verifies exactly 1 node reports is_self=true (T08).
func TestSplitBrainCheck(t *testing.T) {
	leader := h.GetLeaderPort(t)
	h.StepDown(t, leader)
	time.Sleep(5 * time.Second)
	h.WaitForCluster(t, 15, 2*time.Second)

	selfCount := 0
	for _, port := range h.NodePorts {
		status, body := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/sys/leader", h.NodeURL(port)), nil, "")
		if status != 200 {
			continue
		}
		data := h.ParseJSON(t, body)
		if isSelf, ok := data["is_self"].(bool); ok && isSelf {
			selfCount++
		}
	}

	if selfCount != 1 {
		t.Fatalf("expected exactly 1 node with is_self=true, got %d", selfCount)
	}
}
