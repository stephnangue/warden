//go:build e2e

package forwarding

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestStandbyForwardsWriteRequest verifies that a write request sent to a standby
// node is forwarded to the leader and succeeds (T-013).
func TestStandbyForwardsWriteRequest(t *testing.T) {
	standby := h.GetStandbyPort(t)
	leader := h.GetLeaderPort(t)

	h.CleanupNamespaces(t, leader, "e2e-fwd-write")

	writeStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-fwd-write", standby, "")
	if writeStatus != 201 {
		t.Fatalf("expected 201 for namespace creation via standby, got %d", writeStatus)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-fwd-write", leader, "")
	if readStatus != 200 {
		t.Fatalf("expected 200 for namespace read from leader, got %d", readStatus)
	}

	h.CleanupNamespaces(t, leader, "e2e-fwd-write")
}

// TestStandbyForwardsDeleteRequest verifies that a delete request sent to a standby
// node is forwarded to the leader and the resource is removed (T-014).
func TestStandbyForwardsDeleteRequest(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	h.CleanupNamespaces(t, leader, "e2e-fwd-del")
	h.APIRequest(t, "POST", "sys/namespaces/e2e-fwd-del", leader, "")

	h.APIRequest(t, "DELETE", "sys/namespaces/e2e-fwd-del", standby, "")
	time.Sleep(1 * time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-fwd-del", leader, "")
	if readStatus == 200 {
		t.Fatal("expected non-200 (namespace should be deleted), got 200")
	}

	h.CleanupNamespaces(t, leader, "e2e-fwd-del")
}

// TestLargeRequestBodyForwarding verifies that large request bodies (~1MB)
// are correctly forwarded from standby to leader (T-016).
func TestLargeRequestBodyForwarding(t *testing.T) {
	standby := h.GetStandbyPort(t)
	leader := h.GetLeaderPort(t)

	h.APIRequest(t, "DELETE", "sys/providers/e2e-large-body", leader, "")

	largeDesc := strings.Repeat("x", 1000000)
	body := fmt.Sprintf(`{"type":"vault","description":"%s"}`, largeDesc)

	status, _ := h.APIRequest(t, "POST", "sys/providers/e2e-large-body", standby, body)
	if status != 200 && status != 201 && status != 204 && status != 400 && status != 413 {
		t.Fatalf("expected 200, 201, 204, 400, or 413 for large body, got %d", status)
	}

	h.APIRequest(t, "DELETE", "sys/providers/e2e-large-body", leader, "")
}

// TestConcurrentForwardsFromBothStandbys verifies that concurrent requests from
// both standby nodes are handled correctly (T-017).
func TestConcurrentForwardsFromBothStandbys(t *testing.T) {
	standby1, standby2 := h.GetBothStandbyPorts(t)

	successes := h.ConcurrentDo(20, func(i int) bool {
		port := standby1
		if i >= 10 {
			port = standby2
		}
		status, _ := h.TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", h.NodeURL(port)), nil, "")
		return status == 200 || status == 429
	})

	if successes != 20 {
		t.Fatalf("expected 20 successes, got %d", successes)
	}
}

// TestForwardAfterLeaderAddressChange verifies that standby nodes correctly forward
// requests after a leadership change via step-down (T-018).
func TestForwardAfterLeaderAddressChange(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.StepDown(t, leader)
	time.Sleep(5 * time.Second)

	h.WaitForLeader(t, 10, 2*time.Second)
	standby := h.GetStandbyPort(t)

	h.APIRequest(t, "DELETE", "sys/providers/e2e-fwd-change", h.GetLeaderPort(t), "")

	status, _ := h.APIRequest(t, "POST", "sys/providers/e2e-fwd-change", standby, `{"type":"vault"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("expected 200, 201, or 204, got %d", status)
	}

	h.APIRequest(t, "DELETE", "sys/providers/e2e-fwd-change", h.GetLeaderPort(t), "")
	h.WaitForCluster(t, 15, 2*time.Second)
}

// TestStandbyForwardWithInvalidToken verifies that an invalid authentication token
// forwarded through a standby results in a 403 response (T-019).
func TestStandbyForwardWithInvalidToken(t *testing.T) {
	standby := h.GetStandbyPort(t)

	status, _ := h.DoRequest(t, "GET",
		fmt.Sprintf("%s/v1/sys/namespaces?warden-list=true", h.NodeURL(standby)),
		map[string]string{"X-Warden-Token": "invalid-token-12345"}, "")
	if status != 403 {
		t.Fatalf("expected 403 for invalid token via standby, got %d", status)
	}
}

// TestStandbyForwardTimeoutHandling verifies that when the leader is paused (SIGSTOP),
// forwarded requests from the standby time out (T-020).
func TestStandbyForwardTimeoutHandling(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)
	leaderNode := h.NodeNumberForPort(leader)

	h.SignalNode(t, leaderNode, syscall.SIGSTOP)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	token := h.RootToken(t)
	reqURL := fmt.Sprintf("%s/v1/sys/namespaces?warden-list=true", h.NodeURL(standby))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		h.SignalNode(t, leaderNode, syscall.SIGCONT)
		time.Sleep(3 * time.Second)
		h.WaitForCluster(t, 15, 2*time.Second)
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Warden-Token", token)

	var status int
	resp, err := client.Do(req)
	if err != nil {
		status = 0
	} else {
		status = resp.StatusCode
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	h.SignalNode(t, leaderNode, syscall.SIGCONT)
	time.Sleep(3 * time.Second)
	h.WaitForCluster(t, 15, 2*time.Second)

	if status == 200 {
		t.Fatalf("expected non-200 when leader is paused, got %d", status)
	}
}
