//go:build e2e

package namespace

import (
	"encoding/json"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestNamespaceCRUD verifies create and read of a namespace (T21).
func TestNamespaceCRUD(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-ns1")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-ns1", port,
		`{"metadata":{"env":"ci"}}`)
	if createStatus != 201 {
		t.Fatalf("create: expected 201, got %d", createStatus)
	}

	readStatus, body := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-ns1", port, "")
	if readStatus != 200 {
		t.Fatalf("read: expected 200, got %d", readStatus)
	}

	path := h.JSONString(t, body, "data.path")
	if path != "e2e-ci-ns1/" {
		t.Fatalf("expected path 'e2e-ci-ns1/', got %q", path)
	}

	h.CleanupNamespaces(t, port, "e2e-ci-ns1")
}

// TestNestedNamespaces verifies creating child namespace within parent (T22).
func TestNestedNamespaces(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-org/team-a", "e2e-ci-org")

	// Create parent
	parentStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-org", port, "")
	if parentStatus != 201 {
		t.Fatalf("parent create: expected 201, got %d", parentStatus)
	}

	// Create child within parent
	childStatus, _ := h.NSAPIRequest(t, "POST", "sys/namespaces/team-a", "e2e-ci-org", port, "")
	if childStatus != 201 {
		t.Fatalf("child create: expected 201, got %d", childStatus)
	}

	// Read child from root using full path
	readStatus, body := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-org/team-a", port, "")
	if readStatus != 200 {
		t.Fatalf("read child: expected 200, got %d", readStatus)
	}

	path := h.JSONString(t, body, "data.path")
	if path != "e2e-ci-org/team-a/" {
		t.Fatalf("expected path 'e2e-ci-org/team-a/', got %q", path)
	}

	h.CleanupNamespaces(t, port, "e2e-ci-org/team-a", "e2e-ci-org")
}

// TestNamespaceList verifies listing namespaces (T23).
func TestNamespaceList(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-list/child-b", "e2e-ci-list/child-a", "e2e-ci-list")

	// Create parent and 2 children
	h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-list", port, "")
	h.NSAPIRequest(t, "POST", "sys/namespaces/child-a", "e2e-ci-list", port, "")
	h.NSAPIRequest(t, "POST", "sys/namespaces/child-b", "e2e-ci-list", port, "")

	// List children from within parent
	listStatus, listBody := h.NSAPIRequest(t, "GET", "sys/namespaces?warden-list=true", "e2e-ci-list", port, "")
	if listStatus != 200 {
		t.Fatalf("list: expected 200, got %d", listStatus)
	}

	data := h.ParseJSON(t, listBody)
	keys := extractKeys(data)
	if len(keys) != 2 {
		t.Fatalf("expected 2 children, got %d: %v", len(keys), keys)
	}

	// List recursively from root
	recurStatus, recurBody := h.APIRequest(t, "GET", "sys/namespaces?warden-list=true&recursive=true", port, "")
	if recurStatus != 200 {
		t.Fatalf("recursive list: expected 200, got %d", recurStatus)
	}

	recurData := h.ParseJSON(t, recurBody)
	recurKeys := extractKeys(recurData)
	count := 0
	for _, k := range recurKeys {
		if len(k) >= len("e2e-ci-list") && k[:len("e2e-ci-list")] == "e2e-ci-list" {
			count++
		}
	}
	if count < 3 {
		t.Fatalf("expected >= 3 e2e-ci-list entries in recursive list, got %d", count)
	}

	h.CleanupNamespaces(t, port, "e2e-ci-list/child-b", "e2e-ci-list/child-a", "e2e-ci-list")
}

// TestNamespaceIsolation verifies provider in namespace is not visible from root (T24).
func TestNamespaceIsolation(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-iso")

	h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-iso", port, "")

	// Mount provider within namespace
	h.NSAPIRequest(t, "POST", "sys/providers/ns-vault", "e2e-ci-iso", port, `{"type":"vault"}`)

	// Read from within namespace (should exist)
	nsStatus, _ := h.NSAPIRequest(t, "GET", "sys/providers/ns-vault", "e2e-ci-iso", port, "")
	if nsStatus != 200 {
		t.Fatalf("namespace read: expected 200, got %d", nsStatus)
	}

	// Read from root (should NOT exist)
	rootStatus, _ := h.APIRequest(t, "GET", "sys/providers/ns-vault", port, "")
	if rootStatus == 200 {
		t.Fatal("provider should not be visible from root namespace")
	}

	// Cleanup
	h.NSAPIRequest(t, "DELETE", "sys/providers/ns-vault", "e2e-ci-iso", port, "")
	h.CleanupNamespaces(t, port, "e2e-ci-iso")
}

// TestNamespaceViaStandby verifies namespace creation through standby (T25).
func TestNamespaceViaStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)
	h.CleanupNamespaces(t, leader, "e2e-ci-fwd-ns")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-fwd-ns", standby, "")
	if createStatus != 201 {
		t.Fatalf("create via standby: expected 201, got %d", createStatus)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-fwd-ns", leader, "")
	if readStatus != 200 {
		t.Fatalf("read from leader: expected 200, got %d", readStatus)
	}

	h.CleanupNamespaces(t, leader, "e2e-ci-fwd-ns")
}

// TestNamespaceFailover verifies namespace data persists after failover (T26).
func TestNamespaceFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	nodeNum := h.NodeNumberForPort(leader)
	h.CleanupNamespaces(t, leader, "e2e-ci-ha-ns/child", "e2e-ci-ha-ns")

	// Create parent with custom metadata
	h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-ha-ns", leader,
		`{"custom_metadata":{"purpose":"failover-test"}}`)
	h.NSAPIRequest(t, "POST", "sys/namespaces/child", "e2e-ci-ha-ns", leader, "")

	// Kill leader
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	// Verify parent readable with metadata
	parentStatus, parentBody := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-ha-ns", newLeader, "")
	if parentStatus != 200 {
		t.Fatalf("parent read: expected 200, got %d", parentStatus)
	}

	purpose := h.JSONString(t, parentBody, "data.custom_metadata.purpose")
	if purpose != "failover-test" {
		t.Fatalf("expected metadata purpose 'failover-test', got %q", purpose)
	}

	// Verify child readable
	childStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-ha-ns/child", newLeader, "")
	if childStatus != 200 {
		t.Fatalf("child read: expected 200, got %d", childStatus)
	}

	// Restore
	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)
	h.CleanupNamespaces(t, h.GetLeaderPort(t), "e2e-ci-ha-ns/child", "e2e-ci-ha-ns")
}

// TestNamespaceDeletionOrder verifies parent can't be deleted before children (T27).
func TestNamespaceDeletionOrder(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-del-ns/child", "e2e-ci-del-ns")

	h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-del-ns", port, "")
	h.NSAPIRequest(t, "POST", "sys/namespaces/child", "e2e-ci-del-ns", port, "")

	// Try to delete parent (should fail)
	delParentStatus, _ := h.APIRequest(t, "DELETE", "sys/namespaces/e2e-ci-del-ns", port, "")
	if delParentStatus == 200 {
		t.Fatal("parent delete should have failed while children exist")
	}

	time.Sleep(2 * time.Second)

	// Delete child
	delChildStatus, _ := h.APIRequest(t, "DELETE", "sys/namespaces/e2e-ci-del-ns/child", port, "")
	if delChildStatus != 200 {
		t.Fatalf("child delete: expected 200, got %d", delChildStatus)
	}

	time.Sleep(2 * time.Second)

	// Now delete parent
	delParent2Status, _ := h.APIRequest(t, "DELETE", "sys/namespaces/e2e-ci-del-ns", port, "")
	if delParent2Status != 200 {
		t.Fatalf("parent delete after child removed: expected 200, got %d", delParent2Status)
	}

	time.Sleep(1 * time.Second)

	// Verify gone
	verifyStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-ci-del-ns", port, "")
	if verifyStatus == 200 {
		t.Fatal("parent should not exist after deletion")
	}
}

// TestNamespaceRestrictedAPIs verifies restricted APIs return 400 in namespace (T28).
func TestNamespaceRestrictedAPIs(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-ci-restrict")

	h.APIRequest(t, "POST", "sys/namespaces/e2e-ci-restrict", port, "")

	// sys/seal should be restricted
	sealStatus, _ := h.NSAPIRequest(t, "GET", "sys/seal", "e2e-ci-restrict", port, "")
	if sealStatus != 400 {
		t.Fatalf("sys/seal: expected 400, got %d", sealStatus)
	}

	// sys/key-status should be restricted
	keyStatus, _ := h.NSAPIRequest(t, "GET", "sys/key-status", "e2e-ci-restrict", port, "")
	if keyStatus != 400 {
		t.Fatalf("sys/key-status: expected 400, got %d", keyStatus)
	}

	// sys/namespaces should NOT be restricted
	listStatus, _ := h.NSAPIRequest(t, "GET", "sys/namespaces?warden-list=true", "e2e-ci-restrict", port, "")
	if listStatus != 200 {
		t.Fatalf("sys/namespaces: expected 200, got %d", listStatus)
	}

	h.CleanupNamespaces(t, port, "e2e-ci-restrict")
}

// extractKeys gets the keys array from a list response.
func extractKeys(data map[string]interface{}) []string {
	dataField, _ := data["data"].(map[string]interface{})
	if dataField == nil {
		return nil
	}
	keysRaw, _ := dataField["keys"].([]interface{})
	if keysRaw == nil {
		// Try parsing from raw JSON if interface conversion fails
		if keysJSON, ok := dataField["keys"]; ok {
			b, _ := json.Marshal(keysJSON)
			var keys []string
			json.Unmarshal(b, &keys)
			return keys
		}
		return nil
	}
	keys := make([]string, 0, len(keysRaw))
	for _, k := range keysRaw {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys
}
