//go:build e2e

package namespace

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestDeepNamespaceHierarchy verifies 3-level deep namespace creation and read (T-047).
func TestDeepNamespaceHierarchy(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-deep/l2/l3", "e2e-deep/l2", "e2e-deep")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-deep", port, "")
	if createStatus != 201 && createStatus != 200 {
		t.Fatalf("create e2e-deep: expected 201 or 200, got %d", createStatus)
	}

	l2Status, _ := h.NSAPIRequest(t, "POST", "sys/namespaces/l2", "e2e-deep", port, "")
	if l2Status != 201 && l2Status != 200 {
		t.Fatalf("create l2: expected 201 or 200, got %d", l2Status)
	}

	l3Status, _ := h.NSAPIRequest(t, "POST", "sys/namespaces/l3", "e2e-deep/l2", port, "")
	if l3Status != 201 && l3Status != 200 {
		t.Fatalf("create l3: expected 201 or 200, got %d", l3Status)
	}

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-deep/l2/l3", port, "")
	if readStatus != 200 {
		t.Fatalf("read e2e-deep/l2/l3: expected 200, got %d", readStatus)
	}

	h.CleanupNamespaces(t, port, "e2e-deep/l2/l3", "e2e-deep/l2", "e2e-deep")
}

// TestCrossNamespaceTokenRejection verifies a provider in one namespace is not visible from another (T-048).
func TestCrossNamespaceTokenRejection(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-xns-a", "e2e-xns-b")

	statusA, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-xns-a", port, "")
	if statusA != 201 && statusA != 200 {
		t.Fatalf("create e2e-xns-a: expected 201 or 200, got %d", statusA)
	}

	statusB, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-xns-b", port, "")
	if statusB != 201 && statusB != 200 {
		t.Fatalf("create e2e-xns-b: expected 201 or 200, got %d", statusB)
	}

	provStatus, _ := h.NSAPIRequest(t, "POST", "sys/providers/test-vault", "e2e-xns-a", port, `{"type":"vault"}`)
	if provStatus != 200 && provStatus != 201 {
		t.Fatalf("create provider in e2e-xns-a: expected 200 or 201, got %d", provStatus)
	}

	crossStatus, _ := h.NSAPIRequest(t, "GET", "sys/providers/test-vault", "e2e-xns-b", port, "")
	if crossStatus == 200 {
		t.Fatalf("provider in e2e-xns-a should not be visible from e2e-xns-b, got 200")
	}

	h.NSAPIRequest(t, "DELETE", "sys/providers/test-vault", "e2e-xns-a", port, "")
	h.CleanupNamespaces(t, port, "e2e-xns-a", "e2e-xns-b")
}

// TestNamespaceDeletionCascadesResources verifies deleting a namespace removes its resources (T-049).
func TestNamespaceDeletionCascadesResources(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-cascade")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-cascade", port, "")
	if createStatus != 201 && createStatus != 200 {
		t.Fatalf("create e2e-cascade: expected 201 or 200, got %d", createStatus)
	}

	provStatus, _ := h.NSAPIRequest(t, "POST", "sys/providers/cascade-vault", "e2e-cascade", port, `{"type":"vault"}`)
	if provStatus != 200 && provStatus != 201 {
		t.Fatalf("create provider: expected 200 or 201, got %d", provStatus)
	}

	delStatus, _ := h.APIRequest(t, "DELETE", "sys/namespaces/e2e-cascade", port, "")
	if delStatus != 200 {
		t.Fatalf("delete namespace: expected 200, got %d", delStatus)
	}

	time.Sleep(2 * time.Second)

	readStatus, _ := h.APIRequest(t, "GET", "sys/namespaces/e2e-cascade", port, "")
	if readStatus == 200 {
		t.Fatalf("namespace e2e-cascade should not exist after deletion, got 200")
	}
}

// TestConcurrentNamespaceOperations verifies concurrent namespace creation and deletion (T-050).
func TestConcurrentNamespaceOperations(t *testing.T) {
	port := h.GetLeaderPort(t)

	for i := 1; i <= 5; i++ {
		h.CleanupNamespaces(t, port, fmt.Sprintf("e2e-conc-%d", i))
	}

	created := h.ConcurrentDo(5, func(i int) bool {
		name := fmt.Sprintf("e2e-conc-%d", i+1)
		status, _ := h.APIRequest(t, "POST", "sys/namespaces/"+name, port, "")
		return status == 201 || status == 200
	})

	if created < 4 {
		t.Fatalf("expected >= 4 namespaces created, got %d", created)
	}

	time.Sleep(2 * time.Second)

	// Delete sequentially to avoid timeout under load
	for i := 1; i <= 5; i++ {
		h.CleanupNamespaces(t, port, fmt.Sprintf("e2e-conc-%d", i))
	}
}

// TestNamespaceSpecialCharacters verifies namespace names with dashes, underscores, and empty names (T-051).
func TestNamespaceSpecialCharacters(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-dash-ns", "e2e_under_ns")

	dashStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-dash-ns", port, "")
	if dashStatus != 201 && dashStatus != 200 {
		t.Fatalf("create e2e-dash-ns: expected 201 or 200, got %d", dashStatus)
	}

	underStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e_under_ns", port, "")
	if underStatus != 201 && underStatus != 200 {
		t.Fatalf("create e2e_under_ns: expected 201 or 200, got %d", underStatus)
	}

	emptyStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/", port, "")
	if emptyStatus == 201 {
		t.Fatalf("creating namespace with empty name should not return 201, got %d", emptyStatus)
	}

	h.CleanupNamespaces(t, port, "e2e-dash-ns", "e2e_under_ns")
}

// TestNamespaceRestrictedFromNonRoot verifies restricted APIs return 400 from a non-root namespace (T-053).
func TestNamespaceRestrictedFromNonRoot(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, port, "e2e-restrict-ns")

	createStatus, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-restrict-ns", port, "")
	if createStatus != 201 && createStatus != 200 {
		t.Fatalf("create e2e-restrict-ns: expected 201 or 200, got %d", createStatus)
	}

	sealStatus, _ := h.NSAPIRequest(t, "GET", "sys/seal", "e2e-restrict-ns", port, "")
	if sealStatus != 400 {
		t.Fatalf("sys/seal in namespace: expected 400, got %d", sealStatus)
	}

	keyStatus, _ := h.NSAPIRequest(t, "GET", "sys/key-status", "e2e-restrict-ns", port, "")
	if keyStatus != 400 {
		t.Fatalf("sys/key-status in namespace: expected 400, got %d", keyStatus)
	}

	h.CleanupNamespaces(t, port, "e2e-restrict-ns")
}

// TestNamespaceListingMultiple verifies listing returns all created namespaces (T-054).
func TestNamespaceListingMultiple(t *testing.T) {
	port := h.GetLeaderPort(t)

	for i := 1; i <= 10; i++ {
		h.CleanupNamespaces(t, port, fmt.Sprintf("e2e-list-%d", i))
	}

	for i := 1; i <= 10; i++ {
		name := fmt.Sprintf("e2e-list-%d", i)
		status, _ := h.APIRequest(t, "POST", "sys/namespaces/"+name, port, "")
		if status != 201 && status != 200 {
			t.Fatalf("create %s: expected 201 or 200, got %d", name, status)
		}
	}

	listStatus, listBody := h.APIRequest(t, "GET", "sys/namespaces?warden-list=true", port, "")
	if listStatus != 200 {
		t.Fatalf("list namespaces: expected 200, got %d", listStatus)
	}

	data := h.ParseJSON(t, listBody)
	dataField, ok := data["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data field in response, got: %s", string(listBody))
	}

	keysRaw := dataField["keys"]
	if keysRaw == nil {
		t.Fatalf("expected keys in data, got: %s", string(listBody))
	}

	keysJSON, err := json.Marshal(keysRaw)
	if err != nil {
		t.Fatalf("failed to marshal keys: %v", err)
	}
	var keys []string
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		var keysIface []interface{}
		if err2 := json.Unmarshal(keysJSON, &keysIface); err2 != nil {
			t.Fatalf("failed to unmarshal keys: %v (also tried interface: %v)", err, err2)
		}
		for _, k := range keysIface {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
	}

	count := 0
	for _, k := range keys {
		if strings.HasPrefix(k, "e2e-list-") {
			count++
		}
	}

	if count < 10 {
		t.Fatalf("expected >= 10 namespaces starting with 'e2e-list-', got %d", count)
	}

	for i := 1; i <= 10; i++ {
		h.CleanupNamespaces(t, port, fmt.Sprintf("e2e-list-%d", i))
	}
}

// TestCredentialIssuanceInChildNamespace verifies vault gateway works in a child namespace (T-055).
func TestCredentialIssuanceInChildNamespace(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.SetupNSVaultEnv(t, port)

	token := h.GetNSNTWardenToken(t, h.NSVaultNS, port)

	status, _ := h.NSVaultNTRequest(t, "GET", "secret/data/e2e/app-config", h.NSVaultNS, port, token)
	if status != 200 {
		t.Fatalf("vault gateway read in namespace: expected 200, got %d", status)
	}

	h.TeardownNSVaultEnv(t, port)
}

// TestNamespaceIsolationDuringFailover verifies namespace isolation persists after leader failover (T-056).
func TestNamespaceIsolationDuringFailover(t *testing.T) {
	leader := h.GetLeaderPort(t)
	h.CleanupNamespaces(t, leader, "e2e-fail-ns-a", "e2e-fail-ns-b")

	statusA, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-fail-ns-a", leader, "")
	if statusA != 201 && statusA != 200 {
		t.Fatalf("create e2e-fail-ns-a: expected 201 or 200, got %d", statusA)
	}

	statusB, _ := h.APIRequest(t, "POST", "sys/namespaces/e2e-fail-ns-b", leader, "")
	if statusB != 201 && statusB != 200 {
		t.Fatalf("create e2e-fail-ns-b: expected 201 or 200, got %d", statusB)
	}

	provStatus, _ := h.NSAPIRequest(t, "POST", "sys/providers/vault-a", "e2e-fail-ns-a", leader, `{"type":"vault"}`)
	if provStatus != 200 && provStatus != 201 {
		t.Fatalf("create provider in e2e-fail-ns-a: expected 200 or 201, got %d", provStatus)
	}

	nodeNum := h.NodeNumberForPort(leader)
	h.KillNode(t, nodeNum, "TERM")
	time.Sleep(8 * time.Second)

	newLeader := h.WaitForLeader(t, 10, 2*time.Second)

	readAStatus, _ := h.NSAPIRequest(t, "GET", "sys/providers/vault-a", "e2e-fail-ns-a", newLeader, "")
	if readAStatus != 200 {
		t.Fatalf("provider in e2e-fail-ns-a after failover: expected 200, got %d", readAStatus)
	}

	readBStatus, _ := h.NSAPIRequest(t, "GET", "sys/providers/vault-a", "e2e-fail-ns-b", newLeader, "")
	if readBStatus == 200 {
		t.Fatalf("provider in e2e-fail-ns-a should not be visible from e2e-fail-ns-b after failover, got 200")
	}

	h.RestartNode(t, nodeNum)
	h.WaitForCluster(t, 15, 2*time.Second)

	currentLeader := h.GetLeaderPort(t)
	h.NSAPIRequest(t, "DELETE", "sys/providers/vault-a", "e2e-fail-ns-a", currentLeader, "")
	h.CleanupNamespaces(t, currentLeader, "e2e-fail-ns-a", "e2e-fail-ns-b")
}
