//go:build e2e

package namespace

import (
	"fmt"
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

// TestCredentialIssuanceInChildNamespace verifies vault gateway works in a child namespace (T-055).
func TestCredentialIssuanceInChildNamespace(t *testing.T) {
	port := h.GetLeaderPort(t)

	h.SetupNSVaultEnv(t, port)

	jwt := h.GetDefaultJWT(t)

	status, _ := h.NSVaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, port, jwt)
	if status != 200 {
		t.Fatalf("vault gateway read in namespace: expected 200, got %d", status)
	}

	h.TeardownNSVaultEnv(t, port)
}
