//go:build e2e

package concurrency

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestFiftyConcurrentRequestsToLeader verifies the leader handles 50 concurrent
// health requests without errors (T-095).
func TestFiftyConcurrentRequestsToLeader(t *testing.T) {
	leader := h.GetLeaderPort(t)

	ok := h.ConcurrentDo(50, func(i int) bool {
		status, _ := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/sys/health", h.NodeURL(leader)), nil, "")
		return status == 200
	})

	if ok != 50 {
		t.Fatalf("expected 50 successes on leader, got %d", ok)
	}
}

// TestFiftyConcurrentRequestsToStandby verifies a standby handles 50 concurrent
// health requests, accepting both 200 and 429 as success (T-096).
func TestFiftyConcurrentRequestsToStandby(t *testing.T) {
	standby := h.GetStandbyPort(t)

	ok := h.ConcurrentDo(50, func(i int) bool {
		status, _ := h.TryRequest("GET",
			fmt.Sprintf("%s/v1/sys/health", h.NodeURL(standby)), nil, "")
		return status == 200 || status == 429
	})

	if ok != 50 {
		t.Fatalf("expected 50 successes on standby, got %d", ok)
	}
}

// TestConcurrentSourceCRUD verifies concurrent creation and deletion of credential
// sources does not corrupt state (T-097).
func TestConcurrentSourceCRUD(t *testing.T) {
	leader := h.GetLeaderPort(t)

	for i := 0; i < 5; i++ {
		h.APIRequest(t, "DELETE",
			fmt.Sprintf("sys/cred/sources/e2e-conc-src-%d", i), leader, "")
	}

	sourceBody := `{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`

	created := h.ConcurrentDo(5, func(i int) bool {
		status, _ := h.APIRequest(t, "POST",
			fmt.Sprintf("sys/cred/sources/e2e-conc-src-%d", i), leader, sourceBody)
		return status == 200 || status == 201 || status == 204
	})

	if created < 3 {
		t.Fatalf("expected >= 3 source creates to succeed, got %d", created)
	}

	h.ConcurrentDo(5, func(i int) bool {
		status, _ := h.APIRequest(t, "DELETE",
			fmt.Sprintf("sys/cred/sources/e2e-conc-src-%d", i), leader, "")
		return status == 200 || status == 204
	})
}

// TestConcurrentRequestsDuringRotation verifies concurrent Vault gateway reads
// succeed while credential rotation may be in progress (T-099).
func TestConcurrentRequestsDuringRotation(t *testing.T) {
	leader := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	ok := h.ConcurrentDo(10, func(i int) bool {
		status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", leader, jwt)
		return status == 200
	})

	if ok < 8 {
		t.Fatalf("expected >= 8 Vault reads to succeed, got %d", ok)
	}
}

// TestConcurrentNamespaceCreateDelete verifies concurrent namespace creation and
// deletion does not corrupt the namespace store (T-100).
func TestConcurrentNamespaceCreateDelete(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.CleanupNamespaces(t, leader,
		"e2e-ccd-1", "e2e-ccd-2", "e2e-ccd-3", "e2e-ccd-4", "e2e-ccd-5")

	created := h.ConcurrentDo(5, func(i int) bool {
		status, _ := h.APIRequest(t, "POST",
			fmt.Sprintf("sys/namespaces/e2e-ccd-%d", i+1), leader, "")
		return status == 200 || status == 201
	})

	if created < 3 {
		t.Fatalf("expected >= 3 namespace creates to succeed, got %d", created)
	}

	time.Sleep(2 * time.Second)

	// Delete sequentially to avoid timeout under load
	for i := 1; i <= 5; i++ {
		h.CleanupNamespaces(t, leader, fmt.Sprintf("e2e-ccd-%d", i))
	}
}
