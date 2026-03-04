//go:build e2e

package provider

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestNSVaultNonTransparent verifies vault-nt gateway works in a namespace (T29).
func TestNSVaultNonTransparent(t *testing.T) {
	leader := h.GetLeaderPort(t)

	// Clean up any stale environment
	h.TeardownNSVaultEnv(t, leader)

	// Setup full vault env in namespace
	h.SetupNSVaultEnv(t, leader)

	// Get namespace-scoped warden token
	token := h.GetNSNTWardenToken(t, h.NSVaultNS, leader)

	// Request through leader
	leaderStatus, _ := h.NSVaultNTRequest(t, "GET", "secret/data/e2e/app-config", h.NSVaultNS, leader, token)
	if leaderStatus != 200 {
		t.Fatalf("leader: expected 200, got %d", leaderStatus)
	}

	// Request through standby
	standby := h.GetStandbyPort(t)
	standbyStatus, _ := h.NSVaultNTRequest(t, "GET", "secret/data/e2e/app-config", h.NSVaultNS, standby, token)
	if standbyStatus != 200 {
		t.Fatalf("standby: expected 200, got %d", standbyStatus)
	}

	// Leave setup for TestNSVaultTransparent
}

// TestNSVaultTransparent verifies transparent vault gateway works in a namespace (T30).
func TestNSVaultTransparent(t *testing.T) {
	leader := h.GetLeaderPort(t)

	// Ensure namespace vault env exists (idempotent)
	h.SetupNSVaultEnv(t, leader)

	jwt := h.GetDefaultJWT(t)

	// Request through leader
	leaderStatus, _ := h.NSVaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, leader, jwt)
	if leaderStatus != 200 {
		t.Fatalf("leader: expected 200, got %d", leaderStatus)
	}

	// Request through standby
	standby := h.GetStandbyPort(t)
	standbyStatus, _ := h.NSVaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, standby, jwt)
	if standbyStatus != 200 {
		t.Fatalf("standby: expected 200, got %d", standbyStatus)
	}

	// Teardown
	h.TeardownNSVaultEnv(t, leader)
}
