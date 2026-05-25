//go:build e2e

package provider

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestNSVaultTransparentLeaderAndStandby verifies transparent vault gateway works in a namespace
// on both leader and standby (T29).
func TestNSVaultTransparentLeaderAndStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)

	// Clean up any stale environment
	h.TeardownNSVaultEnv(t, leader)

	// Setup full vault env in namespace
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

// TestNSVaultTransparentHeaderRole verifies transparent vault gateway works with X-Warden-Role header (T31).
func TestNSVaultTransparentHeaderRole(t *testing.T) {
	leader := h.GetLeaderPort(t)

	// Ensure namespace vault env exists (idempotent)
	h.SetupNSVaultEnv(t, leader)

	jwt := h.GetDefaultJWT(t)

	// Request using X-Warden-Role header instead of role in URL path
	status, _ := h.NSVaultTransparentHeaderRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, leader, jwt)
	if status != 200 {
		t.Fatalf("header role: expected 200, got %d", status)
	}

	// URL-routed transparent ops still work without any X-Warden-Role header
	// (role is read from the URL path). This is the path-routing fallback
	// when the header is absent; precedence-when-both-present is covered
	// by core/request_handler_test.go.
	status2, _ := h.NSVaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, leader, jwt)
	if status2 != 200 {
		t.Fatalf("URL-routed: expected 200, got %d", status2)
	}

	// Teardown
	h.TeardownNSVaultEnv(t, leader)
}

// TestNSVaultRoleHeaderOverridesURLRole exercises the new precedence: when
// both a URL-embedded role and an X-Warden-Role header are present, the
// header wins. The URL carries a bogus role; if the header overrides it,
// the request succeeds (200) because the real role is in the header. If
// the old URL-wins behavior persists, the bogus URL role causes the auth
// flow to reject with 4xx.
func TestNSVaultRoleHeaderOverridesURLRole(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.SetupNSVaultEnv(t, leader)
	defer h.TeardownNSVaultEnv(t, leader)

	jwt := h.GetDefaultJWT(t)

	status, _ := h.NSVaultTransparentRequestWithHeaderRole(t, "GET", "secret/data/e2e/app-config", "nonexistent-role-in-url", "e2e-reader", h.NSVaultNS, leader, jwt)
	if status != 200 {
		t.Fatalf("header role should override URL role: expected 200, got %d", status)
	}
}

// TestNSVaultTransparentProviderHeader verifies that a request carrying
// X-Warden-Provider (and X-Warden-Role) reaches the same Vault gateway
// backend as the path-routed equivalent. The URL is the literal upstream
// API path (v1/secret/data/...); the mount and role come from headers.
func TestNSVaultTransparentProviderHeader(t *testing.T) {
	leader := h.GetLeaderPort(t)

	h.SetupNSVaultEnv(t, leader)
	defer h.TeardownNSVaultEnv(t, leader)

	jwt := h.GetDefaultJWT(t)

	// Header-routing mode: provider in header, role in header, URL is the
	// literal Vault path. Same upstream call as the path-routed test above.
	status, _ := h.NSVaultTransparentProviderRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", h.NSVaultNS, leader, jwt)
	if status != 200 {
		t.Fatalf("provider header: expected 200, got %d", status)
	}
}
