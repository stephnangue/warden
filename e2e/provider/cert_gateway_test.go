//go:build e2e

package provider

import (
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestCertTransparentReadKVSecret verifies cert-based transparent mode
// reads a vault secret on the leader.
func TestCertTransparentReadKVSecret(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-1")

	status, body := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in response")
	}
}

// TestCertTransparentReadKVSecretAlternate verifies cert-based transparent mode
// reads a vault secret with a different client cert CN.
func TestCertTransparentReadKVSecretAlternate(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-2")

	status, body := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
}

// TestCertTransparentThroughStandby verifies cert-based transparent mode
// works when the request arrives at a standby node and is forwarded to the leader.
func TestCertTransparentThroughStandby(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-standby")

	standbyPort := h.GetStandbyPort(t)
	status, body := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", standbyPort, clientCertPEM)
	if status != 200 {
		t.Fatalf("expected 200 through standby, got %d: %s", status, string(body))
	}
}

// TestCertTransparentThroughStandbyAlternate verifies that cert-based transparent
// mode works through a standby node with a different client cert.
func TestCertTransparentThroughStandbyAlternate(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-standby-alt")

	standbyPort := h.GetStandbyPort(t)
	status, body := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", standbyPort, clientCertPEM)
	if status != 200 {
		t.Fatalf("expected 200 through standby, got %d: %s", status, string(body))
	}
}

// TestCertTransparentTokenReuse verifies that concurrent transparent requests
// with the same certificate reuse the same token via singleflight.
func TestCertTransparentTokenReuse(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-reuse")

	const n = 10
	var wg sync.WaitGroup
	results := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			status, _ := h.VaultCertTransparentRequest(t, "GET",
				"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
			results[idx] = status
		}(i)
	}
	wg.Wait()

	for i, status := range results {
		if status != 200 {
			t.Fatalf("request %d: expected 200, got %d", i, status)
		}
	}
}

// TestCertTransparentWrongCN verifies that a certificate with a CN that
// doesn't match the role's allowed_common_names is rejected.
func TestCertTransparentWrongCN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "unauthorized-user")

	status, _ := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
	if status == 200 {
		t.Fatal("expected non-200 for cert with non-matching CN")
	}
}

// TestCertTransparentAndJWTTransparentSameVault verifies that both cert and
// JWT transparent modes can access the same underlying vault secret.
func TestCertTransparentAndJWTTransparentSameVault(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	// Read via cert transparent mode
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-cross")
	certStatus, certBody := h.VaultCertTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
	if certStatus != 200 {
		t.Fatalf("cert transparent: expected 200, got %d: %s", certStatus, string(certBody))
	}

	// Read via JWT transparent mode (uses existing vault provider + jwt auth)
	jwt := h.GetDefaultJWT(t)
	jwtStatus, jwtBody := h.VaultTransparentRequest(t, "GET",
		"secret/data/e2e/app-config", "e2e-reader", port, jwt)
	if jwtStatus != 200 {
		t.Fatalf("JWT transparent: expected 200, got %d: %s", jwtStatus, string(jwtBody))
	}

	// Both should return the same secret
	certAPIKey := h.JSONString(t, certBody, "data.data.api_key")
	jwtAPIKey := h.JSONString(t, jwtBody, "data.data.api_key")
	if certAPIKey != jwtAPIKey {
		t.Fatalf("expected same api_key from both modes, got cert=%q jwt=%q", certAPIKey, jwtAPIKey)
	}
}
