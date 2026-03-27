//go:build e2e

package mtls

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// --- Direct mTLS tests (connect directly to Warden nodes) ---

// TestMTLSCertTransparentGateway verifies transparent gateway access via direct
// mTLS connection to the leader. The TLS fallback in certForwardingMiddleware
// extracts the client cert from r.TLS.PeerCertificates for implicit auth.
func TestMTLSCertTransparentGateway(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.SetupCertVaultEnvWithMTLSCA(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-mtls-login")

	status, body := h.VaultCertTransparentRequestViaMTLS(t, "GET", "secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("mTLS cert transparent gateway failed (status %d): %s", status, string(body))
	}
}

// TestMTLSCertTransparentGatewayViaStandby verifies transparent gateway access
// via mTLS through a standby node. Exercises the full forwarding chain:
// client → standby (TLS fallback → context) → standby forwarder (context → header)
// → leader cluster listener (header → context) → implicit cert auth → gateway
func TestMTLSCertTransparentGatewayViaStandby(t *testing.T) {
	leaderPort := h.GetLeaderPort(t)
	standbyPort := h.GetStandbyPort(t)

	h.SetupCertVaultEnvWithMTLSCA(t, leaderPort)
	defer h.TeardownCertVaultEnv(t, leaderPort)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-mtls-standby")

	status, body := h.VaultCertTransparentRequestViaMTLS(t, "GET", "secret/data/e2e/app-config", "e2e-cert-reader", standbyPort, clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("mTLS cert transparent gateway via standby failed (status %d): %s", status, string(body))
	}
}

// TestMTLSCertTransparentRead verifies transparent vault read via direct mTLS.
// Path: client → Warden (TLS fallback) → cert auth → mint Vault token → proxy to Vault.
func TestMTLSCertTransparentRead(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.SetupCertVaultEnvWithMTLSCA(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-mtls-transparent")

	status, body := h.VaultCertTransparentRequestViaMTLS(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("mTLS transparent read failed (status %d): %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in mTLS transparent read response")
	}
}

// TestMTLSCertTransparentReadAlternate verifies: mTLS transparent read with a different cert CN.
// Path: client -> Warden (TLS fallback) -> cert auth -> mint Vault token -> proxy to Vault.
func TestMTLSCertTransparentReadAlternate(t *testing.T) {
	port := h.GetLeaderPort(t)
	h.SetupCertVaultEnvWithMTLSCA(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-mtls-alt")

	status, body := h.VaultCertTransparentRequestViaMTLS(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("mTLS transparent read failed (status %d): %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in mTLS transparent read response")
	}
}

// --- LB passthrough tests (connect via nginx port 8001, TLS not terminated) ---

// TestLBPassthroughCertLogin verifies mTLS cert login through the nginx TLS
// passthrough port. The client TLS handshake goes end-to-end to Warden (nginx
// does NOT terminate TLS). Exercises the exact "LB doesn't terminate TLS" scenario.
// TestLBPassthroughCertTransparentGateway verifies transparent gateway access
// via LB TLS passthrough + mTLS cert auth.
func TestLBPassthroughCertTransparentGateway(t *testing.T) {
	h.SkipWithoutLBPassthrough(t)

	port := h.GetLeaderPort(t)
	h.SetupCertVaultEnvWithMTLSCA(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-passthrough-login")

	status, body := h.VaultCertTransparentRequestViaLBPassthrough(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("LB passthrough cert transparent gateway failed (status %d): %s", status, string(body))
	}
}

// TestLBPassthroughCertTransparentRead verifies transparent vault read via LB
// TLS passthrough + mTLS. Full path:
// client → nginx:8001 (passthrough) → Warden TLS fallback → cert auth → gateway → Vault
func TestLBPassthroughCertTransparentRead(t *testing.T) {
	h.SkipWithoutLBPassthrough(t)

	port := h.GetLeaderPort(t)
	h.SetupCertVaultEnvWithMTLSCA(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	caCertPEM, caKey := h.LoadMTLSClientCA(t)
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-passthrough-transparent")

	status, body := h.VaultCertTransparentRequestViaLBPassthrough(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("LB passthrough transparent read failed (status %d): %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in LB passthrough transparent read response")
	}
}

// TestLBPassthroughJWTTransparentRead verifies JWT auth through the TLS
// passthrough port (no client cert). This confirms the TLS fallback is a no-op
// when r.TLS.PeerCertificates is empty — JWT auth works normally over TLS
// without interference from the cert fallback logic.
func TestLBPassthroughJWTTransparentRead(t *testing.T) {
	h.SkipWithoutLBPassthrough(t)

	jwt := h.GetDefaultJWT(t)
	status, body := h.VaultTransparentRequestViaLBPassthrough(t, "GET",
		"secret/data/e2e/app-config", "e2e-reader", jwt)
	if status != 200 {
		t.Fatalf("JWT transparent read via LB passthrough failed (status %d): %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in JWT passthrough response")
	}
}
