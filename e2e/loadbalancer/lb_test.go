//go:build e2e

package loadbalancer

import (
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestLBJWTTransparentRead verifies JWT transparent vault read through the
// nginx load balancer (HTTPS, no client cert).
func TestLBJWTTransparentRead(t *testing.T) {
	h.SkipWithoutLB(t)

	jwt := h.GetDefaultJWT(t)
	status, body := h.VaultTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-reader", jwt)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in response")
	}
}

// TestLBJWTTransparentReadAlternate verifies JWT transparent gateway read
// through the load balancer with a fresh JWT.
func TestLBJWTTransparentReadAlternate(t *testing.T) {
	h.SkipWithoutLB(t)

	jwt := h.GetDefaultJWT(t)

	status, body := h.VaultTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-reader", jwt)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
}

// TestLBCertTransparentRead verifies cert transparent vault read through the
// load balancer. The client presents a TLS certificate to nginx, which
// validates it against the LB CA and forwards it via X-SSL-Client-Cert.
func TestLBCertTransparentRead(t *testing.T) {
	h.SkipWithoutLB(t)

	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.LoadLBCA(t)
	h.SetupCertVaultEnvWithCA(t, port, caCertPEM)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-lb")

	status, body := h.VaultCertTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}

	apiKey := h.JSONString(t, body, "data.data.api_key")
	if apiKey == "" {
		t.Fatal("expected api_key in response")
	}
}

// TestLBCertTransparentReadAlternate verifies cert transparent vault read
// through the load balancer with a fresh client cert.
func TestLBCertTransparentReadAlternate(t *testing.T) {
	h.SkipWithoutLB(t)

	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.LoadLBCA(t)
	h.SetupCertVaultEnvWithCA(t, port, caCertPEM)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-lb-alt")

	status, body := h.VaultCertTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
}

// TestLBCertHeaderForwarding verifies that TLS client certificates presented
// to the LB are properly forwarded to Warden for transparent gateway auth.
// client TLS cert -> nginx validates against CA -> X-SSL-Client-Cert header
// -> Warden trusted_proxies allows Docker bridge CIDR -> implicit cert auth -> gateway.
func TestLBCertHeaderForwarding(t *testing.T) {
	h.SkipWithoutLB(t)

	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.LoadLBCA(t)
	h.SetupCertVaultEnvWithCA(t, port, caCertPEM)
	defer h.TeardownCertVaultEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cert-lb-fwd")

	// Transparent gateway through LB — exercises the full trusted_proxies + TLS forwarding path
	status, body := h.VaultCertTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-cert-reader", clientCertPEM, clientKeyPEM)
	if status != 200 {
		t.Fatalf("cert transparent gateway through LB failed (status %d): %s — "+
			"this may indicate trusted_proxies doesn't include Docker bridge CIDR",
			status, string(body))
	}
}

// TestLBConcurrentJWTTransparent verifies that multiple concurrent JWT
// transparent requests through the load balancer all succeed.
func TestLBConcurrentJWTTransparent(t *testing.T) {
	h.SkipWithoutLB(t)

	jwt := h.GetDefaultJWT(t)

	const n = 10
	var wg sync.WaitGroup
	results := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			status, _ := h.VaultTransparentRequestViaLB(t, "GET",
				"secret/data/e2e/app-config", "e2e-reader", jwt)
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

// TestLBHealthRouting verifies that the LB routes to healthy nodes even when
// one node is temporarily unreachable. We test this by killing a standby node,
// sending requests through the LB, and verifying they still succeed (routed to
// remaining healthy nodes).
func TestLBHealthRouting(t *testing.T) {
	h.SkipWithoutLB(t)

	// Find a standby to kill
	standbyPort := h.GetStandbyPort(t)
	nodeNum := h.NodeNumberForPort(standbyPort)

	// Kill the standby
	h.KillNode(t, nodeNum, "TERM")
	defer func() {
		h.RestartNode(t, nodeNum)
		h.WaitForCluster(t, 30, 1e9) // 1s delay
	}()

	// Wait a moment for the node to go down
	h.WaitForNodeStatus(t, standbyPort, 0, 10, 500e6) // expect unreachable (status 0)

	// Requests through LB should still succeed (routed to healthy nodes)
	jwt := h.GetDefaultJWT(t)
	status, body := h.VaultTransparentRequestViaLB(t, "GET",
		"secret/data/e2e/app-config", "e2e-reader", jwt)
	if status != 200 {
		t.Fatalf("expected 200 through LB with one node down, got %d: %s", status, string(body))
	}
}
