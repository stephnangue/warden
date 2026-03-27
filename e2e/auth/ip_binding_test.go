//go:build e2e

package auth

import (
	"fmt"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// spoofedIP is a trusted proxy IP (in 172.16.0.0/12 from node configs)
// used to simulate a different client IP. It must be in trusted_proxies
// so that certForwardingMiddleware preserves X-SSL-Client-Cert headers.
const spoofedIP = "172.16.0.1"

// TestIPBinding verifies IP binding enforcement across auth methods and gateway modes.
// Tests are grouped by policy to minimize cluster restarts.
func TestIPBinding(t *testing.T) {
	port := h.GetLeaderPort(t)

	// --- Set up cert auth environment (used by cert subtests in both policies) ---
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-ip-test")
	defer h.TeardownCertVaultEnv(t, port)

	t.Run("Optional", func(t *testing.T) {
		h.SetIPBindingPolicy(t, "optional")
		port := h.GetLeaderPort(t) // leader may change after restart

		runIPBindingSubtests(t, port, clientCertPEM)
	})

	t.Run("Required", func(t *testing.T) {
		h.SetIPBindingPolicy(t, "required")
		port := h.GetLeaderPort(t)

		runIPBindingSubtests(t, port, clientCertPEM)
	})

	// Restore disabled policy for other tests
	h.RestoreIPBindingPolicy(t)
}

// runIPBindingSubtests runs all 6 subtests (2 auth methods × 1 mode × 2 IP scenarios + cert transparent).
// Transparent denial returns 401 (ErrUnauthorized from performImplicitAuth).
func runIPBindingSubtests(t *testing.T, port int, clientCertPEM string) {
	t.Helper()

	// --- JWT Transparent ---
	t.Run("JWT_T_SameIP_Allowed", func(t *testing.T) {
		jwt := h.GetDefaultJWT(t)
		status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, jwt)
		if status != 200 {
			t.Fatalf("expected 200, got %d", status)
		}
	})

	t.Run("JWT_T_DifferentIP_Denied", func(t *testing.T) {
		jwt := h.GetDefaultJWT(t)
		// First request creates the cached token with CreatedByIP=127.0.0.1
		status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, jwt)
		if status != 200 {
			t.Fatalf("setup: expected 200, got %d", status)
		}
		// Second request with different IP should be denied (401 for transparent)
		u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
		headers := map[string]string{
			"Authorization":   "Bearer " + jwt,
			"X-Forwarded-For": spoofedIP,
		}
		status, _ = h.DoRequest(t, "GET", u, headers, "")
		if status != 401 {
			t.Fatalf("expected 401, got %d", status)
		}
	})

	// --- Cert Transparent ---
	t.Run("Cert_T_SameIP_Allowed", func(t *testing.T) {
		status, _ := h.VaultCertTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
		if status != 200 {
			t.Fatalf("expected 200, got %d", status)
		}
	})

	t.Run("Cert_T_DifferentIP_Denied", func(t *testing.T) {
		// First request creates cached token with CreatedByIP=127.0.0.1
		status, _ := h.VaultCertTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-cert-reader", port, clientCertPEM)
		if status != 200 {
			t.Fatalf("setup: expected 200, got %d", status)
		}
		// Second request with different IP — must use trusted proxy IP so
		// certForwardingMiddleware preserves the X-SSL-Client-Cert header.
		u := fmt.Sprintf("%s/v1/vault-cert/role/e2e-cert-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
		headers := map[string]string{
			"X-SSL-Client-Cert": h.URLEncodePEM(clientCertPEM),
			"X-Forwarded-For":   spoofedIP,
		}
		status, _ = h.DoRequest(t, "GET", u, headers, "")
		if status != 401 {
			t.Fatalf("expected 401, got %d", status)
		}
	})
}
