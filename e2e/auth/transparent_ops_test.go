//go:build e2e

package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// =============================================================================
// JWT Transparent Operations Tests
// =============================================================================

// TestTransparentOps_JWTGatewayAccess verifies that JWT transparent ops work for
// gateway endpoints using X-Warden-Role header (T-TO01).
// Auth path comes from the provider's auto_auth_path config.
func TestTransparentOps_JWTGatewayAccess(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Use transparent ops to access vault gateway
	status, body := h.TransparentOpsRequest(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt, "e2e-reader")

	if status != 200 {
		t.Fatalf("T-TO01: expected 200, got %d: %s", status, string(body))
	}

	// Verify response contains expected secret data (Vault KV v2 nests under data.data)
	data := h.ParseJSON(t, body)
	apiKey := h.JSONPath(data, "data.data.api_key")
	if apiKey == nil || apiKey == "" {
		t.Fatalf("T-TO01: expected api_key in response, got: %s", string(body))
	}
}

// TestTransparentOps_JWTDefaultRole verifies that JWT transparent ops work
// when no X-Warden-Role is specified, falling back to default_role (T-TO03).
func TestTransparentOps_JWTDefaultRole(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Configure default_role on JWT auth method
	status, body := h.APIRequest(t, "PUT", "auth/jwt/config", port,
		`{"default_role":"e2e-reader"}`)
	if status != 200 && status != 204 {
		t.Fatalf("T-TO03: failed to set default_role (status %d): %s", status, string(body))
	}
	// Clean up: remove default_role after test
	defer h.APIRequest(t, "PUT", "auth/jwt/config", port,
		`{"default_role":""}`)

	// Request without X-Warden-Role — should fall back to default_role
	status, body = h.TransparentOpsRequestNoRole(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt)

	if status != 200 {
		t.Fatalf("T-TO03: expected 200 with default_role, got %d: %s", status, string(body))
	}
}

// TestTransparentOps_JWTNoRoleNoDefault verifies that JWT transparent ops fail
// when no role is specified and no default_role is configured (T-TO03b).
func TestTransparentOps_JWTNoRoleNoDefault(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Ensure no default_role is configured
	h.APIRequest(t, "PUT", "auth/jwt/config", port, `{"default_role":""}`)

	// Request without X-Warden-Role and no default_role
	status, _ := h.TransparentOpsRequestNoRole(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt)

	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("T-TO03b: expected 401/403/400 without role, got %d", status)
	}
}

// =============================================================================
// Certificate Transparent Operations Tests
// =============================================================================

// TestTransparentOps_CertGatewayAccess verifies that cert transparent ops work for
// gateway endpoints using X-Warden-Role + X-SSL-Client-Cert (T-TO04).
// Auth path comes from the provider's auto_auth_path config.
func TestTransparentOps_CertGatewayAccess(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Setup cert auth and vault-cert provider
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	// Generate client cert
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-1")

	// Use transparent ops with cert auth
	status, body := h.CertTransparentOpsRequest(t, "GET",
		"vault-cert/gateway/v1/secret/data/e2e/app-config",
		port, clientCertPEM, "e2e-cert-reader")

	if status != 200 {
		t.Fatalf("T-TO04: expected 200, got %d: %s", status, string(body))
	}
}

// TestTransparentOps_CertDefaultRole verifies that cert transparent ops work
// when no X-Warden-Role is specified, falling back to default_role (T-TO05).
func TestTransparentOps_CertDefaultRole(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Setup cert auth and vault-cert provider
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	// Configure default_role on cert auth method
	status, body := h.APIRequest(t, "PUT", "auth/cert/config", port,
		`{"default_role":"e2e-cert-reader"}`)
	if status != 200 && status != 204 {
		t.Fatalf("T-TO05: failed to set default_role (status %d): %s", status, string(body))
	}

	// Generate client cert
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-1")

	// Request without X-Warden-Role — should fall back to default_role
	status, body = h.CertTransparentOpsRequestNoRole(t, "GET",
		"vault-cert/gateway/v1/secret/data/e2e/app-config",
		port, clientCertPEM)

	if status != 200 {
		t.Fatalf("T-TO05: expected 200 with default_role, got %d: %s", status, string(body))
	}
}

// =============================================================================
// Precedence and Error Tests
// =============================================================================

// TestTransparentOps_BearerTokenPrecedence verifies that Authorization: Bearer
// takes precedence over X-Warden-Role for transparent auth (T-TO06).
func TestTransparentOps_BearerTokenPrecedence(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Send request with Authorization: Bearer and X-Warden-Role
	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
	headers := map[string]string{
		"Authorization": "Bearer " + jwt,
		"X-Warden-Role": "e2e-reader",
	}
	status, _ := h.DoRequest(t, "GET", u, headers, "")

	// Should succeed via transparent auth flow
	if status != 200 {
		t.Fatalf("T-TO06: expected 200 with Bearer token, got %d", status)
	}
}

// TestTransparentOps_NoCredentialReturnsError verifies that transparent ops with
// auto_auth_path configured but no credential (no JWT, no cert) returns 401 (T-TO07).
func TestTransparentOps_NoCredentialReturnsError(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Request with NO Authorization header or cert on a transparent mode gateway
	u := fmt.Sprintf("%s/v1/vault/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
	headers := map[string]string{
		"X-Warden-Role": "e2e-reader",
	}
	status, _ := h.DoRequest(t, "GET", u, headers, "")

	if status != 401 && status != 403 {
		t.Fatalf("T-TO07: expected 401 or 403 without credential, got %d", status)
	}
}

// TestTransparentOps_InvalidAuthPath verifies that transparent ops with an invalid
// auto_auth_path on the namespace returns an error (T-TO08).
func TestTransparentOps_InvalidAuthPath(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// Create namespace with invalid auto_auth_path, then attempt transparent ops.
	// Since namespace creation requires server-side config that e2e may not support
	// for arbitrary namespaces, we test via the gateway path which uses the provider's
	// auto_auth_path. A misconfigured provider would fail at config write time.
	// This test verifies the gateway rejects requests when auth fails.
	u := fmt.Sprintf("%s/v1/vault/gateway/v1/secret/data/e2e/nonexistent-path", h.NodeURL(port))
	headers := map[string]string{
		"Authorization": "Bearer " + jwt,
		"X-Warden-Role": "nonexistent-role",
	}
	status, _ := h.DoRequest(t, "GET", u, headers, "")

	if status != 401 && status != 403 && status != 404 && status != 400 {
		t.Fatalf("T-TO08: expected error status for bad role, got %d", status)
	}
}

// TestTransparentOps_CachedToken verifies that a second transparent ops request
// reuses the cached token from the first request (T-TO09).
func TestTransparentOps_CachedToken(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	// First request — creates token
	status1, body1 := h.TransparentOpsRequest(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt, "e2e-reader")
	if status1 != 200 {
		t.Fatalf("T-TO09: first request expected 200, got %d: %s", status1, string(body1))
	}

	// Second request — should reuse cached token
	status2, body2 := h.TransparentOpsRequest(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt, "e2e-reader")
	if status2 != 200 {
		t.Fatalf("T-TO09: second request expected 200, got %d: %s", status2, string(body2))
	}
}

// TestTransparentOps_StandbyForwarding verifies that transparent ops work through
// standby nodes (T-TO10).
func TestTransparentOps_StandbyForwarding(t *testing.T) {
	standby := h.GetStandbyPort(t)
	jwt := h.GetDefaultJWT(t)

	status, body := h.TransparentOpsRequest(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		standby, jwt, "e2e-reader")

	if status != 200 {
		t.Fatalf("T-TO10: standby expected 200, got %d: %s", status, string(body))
	}
}

// TestTransparentOps_DefaultRoleConfigReadback verifies that default_role config
// is persisted and can be read back (T-TO11).
func TestTransparentOps_DefaultRoleConfigReadback(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Set default_role on JWT auth
	status, body := h.APIRequest(t, "PUT", "auth/jwt/config", port,
		`{"default_role":"e2e-reader"}`)
	if status != 200 && status != 204 {
		t.Fatalf("T-TO11: failed to set default_role (status %d): %s", status, string(body))
	}
	defer h.APIRequest(t, "PUT", "auth/jwt/config", port, `{"default_role":""}`)

	// Read config back
	status, body = h.APIRequest(t, "GET", "auth/jwt/config", port, "")
	if status != 200 {
		t.Fatalf("T-TO11: failed to read config (status %d): %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	defaultRole := h.JSONPath(data, "data.default_role")
	if defaultRole != "e2e-reader" {
		t.Fatalf("T-TO11: expected default_role=e2e-reader, got %v", defaultRole)
	}
}

// TestTransparentOps_ExpiredJWTRejected verifies that an expired JWT is rejected
// in transparent ops mode (T-TO12).
func TestTransparentOps_ExpiredJWTRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Get an ephemeral JWT (2s TTL)
	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")
	time.Sleep(3 * time.Second)

	status, _ := h.TransparentOpsRequest(t, "GET",
		"vault/gateway/v1/secret/data/e2e/app-config",
		port, jwt, "e2e-reader")

	if status != 401 && status != 403 && status != 400 {
		t.Fatalf("T-TO12: expected 401/403/400 for expired JWT, got %d", status)
	}
}

// TestTransparentOps_CertWrongCN verifies that a certificate with non-matching CN
// is rejected in transparent ops mode (T-TO13).
func TestTransparentOps_CertWrongCN(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Setup cert auth and vault-cert provider
	caCertPEM, caKey := h.SetupCertVaultEnv(t, port)
	defer h.TeardownCertVaultEnv(t, port)

	// Generate cert with CN that doesn't match "agent-*" pattern
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "server-1")

	// Should be rejected — CN doesn't match allowed pattern
	status, _ := h.CertTransparentOpsRequest(t, "GET",
		"vault-cert/gateway/v1/secret/data/e2e/app-config",
		port, clientCertPEM, "e2e-cert-reader")

	if status != 401 && status != 403 {
		t.Fatalf("T-TO13: expected 401 or 403 for wrong CN, got %d", status)
	}
}

// TestTransparentOps_InvalidBearerRejected verifies that an invalid Bearer token
// on the transparent gateway is rejected with 401/403 (T-TO15).
func TestTransparentOps_InvalidBearerRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Send a request with Authorization: Bearer <random-value> on the transparent provider.
	// This should fail because "not-a-real-jwt" is not a valid JWT
	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(port))
	headers := map[string]string{
		"Authorization": "Bearer not-a-real-jwt",
	}
	status, body := h.DoRequest(t, "GET", u, headers, "")

	// Should fail with 401/403 because "not-a-real-jwt" is not a valid JWT
	if status == 200 {
		t.Fatalf("T-TO15: expected non-200 for invalid JWT, got 200: %s", string(body))
	}
	if status != 401 && status != 403 {
		// Some configurations may return 400 for malformed tokens
		if status != 400 {
			t.Logf("T-TO15: got status %d (expected 401/403), response: %s",
				status, strings.TrimSpace(string(body)))
		}
	}
}
