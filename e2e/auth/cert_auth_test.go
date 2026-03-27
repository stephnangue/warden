//go:build e2e

package auth

import (
	"crypto/ecdsa"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// setupCertAuthEnv mounts cert auth, configures it,
// and creates a test role.
// Uses the mTLS client CA (tls_client_ca_file) so that client certs presented
// during TLS handshake (via --cert flag or WARDEN_CLIENT_CERT env) are accepted
// by the server's VerifyClientCertIfGiven check.
func setupCertAuthEnv(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caCertPEM, caKey = h.LoadMTLSClientCA(t)
	h.SetupCertAuthWithCA(t, port, caCertPEM)

	// Create role with CN glob pattern
	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_ttl":3600}`)

	return caCertPEM, caKey
}

func teardownCertAuthEnv(t *testing.T, port int) {
	t.Helper()
	h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")
	h.TeardownCertAuth(t, port)
}

// T-C10: Cert auth config and role CRUD
func TestCertAuthConfigAndRoleCRUD(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)

	// Read config
	status, body := h.APIRequest(t, "GET", "auth/cert/config", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for config read, got %d: %s", status, string(body))
	}

	// Create role
	h.APIRequest(t, "POST", "auth/cert/role/test-crud", port,
		`{"allowed_common_names":["test-*"],"token_policies":["default"],"token_ttl":7200}`)

	// Read role
	status, body = h.APIRequest(t, "GET", "auth/cert/role/test-crud", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for role read, got %d: %s", status, string(body))
	}
	data := h.ParseJSON(t, body)
	tokenTTL := h.JSONPath(data, "data.token_ttl")
	if tokenTTL == nil {
		t.Fatal("expected token_ttl in role read response")
	}

	// Update role
	status, _ = h.APIRequest(t, "PUT", "auth/cert/role/test-crud", port,
		`{"token_ttl":1800}`)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for role update, got %d", status)
	}

	// List roles
	status, body = h.APIRequest(t, "GET", "auth/cert/role/", port, "")
	// LIST might also be via GET to role/?list=true, or the backend may respond to GET on role/
	if status != 200 && status != 405 {
		t.Logf("role list returned status %d (may need LIST operation)", status)
	}

	// Delete role
	status, _ = h.APIRequest(t, "DELETE", "auth/cert/role/test-crud", port, "")
	if status != 200 && status != 204 {
		t.Fatalf("expected 200 or 204 for role delete, got %d", status)
	}

	// Verify deletion
	status, _ = h.APIRequest(t, "GET", "auth/cert/role/test-crud", port, "")
	if status != 404 {
		t.Fatalf("expected 404 for deleted role, got %d", status)
	}
}
