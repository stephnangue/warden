//go:build e2e

package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// writeTempPEM writes PEM content to a temp file and returns its path.
// The file is cleaned up when the test finishes.
func writeTempPEM(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp PEM %s: %v", name, err)
	}
	return path
}

// TC-CLI-01: warden login --method=cert with --cert/--key/--role flags
func TestCLI_CertLogin_WithFlags(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-1")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	// Write the server CA cert so the CLI can verify TLS
	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT": serverCACert,
	},
		"login", "--method=cert", "--role=agent",
		"--cert="+certFile, "--key="+keyFile,
	)
	if err != nil {
		t.Fatalf("warden login --method=cert failed: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "principal_id") {
		t.Fatalf("expected principal_id in output, got: %s", out)
	}
}

// TC-CLI-02: warden login --method=cert with env vars (WARDEN_CLIENT_CERT, WARDEN_CLIENT_KEY, WARDEN_ROLE)
func TestCLI_CertLogin_WithEnvVars(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-2")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT":      serverCACert,
		"WARDEN_CLIENT_CERT": certFile,
		"WARDEN_CLIENT_KEY":  keyFile,
		"WARDEN_ROLE":        "agent",
	},
		"login", "--method=cert",
	)
	if err != nil {
		t.Fatalf("warden login --method=cert (env vars) failed: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "principal_id") {
		t.Fatalf("expected principal_id in output, got: %s", out)
	}
}

// TC-CLI-03: warden login --method=cert fails without role
func TestCLI_CertLogin_MissingRole(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-3")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT": serverCACert,
	},
		"login", "--method=cert",
		"--cert="+certFile, "--key="+keyFile,
	)
	if err == nil {
		t.Fatalf("expected error when role is missing, got success: %s", out)
	}

	if !strings.Contains(out, "role is required") {
		t.Fatalf("expected 'role is required' error, got: %s", out)
	}
}

// TC-CLI-04: warden login --method=cert with wrong CN is rejected
func TestCLI_CertLogin_WrongCN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	// Generate cert with CN that doesn't match the role's allowed_common_names
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "unauthorized-user")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	_, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT": serverCACert,
	},
		"login", "--method=cert", "--role=agent",
		"--cert="+certFile, "--key="+keyFile,
	)
	if err == nil {
		t.Fatal("expected error for wrong CN, but login succeeded")
	}
}

// TC-CLI-05: warden login --method=cert with global -r flag
func TestCLI_CertLogin_GlobalRoleFlag(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-5")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	// Use -r (global shorthand) instead of --role
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT": serverCACert,
	},
		"-r", "agent", "login", "--method=cert",
		"--cert="+certFile, "--key="+keyFile,
	)
	if err != nil {
		t.Fatalf("warden -r agent login --method=cert failed: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "principal_id") {
		t.Fatalf("expected principal_id in output, got: %s", out)
	}
}

// TC-CLI-06: warden login --method=cert via mTLS (no --cert/--key, uses WARDEN_CLIENT_CERT/KEY env)
func TestCLI_CertLogin_MTLS(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Use the mTLS client CA so the TLS handshake succeeds (server trusts this CA)
	caCertPEM, caKey := h.LoadMTLSClientCA(t)

	// Mount cert auth with the mTLS CA
	h.SetupCertAuthWithCA(t, port, caCertPEM)
	defer h.TeardownCertAuth(t, port)

	// Create role
	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-mtls")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")

	// No --cert/--key flags — client cert comes from env vars and goes through TLS handshake
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_CACERT":      serverCACert,
		"WARDEN_CLIENT_CERT": certFile,
		"WARDEN_CLIENT_KEY":  keyFile,
		"WARDEN_ROLE":        "agent",
	},
		"login", "--method=cert",
	)
	if err != nil {
		t.Fatalf("warden login --method=cert (mTLS) failed: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "principal_id") {
		t.Fatalf("expected principal_id in output, got: %s", out)
	}
}

// =============================================================================
// Transparent Operations via CLI over mTLS with Privilege Escalation
// =============================================================================

const cliOpsNamespace = "e2e-cli-ops"

// setupCLITransparentOpsEnv sets up a namespace-level transparent operations
// environment for CLI privilege escalation tests:
//   - Namespace "e2e-cli-ops" with auto_auth_path="auth/cert/"
//   - Cert auth mounted with mTLS client CA, default_role="reader"
//   - reader role (read-only Warden API access, long-lived 1h token)
//   - admin role (full Warden API access, short-lived 2m token)
//
// The reader role is set as default_role, so reads don't require --role or
// WARDEN_ROLE. Only writes use --role=admin to escalate privileges.
//
// Returns temp file paths for the client cert and key (signed by the mTLS CA).
func setupCLITransparentOpsEnv(t *testing.T, port int) (clientCertFile, clientKeyFile string) {
	t.Helper()
	ns := cliOpsNamespace

	// Create namespace with auto_auth_path for transparent operations
	h.APIRequest(t, "POST", "sys/namespaces/"+ns, port,
		`{"custom_metadata":{"auto_auth_path":"auth/cert/"}}`)

	// Mount cert auth with mTLS client CA
	caCertPEM, caKey := h.LoadMTLSClientCA(t)

	status, body := h.NSAPIRequest(t, "POST", "sys/auth/cert", ns, port, `{"type":"cert"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("failed to mount cert auth in namespace (status %d): %s", status, string(body))
	}

	escapedPEM := strings.ReplaceAll(caCertPEM, "\n", "\\n")
	configBody := fmt.Sprintf(`{"trusted_ca_pem":"%s","default_role":"reader"}`, escapedPEM)
	status, body = h.NSAPIRequest(t, "PUT", "auth/cert/config", ns, port, configBody)
	if status != 200 && status != 204 {
		t.Fatalf("failed to configure cert auth in namespace (status %d): %s", status, string(body))
	}

	// Reader policy: read-only on sys/ and auth/ paths
	h.NSAPIRequest(t, "POST", "sys/policies/cbp/reader-policy", ns, port,
		`{"policy":"path \"sys/*\" {\n  capabilities = [\"read\", \"list\"]\n}\npath \"auth/*\" {\n  capabilities = [\"read\", \"list\"]\n}"}`)

	// Admin policy: full access on sys/ and auth/ paths
	h.NSAPIRequest(t, "POST", "sys/policies/cbp/admin-policy", ns, port,
		`{"policy":"path \"sys/*\" {\n  capabilities = [\"read\", \"create\", \"update\", \"delete\", \"list\"]\n}\npath \"auth/*\" {\n  capabilities = [\"read\", \"create\", \"update\", \"delete\", \"list\"]\n}"}`)

	// Reader cert role: long-lived (1h), read-only.
	// Must use cert_role token type for transparent mode — LookupCertTokenWithRole
	// computes a deterministic ID from fingerprint+role, which requires cert_role.
	h.NSAPIRequest(t, "POST", "auth/cert/role/reader", ns, port,
		`{"allowed_common_names":["agent-*"],"token_policies":["reader-policy"],"token_type":"transparent","token_ttl":3600}`)

	// Admin cert role: short-lived (2m), full access
	h.NSAPIRequest(t, "POST", "auth/cert/role/admin", ns, port,
		`{"allowed_common_names":["agent-*"],"token_policies":["admin-policy"],"token_type":"transparent","token_ttl":120}`)

	// Generate client cert signed by mTLS CA
	clientCertPEM, clientKeyPEM := h.GenerateClientCert(t, caCertPEM, caKey, "agent-cli-ops")
	certFile := writeTempPEM(t, "client.crt", clientCertPEM)
	keyFile := writeTempPEM(t, "client.key", clientKeyPEM)

	return certFile, keyFile
}

func teardownCLITransparentOpsEnv(t *testing.T, port int) {
	t.Helper()
	ns := cliOpsNamespace

	// Cleanup within namespace
	h.NSAPIRequest(t, "DELETE", "auth/cert/role/reader", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "auth/cert/role/admin", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/auth/cert", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/reader-policy", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/admin-policy", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/e2e-test-created", ns, port, "")
	time.Sleep(1 * time.Second)

	// Delete namespace
	h.CleanupNamespaces(t, port, ns)
}

// TC-CLI-07: Transparent operations via CLI over mTLS with privilege escalation.
// Reader role is the default (no --role needed for reads).
// Admin role requires --role=admin flag for writes.
// Operates on Warden's own API (namespace-level transparent operations), not gateway.
func TestCLI_TransparentOps_PrivilegeEscalation(t *testing.T) {
	port := h.GetLeaderPort(t)
	certFile, keyFile := setupCLITransparentOpsEnv(t, port)
	defer teardownCLITransparentOpsEnv(t, port)

	serverCACert := filepath.Join(h.E2EDir(), ".certs", "server.crt")
	env := map[string]string{
		"WARDEN_CACERT":      serverCACert,
		"WARDEN_CLIENT_CERT": certFile,
		"WARDEN_CLIENT_KEY":  keyFile,
		"WARDEN_NAMESPACE":   cliOpsNamespace,
	}

	// Step 1: Read cert auth config — no --role needed (default_role=reader)
	out, err := h.WardenCLIWithPort(t, port, env,
		"read", "-f", "json", "auth/cert/config")
	if err != nil {
		t.Fatalf("Step 1: read auth/cert/config failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "trusted_ca_pem") {
		t.Fatalf("Step 1: expected trusted_ca_pem in output, got: %s", out)
	}

	// Step 2: Create a policy with --role=admin (escalate to write access)
	out, err = h.WardenCLIWithPort(t, port, env,
		"--role", "admin", "write", "sys/policies/cbp/e2e-test-created",
		`policy=path "sys/health" { capabilities = ["read"] }`)
	if err != nil {
		t.Fatalf("Step 2: write policy with --role=admin failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "Success") {
		t.Fatalf("Step 2: expected success message, got: %s", out)
	}

	// Step 3: Read back the created policy — default reader role
	out, err = h.WardenCLIWithPort(t, port, env,
		"read", "-f", "json", "sys/policies/cbp/e2e-test-created")
	if err != nil {
		t.Fatalf("Step 3: read back policy failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "sys/health") {
		t.Fatalf("Step 3: expected policy content in output, got: %s", out)
	}

	// Step 4: Verify default reader role cannot write
	_, err = h.WardenCLIWithPort(t, port, env,
		"write", "sys/policies/cbp/e2e-test-forbidden",
		`policy=path "sys/health" { capabilities = ["read"] }`)
	if err == nil {
		t.Fatal("Step 4: expected write with default reader role to fail, but it succeeded")
	}
}
