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

// =============================================================================
// Transparent Operations via CLI over mTLS with Privilege Escalation
// =============================================================================

const cliOpsNamespace = "e2e-cli-ops"

// setupCLITransparentOpsEnv sets up a namespace-level transparent operations
// environment for CLI privilege escalation tests:
//   - Namespace "e2e-cli-ops" with auto_auth_path="auth/cert/"
//   - Cert auth mounted with mTLS client CA
//   - reader role (read-only Warden API access)
//   - admin role (full Warden API access)
//
// Both roles are granted to agent-* certificates; the request picks one, with
// --role, since a transparent operation selects no role by default. Reads run
// under reader, and writes escalate with --role=admin.
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
	configBody := fmt.Sprintf(`{"trusted_ca_pem":"%s"}`, escapedPEM)
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

	// Reader: read-only. Admin: full access. Both granted to agent-* certs.
	agents := h.Rule{"cn": {"agent-*"}}
	h.GrantRoleInNS(t, port, ns, "auth/cert/", "reader", h.Role{Policies: []string{"reader-policy"}}, agents)
	h.GrantRoleInNS(t, port, ns, "auth/cert/", "admin", h.Role{Policies: []string{"admin-policy"}}, agents)

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
	h.RevokeRoleInNSBestEffort(port, ns, "auth/cert/", "reader")
	h.RevokeRoleInNSBestEffort(port, ns, "auth/cert/", "admin")
	h.NSAPIRequest(t, "DELETE", "sys/auth/cert", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/reader-policy", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/admin-policy", ns, port, "")
	h.NSAPIRequest(t, "DELETE", "sys/policies/cbp/e2e-test-created", ns, port, "")
	time.Sleep(1 * time.Second)

	// Delete namespace
	h.CleanupNamespaces(t, port, ns)
}

// TC-CLI-07: Transparent operations via CLI over mTLS with privilege escalation.
// Reads run under --role=reader; writes escalate with --role=admin; a request
// that selects no role is refused.
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

	// Step 0: a request that selects no role is refused: nothing picks one.
	if out, err := h.WardenCLIWithPort(t, port, env,
		"-o", "json", "read", "auth/cert/config"); err == nil {
		t.Fatalf("Step 0: expected a read without a role to be refused, got: %s", out)
	}

	// Step 1: Read cert auth config under the reader role
	out, err := h.WardenCLIWithPort(t, port, env,
		"-o", "json", "--role", "reader", "read", "auth/cert/config")
	if err != nil {
		t.Fatalf("Step 1: read auth/cert/config failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "trusted_ca_pem") {
		t.Fatalf("Step 1: expected trusted_ca_pem in output, got: %s", out)
	}

	// Step 2: Create a policy with --role=admin (escalate to write access)
	out, err = h.WardenCLIWithPort(t, port, env,
		"-o", "json", "--role", "admin", "write", "sys/policies/cbp/e2e-test-created",
		`policy=path "sys/health" { capabilities = ["read"] }`)
	if err != nil {
		t.Fatalf("Step 2: write policy with --role=admin failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, `"written": true`) {
		t.Fatalf("Step 2: expected success envelope with \"written\": true, got: %s", out)
	}

	// Step 3: Read back the created policy under the reader role
	out, err = h.WardenCLIWithPort(t, port, env,
		"-o", "json", "--role", "reader", "read", "sys/policies/cbp/e2e-test-created")
	if err != nil {
		t.Fatalf("Step 3: read back policy failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "sys/health") {
		t.Fatalf("Step 3: expected policy content in output, got: %s", out)
	}

	// Step 4: Verify the reader role cannot write
	_, err = h.WardenCLIWithPort(t, port, env,
		"-o", "json", "--role", "reader", "write", "sys/policies/cbp/e2e-test-forbidden",
		`policy=path "sys/health" { capabilities = ["read"] }`)
	if err == nil {
		t.Fatal("Step 4: expected write with the reader role to fail, but it succeeded")
	}
}
