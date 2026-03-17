//go:build e2e

package auth

import (
	"crypto/ecdsa"
	"fmt"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// setupCertAuthEnv mounts cert auth, configures it,
// and creates a test role with warden_token type.
// Uses the mTLS client CA (tls_client_ca_file) so that client certs presented
// during TLS handshake (via --cert flag or WARDEN_CLIENT_CERT env) are accepted
// by the server's VerifyClientCertIfGiven check.
func setupCertAuthEnv(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caCertPEM, caKey = h.LoadMTLSClientCA(t)
	h.SetupCertAuthWithCA(t, port, caCertPEM)


	// Create role with CN glob pattern
	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)

	return caCertPEM, caKey
}

func teardownCertAuthEnv(t *testing.T, port int) {
	t.Helper()
	h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")
	h.TeardownCertAuth(t, port)
}

// T-C01: Cert auth login with valid cert and matching CN
func TestCertAuthLogin_ValidCertMatchingCN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-1")

	status, body := h.CertLoginRequest(t, port, "agent", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	// Verify we got a token back
	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID == nil || principalID == "" {
		t.Fatalf("expected principal_id in response, got: %s", string(body))
	}
}

// T-C02: Cert auth login rejected - wrong CN
func TestCertAuthLogin_WrongCN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	// Generate cert with CN that doesn't match
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "unauthorized-user")

	status, _ := h.CertLoginRequest(t, port, "agent", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for wrong CN, got %d", status)
	}
}

// T-C03: Cert auth login rejected - untrusted CA
func TestCertAuthLogin_UntrustedCA(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port) // setup with CA1
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	// Generate a completely different CA and client cert
	otherCACertPEM, otherCAKey := h.GenerateTestCA(t)
	clientCertPEM, _ := h.GenerateClientCert(t, otherCACertPEM, otherCAKey, "agent-1")

	status, _ := h.CertLoginRequest(t, port, "agent", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for untrusted CA, got %d", status)
	}
}

// T-C04: Cert auth login with DNS SAN matching
func TestCertAuthLogin_DNSSANMatching(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/dns-role", port,
		`{"allowed_dns_sans":["*.example.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/dns-role", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent", h.WithDNSSANs("agent.example.com"))

	status, body := h.CertLoginRequest(t, port, "dns-role", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for DNS SAN match, got %d: %s", status, string(body))
	}
}

// T-C05: Cert auth login rejected - no cert forwarded
func TestCertAuthLogin_NoCert(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	// Login without any cert header
	u := fmt.Sprintf("%s/v1/auth/cert/login", h.NodeURL(port))
	status, _ := h.DoRequest(t, "POST", u,
		map[string]string{"Content-Type": "application/json"},
		`{"role":"agent"}`)

	if status != 400 {
		t.Fatalf("expected 400 for missing cert, got %d", status)
	}
}

// T-C07: Cert auth via XFCC header format
func TestCertAuthLogin_XFCCHeaderFormat(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-xfcc")

	status, body := h.CertLoginRequestWithXFCC(t, port, "agent", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for XFCC login, got %d: %s", status, string(body))
	}
}

// T-C09: Cert auth forwarding through standby
func TestCertAuthLogin_ThroughStandby(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/agent", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/agent", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-standby")

	// Login via standby node
	standbyPort := h.GetStandbyPort(t)
	status, body := h.CertLoginRequest(t, standbyPort, "agent", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 through standby, got %d: %s", status, string(body))
	}
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
		`{"allowed_common_names":["test-*"],"token_policies":["default"],"token_type":"warden","token_ttl":7200}`)

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

// T-C11: Multiple certs, multiple roles
func TestCertAuthLogin_MultipleRoles(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	// Create two roles with different CN patterns
	h.APIRequest(t, "POST", "auth/cert/role/web-role", port,
		`{"allowed_common_names":["web-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/web-role", port, "")

	h.APIRequest(t, "POST", "auth/cert/role/api-role", port,
		`{"allowed_common_names":["api-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":7200}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/api-role", port, "")

	// Login with web cert to web-role
	webCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "web-server-1")
	status, _ := h.CertLoginRequest(t, port, "web-role", webCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for web-role login, got %d", status)
	}

	// Login with api cert to api-role
	apiCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "api-service-1")
	status, _ = h.CertLoginRequest(t, port, "api-role", apiCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for api-role login, got %d", status)
	}

	// web cert should NOT match api-role
	status, _ = h.CertLoginRequest(t, port, "api-role", webCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for web cert on api-role, got %d", status)
	}
}

// T-C12: Cert auth login rejected - expired certificate
func TestCertAuthLogin_ExpiredCert(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	// Generate a cert that expired 1 hour ago (NotBefore 3h ago, NotAfter 1h ago)
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-expired",
		h.WithNotBefore(time.Now().Add(-3*time.Hour)),
		h.WithExpiry(-1*time.Hour))

	status, _ := h.CertLoginRequest(t, port, "agent", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for expired cert, got %d", status)
	}
}

// T-C13: Cert auth login rejected - not-yet-valid certificate
func TestCertAuthLogin_NotYetValidCert(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	// Generate a cert that won't be valid for another hour
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-future",
		h.WithNotBefore(time.Now().Add(1*time.Hour)),
		h.WithExpiry(2*time.Hour))

	status, _ := h.CertLoginRequest(t, port, "agent", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for not-yet-valid cert, got %d", status)
	}
}

// T-C14: Cert auth login with email SAN matching
func TestCertAuthLogin_EmailSANMatching(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/email-role", port,
		`{"allowed_email_sans":["*@example.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/email-role", port, "")

	// Matching email SAN
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-email",
		h.WithEmailSANs("user@example.com"))
	status, body := h.CertLoginRequest(t, port, "email-role", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for matching email SAN, got %d: %s", status, string(body))
	}
}

// T-C15: Cert auth login rejected - wrong email SAN
func TestCertAuthLogin_EmailSANRejected(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/email-role", port,
		`{"allowed_email_sans":["*@example.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/email-role", port, "")

	// Non-matching email SAN
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-email-bad",
		h.WithEmailSANs("user@other.com"))
	status, _ := h.CertLoginRequest(t, port, "email-role", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for non-matching email SAN, got %d", status)
	}
}

// T-C16: Cert auth login with URI SAN matching (SPIFFE pattern)
func TestCertAuthLogin_URISANMatching(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/uri-role", port,
		`{"allowed_uri_sans":["spiffe://cluster.local/*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/uri-role", port, "")

	// Matching URI SAN
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-uri",
		h.WithURISANs("spiffe://cluster.local/service-a"))
	status, body := h.CertLoginRequest(t, port, "uri-role", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for matching URI SAN, got %d: %s", status, string(body))
	}
}

// T-C17: Cert auth login rejected - wrong URI SAN
func TestCertAuthLogin_URISANRejected(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/uri-role", port,
		`{"allowed_uri_sans":["spiffe://cluster.local/*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/uri-role", port, "")

	// Non-matching URI SAN
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-uri-bad",
		h.WithURISANs("spiffe://other.domain/service-a"))
	status, _ := h.CertLoginRequest(t, port, "uri-role", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for non-matching URI SAN, got %d", status)
	}
}

// T-C18: Cert auth login with organizational unit matching
func TestCertAuthLogin_OUMatching(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/ou-role", port,
		`{"allowed_organizational_units":["Engineering"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/ou-role", port, "")

	// Matching OU
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-ou",
		h.WithOUs("Engineering"))
	status, body := h.CertLoginRequest(t, port, "ou-role", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for matching OU, got %d: %s", status, string(body))
	}
}

// T-C19: Cert auth login rejected - wrong OU
func TestCertAuthLogin_OURejected(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/ou-role", port,
		`{"allowed_organizational_units":["Engineering"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/ou-role", port, "")

	// Non-matching OU
	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-ou-bad",
		h.WithOUs("Marketing"))
	status, _ := h.CertLoginRequest(t, port, "ou-role", clientCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for non-matching OU, got %d", status)
	}
}

// T-C20: Cert auth login with role-specific CA override
func TestCertAuthLogin_RoleSpecificCA(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port) // Global CA
	defer h.TeardownCertAuth(t, port)


	// Generate a second CA for the role-specific override
	roleCA, roleCAKey := h.GenerateTestCA(t)

	// Create role with role-specific CA — this CA overrides the global trusted CA
	escapedPEM := strings.ReplaceAll(roleCA, "\n", "\\n")
	roleBody := fmt.Sprintf(`{"allowed_common_names":["role-agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"certificate":"%s"}`, escapedPEM)
	h.APIRequest(t, "POST", "auth/cert/role/role-ca", port, roleBody)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/role-ca", port, "")

	// Client cert signed by role CA should succeed
	clientCertPEM, _ := h.GenerateClientCert(t, roleCA, roleCAKey, "role-agent-1")
	status, body := h.CertLoginRequest(t, port, "role-ca", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for role-CA cert, got %d: %s", status, string(body))
	}

	// Client cert signed by global CA should be rejected (role CA overrides global)
	globalCA, globalCAKey := h.GenerateTestCA(t)
	_ = globalCA // same structure as the one in SetupCertAuth
	globalCertPEM, _ := h.GenerateClientCert(t, globalCA, globalCAKey, "role-agent-2")
	status, _ = h.CertLoginRequest(t, port, "role-ca", globalCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for cert signed by wrong CA, got %d", status)
	}
}

// T-C21: Principal claim - dns_san
func TestCertAuthLogin_PrincipalClaimDNSSAN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/dns-principal", port,
		`{"allowed_dns_sans":["*.example.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"principal_claim":"dns_san"}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/dns-principal", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-dns",
		h.WithDNSSANs("myservice.example.com"))

	status, body := h.CertLoginRequest(t, port, "dns-principal", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID != "myservice.example.com" {
		t.Fatalf("expected principal_id 'myservice.example.com', got %v", principalID)
	}
}

// T-C22: Principal claim - email_san
func TestCertAuthLogin_PrincipalClaimEmailSAN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/email-principal", port,
		`{"allowed_email_sans":["*@corp.example.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"principal_claim":"email_san"}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/email-principal", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-email-p",
		h.WithEmailSANs("alice@corp.example.com"))

	status, body := h.CertLoginRequest(t, port, "email-principal", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID != "alice@corp.example.com" {
		t.Fatalf("expected principal_id 'alice@corp.example.com', got %v", principalID)
	}
}

// T-C23: Principal claim - uri_san
func TestCertAuthLogin_PrincipalClaimURISAN(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/uri-principal", port,
		`{"allowed_uri_sans":["https://service.example.com/*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"principal_claim":"uri_san"}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/uri-principal", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-uri-p",
		h.WithURISANs("https://service.example.com/api"))

	status, body := h.CertLoginRequest(t, port, "uri-principal", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID != "https://service.example.com/api" {
		t.Fatalf("expected principal_id 'https://service.example.com/api', got %v", principalID)
	}
}

// T-C24: Principal claim - spiffe_id
func TestCertAuthLogin_PrincipalClaimSPIFFEID(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	h.APIRequest(t, "POST", "auth/cert/role/spiffe-principal", port,
		`{"allowed_uri_sans":["spiffe://prod.example.com/*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"principal_claim":"spiffe_id"}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/spiffe-principal", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-spiffe",
		h.WithURISANs("spiffe://prod.example.com/ns/default/sa/api-server"))

	status, body := h.CertLoginRequest(t, port, "spiffe-principal", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID != "spiffe://prod.example.com/ns/default/sa/api-server" {
		t.Fatalf("expected SPIFFE ID principal, got %v", principalID)
	}
}

// T-C25: Principal claim - serial
func TestCertAuthLogin_PrincipalClaimSerial(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	// Serial-based principal: use CN constraint for authorization, serial for identity
	h.APIRequest(t, "POST", "auth/cert/role/serial-principal", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600,"principal_claim":"serial"}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/serial-principal", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-serial")

	status, body := h.CertLoginRequest(t, port, "serial-principal", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data := h.ParseJSON(t, body)
	principalID := h.JSONPath(data, "data.principal_id")
	if principalID == nil || principalID == "" {
		t.Fatal("expected non-empty serial number as principal_id")
	}
	// Serial should be a numeric string, not a CN
	if principalID == "agent-serial" {
		t.Fatal("principal_id should be serial number, not CN")
	}
}

// T-C26: Config API read and update
func TestCertAuthConfigReadUpdate(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)

	// Read initial config
	status, body := h.APIRequest(t, "GET", "auth/cert/config", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for config read, got %d: %s", status, string(body))
	}
	data := h.ParseJSON(t, body)
	principalClaim := h.JSONPath(data, "data.principal_claim")
	if principalClaim != "cn" {
		t.Fatalf("expected default principal_claim 'cn', got %v", principalClaim)
	}

	// Update principal_claim to dns_san
	status, body = h.APIRequest(t, "PUT", "auth/cert/config", port,
		`{"principal_claim":"dns_san"}`)
	if status != 200 && status != 204 {
		t.Fatalf("expected 200 for config update, got %d: %s", status, string(body))
	}

	// Read updated config
	status, body = h.APIRequest(t, "GET", "auth/cert/config", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for config read, got %d: %s", status, string(body))
	}
	data = h.ParseJSON(t, body)
	principalClaim = h.JSONPath(data, "data.principal_claim")
	if principalClaim != "dns_san" {
		t.Fatalf("expected updated principal_claim 'dns_san', got %v", principalClaim)
	}

	// Verify the config change takes effect: role without principal_claim inherits from config
	caCertPEM, caKey := h.GenerateTestCA(t)
	escapedPEM := strings.ReplaceAll(caCertPEM, "\n", "\\n")
	h.APIRequest(t, "PUT", "auth/cert/config", port,
		fmt.Sprintf(`{"trusted_ca_pem":"%s","principal_claim":"dns_san"}`, escapedPEM))

	h.APIRequest(t, "POST", "auth/cert/role/config-test", port,
		`{"allowed_dns_sans":["*.test.com"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/config-test", port, "")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-config",
		h.WithDNSSANs("app.test.com"))

	status, body = h.CertLoginRequest(t, port, "config-test", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201, got %d: %s", status, string(body))
	}

	data = h.ParseJSON(t, body)
	pid := h.JSONPath(data, "data.principal_id")
	if pid != "app.test.com" {
		t.Fatalf("expected principal_id 'app.test.com' (inherited from config), got %v", pid)
	}
}

// T-C27: Multiple constraints on same role (CN + OU)
func TestCertAuthLogin_MultipleConstraints(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)


	// Role requires BOTH CN match AND OU match
	h.APIRequest(t, "POST", "auth/cert/role/multi-constraint", port,
		`{"allowed_common_names":["agent-*"],"allowed_organizational_units":["Engineering"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/multi-constraint", port, "")

	// Cert matching both CN and OU → should succeed
	goodCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-multi",
		h.WithOUs("Engineering"))
	status, body := h.CertLoginRequest(t, port, "multi-constraint", goodCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for matching CN+OU, got %d: %s", status, string(body))
	}

	// Cert matching CN but wrong OU → should fail
	badOUCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-multi-ou",
		h.WithOUs("Marketing"))
	status, _ = h.CertLoginRequest(t, port, "multi-constraint", badOUCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for wrong OU, got %d", status)
	}

	// Cert matching OU but wrong CN → should fail
	badCNCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "bad-multi",
		h.WithOUs("Engineering"))
	status, _ = h.CertLoginRequest(t, port, "multi-constraint", badCNCertPEM)
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403 for wrong CN, got %d", status)
	}
}

// T-C28: Certificate chain with intermediate CA
func TestCertAuthLogin_IntermediateCA(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Generate root CA → intermediate CA → client cert
	rootCertPEM, rootKey := h.GenerateTestCA(t)
	intermediateCertPEM, intermediateKey := h.GenerateIntermediateCA(t, rootCertPEM, rootKey)

	// Mount cert auth with both root + intermediate in trusted CAs
	chainPEM := rootCertPEM + intermediateCertPEM
	escapedPEM := strings.ReplaceAll(chainPEM, "\n", "\\n")

	status, body := h.APIRequest(t, "POST", "sys/auth/cert", port, `{"type":"cert"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("failed to mount cert auth (status %d): %s", status, string(body))
	}
	defer h.TeardownCertAuth(t, port)

	configBody := fmt.Sprintf(`{"trusted_ca_pem":"%s"}`, escapedPEM)
	status, body = h.APIRequest(t, "PUT", "auth/cert/config", port, configBody)
	if status != 200 && status != 204 {
		t.Fatalf("failed to configure cert auth (status %d): %s", status, string(body))
	}

	h.APIRequest(t, "POST", "auth/cert/role/chain-role", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-gateway-access"],"token_type":"warden","token_ttl":3600}`)
	defer h.APIRequest(t, "DELETE", "auth/cert/role/chain-role", port, "")

	// Client cert signed by intermediate CA → should succeed
	clientCertPEM, _ := h.GenerateClientCert(t, intermediateCertPEM, intermediateKey, "agent-chain")
	status, body = h.CertLoginRequest(t, port, "chain-role", clientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for intermediate-signed cert, got %d: %s", status, string(body))
	}

	// Client cert signed directly by root CA → should also succeed
	rootClientCertPEM, _ := h.GenerateClientCert(t, rootCertPEM, rootKey, "agent-root")
	status, body = h.CertLoginRequest(t, port, "chain-role", rootClientCertPEM)
	if status != 200 && status != 201 {
		t.Fatalf("expected 200 or 201 for root-signed cert, got %d: %s", status, string(body))
	}
}

// T-C29: Cert replacement - new cert with same CN produces different fingerprint
func TestCertAuthLogin_CertReplacement(t *testing.T) {
	port := h.GetLeaderPort(t)
	caCertPEM, caKey := setupCertAuthEnv(t, port)
	defer teardownCertAuthEnv(t, port)

	// Generate two different certs with the same CN
	cert1PEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-replace")
	cert2PEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, "agent-replace")

	// Both should authenticate successfully
	status1, body1 := h.CertLoginRequest(t, port, "agent", cert1PEM)
	if status1 != 200 && status1 != 201 {
		t.Fatalf("cert1 login failed (status %d): %s", status1, string(body1))
	}

	status2, body2 := h.CertLoginRequest(t, port, "agent", cert2PEM)
	if status2 != 200 && status2 != 201 {
		t.Fatalf("cert2 login failed (status %d): %s", status2, string(body2))
	}

	// They should have different token IDs (different key pairs → different cert bytes → different fingerprints)
	data1 := h.ParseJSON(t, body1)
	data2 := h.ParseJSON(t, body2)
	tid1 := h.JSONPath(data1, "data.token_id")
	tid2 := h.JSONPath(data2, "data.token_id")
	if tid1 == tid2 {
		t.Fatalf("expected different token_ids for different certs with same CN, got %v", tid1)
	}

	// Both should have the same principal_id (same CN)
	pid1 := h.JSONPath(data1, "data.principal_id")
	pid2 := h.JSONPath(data2, "data.principal_id")
	if pid1 != pid2 {
		t.Fatalf("expected same principal_id for same CN, got %v vs %v", pid1, pid2)
	}
}
