//go:build e2e

package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CertOption configures optional fields on a generated client certificate.
type CertOption func(*x509.Certificate)

// WithDNSSANs adds DNS SANs to the certificate.
func WithDNSSANs(names ...string) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.DNSNames = names
	}
}

// WithEmailSANs adds email SANs to the certificate.
func WithEmailSANs(emails ...string) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.EmailAddresses = emails
	}
}

// WithURISANs adds URI SANs to the certificate.
func WithURISANs(uris ...string) CertOption {
	return func(tmpl *x509.Certificate) {
		for _, u := range uris {
			parsed, err := url.Parse(u)
			if err == nil {
				tmpl.URIs = append(tmpl.URIs, parsed)
			}
		}
	}
}

// WithOUs sets the organizational units.
func WithOUs(ous ...string) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.Subject.OrganizationalUnit = ous
	}
}

// WithOrganizations sets the organizations.
func WithOrganizations(orgs ...string) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.Subject.Organization = orgs
	}
}

// WithExpiry sets a custom validity duration.
func WithExpiry(d time.Duration) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.NotAfter = time.Now().Add(d)
	}
}

// WithNotBefore sets the certificate's NotBefore field.
func WithNotBefore(t time.Time) CertOption {
	return func(tmpl *x509.Certificate) {
		tmpl.NotBefore = t
	}
}

// GenerateTestCA creates a self-signed CA certificate and private key for testing.
func GenerateTestCA(t *testing.T) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Warden E2E Tests"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, key
}

// GenerateIntermediateCA creates an intermediate CA signed by the given root CA.
func GenerateIntermediateCA(t *testing.T, rootCertPEM string, rootKey *ecdsa.PrivateKey) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()

	// Parse root CA cert
	block, _ := pem.Decode([]byte(rootCertPEM))
	if block == nil {
		t.Fatal("failed to decode root CA cert PEM")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse root CA certificate: %v", err)
	}

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate CA key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Warden E2E Tests"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate CA certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, key
}

// GenerateClientCert creates a client certificate signed by the given CA.
func GenerateClientCert(t *testing.T, caCertPEM string, caKey *ecdsa.PrivateKey, cn string, opts ...CertOption) (certPEM string, keyPEM string) {
	t.Helper()

	// Parse CA cert
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	// Generate client key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(8 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	for _, opt := range opts {
		opt(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return certPEM, keyPEM
}

// URLEncodePEM URL-encodes a PEM string for use in X-SSL-Client-Cert header.
func URLEncodePEM(pemStr string) string {
	return url.QueryEscape(pemStr)
}

// BuildXFCCHeader builds an X-Forwarded-Client-Cert header value with the Cert field.
func BuildXFCCHeader(certPEM string) string {
	encoded := url.QueryEscape(certPEM)
	return fmt.Sprintf("Cert=%s", encoded)
}

// CertLoginRequest performs a cert auth login request with a forwarded client cert.
func CertLoginRequest(t *testing.T, port int, role string, clientCertPEM string) (int, []byte) {
	t.Helper()
	return certLoginRequestOnMount(t, port, "auth/cert", role, clientCertPEM)
}

func certLoginRequestOnMount(t *testing.T, port int, mount, role, clientCertPEM string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s/login", NodeURL(port), mount)
	headers := map[string]string{
		"Content-Type":      "application/json",
		"X-SSL-Client-Cert": URLEncodePEM(clientCertPEM),
	}
	body := fmt.Sprintf(`{"role":"%s"}`, role)
	return DoRequest(t, "POST", u, headers, body)
}

// CertLoginRequestWithXFCC performs a cert auth login using XFCC header format.
func CertLoginRequestWithXFCC(t *testing.T, port int, role string, clientCertPEM string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/auth/cert/login", NodeURL(port))
	headers := map[string]string{
		"Content-Type":            "application/json",
		"X-Forwarded-Client-Cert": BuildXFCCHeader(clientCertPEM),
	}
	body := fmt.Sprintf(`{"role":"%s"}`, role)
	return DoRequest(t, "POST", u, headers, body)
}

// SetupCertAuth mounts cert auth, configures trusted CA, and returns the CA cert/key.
// The mount defaults to cert_role token type.
func SetupCertAuth(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caCertPEM, caKey = GenerateTestCA(t)

	// Mount cert auth
	status, body := APIRequest(t, "POST", "sys/auth/cert", port, `{"type":"cert"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("failed to mount cert auth (status %d): %s", status, string(body))
	}

	// Configure trusted CA — escape the PEM for JSON
	escapedPEM := strings.ReplaceAll(caCertPEM, "\n", "\\n")
	configBody := fmt.Sprintf(`{"trusted_ca_pem":"%s"}`, escapedPEM)
	status, body = APIRequest(t, "PUT", "auth/cert/config", port, configBody)
	if status != 200 && status != 204 {
		t.Fatalf("failed to configure cert auth (status %d): %s", status, string(body))
	}

	return caCertPEM, caKey
}

// TeardownCertAuth unmounts cert auth.
func TeardownCertAuth(t *testing.T, port int) {
	t.Helper()
	APIRequest(t, "DELETE", "sys/auth/cert", port, "")
}

// VaultCertTransparentRequest makes a transparent vault gateway request using
// a client certificate in the X-SSL-Client-Cert header.
func VaultCertTransparentRequest(t *testing.T, method, vaultPath, role string, port int, clientCertPEM string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault-cert/role/%s/gateway/v1/%s", NodeURL(port), role, vaultPath)
	headers := map[string]string{
		"X-SSL-Client-Cert": URLEncodePEM(clientCertPEM),
	}
	return DoRequest(t, method, u, headers, "")
}

// gateway access.
// SetupCertVaultEnv sets up a vault provider with cert-based authentication.
// Returns the CA cert and key for generating client certificates.
func SetupCertVaultEnv(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	caCertPEM, caKey = SetupCertAuth(t, port)

	// Mount vault-cert provider
	APIRequest(t, "POST", "sys/providers/vault-cert", port, `{"type":"vault"}`)
	time.Sleep(1 * time.Second)

	// Configure vault-cert provider
	APIRequest(t, "PUT", "vault-cert/config", port,
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s"}`)

	// Configure auth path (cert auth must exist first)
	APIRequest(t, "POST", "vault-cert/config", port,
		`{"auto_auth_path":"auth/cert/"}`)

	// Policy for vault-cert gateway access
	APIRequest(t, "POST", "sys/policies/cbp/vault-cert-gateway-access", port,
		`{"policy":"path \"vault-cert/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"vault-cert/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)

	// Cert role
	APIRequest(t, "POST", "auth/cert/role/e2e-cert-reader", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-cert-gateway-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`)

	return caCertPEM, caKey
}

// TeardownCertVaultEnv removes all resources created by SetupCertVaultEnv.
func TeardownCertVaultEnv(t *testing.T, port int) {
	t.Helper()
	APIRequest(t, "DELETE", "auth/cert/role/e2e-cert-reader", port, "")
	APIRequest(t, "DELETE", "auth/cert/role/e2e-cert-login", port, "")
	TeardownCertAuth(t, port)
	APIRequest(t, "DELETE", "sys/policies/cbp/vault-cert-gateway-access", port, "")
	APIRequest(t, "DELETE", "sys/providers/vault-cert", port, "")
	time.Sleep(1 * time.Second)
}

// --- Load Balancer CA Helpers ---

// LoadLBCA loads the pre-generated LB CA certificate and key from
// e2e/loadbalancer/certs/. This CA is used by nginx to validate client
// certificates, so LB cert tests must generate client certs from this CA.
func LoadLBCA(t *testing.T) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	certPath := filepath.Join(E2EDir(), "loadbalancer", "certs", "ca.crt")
	keyPath := filepath.Join(E2EDir(), "loadbalancer", "certs", "ca.key")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to load LB CA cert: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to load LB CA key: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		t.Fatal("failed to decode LB CA key PEM")
	}

	// Handle both PKCS8 ("PRIVATE KEY" from genpkey) and SEC1 ("EC PRIVATE KEY")
	switch block.Type {
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			t.Fatalf("failed to parse LB CA PKCS8 key: %v", parseErr)
		}
		var ok bool
		caKey, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("LB CA key is not ECDSA: %T", parsed)
		}
	default:
		caKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse LB CA key: %v", err)
		}
	}

	return string(certData), caKey
}

// SetupCertAuthWithCA mounts cert auth and configures it with the given CA
// (instead of generating a new one). Use this when the CA must match what
// an external component (like the LB) trusts.
func SetupCertAuthWithCA(t *testing.T, port int, caCertPEM string) {
	t.Helper()

	status, body := APIRequest(t, "POST", "sys/auth/cert", port, `{"type":"cert"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("failed to mount cert auth (status %d): %s", status, string(body))
	}

	escapedPEM := strings.ReplaceAll(caCertPEM, "\n", "\\n")
	configBody := fmt.Sprintf(`{"trusted_ca_pem":"%s"}`, escapedPEM)
	status, body = APIRequest(t, "PUT", "auth/cert/config", port, configBody)
	if status != 200 && status != 204 {
		t.Fatalf("failed to configure cert auth (status %d): %s", status, string(body))
	}
}

// SetupCertVaultEnvWithCA sets up a vault provider with cert-based transparent
// mode using the given CA. Use this with LoadLBCA for LB tests so that nginx
// and Warden trust the same CA.
func SetupCertVaultEnvWithCA(t *testing.T, port int, caCertPEM string) {
	t.Helper()

	SetupCertAuthWithCA(t, port, caCertPEM)

	// Mount vault-cert provider
	APIRequest(t, "POST", "sys/providers/vault-cert", port, `{"type":"vault"}`)
	time.Sleep(1 * time.Second)

	// Configure vault-cert provider
	APIRequest(t, "PUT", "vault-cert/config", port,
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s"}`)

	// Configure auth path (cert auth must exist first)
	APIRequest(t, "POST", "vault-cert/config", port,
		`{"auto_auth_path":"auth/cert/"}`)

	// Policy for vault-cert gateway access
	APIRequest(t, "POST", "sys/policies/cbp/vault-cert-gateway-access", port,
		`{"policy":"path \"vault-cert/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"vault-cert/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)

	// Cert role
	APIRequest(t, "POST", "auth/cert/role/e2e-cert-reader", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-cert-gateway-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`)

	// Cert role for explicit login on the transparent cert mount
	APIRequest(t, "POST", "auth/cert/role/e2e-cert-login", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-cert-gateway-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`)
}

// --- mTLS Client CA Helpers ---

// LoadMTLSClientCA loads the pre-generated mTLS client CA certificate and key
// from e2e/.certs/. This CA is configured as the tls_client_ca_file on all
// Warden nodes, so mTLS client certs must be signed by this CA.
func LoadMTLSClientCA(t *testing.T) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	certPath := filepath.Join(E2EDir(), ".certs", "client-ca.crt")
	keyPath := filepath.Join(E2EDir(), ".certs", "client-ca.key")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to load mTLS client CA cert: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to load mTLS client CA key: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		t.Fatal("failed to decode mTLS client CA key PEM")
	}

	switch block.Type {
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			t.Fatalf("failed to parse mTLS client CA PKCS8 key: %v", parseErr)
		}
		var ok bool
		caKey, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("mTLS client CA key is not ECDSA: %T", parsed)
		}
	default:
		caKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse mTLS client CA key: %v", err)
		}
	}

	return string(certData), caKey
}

// --- mTLS Request Helpers ---

// CertLoginRequestViaMTLS performs a cert auth login via direct mTLS connection.
// The client cert is presented during the TLS handshake (not via headers).
// Warden extracts it from r.TLS.PeerCertificates via the TLS fallback.
func CertLoginRequestViaMTLS(t *testing.T, port int, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	return certLoginRequestViaMTLSOnMount(t, port, "auth/cert", role, clientCertPEM, clientKeyPEM)
}

func certLoginRequestViaMTLSOnMount(t *testing.T, port int, mount, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/%s/login", NodeURL(port), mount)
	headers := map[string]string{"Content-Type": "application/json"}
	body := fmt.Sprintf(`{"role":"%s"}`, role)
	return DoMTLSRequest(t, "POST", u, headers, body, cert)
}

// CertLoginRequestViaLBPassthrough performs a cert auth login through the nginx
// TLS passthrough port. The TLS handshake goes end-to-end to Warden, so
// r.TLS.PeerCertificates contains the client cert.
func CertLoginRequestViaLBPassthrough(t *testing.T, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/auth/cert/login", LBPassthroughURL())
	headers := map[string]string{"Content-Type": "application/json"}
	body := fmt.Sprintf(`{"role":"%s"}`, role)
	return DoMTLSRequest(t, "POST", u, headers, body, cert)
}

// VaultCertTransparentRequestViaMTLS makes a transparent vault gateway request
// via direct mTLS connection. The client cert is presented during the TLS
// handshake and extracted by Warden's TLS fallback.
func VaultCertTransparentRequestViaMTLS(t *testing.T, method, vaultPath, role string, port int, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/vault-cert/role/%s/gateway/v1/%s", NodeURL(port), role, vaultPath)
	return DoMTLSRequest(t, method, u, nil, "", cert)
}

// VaultCertTransparentRequestViaLBPassthrough makes a transparent vault gateway
// request through the nginx TLS passthrough port via mTLS.
func VaultCertTransparentRequestViaLBPassthrough(t *testing.T, method, vaultPath, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/vault-cert/role/%s/gateway/v1/%s", LBPassthroughURL(), role, vaultPath)
	return DoMTLSRequest(t, method, u, nil, "", cert)
}

// LoginJWTViaLBPassthrough logs in with a JWT through the LB passthrough port.
// No client cert — just HTTPS with InsecureSkipVerify.
func LoginJWTViaLBPassthrough(t *testing.T, jwt, role string) (int, string) {
	t.Helper()
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"%s"}`, jwt, role)
	// Use doLBHTTP (which has InsecureSkipVerify) with no client cert
	status, body := DoLBRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", LBPassthroughURL()),
		map[string]string{"Content-Type": "application/json"},
		loginBody, nil,
	)
	if status != 200 && status != 201 {
		return status, ""
	}
	data := ParseJSON(t, body)
	token, _ := JSONPath(data, "data.data.token").(string)
	if token == "" {
		token, _ = JSONPath(data, "data.token_id").(string)
	}
	return status, token
}

// VaultTransparentRequestViaLBPassthrough makes a JWT transparent vault gateway
// request through the nginx TLS passthrough port. No client cert.
func VaultTransparentRequestViaLBPassthrough(t *testing.T, method, vaultPath, role, jwt string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault/role/%s/gateway/v1/%s", LBPassthroughURL(), role, vaultPath)
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	return DoLBRequest(t, method, u, headers, "", nil)
}

// SetupCertVaultEnvWithMTLSCA sets up a vault provider with cert-based transparent
// mode using the mTLS client CA. Use this for mTLS tests where clients present
// their cert during the TLS handshake instead of via headers.
func SetupCertVaultEnvWithMTLSCA(t *testing.T, port int) {
	t.Helper()
	caCertPEM, _ := LoadMTLSClientCA(t)

	SetupCertAuthWithCA(t, port, caCertPEM)

	// Mount vault-cert provider
	APIRequest(t, "POST", "sys/providers/vault-cert", port, `{"type":"vault"}`)
	time.Sleep(1 * time.Second)

	// Configure vault-cert provider
	APIRequest(t, "PUT", "vault-cert/config", port,
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s"}`)

	// Configure auth path (cert auth must exist first)
	APIRequest(t, "POST", "vault-cert/config", port,
		`{"auto_auth_path":"auth/cert/"}`)

	// Policy for vault-cert gateway access
	APIRequest(t, "POST", "sys/policies/cbp/vault-cert-gateway-access", port,
		`{"policy":"path \"vault-cert/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"vault-cert/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)

	// Cert role
	APIRequest(t, "POST", "auth/cert/role/e2e-cert-reader", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-cert-gateway-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`)

	// Cert role for explicit login on the transparent cert mount
	APIRequest(t, "POST", "auth/cert/role/e2e-cert-login", port,
		`{"allowed_common_names":["agent-*"],"token_policies":["vault-cert-gateway-access"],"cred_spec_name":"vault-token-reader","token_ttl":3600}`)
}

// --- Cert Transparent Operations Helpers ---

// CertTransparentOpsRequest makes a transparent operations request using cert implicit auth.
// Sends client cert via X-SSL-Client-Cert header (simulating LB forwarding).
// The namespace must have auto_auth_path configured.
func CertTransparentOpsRequest(t *testing.T, method, path string, port int, clientCertPEM, role string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s", NodeURL(port), path)
	headers := map[string]string{
		"X-SSL-Client-Cert": URLEncodePEM(clientCertPEM),
		"X-Warden-Role":     role,
	}
	return DoRequest(t, method, u, headers, "")
}

// CertTransparentOpsRequestNoRole makes a transparent operations request using cert implicit auth
// without specifying a role (relies on default_role configured on the auth method).
func CertTransparentOpsRequestNoRole(t *testing.T, method, path string, port int, clientCertPEM string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s", NodeURL(port), path)
	headers := map[string]string{
		"X-SSL-Client-Cert": URLEncodePEM(clientCertPEM),
	}
	return DoRequest(t, method, u, headers, "")
}
