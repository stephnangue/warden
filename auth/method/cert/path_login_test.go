package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testLogger creates a logger for tests that discards output
func testLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gateConfig := logger.GatedWriterConfig{
		Underlying: io.Discard,
	}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

// inmemStorage implements sdklogical.Storage for testing
type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{
		data: make(map[string]*sdklogical.StorageEntry),
	}
}

func (s *inmemStorage) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}

func (s *inmemStorage) Get(_ context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(_ context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *inmemStorage) ListPage(_ context.Context, prefix string, _ string, _ int) ([]string, error) {
	return s.List(context.Background(), prefix)
}

var _ sdklogical.Storage = (*inmemStorage)(nil)

// testCA generates a test CA certificate and key.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)

	// PEM encode
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return cert, key, string(pemBytes)
}

// testClientCert generates a client certificate signed by the given CA.
func testClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, opt := range opts {
		opt(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func TestValidateCertConstraints_AllowedCommonNames(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent-1")

	// Matching glob pattern
	role := &CertRole{AllowedCommonNames: []string{"agent-*"}}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for matching CN, got: %v", err)
	}

	// Non-matching glob pattern
	role = &CertRole{AllowedCommonNames: []string{"server-*"}}
	if err := validateCertConstraints(cert, role); err == nil {
		t.Fatal("expected error for non-matching CN")
	}

	// Empty constraint (should pass)
	role = &CertRole{}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for empty constraints, got: %v", err)
	}
}

func TestValidateCertConstraints_AllowedDNSSANs(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		tmpl.DNSNames = []string{"agent.example.com"}
	})

	// Matching glob
	role := &CertRole{AllowedDNSSANs: []string{"*.example.com"}}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for matching DNS SAN, got: %v", err)
	}

	// Non-matching
	role = &CertRole{AllowedDNSSANs: []string{"*.other.com"}}
	if err := validateCertConstraints(cert, role); err == nil {
		t.Fatal("expected error for non-matching DNS SAN")
	}
}

func TestValidateCertConstraints_AllowedEmailSANs(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		tmpl.EmailAddresses = []string{"agent@example.com"}
	})

	role := &CertRole{AllowedEmailSANs: []string{"*@example.com"}}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for matching email SAN, got: %v", err)
	}

	role = &CertRole{AllowedEmailSANs: []string{"*@other.com"}}
	if err := validateCertConstraints(cert, role); err == nil {
		t.Fatal("expected error for non-matching email SAN")
	}
}

func TestValidateCertConstraints_AllowedURISANs(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		u, _ := url.Parse("spiffe://example.com/dept/team/agent")
		tmpl.URIs = append(tmpl.URIs, u)
	})

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Prefix wildcard
		{"prefix match", "spiffe://example.com/dept/*", false},
		{"prefix mismatch domain", "spiffe://other.com/dept/*", true},
		{"prefix mismatch path", "spiffe://example.com/other/*", true},

		// Segment wildcard (+)
		{"plus trust domain", "spiffe://+/dept/team/agent", false},
		{"plus middle segment", "spiffe://example.com/+/team/agent", false},
		{"plus multiple", "spiffe://+/+/+/agent", false},
		{"plus mismatch", "spiffe://+/other/team/agent", true},

		// Catch-all
		{"scheme catch-all", "spiffe://*", false},
		{"scheme catch-all wrong scheme", "https://*", true},

		// Exact match
		{"exact match", "spiffe://example.com/dept/team/agent", false},
		{"exact mismatch", "spiffe://example.com/dept/team/other", true},

		// Combined + and *
		{"plus and star", "spiffe://+/dept/*", false},
		{"plus and star mismatch", "spiffe://+/other/*", true},

		// Empty constraint (should pass)
		{"empty constraint", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var role *CertRole
			if tc.pattern == "" {
				role = &CertRole{}
			} else {
				role = &CertRole{AllowedURISANs: []string{tc.pattern}}
			}
			err := validateCertConstraints(cert, role)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for pattern %q, got nil", tc.pattern)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for pattern %q, got: %v", tc.pattern, err)
			}
		})
	}
}

func TestValidateCertConstraints_AllowedOrganizationalUnits(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		tmpl.Subject.OrganizationalUnit = []string{"Engineering"}
	})

	role := &CertRole{AllowedOrganizationalUnits: []string{"Engineering"}}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for matching OU, got: %v", err)
	}

	role = &CertRole{AllowedOrganizationalUnits: []string{"Marketing"}}
	if err := validateCertConstraints(cert, role); err == nil {
		t.Fatal("expected error for non-matching OU")
	}
}

func TestValidateCertConstraints_AllowedOrganizations(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		tmpl.Subject.Organization = []string{"Acme Corp"}
	})

	role := &CertRole{AllowedOrganizations: []string{"Acme Corp"}}
	if err := validateCertConstraints(cert, role); err != nil {
		t.Fatalf("expected no error for matching org, got: %v", err)
	}

	role = &CertRole{AllowedOrganizations: []string{"Other Corp"}}
	if err := validateCertConstraints(cert, role); err == nil {
		t.Fatal("expected error for non-matching org")
	}
}

func TestExtractPrincipal(t *testing.T) {
	caCert, caKey, _ := testCA(t)

	cert := testClientCert(t, caCert, caKey, "my-agent", func(tmpl *x509.Certificate) {
		tmpl.DNSNames = []string{"agent.example.com"}
		tmpl.EmailAddresses = []string{"agent@example.com"}
		u, _ := url.Parse("spiffe://example.com/agent")
		tmpl.URIs = append(tmpl.URIs, u)
	})

	tests := []struct {
		claim    string
		expected string
	}{
		{"cn", "my-agent"},
		{"dns_san", "agent.example.com"},
		{"email_san", "agent@example.com"},
		{"uri_san", "spiffe://example.com/agent"},
		{"spiffe_id", "spiffe://example.com/agent"},
		{"serial", cert.SerialNumber.String()},
		{"unknown", ""},
	}

	for _, tc := range tests {
		t.Run(tc.claim, func(t *testing.T) {
			result := extractPrincipal(cert, tc.claim)
			if result != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestMatchesGlob(t *testing.T) {
	tests := []struct {
		value    string
		patterns []string
		expected bool
	}{
		{"agent-1", []string{"agent-*"}, true},
		{"agent-1", []string{"server-*"}, false},
		{"agent-1", []string{"server-*", "agent-*"}, true},
		{"exact-match", []string{"exact-match"}, true},
		{"foo", []string{}, false},
	}

	for _, tc := range tests {
		result := matchesGlob(tc.value, tc.patterns)
		if result != tc.expected {
			t.Fatalf("matchesGlob(%q, %v) = %v, want %v", tc.value, tc.patterns, result, tc.expected)
		}
	}
}

func TestMatchesAnyExact(t *testing.T) {
	tests := []struct {
		values   []string
		allowed  []string
		expected bool
	}{
		{[]string{"Engineering"}, []string{"Engineering", "Sales"}, true},
		{[]string{"Marketing"}, []string{"Engineering", "Sales"}, false},
		{[]string{"A", "B"}, []string{"B"}, true},
		{[]string{}, []string{"A"}, false},
	}

	for _, tc := range tests {
		result := matchesAnyExact(tc.values, tc.allowed)
		if result != tc.expected {
			t.Fatalf("matchesAnyExact(%v, %v) = %v, want %v", tc.values, tc.allowed, result, tc.expected)
		}
	}
}

func TestCertFingerprint(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	cert := testClientCert(t, caCert, caKey, "fingerprint-test")

	fp1 := certFingerprint(cert)
	fp2 := certFingerprint(cert)

	if fp1 == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if fp1 != fp2 {
		t.Fatal("fingerprint should be deterministic")
	}

	// Different cert → different fingerprint
	cert2 := testClientCert(t, caCert, caKey, "fingerprint-test-2")
	fp3 := certFingerprint(cert2)
	if fp1 == fp3 {
		t.Fatal("different certs should have different fingerprints")
	}
}

// =============================================================================
// Default Role Fallback Tests
// =============================================================================

func TestHandleLogin_DefaultRoleFallback(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	t.Run("uses default_role when role is empty", func(t *testing.T) {
		storage := newInmemStorage()
		conf := &logical.BackendConfig{
			Logger:      testLogger(),
			StorageView: storage,
		}
		backend, err := Factory(context.Background(), conf)
		require.NoError(t, err)
		b := backend.(*certAuthBackend)
		b.config = &CertAuthConfig{
			TrustedCAPEM:   caPEM,
			PrincipalClaim: "cn",
			TokenTTL:       time.Hour,
			DefaultRole:    "fallback-role",
		}
		b.config.caPool, _ = buildCAPool(caPEM)

		req := &logical.Request{
			HTTPRequest: newCertHTTPRequest(t, clientCert),
		}
		d := &framework.FieldData{
			Raw: map[string]any{
				"role": "",
			},
			Schema: b.pathLogin().Fields,
		}

		resp, err := b.handleLogin(context.Background(), req, d)
		require.NoError(t, err)
		require.NotNil(t, resp)
		// Should NOT get "missing role" — should proceed past role check
		if resp.Err != nil {
			assert.NotContains(t, resp.Err.Error(), "missing role")
		}
	})

	t.Run("missing role with no default_role returns error", func(t *testing.T) {
		storage := newInmemStorage()
		conf := &logical.BackendConfig{
			Logger:      testLogger(),
			StorageView: storage,
		}
		backend, err := Factory(context.Background(), conf)
		require.NoError(t, err)
		b := backend.(*certAuthBackend)
		b.config = &CertAuthConfig{
			TrustedCAPEM:   caPEM,
			PrincipalClaim: "cn",
			TokenTTL:       time.Hour,
			DefaultRole:    "",
		}

		req := &logical.Request{
			HTTPRequest: newCertHTTPRequest(t, clientCert),
		}
		d := &framework.FieldData{
			Raw: map[string]any{
				"role": "",
			},
			Schema: b.pathLogin().Fields,
		}

		resp, err := b.handleLogin(context.Background(), req, d)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "missing role")
	})
}

// newCertHTTPRequest creates an HTTP request with a client certificate in the
// X-SSL-Client-Cert forwarded header context (simulating LB forwarding).
func newCertHTTPRequest(t *testing.T, cert *x509.Certificate) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/cert/login", nil)
	// Store the cert in the context via the cert forwarding middleware's context key
	ctx := listener.WithForwardedClientCert(req.Context(), cert)
	return req.WithContext(ctx)
}
