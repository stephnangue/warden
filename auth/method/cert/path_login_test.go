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

	"github.com/stephnangue/warden/auth/helper/factstest"
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
// A login selects no role
// =============================================================================

// A login neither needs nor reads a role: none, an empty one, or one sent
// anyway, admits alike.
func TestHandleLogin_NoRole(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	for _, raw := range []map[string]any{{}, {"role": ""}, {"role": "explicit-role"}} {
		resp, err := b.handleLogin(context.Background(),
			&logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)},
			&framework.FieldData{Raw: raw, Schema: b.pathLogin().Fields})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "login %v: %v", raw, resp.Err)
		assert.Nil(t, resp.Auth.Policies)
		assert.NotContains(t, resp.Data, "role")
	}
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

// TestX509Login_Regression confirms the classic certificate login path
// authenticates end-to-end (ported from the removed spiffe enforcement suite).
func TestX509Login_Regression(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem":  caPEM,
		"principal_claim": "cn",
	}))

	clientCert := testClientCert(t, caCert, caKey, "inventory-svc")
	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)}
	d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "inventory-svc", resp.Auth.PrincipalID)
}

// TestSetupCertConfig_RejectsSpiffeID pins the breaking removal of the spiffe_id
// principal claim: it is no longer coerced to uri_san. A config carrying it —
// including a value persisted by an older version and reloaded via Initialize —
// is now rejected by validation. Migrate such mounts to the spiffe auth method.
func TestSetupCertConfig_RejectsSpiffeID(t *testing.T) {
	b, ctx := createTestBackend(t)
	err := b.setupCertConfig(ctx, map[string]any{"principal_claim": "spiffe_id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid principal_claim")
}

// TestHandleLogin_LegacyRoleClaimIgnored pins that a role an older version
// stored with principal_claim=spiffe_id is never read: the principal comes
// from the mount's principal_claim.
func TestHandleLogin_LegacyRoleClaimIgnored(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"trusted_ca_pem": caPEM, "principal_claim": "cn"}))
	factstest.SeedRole(t, b.storageView, "legacy", map[string]any{
		"name":                 "legacy",
		"allowed_common_names": []string{"*"},
		"principal_claim":      "spiffe_id",
		"token_ttl":            "1h",
	})

	clientCert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		u, _ := url.Parse("spiffe://example.com/ns/default/sa/agent")
		tmpl.URIs = append(tmpl.URIs, u)
	})
	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)}
	d := &framework.FieldData{Raw: map[string]any{"role": "legacy"}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.Equal(t, "agent", resp.Auth.PrincipalID)
}
