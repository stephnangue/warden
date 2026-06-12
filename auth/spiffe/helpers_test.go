package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// --- logger + storage ---

func testLogger() *lgr.GatedLogger {
	config := &lgr.Config{Level: lgr.ErrorLevel, Format: lgr.JSONFormat, Outputs: []io.Writer{io.Discard}}
	gl, _ := lgr.NewGatedLogger(config, lgr.GatedWriterConfig{Underlying: io.Discard})
	return gl
}

type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{data: make(map[string]*sdklogical.StorageEntry)}
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

// newTestManager returns a Manager backed by in-memory storage.
func newTestManager(t *testing.T) (*Manager, context.Context) {
	t.Helper()
	return NewManager(newInmemStorage(), testLogger()), context.Background()
}

// --- X.509 helpers ---

func mustTD(t *testing.T, s string) spiffeid.TrustDomain {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(s)
	require.NoError(t, err)
	return td
}

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// testCA generates a test CA certificate and key, returning the cert, key, and PEM.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testClientCert generates a client certificate signed by the given CA.
func testClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, opt := range opts {
		opt(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// testSVID mints an X.509-SVID: a leaf signed by the given CA carrying exactly one
// URI SAN set to spiffeID. Extra opts can mutate the template for negative cases.
func testSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	setURI := func(tmpl *x509.Certificate) {
		u, err := url.Parse(spiffeID)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{u}
	}
	return testClientCert(t, caCert, caKey, "", append([]func(*x509.Certificate){setURI}, opts...)...)
}

// marshalBundle produces a SPIFFE trust-bundle (JWKS) document for tdName carrying
// the given X.509 authorities, with an optional sequence number.
func marshalBundle(t *testing.T, tdName string, authorities []*x509.Certificate, seq uint64) []byte {
	t.Helper()
	b := spiffebundle.FromX509Authorities(mustTD(t, tdName), authorities)
	if seq != 0 {
		b.SetSequenceNumber(seq)
	}
	out, err := b.Marshal()
	require.NoError(t, err)
	return out
}

// startBundleEndpoint serves body over TLS at any path. A non-nil tlsCert sets the
// server's certificate (used for the https_spiffe profile, where it is an SVID).
func startBundleEndpoint(t *testing.T, body []byte, tlsCert *tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	if tlsCert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*tlsCert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// endpointSVIDCert mints an X.509-SVID (single spiffe:// URI SAN) usable as a TLS
// server certificate, signed by the given CA.
func endpointSVIDCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	u, err := url.Parse(spiffeID)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// --- JWT-SVID helpers ---

// jwtAuthority is a JWT signing key plus its key ID, the issuing half of a JWT
// trust domain.
type jwtAuthority struct {
	key *ecdsa.PrivateKey
	kid string
}

func newJWTAuthority(t *testing.T) *jwtAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &jwtAuthority{key: key, kid: "kid-" + randHex(t)}
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0x0f]
	}
	return string(out)
}

// bundleJSON marshals a SPIFFE trust-bundle document for tdName carrying this
// authority's JWT public key (a JWT-SVID-only bundle), with an optional sequence.
func (a *jwtAuthority) bundleJSON(t *testing.T, tdName string, seq uint64) string {
	t.Helper()
	b := spiffebundle.New(mustTD(t, tdName))
	require.NoError(t, b.AddJWTAuthority(a.kid, a.key.Public()))
	if seq != 0 {
		b.SetSequenceNumber(seq)
	}
	out, err := b.Marshal()
	require.NoError(t, err)
	return string(out)
}

// sign produces a JWT-SVID signed by this authority: a token with the given
// subject (a SPIFFE ID), audience, and expiry.
func (a *jwtAuthority) sign(t *testing.T, sub string, aud []string, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: cryptosigner.Opaque(a.key), KeyID: a.kid}},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := jwt.Claims{
		Subject:  sub,
		Audience: aud,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(exp),
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

// --- path-handler helpers ---

func writeTrustDomain(t *testing.T, m *Manager, ctx context.Context, raw map[string]any) *logical.Response {
	t.Helper()
	d := &framework.FieldData{Raw: raw, Schema: m.pathTrustDomain().Fields}
	resp, err := m.HandleTrustDomainWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	return resp
}

func refreshTrustDomain(t *testing.T, m *Manager, ctx context.Context, name string) *logical.Response {
	t.Helper()
	d := &framework.FieldData{Raw: map[string]any{"name": name}, Schema: m.pathTrustDomainRefresh().Fields}
	resp, err := m.HandleTrustDomainRefresh(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	return resp
}
