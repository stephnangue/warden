package spiffe

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

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/listener"
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

func createTestBackend(t *testing.T) (*spiffeAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), StorageView: newInmemStorage()})
	require.NoError(t, err)
	return backend.(*spiffeAuthBackend), ctx
}

// registerTD registers a static trust-domain bundle and rebuilds the set.
func registerTD(t *testing.T, b *spiffeAuthBackend, ctx context.Context, td *spiffelib.TrustDomain) {
	t.Helper()
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, td))
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
}

// --- X.509-SVID helpers ---

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
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

// testSVID mints an X.509-SVID with a single spiffe:// URI SAN, signed by the CA.
func testSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string, opts ...func(*x509.Certificate)) *x509.Certificate {
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
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	for _, opt := range opts {
		opt(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// newSVIDHTTPRequest builds a request carrying cert in the forwarded-cert context.
func newSVIDHTTPRequest(t *testing.T, cert *x509.Certificate) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/spiffe/login", nil)
	return req.WithContext(listener.WithForwardedClientCert(req.Context(), cert))
}

// --- JWT-SVID helpers ---

type jwtAuthority struct {
	key *ecdsa.PrivateKey
	kid string
}

func newJWTAuthority(t *testing.T) *jwtAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b := make([]byte, 8)
	_, err = rand.Read(b)
	require.NoError(t, err)
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = hexd[c>>4], hexd[c&0x0f]
	}
	return &jwtAuthority{key: key, kid: "kid-" + string(out)}
}

// bundleJSON marshals a SPIFFE trust-bundle for tdName carrying this authority's
// JWT public key (a JWT-SVID-only bundle).
func (a *jwtAuthority) bundleJSON(t *testing.T, tdName string) string {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(tdName)
	require.NoError(t, err)
	b := spiffebundle.New(td)
	require.NoError(t, b.AddJWTAuthority(a.kid, a.key.Public()))
	out, err := b.Marshal()
	require.NoError(t, err)
	return string(out)
}

// combinedBundle marshals a trust-bundle for tdName carrying BOTH the CA's X.509
// authority and the authority's JWT key, so one trust domain verifies both SVID
// types.
func combinedBundle(t *testing.T, tdName string, caCert *x509.Certificate, a *jwtAuthority) string {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(tdName)
	require.NoError(t, err)
	b := spiffebundle.New(td)
	b.AddX509Authority(caCert)
	require.NoError(t, b.AddJWTAuthority(a.kid, a.key.Public()))
	out, err := b.Marshal()
	require.NoError(t, err)
	return string(out)
}

// sign produces a JWT-SVID with the given subject (SPIFFE ID), audience, expiry,
// and any extra claims (e.g. groups, act).
func (a *jwtAuthority) sign(t *testing.T, sub string, aud []string, exp time.Time, extra map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: cryptosigner.Opaque(a.key), KeyID: a.kid}},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := jwt.Claims{Subject: sub, Audience: aud, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(exp)}
	builder := jwt.Signed(signer).Claims(claims)
	if len(extra) > 0 {
		builder = builder.Claims(extra)
	}
	token, err := builder.Serialize()
	require.NoError(t, err)
	return token
}

// --- login helpers ---

func x509Login(t *testing.T, b *spiffeAuthBackend, ctx context.Context, role string, svid *x509.Certificate) *logical.Response {
	t.Helper()
	req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid), ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{"role": role}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	return resp
}

func jwtLogin(t *testing.T, b *spiffeAuthBackend, ctx context.Context, role, token string) *logical.Response {
	t.Helper()
	req := &logical.Request{ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{"role": role, "jwt": token}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	return resp
}
