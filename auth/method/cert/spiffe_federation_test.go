package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// marshalBundle produces a SPIFFE trust-bundle (JWKS) document for tdName carrying
// the given authorities, with an optional sequence number.
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

func spiffeFederationBackend(t *testing.T) (*certAuthBackend, context.Context) {
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))
	return b, ctx
}

func writeTrustDomain(t *testing.T, b *certAuthBackend, ctx context.Context, raw map[string]any) *logical.Response {
	t.Helper()
	d := &framework.FieldData{Raw: raw, Schema: b.pathSPIFFETrustDomain().Fields}
	resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	return resp
}

func refreshTrustDomain(t *testing.T, b *certAuthBackend, ctx context.Context, name string) *logical.Response {
	t.Helper()
	d := &framework.FieldData{Raw: map[string]any{"name": name}, Schema: b.pathSPIFFETrustDomainRefresh().Fields}
	resp, err := b.handleTrustDomainRefresh(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	return resp
}

// --- tests ---

func TestFederation_HTTPSWeb(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	const td = "partner.example.org"
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), nil)

	b, ctx := spiffeFederationBackend(t)

	resp := writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/default/sa/api")

	// Before the first fetch the trust domain has no authorities -> fails closed.
	_, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.Error(t, err)

	rr := refreshTrustDomain(t, b, ctx, td)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	assert.Equal(t, true, rr.Data["changed"])

	// After the fetch the bundle is active and the SVID verifies.
	id, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+td+"/ns/default/sa/api", id.String())
}

func TestFederation_HTTPSSpiffe(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	const td = "partner.example.org"
	endpointID := "spiffe://" + td + "/spire/server"
	endpointCert := endpointSVIDCert(t, caCert, caKey, endpointID)
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), &endpointCert)

	b, ctx := spiffeFederationBackend(t)

	resp := writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id":      endpointID,
		"bundle_pem":              caPEM, // bootstrap, authenticates the endpoint SVID
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rr := refreshTrustDomain(t, b, ctx, td)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	assert.Equal(t, true, rr.Data["changed"])

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/default/sa/api")
	_, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
}

func TestFederation_HTTPSSpiffe_WrongEndpointID(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	const td = "partner.example.org"
	endpointCert := endpointSVIDCert(t, caCert, caKey, "spiffe://"+td+"/spire/server")
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), &endpointCert)

	b, ctx := spiffeFederationBackend(t)

	// Config expects a different in-domain ID than the endpoint actually presents.
	writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id":      "spiffe://" + td + "/spire/wrong",
		"bundle_pem":              caPEM,
	})

	rr := refreshTrustDomain(t, b, ctx, td)
	assert.Equal(t, http.StatusBadGateway, rr.StatusCode)
}

func TestFederation_SequenceDedup(t *testing.T) {
	caCert, _, _ := testCA(t)
	const td = "partner.example.org"
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 5), nil)

	b, ctx := spiffeFederationBackend(t)
	writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})

	first := refreshTrustDomain(t, b, ctx, td)
	assert.Equal(t, true, first.Data["changed"])

	second := refreshTrustDomain(t, b, ctx, td) // same sequence -> no change
	assert.Equal(t, false, second.Data["changed"])
}

func TestFederation_EmptyBundleKeepsLastGood(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	const td = "partner.example.org"
	good := marshalBundle(t, td, []*x509.Certificate{caCert}, 1)
	empty := marshalBundle(t, td, nil, 2) // valid bundle, but no X.509 authorities

	var body atomic.Value
	body.Store(good)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body.Load().([]byte))
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)

	b, ctx := spiffeFederationBackend(t)
	writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	require.Equal(t, http.StatusOK, refreshTrustDomain(t, b, ctx, td).StatusCode)

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/x/sa/y")
	_, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err) // good bundle is active

	// The endpoint now serves an authority-less bundle: refresh must reject it...
	body.Store(empty)
	assert.Equal(t, http.StatusBadGateway, refreshTrustDomain(t, b, ctx, td).StatusCode)

	// ...and the last-good bundle must remain active.
	_, _, err = verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
}

func TestFederation_RefreshRejectsStaticTrustDomain(t *testing.T) {
	_, _, caPEM := testCA(t)
	const td = "static.example.org"
	b, ctx := spiffeFederationBackend(t)
	writeTrustDomain(t, b, ctx, map[string]any{"name": td, "bundle_pem": caPEM})

	rr := refreshTrustDomain(t, b, ctx, td)
	assert.Equal(t, http.StatusBadRequest, rr.StatusCode)
	assert.Contains(t, rr.Err.Error(), "no bundle endpoint")
}

func TestValidateTrustDomainConfig(t *testing.T) {
	_, _, caPEM := testCA(t)
	const td = "partner.example.org"

	cases := []struct {
		name    string
		d       *SPIFFETrustDomain
		wantErr string
	}{
		{"static ok", &SPIFFETrustDomain{Name: td, BundlePEM: caPEM}, ""},
		{"static with endpoint field", &SPIFFETrustDomain{Name: td, BundlePEM: caPEM, BundleEndpointURL: "https://x"}, "require bundle_endpoint_profile"},
		{"bad profile", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "ftp", BundleEndpointURL: "https://x"}, "invalid bundle_endpoint_profile"},
		{"web missing url", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_web"}, "bundle_endpoint_url is required"},
		{"web non-https", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "http://x"}, "must be an https"},
		{"web ok no bootstrap", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "https://x"}, ""},
		{"web with endpoint id", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s"}, "not valid for the https_web"},
		{"spiffe missing id", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", BundlePEM: caPEM}, "valid endpoint_spiffe_id"},
		{"spiffe missing bootstrap", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s"}, "requires a bootstrap bundle"},
		{"spiffe id wrong domain", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://other.org/s", BundlePEM: caPEM}, "must be in trust domain"},
		{"spiffe ok", &SPIFFETrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s", BundlePEM: caPEM}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTrustDomainConfig(tc.d)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
