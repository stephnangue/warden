package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiffemethod "github.com/stephnangue/warden/auth/method/spiffe"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spiffeMintCA returns a self-signed CA cert + key + its PEM, for an X.509
// trust-domain bundle.
func spiffeMintCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// spiffeMintSVID mints an X.509-SVID (single spiffe:// URI SAN) signed by the CA.
func spiffeMintSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string) *x509.Certificate {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// mountRealSpiffe mounts the real spiffe auth backend and returns a writer that
// configures it by calling the mounted backend instance directly (the same
// instance the login round-trip routes to), bypassing core's ACL. The path is
// relative to the mount (e.g. "trust-domain/example.org").
func mountRealSpiffe(t *testing.T, core *Core, ctx context.Context) func(path string, data map[string]any) {
	t.Helper()
	core.authMethods["spiffe"] = spiffemethod.Factory
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "spiffe", Path: "spiffe/"}))
	backend := core.router.MatchingBackend(ctx, "auth/spiffe/login")
	require.NotNil(t, backend, "spiffe mount not routable")
	return func(path string, data map[string]any) {
		t.Helper()
		resp, err := backend.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Data:      data,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Less(t, resp.StatusCode, 300, "write %s failed (%d): %v", path, resp.StatusCode, resp.Err)
	}
}

// TestHandleTransparentAuth_Spiffe_LoginOnMiss exercises the full case "spiffe"
// dispatch on a COLD cache: a real spiffe mount, configured with a trust domain
// and role, mints a token via the login round-trip for a fresh X.509-SVID. This
// covers the dispatch loginData/credKey wiring and the cert-branch ClientToken
// reset that the cache-hit test cannot reach.
func TestHandleTransparentAuth_Spiffe_LoginOnMiss_X509(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	write := mountRealSpiffe(t, core, ctx)

	caCert, caKey, caPEM := spiffeMintCA(t)
	write("trust-domain/example.org", map[string]any{"bundle_pem": caPEM})
	write("role/api", map[string]any{
		"trust_domain":       "example.org",
		"allowed_spiffe_ids": "spiffe://example.org/ns/+/sa/+",
		"token_policies":     "svid",
	})

	provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/spiffe/"}
	svid := spiffeMintSVID(t, caCert, caKey, "spiffe://example.org/ns/default/sa/api")
	req := spiffeReqWithCert(svid, "")

	require.NoError(t, core.handleTransparentAuth(ctx, req, provider, "api"))
	require.NotNil(t, req.TokenEntry())
	assert.Equal(t, "spiffe://example.org/ns/default/sa/api", req.TokenEntry().PrincipalID)
	// Cert auth carries no bearer; the cold-login path must set ClientToken to the ID.
	assert.Equal(t, req.TokenEntry().ID, req.ClientToken)
}

// spiffeJWTAuthority mints a JWT signing key + its JWKS trust-bundle for tdName.
func spiffeJWTAuthority(t *testing.T, tdName string) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := "kid-spiffe"
	td, err := spiffeid.TrustDomainFromString(tdName)
	require.NoError(t, err)
	b := spiffebundle.New(td)
	require.NoError(t, b.AddJWTAuthority(kid, key.Public()))
	jwks, err := b.Marshal()
	require.NoError(t, err)
	return key, kid, string(jwks)
}

func spiffeSignJWTSVID(t *testing.T, key *ecdsa.PrivateKey, kid, sub string, aud []string, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: cryptosigner.Opaque(key), KeyID: kid}},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(t, err)
	token, err := gojwt.Signed(signer).Claims(gojwt.Claims{
		Subject: sub, Audience: aud, IssuedAt: gojwt.NewNumericDate(time.Now()), Expiry: gojwt.NewNumericDate(exp),
	}).Serialize()
	require.NoError(t, err)
	return token
}

// TestHandleTransparentAuth_Spiffe_LoginOnMiss_JWT exercises the case "spiffe"
// JWT branch on a cold cache: a fresh JWT-SVID bearer mints a token via the login
// round-trip, covering the jwt-branch loginData/credKey wiring.
func TestHandleTransparentAuth_Spiffe_LoginOnMiss_JWT(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	write := mountRealSpiffe(t, core, ctx)

	key, kid, jwks := spiffeJWTAuthority(t, "example.org")
	write("trust-domain/example.org", map[string]any{"bundle_json": jwks})
	write("role/api", map[string]any{
		"trust_domain":    "example.org",
		"bound_audiences": "warden",
		"token_policies":  "svid",
	})

	provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/spiffe/"}
	token := spiffeSignJWTSVID(t, key, kid, "spiffe://example.org/ns/default/sa/api", []string{"warden"}, time.Now().Add(30*time.Minute))
	req := &logical.Request{ClientToken: token}

	require.NoError(t, core.handleTransparentAuth(ctx, req, provider, "api"))
	require.NotNil(t, req.TokenEntry())
	assert.Equal(t, "spiffe://example.org/ns/default/sa/api", req.TokenEntry().PrincipalID)
}
