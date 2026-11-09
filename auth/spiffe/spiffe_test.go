package spiffe

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// parseTrustDomainBundle
// =============================================================================

func TestParseTrustDomainBundle_PEM(t *testing.T) {
	caCert, _, caPEM := testCA(t)
	bundle, err := parseTrustDomainBundle(mustTD(t, "example.org"), caPEM, "")
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)
	assert.Equal(t, caCert.Raw, bundle.X509Authorities()[0].Raw)
	assert.Empty(t, bundle.JWTAuthorities())
}

func TestParseTrustDomainBundle_JWKS(t *testing.T) {
	caCert, _, _ := testCA(t)
	td := mustTD(t, "example.org")
	jwks, err := spiffebundle.FromX509Authorities(td, []*x509.Certificate{caCert}).Marshal()
	require.NoError(t, err)

	bundle, err := parseTrustDomainBundle(td, "", string(jwks))
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)
	assert.Equal(t, caCert.Raw, bundle.X509Authorities()[0].Raw)
}

// A JWKS carrying only JWT authorities (no X.509) is a valid trust-domain bundle
// — the generalization that lets a JWT-SVID-only trust domain be configured. The
// missing X.509 material is enforced at X.509 login, not at parse time.
func TestParseTrustDomainBundle_JWTOnly(t *testing.T) {
	auth := newJWTAuthority(t)
	bundle, err := parseTrustDomainBundle(mustTD(t, "example.org"), "", auth.bundleJSON(t, "example.org", 0))
	require.NoError(t, err)
	assert.Empty(t, bundle.X509Authorities())
	assert.Len(t, bundle.JWTAuthorities(), 1)
}

func TestParseTrustDomainBundle_Errors(t *testing.T) {
	_, _, caPEM := testCA(t)
	td := mustTD(t, "example.org")

	t.Run("both provided", func(t *testing.T) {
		_, err := parseTrustDomainBundle(td, caPEM, "{}")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not both")
	})
	t.Run("neither provided", func(t *testing.T) {
		_, err := parseTrustDomainBundle(td, "", "")
		require.Error(t, err)
	})
	t.Run("invalid pem", func(t *testing.T) {
		_, err := parseTrustDomainBundle(td, "not a pem", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid certificates")
	})
	t.Run("invalid json", func(t *testing.T) {
		_, err := parseTrustDomainBundle(td, "", "not json")
		require.Error(t, err)
	})
	t.Run("empty jwks", func(t *testing.T) {
		// A document whose keys array is present but empty parses into an empty
		// bundle; parseTrustDomainBundle rejects it via the authority-presence guard.
		_, err := parseTrustDomainBundle(td, "", `{"keys":[]}`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no X.509 or JWT authorities")
	})
	t.Run("keyless jwks", func(t *testing.T) {
		// A document with no keys field at all is rejected by the parser itself.
		_, err := parseTrustDomainBundle(td, "", `{}`)
		require.Error(t, err)
	})
}

// =============================================================================
// BuildBundleSet
// =============================================================================

func TestBuildBundleSet(t *testing.T) {
	_, _, pemA := testCA(t)
	_, _, pemB := testCA(t)

	set, err := BuildBundleSet([]*TrustDomain{
		{Name: "a.example.org", BundlePEM: pemA},
		{Name: "b.example.org", BundlePEM: pemB},
	})
	require.NoError(t, err)

	for _, name := range []string{"a.example.org", "b.example.org"} {
		b, err := set.GetX509BundleForTrustDomain(mustTD(t, name))
		require.NoError(t, err, name)
		assert.Len(t, b.X509Authorities(), 1, name)
	}
}

// A JWT-only trust domain joins the set and serves the JWT verifier.
func TestBuildBundleSet_JWTOnly(t *testing.T) {
	auth := newJWTAuthority(t)
	set, err := BuildBundleSet([]*TrustDomain{
		{Name: "jwt.example.org", BundleJSON: auth.bundleJSON(t, "jwt.example.org", 0)},
	})
	require.NoError(t, err)

	b, err := set.GetJWTBundleForTrustDomain(mustTD(t, "jwt.example.org"))
	require.NoError(t, err)
	assert.Len(t, b.JWTAuthorities(), 1)
}

func TestBuildBundleSet_InvalidTrustDomain(t *testing.T) {
	_, _, caPEM := testCA(t)
	_, err := BuildBundleSet([]*TrustDomain{{Name: "Example.org", BundlePEM: caPEM}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust domain")
}

func TestBuildBundleSet_BadBundle(t *testing.T) {
	_, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: "garbage"}})
	require.Error(t, err)
}

// A federated trust domain with no bundle yet is skipped, not an error.
func TestBuildBundleSet_SkipsUnprimedFederated(t *testing.T) {
	set, err := BuildBundleSet([]*TrustDomain{
		{Name: "partner.example.org", BundleEndpointURL: "https://x", BundleEndpointProfile: bundleProfileWeb},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, set.Len())
}

// =============================================================================
// VerifyX509SVIDChain
// =============================================================================

func TestVerifyX509SVIDChain_ValidSVID(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/ns/default/sa/foo")

	id, chains, err := VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/ns/default/sa/foo", id.String())
	assert.NotEmpty(t, chains)
}

func TestVerifyX509SVIDChain_NilSet(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	svid := testSVID(t, caCert, caKey, "spiffe://example.org/foo")
	_, _, err := VerifyX509SVIDChain(nil, []*x509.Certificate{svid})
	require.Error(t, err)
}

func TestVerifyX509SVIDChain_UnknownTrustDomain(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://other.org/foo")
	_, _, err = VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.Error(t, err)
}

func TestVerifyX509SVIDChain_TwoURISANs(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/foo", func(tmpl *x509.Certificate) {
		extra, _ := url.Parse("spiffe://example.org/bar")
		tmpl.URIs = append(tmpl.URIs, extra)
	})
	_, _, err = VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one URI SAN")
}

func TestVerifyX509SVIDChain_CALeafRejected(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/foo", func(tmpl *x509.Certificate) {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
	})
	_, _, err = VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA flag")
}

func TestVerifyX509SVIDChain_WrongCA(t *testing.T) {
	_, _, pemA := testCA(t)
	caB, keyB, _ := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: pemA}})
	require.NoError(t, err)

	svid := testSVID(t, caB, keyB, "spiffe://example.org/foo")
	_, _, err = VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.Error(t, err)
}

func TestVerifyX509SVIDChain_NonSpiffeURIRejected(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := BuildBundleSet([]*TrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "https://example.org/not-spiffe")
	_, _, err = VerifyX509SVIDChain(set, []*x509.Certificate{svid})
	require.Error(t, err)
}
