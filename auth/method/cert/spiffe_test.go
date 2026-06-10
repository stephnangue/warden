package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSVID mints an X.509-SVID: a leaf signed by the given CA carrying exactly
// one URI SAN set to spiffeID. Extra opts can mutate the template (e.g. to make
// it a CA cert or add a second URI SAN) for negative cases.
func testSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	setURI := func(tmpl *x509.Certificate) {
		u, err := url.Parse(spiffeID)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{u}
	}
	return testClientCert(t, caCert, caKey, "", append([]func(*x509.Certificate){setURI}, opts...)...)
}

func mustTD(t *testing.T, s string) spiffeid.TrustDomain {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(s)
	require.NoError(t, err)
	return td
}

// =============================================================================
// parseTrustDomainAuthorities
// =============================================================================

func TestParseTrustDomainAuthorities_PEM(t *testing.T) {
	caCert, _, caPEM := testCA(t)
	td := mustTD(t, "example.org")

	authorities, err := parseTrustDomainAuthorities(td, caPEM, "")
	require.NoError(t, err)
	require.Len(t, authorities, 1)
	assert.Equal(t, caCert.Raw, authorities[0].Raw)
}

func TestParseTrustDomainAuthorities_JWKS(t *testing.T) {
	caCert, _, _ := testCA(t)
	td := mustTD(t, "example.org")

	// Generate a valid SPIFFE trust-bundle (JWKS) document from the CA cert.
	jwks, err := spiffebundle.FromX509Authorities(td, []*x509.Certificate{caCert}).Marshal()
	require.NoError(t, err)

	authorities, err := parseTrustDomainAuthorities(td, "", string(jwks))
	require.NoError(t, err)
	require.Len(t, authorities, 1)
	assert.Equal(t, caCert.Raw, authorities[0].Raw)
}

func TestParseTrustDomainAuthorities_Errors(t *testing.T) {
	_, _, caPEM := testCA(t)
	td := mustTD(t, "example.org")

	t.Run("both provided", func(t *testing.T) {
		_, err := parseTrustDomainAuthorities(td, caPEM, "{}")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not both")
	})
	t.Run("neither provided", func(t *testing.T) {
		_, err := parseTrustDomainAuthorities(td, "", "")
		require.Error(t, err)
	})
	t.Run("invalid pem", func(t *testing.T) {
		_, err := parseTrustDomainAuthorities(td, "not a pem", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid certificates")
	})
	t.Run("invalid json", func(t *testing.T) {
		_, err := parseTrustDomainAuthorities(td, "", "not json")
		require.Error(t, err)
	})
}

// =============================================================================
// buildBundleSet
// =============================================================================

func TestBuildBundleSet(t *testing.T) {
	_, _, pemA := testCA(t)
	_, _, pemB := testCA(t)

	set, err := buildBundleSet([]*SPIFFETrustDomain{
		{Name: "a.example.org", BundlePEM: pemA},
		{Name: "b.example.org", BundlePEM: pemB},
	})
	require.NoError(t, err)

	// Both trust domains resolve to a bundle with one authority.
	for _, name := range []string{"a.example.org", "b.example.org"} {
		b, err := set.GetX509BundleForTrustDomain(mustTD(t, name))
		require.NoError(t, err, name)
		assert.Len(t, b.X509Authorities(), 1, name)
	}
}

func TestBuildBundleSet_InvalidTrustDomain(t *testing.T) {
	_, _, caPEM := testCA(t)
	// Trust domain names must be lowercase; an uppercase letter is rejected.
	_, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "Example.org", BundlePEM: caPEM}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust domain")
}

func TestBuildBundleSet_BadBundle(t *testing.T) {
	_, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: "garbage"}})
	require.Error(t, err)
}

// =============================================================================
// verifySPIFFE
// =============================================================================

func TestVerifySPIFFE_ValidSVID(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/ns/default/sa/foo")

	id, chains, err := verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/ns/default/sa/foo", id.String())
	assert.NotEmpty(t, chains)
}

func TestVerifySPIFFE_UnknownTrustDomain(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	// Set only knows example.org; the SVID and expected TD are other.org.
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://other.org/foo")

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "other.org"), nil)
	require.Error(t, err)
}

func TestVerifySPIFFE_TrustDomainMismatch(t *testing.T) {
	_, _, pemA := testCA(t)
	caB, keyB, pemB := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{
		{Name: "example.org", BundlePEM: pemA},
		{Name: "other.org", BundlePEM: pemB},
	})
	require.NoError(t, err)

	// A genuine other.org SVID (in the set) but the role pins example.org.
	svid := testSVID(t, caB, keyB, "spiffe://other.org/foo")

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match role trust domain")
}

func TestVerifySPIFFE_TwoURISANs(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/foo", func(tmpl *x509.Certificate) {
		extra, _ := url.Parse("spiffe://example.org/bar")
		tmpl.URIs = append(tmpl.URIs, extra)
	})

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one URI SAN")
}

func TestVerifySPIFFE_CALeafRejected(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/foo", func(tmpl *x509.Certificate) {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
	})

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA flag")
}

func TestVerifySPIFFE_WrongCA(t *testing.T) {
	_, _, pemA := testCA(t)
	caB, keyB, _ := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: pemA}})
	require.NoError(t, err)

	// URI claims example.org, but the SVID is signed by an authority not in that bundle.
	svid := testSVID(t, caB, keyB, "spiffe://example.org/foo")

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.Error(t, err)
}

func TestVerifySPIFFE_NonSpiffeURIRejected(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "https://example.org/not-spiffe")

	_, _, err = verifySPIFFE(set, []*x509.Certificate{svid}, mustTD(t, "example.org"), nil)
	require.Error(t, err)
}

func TestVerifySPIFFE_AllowedSPIFFEIDs(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	set, err := buildBundleSet([]*SPIFFETrustDomain{{Name: "example.org", BundlePEM: caPEM}})
	require.NoError(t, err)

	svid := testSVID(t, caCert, caKey, "spiffe://example.org/ns/default/sa/api")
	td := mustTD(t, "example.org")

	t.Run("match", func(t *testing.T) {
		id, _, err := verifySPIFFE(set, []*x509.Certificate{svid}, td, []string{"spiffe://example.org/ns/+/sa/*"})
		require.NoError(t, err)
		assert.Equal(t, "spiffe://example.org/ns/default/sa/api", id.String())
	})
	t.Run("mismatch", func(t *testing.T) {
		_, _, err := verifySPIFFE(set, []*x509.Certificate{svid}, td, []string{"spiffe://example.org/ns/other/*"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not allowed by role")
	})
}
