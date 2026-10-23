package spiffe

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jwtTD = "prod.example.org"

// unsignedJWT returns a well-formed JWT with payloadJSON and a dummy signature.
func unsignedJWT(payloadJSON string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc([]byte(payloadJSON)) + "." + enc([]byte("sig"))
}

// IsJWTSVID is the unverified detection that prefers a bearer JWT-SVID over a
// forwarded certificate.
func TestIsJWTSVID(t *testing.T) {
	assert.True(t, IsJWTSVID(unsignedJWT(`{"sub":"spiffe://example.org/ns/default/sa/api"}`)),
		"a JWT with a spiffe:// sub is a JWT-SVID")
	assert.False(t, IsJWTSVID(unsignedJWT(`{"sub":"system:serviceaccount:default:app"}`)),
		"a k8s SA token is not a JWT-SVID")
	assert.False(t, IsJWTSVID(unsignedJWT(`{"sub":"1234567890"}`)),
		"a generic OIDC JWT is not a JWT-SVID")
	assert.False(t, IsJWTSVID("not-a-jwt"), "a non-eyJ string is not a JWT")
	assert.False(t, IsJWTSVID(""), "empty is not a JWT")
	assert.False(t, IsJWTSVID("eyJ.garbage.sig"), "an unparseable JWT is rejected")
}

func TestVerifyJWTSVIDToken_Valid(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(time.Hour))

	svid, err := VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+jwtTD+"/ns/default/sa/api", svid.ID.String())
}

func TestVerifyJWTSVIDToken_AudienceIntersection(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	// Token carries two audiences; the mount accepts one of them: they intersect.
	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"aud-a", "aud-b"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"aud-b", "aud-c"})
	require.NoError(t, err)
}

func TestVerifyJWTSVIDToken_WrongAudience(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"other"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.Error(t, err)
}

func TestVerifyJWTSVIDToken_EmptyAudienceRejected(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is required")
}

func TestVerifyJWTSVIDToken_Expired(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(-time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.Error(t, err)
}

func TestVerifyJWTSVIDToken_NilSet(t *testing.T) {
	auth := newJWTAuthority(t)
	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err := VerifyJWTSVIDToken(nil, token, []string{"warden"})
	require.Error(t, err)
}

// The set has no bundle for the SVID's trust domain at all.
func TestVerifyJWTSVIDToken_UnknownTrustDomain(t *testing.T) {
	authA := newJWTAuthority(t)
	authOther := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: "a.example.org", BundleJSON: authA.bundleJSON(t, "a.example.org", 0)}})
	require.NoError(t, err)

	token := authOther.sign(t, "spiffe://other.org/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.Error(t, err)
}

// A token signed by an authority not in the trust domain's JWT bundle is rejected.
func TestVerifyJWTSVIDToken_WrongSigningKey(t *testing.T) {
	good := newJWTAuthority(t)
	rogue := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: good.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := rogue.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.Error(t, err)
}

// A trust domain configured with only an X.509 (PEM) bundle has no JWT
// authorities, so a JWT-SVID for it fails closed.
func TestVerifyJWTSVIDToken_X509OnlyBundleFailsClosed(t *testing.T) {
	_, _, caPEM := testCA(t)
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundlePEM: caPEM}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.Error(t, err)
}

// Verification admits a genuine SVID of any trust domain in the set, each
// against its own trust domain's authorities: which trust domains a mount's
// grants accept is decided by the rules over its facts.
func TestVerify_AnyTrustDomainInTheSet(t *testing.T) {
	authB := newJWTAuthority(t)
	caB, keyB, pemB := testCA(t)
	_, _, pemA := testCA(t)
	s, err := BuildBundleSet([]*TrustDomain{
		{Name: "a.example.org", BundlePEM: pemA},
		{Name: "b.example.org", BundleJSON: authB.bundleJSON(t, "b.example.org", 0)},
	})
	require.NoError(t, err)
	sX, err := BuildBundleSet([]*TrustDomain{
		{Name: "a.example.org", BundlePEM: pemA},
		{Name: "b.example.org", BundlePEM: pemB},
	})
	require.NoError(t, err)

	token := authB.sign(t, "spiffe://b.example.org/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	svid, err := VerifyJWTSVIDToken(s, token, []string{"warden"})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://b.example.org/sa/api", svid.ID.String())
	_, err = VerifyJWTSVIDToken(s, token, nil)
	assert.ErrorContains(t, err, "audience is required")
	_, err = VerifyJWTSVIDToken(nil, token, []string{"warden"})
	assert.ErrorContains(t, err, "no trust bundles loaded")

	cert := testSVID(t, caB, keyB, "spiffe://b.example.org/sa/api")
	id, chains, err := VerifyX509SVIDChain(sX, []*x509.Certificate{cert})
	require.NoError(t, err)
	assert.Equal(t, svid.ID, id)
	assert.NotEmpty(t, chains)
	_, _, err = VerifyX509SVIDChain(nil, []*x509.Certificate{cert})
	assert.ErrorContains(t, err, "no trust bundles loaded")

	// An SVID claiming b, signed by an authority b's bundle does not hold, is
	// refused.
	rogueCA, rogueKey, _ := testCA(t)
	_, _, err = VerifyX509SVIDChain(sX, []*x509.Certificate{testSVID(t, rogueCA, rogueKey, "spiffe://b.example.org/sa/api")})
	assert.Error(t, err)
}
