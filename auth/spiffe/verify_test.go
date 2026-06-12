package spiffe

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jwtTD = "prod.example.org"

func TestVerifyJWTSVID_Valid(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(time.Hour))

	svid, err := VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+jwtTD+"/ns/default/sa/api", svid.ID.String())
}

func TestVerifyJWTSVID_AudienceIntersection(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	// Token carries two audiences; the role accepts one of them — they intersect.
	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"aud-a", "aud-b"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"aud-b", "aud-c"}, mustTD(t, jwtTD), nil)
	require.NoError(t, err)
}

func TestVerifyJWTSVID_WrongAudience(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"other"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.Error(t, err)
}

func TestVerifyJWTSVID_EmptyAudienceRejected(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, nil, mustTD(t, jwtTD), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is required")
}

func TestVerifyJWTSVID_Expired(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(-time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.Error(t, err)
}

func TestVerifyJWTSVID_NilSet(t *testing.T) {
	auth := newJWTAuthority(t)
	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err := VerifyJWTSVID(nil, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.Error(t, err)
}

// A genuine SVID from a trust domain in the set, but the role pins a different
// trust domain — rejected (the cross-domain isolation guarantee for JWT-SVIDs).
func TestVerifyJWTSVID_TrustDomainMismatch(t *testing.T) {
	authA := newJWTAuthority(t)
	authB := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{
		{Name: "a.example.org", BundleJSON: authA.bundleJSON(t, "a.example.org", 0)},
		{Name: "b.example.org", BundleJSON: authB.bundleJSON(t, "b.example.org", 0)},
	})
	require.NoError(t, err)

	token := authB.sign(t, "spiffe://b.example.org/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, "a.example.org"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match role trust domain")
}

// The set has no bundle for the SVID's trust domain at all.
func TestVerifyJWTSVID_UnknownTrustDomain(t *testing.T) {
	authA := newJWTAuthority(t)
	authOther := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: "a.example.org", BundleJSON: authA.bundleJSON(t, "a.example.org", 0)}})
	require.NoError(t, err)

	token := authOther.sign(t, "spiffe://other.org/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, "other.org"), nil)
	require.Error(t, err)
}

// A token signed by an authority not in the trust domain's JWT bundle is rejected.
func TestVerifyJWTSVID_WrongSigningKey(t *testing.T) {
	good := newJWTAuthority(t)
	rogue := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: good.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := rogue.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.Error(t, err)
}

// A trust domain configured with only an X.509 (PEM) bundle has no JWT
// authorities, so a JWT-SVID for it fails closed.
func TestVerifyJWTSVID_X509OnlyBundleFailsClosed(t *testing.T) {
	_, _, caPEM := testCA(t)
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundlePEM: caPEM}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	_, err = VerifyJWTSVID(s, token, []string{"warden"}, mustTD(t, jwtTD), nil)
	require.Error(t, err)
}

func TestVerifyJWTSVID_AllowedSPIFFEIDs(t *testing.T) {
	auth := newJWTAuthority(t)
	s, err := BuildBundleSet([]*TrustDomain{{Name: jwtTD, BundleJSON: auth.bundleJSON(t, jwtTD, 0)}})
	require.NoError(t, err)

	token := auth.sign(t, "spiffe://"+jwtTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(time.Hour))
	td := mustTD(t, jwtTD)

	t.Run("match", func(t *testing.T) {
		svid, err := VerifyJWTSVID(s, token, []string{"warden"}, td, []string{"spiffe://" + jwtTD + "/ns/+/sa/*"})
		require.NoError(t, err)
		assert.Equal(t, "spiffe://"+jwtTD+"/ns/default/sa/api", svid.ID.String())
	})
	t.Run("mismatch", func(t *testing.T) {
		_, err := VerifyJWTSVID(s, token, []string{"warden"}, td, []string{"spiffe://" + jwtTD + "/ns/other/*"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not allowed by role")
	})
}
