package spiffe

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/auth/helper/factstest"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// admitRequest routes introspect/admit to b with bearer and cert presented
// (either may be empty), marked internal as core marks it when internal is set.
func admitRequest(t *testing.T, b *spiffeAuthBackend, bearer string, cert *x509.Certificate, internal bool) *logical.Response {
	t.Helper()
	resp, err := routeAdmit(b, bearer, cert, internal)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func routeAdmit(b *spiffeAuthBackend, bearer string, cert *x509.Certificate, internal bool) (*logical.Response, error) {
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/auth/spiffe/introspect/admit", nil)
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cert != nil {
		httpReq = httpReq.WithContext(listener.WithForwardedClientCert(httpReq.Context(), cert))
	}
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        helper.AdmitPattern,
		HTTPRequest: httpReq,
		Internal:    internal,
	})
}

func admitted(t *testing.T, resp *logical.Response) *logical.Admission {
	t.Helper()
	require.NoError(t, resp.Err)
	ok, _ := resp.Data[helper.AdmittedKey].(bool)
	adm, _ := resp.Data[helper.AdmissionKey].(*logical.Admission)
	assert.Equal(t, ok, adm != nil)
	return adm
}

const admitID = "spiffe://" + testTD + "/ns/a/sa/b"

func svidKind(adm *logical.Admission) []string {
	return factstest.Values(adm, adm.Mount.Load(), "svid")
}

func TestAdmit_RefusedUnlessInternal(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"warden"}})
	resp := admitRequest(t, f.b, "", f.svid(t, admitID), false)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotContains(t, resp.Data, helper.AdmissionKey)
	assert.NotContains(t, f.b.PathsSpecial.Unauthenticated, helper.AdmitPattern)
}

func TestAdmit_X509SVID(t *testing.T) {
	// max_age does not apply to X.509-SVIDs, which carry no issue time.
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"warden"}, "max_age": "1m"})
	// No role constrains admission: a SPIFFE ID the "api" role would refuse.
	const id = "spiffe://" + testTD + "/other/path"
	adm := admitted(t, admitRequest(t, f.b, "", f.svid(t, id), true))
	require.NotNil(t, adm)
	assert.Same(t, f.b.mountFacts, adm.Mount)
	assert.Empty(t, adm.MountPath)
	assert.Equal(t, []string{"x509"}, svidKind(adm))
	assert.Equal(t, []string{id}, factstest.Values(adm, adm.Mount.Load(), "spiffe_id"))

	rogue, rogueKey, _ := testCA(t)
	assert.Nil(t, admitted(t, admitRequest(t, f.b, "", testSVID(t, rogue, rogueKey, admitID), true)), "untrusted CA")

	got, err := f.b.admitX509SVID(f.b.spiffe.SnapshotBundleSet(), f.svid(t, id))
	require.NoError(t, err)
	assert.Equal(t, id, got.id.String())
	assert.False(t, got.expiry.IsZero())
	assert.Nil(t, got.claims)
}

func TestAdmit_JWTSVID(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"warden", "warden-b"}})
	exp := time.Now().Add(time.Hour)

	adm := admitted(t, admitRequest(t, f.b, f.jwt.sign(t, admitID, []string{"warden-b"}, exp, nil), nil, true))
	require.NotNil(t, adm)
	assert.Equal(t, []string{"jwt"}, svidKind(adm))
	assert.Equal(t, []string{"warden-b"}, factstest.Values(adm, adm.Mount.Load(), "aud"))
	assert.False(t, adm.IssuedAt.IsZero())

	assert.Nil(t, admitted(t, admitRequest(t, f.b, f.jwt.sign(t, admitID, []string{"other"}, exp, nil), nil, true)), "wrong audience")
	assert.Nil(t, admitted(t, admitRequest(t, f.b, f.jwt.sign(t, admitID, []string{"warden"}, time.Now().Add(-time.Hour), nil), nil, true)), "expired")
	other := newJWTAuthority(t)
	assert.Nil(t, admitted(t, admitRequest(t, f.b, other.sign(t, admitID, []string{"warden"}, exp, nil), nil, true)), "untrusted key")

	set := f.b.spiffe.SnapshotBundleSet()
	got, err := f.b.admitJWTSVID(set, f.b.config, f.jwt.sign(t, admitID, []string{"warden"}, exp, map[string]any{"team": "core"}), time.Now())
	require.NoError(t, err)
	assert.Equal(t, admitID, got.id.String())
	assert.Equal(t, exp.Unix(), got.expiry.Unix())
	assert.Equal(t, "core", got.claims["team"])
}

// Without bound_audiences on the mount (or with no config at all), the mount
// cannot decide on a JWT-SVID: an error, which discovery reports as the mount's
// warning. A stored agent config without them (written before audience binding
// was required, since a write now refuses it) says so. X.509-SVIDs are still
// admitted.
func TestAdmit_JWTSVIDNeedsMountAudiences(t *testing.T) {
	for name, tc := range map[string]struct {
		stored map[string]any // installed as storage holds it; nil: no config
		want   error
	}{
		"no config":                {nil, errNoMountAudiences},
		"stored without audiences": {map[string]any{"token_ttl": "1h"}, helper.ErrAgentAudiencesRequired},
		"human without audiences":  {map[string]any{"entity_kind": "human"}, errNoMountAudiences},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFactsFixture(t, nil)
			f.b.config = nil
			if tc.stored != nil {
				require.NoError(t, f.b.setupSPIFFEConfig(context.Background(), tc.stored))
			}
			token := f.jwt.sign(t, admitID, []string{"warden"}, time.Now().Add(time.Hour), nil)
			resp, err := routeAdmit(f.b, token, nil, true)
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, resp)
			assert.NotNil(t, admitted(t, admitRequest(t, f.b, "", f.svid(t, admitID), true)))
		})
	}
}

// The mount's max_age refuses a stale JWT-SVID.
func TestAdmit_JWTSVIDMaxAge(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"warden"}, "max_age": "10m"})
	exp := time.Now().Add(time.Hour)
	fresh := f.jwt.sign(t, admitID, []string{"warden"}, exp, nil)
	stale := f.jwt.sign(t, admitID, []string{"warden"}, exp, map[string]any{"iat": time.Now().Add(-20 * time.Minute).Unix()})

	assert.NotNil(t, admitted(t, admitRequest(t, f.b, fresh, nil, true)))
	assert.Nil(t, admitted(t, admitRequest(t, f.b, stale, nil, true)))

	_, err := f.b.admitJWTSVID(f.b.spiffe.SnapshotBundleSet(), f.b.config, fresh, time.Now().Add(15*time.Minute))
	assert.ErrorContains(t, err, "max_age")
}

// The SVID is picked as the gateway picks it: a bearer JWT-SVID over a
// forwarded certificate, and the certificate when the bearer is not a JWT-SVID.
func TestAdmit_SVIDChoice(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"warden"}})
	cert := f.svid(t, admitID)
	token := f.jwt.sign(t, admitID, []string{"warden"}, time.Now().Add(time.Hour), nil)

	adm := admitted(t, admitRequest(t, f.b, token, cert, true))
	require.NotNil(t, adm)
	assert.Equal(t, []string{"jwt"}, svidKind(adm))

	adm = admitted(t, admitRequest(t, f.b, "eyJ.not-an.svid", cert, true))
	require.NotNil(t, adm)
	assert.Equal(t, []string{"x509"}, svidKind(adm))

	assert.Nil(t, admitted(t, admitRequest(t, f.b, "", nil, true)), "no credential")
}

// With no trust bundle loaded the mount cannot decide: an error, which
// discovery reports as the mount's warning.
func TestAdmit_NoBundles(t *testing.T) {
	b, _ := createTestBackend(t)
	ca, caKey, _ := testCA(t)
	resp, err := routeAdmit(b, "", testSVID(t, ca, caKey, admitID), true)
	assert.ErrorIs(t, err, errNoBundles)
	assert.Nil(t, resp)
	assert.Nil(t, admitted(t, admitRequest(t, b, "", nil, true)), "no credential: nothing to decide")
}
