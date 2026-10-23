package spiffe

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/stephnangue/warden/auth/helper"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTD = "prod.example.org"

// withAudiences configures b with bound_audiences, as an agent mount needs to
// admit JWT-SVIDs.
func withAudiences(t *testing.T, b *spiffeAuthBackend, auds ...string) {
	t.Helper()
	resp := writeConfig(b, map[string]any{"bound_audiences": auds})
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
}

// --- X.509-SVID login ---

func TestX509SVIDLogin_Valid(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
	resp := x509Login(t, b, ctx, svid)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "spiffe://"+testTD+"/ns/default/sa/api", resp.Auth.PrincipalID)
	assert.Equal(t, logical.TokenTypeIdentity, resp.Auth.TokenType)
	assert.Equal(t, logical.CredentialFormatSPIFFE, b.CredentialFormat())
	assert.Nil(t, resp.Auth.Policies, "a login is an admission: no policies")
	assert.Nil(t, resp.Auth.Metadata, "a login is an admission: no metadata")
	assert.Nil(t, resp.Auth.Actors)
	assert.Equal(t, certFingerprint(svid), resp.Auth.ClientToken)
	require.NotNil(t, resp.Auth.Admission)
	assert.Same(t, b.mountFacts, resp.Auth.Admission.Mount)
	assert.NotContains(t, resp.Data, "role")
}

func TestX509SVIDLogin_Rejections(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	rogueCert, rogueKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})

	t.Run("trust domain with no bundle", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://other.org/ns/default/sa/api")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, svid).StatusCode)
	})
	t.Run("untrusted CA", func(t *testing.T) {
		svid := testSVID(t, rogueCert, rogueKey, "spiffe://"+testTD+"/ns/default/sa/api")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, svid).StatusCode)
	})
}

// No trust domains registered → fail closed.
func TestX509SVIDLogin_NoBundlesFailsClosed(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
	assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, svid).StatusCode)
}

// Each SVID verifies against its own trust domain's bundle only: with both
// bundles loaded, an SVID of b signed by a's authority is refused.
func TestX509SVIDLogin_CrossTrustDomainRejected(t *testing.T) {
	caA, keyA, pemA := testCA(t)
	caB, keyB, pemB := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "a.example.org", BundlePEM: pemA}))
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "b.example.org", BundlePEM: pemB}))
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))

	forged := testSVID(t, caA, keyA, "spiffe://b.example.org/sa/svc")
	assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, forged).StatusCode)

	svidB := testSVID(t, caB, keyB, "spiffe://b.example.org/sa/svc")
	resp := x509Login(t, b, ctx, svidB)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://b.example.org/sa/svc", resp.Auth.PrincipalID)
}

// The token TTL is capped by the SVID's NotAfter, under the mount's TTL.
func TestX509SVIDLogin_TTLCappedByNotAfter(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/api", func(tmpl *x509.Certificate) {
		tmpl.NotAfter = time.Now().Add(5 * time.Minute)
	})
	resp := x509Login(t, b, ctx, svid)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Greater(t, resp.Auth.TokenTTL, 4*time.Minute)
	assert.LessOrEqual(t, resp.Auth.TokenTTL, 5*time.Minute)
}

// The TTL comes from the config the login snapshotted, never the live one, so
// a config write mid-login cannot change it: the smaller of the SVID's
// remaining life and that config's TTL, a zero meaning no cap.
func TestCalculateTTL_UsesTheGivenConfig(t *testing.T) {
	now := time.Now()
	expiry := now.Add(time.Hour)

	assert.Equal(t, 10*time.Minute, calculateTTL(&SPIFFEAuthConfig{TokenTTL: 10 * time.Minute}, expiry, now))
	assert.Equal(t, time.Hour, calculateTTL(&SPIFFEAuthConfig{TokenTTL: 2 * time.Hour}, expiry, now))
	assert.Equal(t, time.Hour, calculateTTL(nil, expiry, now))
	assert.Equal(t, time.Duration(0), calculateTTL(nil, now.Add(-time.Minute), now))
}

// --- JWT-SVID login ---

func TestJWTSVIDLogin_Valid(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	withAudiences(t, b, "warden")

	token := auth.sign(t, "spiffe://"+testTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(30*time.Minute), nil)
	resp := jwtLogin(t, b, ctx, token)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://"+testTD+"/ns/default/sa/api", resp.Auth.PrincipalID)
	assert.Equal(t, logical.TokenTypeIdentity, resp.Auth.TokenType)
	assert.Equal(t, token, resp.Auth.ClientToken)
	assert.Nil(t, resp.Auth.Policies)
	assert.Nil(t, resp.Auth.Metadata)
	// TTL capped by the SVID exp (~30m), under the mount's 1h.
	assert.Greater(t, resp.Auth.TokenTTL, 29*time.Minute)
	assert.LessOrEqual(t, resp.Auth.TokenTTL, 30*time.Minute)
}

// Without bound_audiences no JWT-SVID is admitted: a nil config (an
// unconfigured mount) and a stored agent config written before audience
// binding was required alike. X.509-SVIDs, which carry no audience, are still
// admitted by an unconfigured mount.
func TestJWTSVIDLogin_NoMountAudiencesRejected(t *testing.T) {
	jwtAuth := newJWTAuthority(t)
	caCert, caKey, caPEM := testCA(t)
	token := jwtAuth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour), nil)

	t.Run("nil config", func(t *testing.T) {
		b, ctx := createTestBackend(t)
		require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: jwtAuth.bundleJSON(t, testTD)}))
		require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "x509.example.org", BundlePEM: caPEM}))
		require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
		require.Nil(t, b.config)

		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, token).StatusCode)
		_, err := b.admit(ctx, &logical.Request{ClientToken: token}, time.Now())
		require.ErrorIs(t, err, errNoMountAudiences)

		resp := x509Login(t, b, ctx, testSVID(t, caCert, caKey, "spiffe://x509.example.org/sa/api"))
		require.Equal(t, http.StatusOK, resp.StatusCode, "X.509-SVIDs need no audience: %v", resp.Err)
		assert.Equal(t, logical.EntityKindAgent, resp.Auth.Admission.Mount.Load().Kind)
	})

	t.Run("stored agent config without audiences", func(t *testing.T) {
		b, ctx := createTestBackend(t)
		registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: jwtAuth.bundleJSON(t, testTD)})
		require.NoError(t, b.setupSPIFFEConfig(ctx, map[string]any{"token_ttl": "1h"}))

		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, token).StatusCode)
		_, err := b.admit(ctx, &logical.Request{ClientToken: token}, time.Now())
		require.ErrorIs(t, err, helper.ErrAgentAudiencesRequired, "the admission check itself refuses")
	})
}

func TestJWTSVIDLogin_WrongAudienceAndExpired(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	withAudiences(t, b, "warden")

	t.Run("another relying party's audience", func(t *testing.T) {
		token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"other"}, time.Now().Add(time.Hour), nil)
		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, token).StatusCode)
	})
	t.Run("expired", func(t *testing.T) {
		token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(-time.Hour), nil)
		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, token).StatusCode)
	})
}

// A JWT-SVID's act chain is carried; a groups claim grants nothing (groups
// are granted by Warden's groups, not by the IdP).
func TestJWTSVIDLogin_ActChainNoGroupPolicies(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	withAudiences(t, b, "warden")

	token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour), map[string]any{
		"groups": []any{"admins", "ops"},
		"act": map[string]any{
			"sub": "broker-beta",
			"iss": "https://idp.example.com",
			"act": map[string]any{"sub": "agents/alpha"},
		},
	})
	resp := jwtLogin(t, b, ctx, token)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, resp.Auth.Policies)
	// A layer's iss is carried only when the SVID's act layer had one; it is never
	// defaulted from the SVID's own iss.
	assert.Equal(t, []logical.ActorRef{
		{Subject: "broker-beta", Issuer: "https://idp.example.com"},
		{Subject: "agents/alpha"},
	}, resp.Auth.Actors)
}

// --- precedence + isolation ---

// When a request carries BOTH a JWT-SVID and a forwarded cert, the JWT-SVID wins
// (an explicit credential beats an ambient mesh cert) — the A-5 decision.
func TestLogin_DualPresentation_JWTWins(t *testing.T) {
	auth := newJWTAuthority(t)
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	withAudiences(t, b, "warden")

	token := auth.sign(t, "spiffe://"+testTD+"/sa/jwt-id", []string{"warden"}, time.Now().Add(time.Hour), nil)
	certSVID := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/cert-id")

	req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, certSVID), ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{"jwt": token}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://"+testTD+"/sa/jwt-id", resp.Auth.PrincipalID)
	assert.Equal(t, token, resp.Auth.ClientToken)
}

// A JWT-SVID verifies against its own trust domain's JWT authorities only.
func TestLogin_CrossTrustDomainIsolation(t *testing.T) {
	authA := newJWTAuthority(t)
	authB := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "a.example.org", BundleJSON: authA.bundleJSON(t, "a.example.org")}))
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "b.example.org", BundleJSON: authB.bundleJSON(t, "b.example.org")}))
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
	withAudiences(t, b, "warden")

	// An a.example.org SVID signed by b's authority is refused.
	forged := authB.sign(t, "spiffe://a.example.org/sa/svc", []string{"warden"}, time.Now().Add(time.Hour), nil)
	assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, forged).StatusCode)

	tokenA := authA.sign(t, "spiffe://a.example.org/sa/svc", []string{"warden"}, time.Now().Add(time.Hour), nil)
	resp := jwtLogin(t, b, ctx, tokenA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://a.example.org/sa/svc", resp.Auth.PrincipalID)
}

// A login neither needs nor reads a role: one sent anyway, or a default_role
// a stored config still sets (and the mount ignores), changes nothing.
func TestLogin_NoRole(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupSPIFFEConfig(ctx, map[string]any{"default_role": "api", "bound_audiences": "warden"}))
	assert.Equal(t, []string{"default_role"}, b.config.removed)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})

	_, hasRole := b.pathLogin().Fields["role"]
	assert.False(t, hasRole, "a login has no role field")

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/api")
	req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid), ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{"role": "other"}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, resp.Auth.Policies)
	assert.NotContains(t, resp.Data, "role")
}
