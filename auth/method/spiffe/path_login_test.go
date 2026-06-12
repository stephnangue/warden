package spiffe

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTD = "prod.example.org"

// --- X.509-SVID login ---

func TestX509SVIDLogin_Valid(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{
		Name: "api", TrustDomain: testTD,
		AllowedSPIFFEIDs: []string{"spiffe://" + testTD + "/ns/+/sa/+"},
		TokenPolicies:    []string{"svid-policy"}, TokenTTL: "1h",
	}))

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
	resp := x509Login(t, b, ctx, "api", svid)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "spiffe://"+testTD+"/ns/default/sa/api", resp.Auth.PrincipalID)
	assert.Equal(t, "spiffe_role", resp.Auth.TokenType)
	assert.Equal(t, []string{"svid-policy"}, resp.Auth.Policies)
	assert.Equal(t, certFingerprint(svid), resp.Auth.ClientToken)
}

func TestX509SVIDLogin_Rejections(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	rogueCert, rogueKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{
		Name: "api", TrustDomain: testTD,
		AllowedSPIFFEIDs: []string{"spiffe://" + testTD + "/ns/+/sa/api"}, TokenTTL: "1h",
	}))

	t.Run("wrong trust domain", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://other.org/ns/default/sa/api")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "api", svid).StatusCode)
	})
	t.Run("disallowed spiffe id", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/other")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "api", svid).StatusCode)
	})
	t.Run("untrusted CA", func(t *testing.T) {
		svid := testSVID(t, rogueCert, rogueKey, "spiffe://"+testTD+"/ns/default/sa/api")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "api", svid).StatusCode)
	})
	t.Run("unknown role", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
		assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "nope", svid).StatusCode)
	})
}

// No trust domains registered → fail closed.
func TestX509SVIDLogin_NoBundlesFailsClosed(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, TokenTTL: "1h"}))
	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
	assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "api", svid).StatusCode)
}

// A genuine, fully-loaded X.509-SVID from another trust domain must be rejected
// for a role pinned to a different domain (the MemberOf guard, with both bundles
// loaded so verification reaches the trust-domain check rather than failing on a
// missing authority).
func TestX509SVIDLogin_CrossTrustDomainRejected(t *testing.T) {
	caA, keyA, pemA := testCA(t)
	caB, keyB, pemB := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "a.example.org", BundlePEM: pemA}))
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "b.example.org", BundlePEM: pemB}))
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "a-only", TrustDomain: "a.example.org", TokenTTL: "1h"}))

	svidB := testSVID(t, caB, keyB, "spiffe://b.example.org/sa/svc")
	assert.Equal(t, http.StatusUnauthorized, x509Login(t, b, ctx, "a-only", svidB).StatusCode)

	svidA := testSVID(t, caA, keyA, "spiffe://a.example.org/sa/svc")
	assert.Equal(t, http.StatusOK, x509Login(t, b, ctx, "a-only", svidA).StatusCode)
}

// The token TTL is capped by the SVID's NotAfter, under the role's TTL.
func TestX509SVIDLogin_TTLCappedByNotAfter(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, TokenTTL: "1h"}))

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/api", func(tmpl *x509.Certificate) {
		tmpl.NotAfter = time.Now().Add(5 * time.Minute)
	})
	resp := x509Login(t, b, ctx, "api", svid)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Greater(t, resp.Auth.TokenTTL, 4*time.Minute)
	assert.LessOrEqual(t, resp.Auth.TokenTTL, 5*time.Minute)
}

// --- JWT-SVID login ---

func TestJWTSVIDLogin_Valid(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{
		Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"},
		TokenPolicies: []string{"svid-policy"}, TokenTTL: "1h",
	}))

	token := auth.sign(t, "spiffe://"+testTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(30*time.Minute), nil)
	resp := jwtLogin(t, b, ctx, "api", token)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://"+testTD+"/ns/default/sa/api", resp.Auth.PrincipalID)
	assert.Equal(t, "spiffe_role", resp.Auth.TokenType)
	assert.Equal(t, token, resp.Auth.ClientToken)
	// TTL capped by the SVID exp (~30m), under the role's 1h.
	assert.Greater(t, resp.Auth.TokenTTL, 29*time.Minute)
	assert.LessOrEqual(t, resp.Auth.TokenTTL, 30*time.Minute)
}

func TestJWTSVIDLogin_EmptyAudienceRejected(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	// Role has NO bound_audiences → JWT-SVID login must fail closed.
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, TokenTTL: "1h"}))

	token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour), nil)
	assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, "api", token).StatusCode)
}

func TestJWTSVIDLogin_WrongAudienceAndExpired(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"}, TokenTTL: "1h"}))

	t.Run("wrong audience", func(t *testing.T) {
		token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"other"}, time.Now().Add(time.Hour), nil)
		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, "api", token).StatusCode)
	})
	t.Run("expired", func(t *testing.T) {
		token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(-time.Hour), nil)
		assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, "api", token).StatusCode)
	})
}

func TestJWTSVIDLogin_GroupsAndActChain(t *testing.T) {
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{
		Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"},
		TokenPolicies: []string{"base"}, GroupsClaim: "groups", TokenTTL: "1h",
	}))

	token := auth.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour), map[string]any{
		"groups": []any{"admins", "ops"},
		"act":    map[string]any{"sub": "broker-beta"},
	})
	resp := jwtLogin(t, b, ctx, "api", token)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Subset(t, resp.Auth.Policies, []string{"base", "group-admins", "group-ops"})
	require.Len(t, resp.Auth.Actors, 1)
	assert.Equal(t, "broker-beta", resp.Auth.Actors[0].Subject)
	assert.True(t, resp.Auth.Actors[0].Verified)
}

// --- precedence + isolation ---

// When a request carries BOTH a JWT-SVID and a forwarded cert, the JWT-SVID wins
// (an explicit credential beats an ambient mesh cert) — the A-5 decision.
func TestLogin_DualPresentation_JWTWins(t *testing.T) {
	auth := newJWTAuthority(t)
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: auth.bundleJSON(t, testTD)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"}, TokenTTL: "1h"}))

	token := auth.sign(t, "spiffe://"+testTD+"/sa/jwt-id", []string{"warden"}, time.Now().Add(time.Hour), nil)
	certSVID := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/cert-id")

	req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, certSVID), ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{"role": "api", "jwt": token}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://"+testTD+"/sa/jwt-id", resp.Auth.PrincipalID)
	assert.Equal(t, token, resp.Auth.ClientToken)
}

func TestLogin_CrossTrustDomainIsolation(t *testing.T) {
	caA, keyA, pemA := testCA(t)
	authB := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: "a.example.org", BundlePEM: pemA})
	// b.example.org carries JWT keys; both domains are configured, but the role pins a.
	require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: "b.example.org", BundleJSON: authB.bundleJSON(t, "b.example.org")}))
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "a-only", TrustDomain: "a.example.org", BoundAudiences: []string{"warden"}, TokenTTL: "1h"}))

	// A genuine b.example.org JWT-SVID must be rejected for the a-bound role.
	tokenB := authB.sign(t, "spiffe://b.example.org/sa/svc", []string{"warden"}, time.Now().Add(time.Hour), nil)
	assert.Equal(t, http.StatusUnauthorized, jwtLogin(t, b, ctx, "a-only", tokenB).StatusCode)

	// The matching-domain X.509-SVID is accepted.
	svidA := testSVID(t, caA, keyA, "spiffe://a.example.org/sa/svc")
	resp := x509Login(t, b, ctx, "a-only", svidA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://a.example.org/sa/svc", resp.Auth.PrincipalID)
}

func TestLogin_DefaultRole(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupSPIFFEConfig(ctx, map[string]any{"default_role": "api"}))
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, TokenTTL: "1h"}))

	svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/sa/api")
	// No role in the request → falls back to default_role.
	req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid), ClientIP: "10.0.0.1"}
	d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "api", resp.Auth.RoleName)
}
