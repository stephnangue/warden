package spiffe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func introspect(t *testing.T, b *spiffeAuthBackend, ctx context.Context, req *logical.Request) *logical.Response {
	t.Helper()
	resp, err := b.handleIntrospectRoles(ctx, req, &framework.FieldData{})
	require.NoError(t, err)
	require.Nil(t, resp.Err, "introspect must never surface an error (lenient)")
	require.Empty(t, resp.Warnings, "introspect must not leak a per-verify-failure warning")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp
}

func introspectRoleNames(resp *logical.Response) []string {
	roles := resp.Data["roles"].([]introspectedRole)
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names
}

func bearerRequest(token string) *logical.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/auth/spiffe/introspect/roles", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return &logical.Request{HTTPRequest: r}
}

func TestIntrospect_X509AndJWT(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	auth := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	// One trust domain serving both key types.
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: combinedBundle(t, testTD, caCert, auth)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{
		Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"},
		AllowedSPIFFEIDs: []string{"spiffe://" + testTD + "/ns/+/sa/api"}, TokenTTL: "1h",
	}))

	t.Run("matching X.509-SVID lists the role", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/api")
		resp := introspect(t, b, ctx, &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid)})
		assert.Equal(t, []string{"api"}, introspectRoleNames(resp))
	})
	t.Run("matching JWT-SVID lists the role", func(t *testing.T) {
		token := auth.sign(t, "spiffe://"+testTD+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(time.Hour), nil)
		resp := introspect(t, b, ctx, bearerRequest(token))
		assert.Equal(t, []string{"api"}, introspectRoleNames(resp))
	})
	t.Run("non-matching X.509-SVID lists nothing", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://"+testTD+"/ns/default/sa/other")
		resp := introspect(t, b, ctx, &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid)})
		assert.Empty(t, introspectRoleNames(resp))
	})
}

// A generic / non-SVID JWT presented to a spiffe mount must produce no match and
// no error (the aggregator must not see a "trust domain mismatch" warning).
func TestIntrospect_GenericJWTIsLenient(t *testing.T) {
	caCert, _, _ := testCA(t)
	auth := newJWTAuthority(t)
	rogue := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: combinedBundle(t, testTD, caCert, auth)})
	require.NoError(t, b.setRole(ctx, &SPIFFERole{Name: "api", TrustDomain: testTD, BoundAudiences: []string{"warden"}, TokenTTL: "1h"}))

	// A JWT signed by an authority the trust domain does not know.
	token := rogue.sign(t, "spiffe://"+testTD+"/sa/api", []string{"warden"}, time.Now().Add(time.Hour), nil)
	resp := introspect(t, b, ctx, bearerRequest(token))
	assert.Empty(t, introspectRoleNames(resp))
}

func TestIntrospect_NoCredentialEmpty(t *testing.T) {
	b, ctx := createTestBackend(t)
	resp := introspect(t, b, ctx, &logical.Request{HTTPRequest: httptest.NewRequest(http.MethodGet, "/x", nil)})
	assert.Empty(t, introspectRoleNames(resp))
}
