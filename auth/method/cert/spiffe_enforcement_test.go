package cert

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSpiffeMount returns a spiffe-mode backend with one trust domain registered
// (backed by caPEM) and one spiffe role bound to it.
func setupSpiffeMount(t *testing.T, caPEM, trustDomain, roleName string, allowedIDs []string) (*certAuthBackend, context.Context) {
	t.Helper()
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"name": trustDomain, "bundle_pem": caPEM},
		Schema: b.pathSPIFFETrustDomain().Fields,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:             roleName,
		TrustDomain:      trustDomain,
		AllowedSPIFFEIDs: allowedIDs,
		TokenPolicies:    []string{"svid-policy"},
		TokenTTL:         "1h",
	}))
	return b, ctx
}

func spiffeLogin(t *testing.T, b *certAuthBackend, ctx context.Context, role string, svid *x509.Certificate) *logical.Response {
	t.Helper()
	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, svid)}
	d := &framework.FieldData{Raw: map[string]any{"role": role}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	return resp
}

func TestSPIFFELogin_ValidSVID(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := setupSpiffeMount(t, caPEM, "prod.example.org", "api", []string{"spiffe://prod.example.org/ns/+/sa/+"})

	svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/api")
	resp := spiffeLogin(t, b, ctx, "api", svid)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "spiffe://prod.example.org/ns/default/sa/api", resp.Auth.PrincipalID)
	assert.Equal(t, "api", resp.Auth.RoleName)
	assert.Equal(t, []string{"svid-policy"}, resp.Auth.Policies)
	assert.Equal(t, "cert_role", resp.Auth.TokenType)
}

func TestSPIFFELogin_Rejections(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	rogueCert, rogueKey, _ := testCA(t)

	b, ctx := setupSpiffeMount(t, caPEM, "prod.example.org", "api", []string{"spiffe://prod.example.org/ns/+/sa/api"})

	t.Run("wrong trust domain", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://other.org/ns/default/sa/api")
		resp := spiffeLogin(t, b, ctx, "api", svid)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("path not allowed", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/other")
		resp := spiffeLogin(t, b, ctx, "api", svid)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("signed by untrusted CA", func(t *testing.T) {
		svid := testSVID(t, rogueCert, rogueKey, "spiffe://prod.example.org/ns/default/sa/api")
		resp := spiffeLogin(t, b, ctx, "api", svid)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("CA leaf", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/api", func(tmpl *x509.Certificate) {
			tmpl.IsCA = true
			tmpl.BasicConstraintsValid = true
		})
		resp := spiffeLogin(t, b, ctx, "api", svid)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("unknown role", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/api")
		resp := spiffeLogin(t, b, ctx, "nope", svid)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestSPIFFELogin_CrossTrustDomainIsolation is the headline guarantee: with two
// trust domains configured, a valid SVID from one cannot assume a role bound to
// the other — the property a single shared CA pool cannot provide.
func TestSPIFFELogin_CrossTrustDomainIsolation(t *testing.T) {
	caA, keyA, pemA := testCA(t)
	caB, keyB, pemB := testCA(t)

	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))
	for _, td := range []struct{ name, pem string }{{"a.example.org", pemA}, {"b.example.org", pemB}} {
		resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
			Raw:    map[string]any{"name": td.name, "bundle_pem": td.pem},
			Schema: b.pathSPIFFETrustDomain().Fields,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	require.NoError(t, b.setRole(ctx, &CertRole{Name: "a-only", TrustDomain: "a.example.org", TokenTTL: "1h"}))

	// A genuine, fully-valid b.example.org SVID (its bundle is configured) must
	// still be rejected for the a.example.org-bound role.
	svidB := testSVID(t, caB, keyB, "spiffe://b.example.org/ns/default/sa/svc")
	assert.Equal(t, http.StatusUnauthorized, spiffeLogin(t, b, ctx, "a-only", svidB).StatusCode)

	// The matching-domain SVID is accepted.
	svidA := testSVID(t, caA, keyA, "spiffe://a.example.org/ns/default/sa/svc")
	resp := spiffeLogin(t, b, ctx, "a-only", svidA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe://a.example.org/ns/default/sa/svc", resp.Auth.PrincipalID)
}

func TestSPIFFEIntrospect(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := setupSpiffeMount(t, caPEM, "prod.example.org", "api", []string{"spiffe://prod.example.org/ns/+/sa/api"})

	introspect := func(svid *x509.Certificate) []introspectedRole {
		req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, svid)}
		resp, err := b.handleIntrospectRoles(ctx, req, &framework.FieldData{})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return resp.Data["roles"].([]introspectedRole)
	}

	t.Run("matching SVID lists the role", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/api")
		roles := introspect(svid)
		require.Len(t, roles, 1)
		assert.Equal(t, "api", roles[0].Name)
	})

	t.Run("non-matching SVID lists nothing", func(t *testing.T) {
		svid := testSVID(t, caCert, caKey, "spiffe://prod.example.org/ns/default/sa/other")
		assert.Empty(t, introspect(svid))
	})
}

// TestX509Login_Regression confirms the classic x509 path still authenticates
// after the spiffe branch was added.
func TestX509Login_Regression(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem":  caPEM,
		"principal_claim": "cn",
	}))
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:               "inventory",
		AllowedCommonNames: []string{"inventory-*"},
		TokenPolicies:      []string{"inv"},
		TokenTTL:           "1h",
	}))

	clientCert := testClientCert(t, caCert, caKey, "inventory-svc")
	resp := spiffeLogin(t, b, ctx, "inventory", clientCert)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "inventory-svc", resp.Auth.PrincipalID)
}
