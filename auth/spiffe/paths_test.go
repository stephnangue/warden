package spiffe

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrustDomainRoutePatterns locks the API routes so they stay
// "auth/<mount>/trust-domain/..." (no redundant "spiffe/" segment that would
// double up on a spiffe-named mount), keeping the documented paths correct.
func TestTrustDomainRoutePatterns(t *testing.T) {
	m, _ := newTestManager(t)
	assert.Equal(t, "trust-domain/"+framework.GenericNameRegex("name"), m.pathTrustDomain().Pattern)
	assert.Equal(t, "trust-domain/?$", m.pathTrustDomainList().Pattern)
	assert.Equal(t, "trust-domain/"+framework.GenericNameRegex("name")+"/refresh", m.pathTrustDomainRefresh().Pattern)
	assert.Len(t, m.Paths(), 3)
}

func TestTrustDomainCRUD(t *testing.T) {
	_, _, caPEM := testCA(t)
	m, ctx := newTestManager(t)
	schema := m.pathTrustDomain().Fields

	// Write.
	resp := writeTrustDomain(t, m, ctx, map[string]any{"name": "prod.example.org", "bundle_pem": caPEM})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The in-memory verification set is rebuilt and resolves the trust domain.
	set := m.SnapshotBundleSet()
	require.NotNil(t, set)
	bundle, err := set.GetX509BundleForTrustDomain(mustTD(t, "prod.example.org"))
	require.NoError(t, err)
	assert.Len(t, bundle.X509Authorities(), 1)

	// Read returns a summary, not raw PEM.
	readData := &framework.FieldData{Raw: map[string]any{"name": "prod.example.org"}, Schema: schema}
	resp, err = m.HandleTrustDomainRead(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, resp.Data["x509_authority_count"])
	assert.Equal(t, 0, resp.Data["jwt_authority_count"])
	assert.Equal(t, "bundle_pem", resp.Data["bundle_source"])
	_, hasRawPEM := resp.Data["bundle_pem"]
	assert.False(t, hasRawPEM, "raw bundle must not be echoed")

	// List.
	listResp, err := m.HandleTrustDomainList(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Contains(t, listResp.Data["keys"], "prod.example.org")

	// Delete, then it is gone from storage.
	resp, err = m.HandleTrustDomainDelete(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got, err := m.GetTrustDomain(ctx, "prod.example.org")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// A JWT-only trust domain reads back with a jwt authority count and no x509.
func TestTrustDomainRead_JWTOnly(t *testing.T) {
	auth := newJWTAuthority(t)
	m, ctx := newTestManager(t)
	resp := writeTrustDomain(t, m, ctx, map[string]any{"name": "jwt.example.org", "bundle_json": auth.bundleJSON(t, "jwt.example.org", 0)})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	readData := &framework.FieldData{Raw: map[string]any{"name": "jwt.example.org"}, Schema: m.pathTrustDomain().Fields}
	resp, err := m.HandleTrustDomainRead(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Data["x509_authority_count"])
	assert.Equal(t, 1, resp.Data["jwt_authority_count"])
	assert.Equal(t, "bundle_json", resp.Data["bundle_source"])
}

func TestTrustDomainWrite_Validation(t *testing.T) {
	_, _, caPEM := testCA(t)
	m, ctx := newTestManager(t)

	t.Run("invalid name", func(t *testing.T) {
		resp := writeTrustDomain(t, m, ctx, map[string]any{"name": "Bad.Domain", "bundle_pem": caPEM})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
	t.Run("invalid bundle", func(t *testing.T) {
		resp := writeTrustDomain(t, m, ctx, map[string]any{"name": "example.org", "bundle_pem": "garbage"})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestValidateTrustDomainConfig(t *testing.T) {
	_, _, caPEM := testCA(t)
	auth := newJWTAuthority(t)
	const td = "partner.example.org"

	cases := []struct {
		name    string
		d       *TrustDomain
		wantErr string
	}{
		{"static ok", &TrustDomain{Name: td, BundlePEM: caPEM}, ""},
		{"static jwt-only ok", &TrustDomain{Name: td, BundleJSON: auth.bundleJSON(t, td, 0)}, ""},
		{"static with endpoint field", &TrustDomain{Name: td, BundlePEM: caPEM, BundleEndpointURL: "https://x"}, "require bundle_endpoint_profile"},
		{"bad profile", &TrustDomain{Name: td, BundleEndpointProfile: "ftp", BundleEndpointURL: "https://x"}, "invalid bundle_endpoint_profile"},
		{"web missing url", &TrustDomain{Name: td, BundleEndpointProfile: "https_web"}, "bundle_endpoint_url is required"},
		{"web non-https", &TrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "http://x"}, "must be an https"},
		{"web ok no bootstrap", &TrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "https://x"}, ""},
		{"web with endpoint id", &TrustDomain{Name: td, BundleEndpointProfile: "https_web", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s"}, "not valid for the https_web"},
		{"spiffe missing id", &TrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", BundlePEM: caPEM}, "valid endpoint_spiffe_id"},
		{"spiffe missing bootstrap", &TrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s"}, "requires a bootstrap bundle"},
		{"spiffe jwt-only bootstrap", &TrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s", BundleJSON: auth.bundleJSON(t, td, 0)}, "must contain X.509 authorities"},
		{"spiffe id wrong domain", &TrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://other.org/s", BundlePEM: caPEM}, "must be in trust domain"},
		{"spiffe ok", &TrustDomain{Name: td, BundleEndpointProfile: "https_spiffe", BundleEndpointURL: "https://x", EndpointSPIFFEID: "spiffe://" + td + "/s", BundlePEM: caPEM}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTrustDomainConfig(tc.d)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
