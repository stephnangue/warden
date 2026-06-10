package cert

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// mode config
// =============================================================================

func TestSetupCertConfig_ModeDefaultAndValidation(t *testing.T) {
	b, ctx := createTestBackend(t)

	require.NoError(t, b.setupCertConfig(ctx, map[string]any{}))
	assert.Equal(t, modeX509, b.config.Mode)

	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))
	assert.Equal(t, modeSPIFFE, b.config.Mode)

	err := b.setupCertConfig(ctx, map[string]any{"mode": "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

func TestHandleConfigWrite_SpiffeModeRejectsPKIFields(t *testing.T) {
	_, _, caPEM := testCA(t)

	t.Run("trusted_ca_pem", func(t *testing.T) {
		b, ctx := createTestBackend(t)
		d := &framework.FieldData{
			Raw:    map[string]any{"mode": "spiffe", "trusted_ca_pem": caPEM},
			Schema: b.pathConfig().Fields,
		}
		resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "trusted_ca_pem is not allowed in spiffe mode")
	})

	t.Run("principal_claim", func(t *testing.T) {
		b, ctx := createTestBackend(t)
		d := &framework.FieldData{
			Raw:    map[string]any{"mode": "spiffe", "principal_claim": "cn"},
			Schema: b.pathConfig().Fields,
		}
		resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "principal_claim is not allowed in spiffe mode")
	})
}

func TestHandleConfigWrite_ModeChangeGuard(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	// Register a trust domain so the mount is no longer a clean slate.
	resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"name": "example.org", "bundle_pem": caPEM},
		Schema: b.pathSPIFFETrustDomain().Fields,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Switching mode now must be rejected.
	resp, err = b.handleConfigWrite(ctx, &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"mode": "x509"},
		Schema: b.pathConfig().Fields,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "cannot change mode")
}

// =============================================================================
// trust-domain CRUD + bundle-set wiring
// =============================================================================

func TestTrustDomainCRUD(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	tdSchema := b.pathSPIFFETrustDomain().Fields

	// Write.
	resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"name": "prod.example.org", "bundle_pem": caPEM},
		Schema: tdSchema,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The in-memory verification set is rebuilt and resolves the trust domain.
	require.NotNil(t, b.spiffeBundleSet)
	bundle, err := b.spiffeBundleSet.GetX509BundleForTrustDomain(mustTD(t, "prod.example.org"))
	require.NoError(t, err)
	assert.Len(t, bundle.X509Authorities(), 1)

	// Read returns a summary, not raw PEM.
	readData := &framework.FieldData{Raw: map[string]any{"name": "prod.example.org"}, Schema: tdSchema}
	resp, err = b.handleTrustDomainRead(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, resp.Data["x509_authority_count"])
	assert.Equal(t, "bundle_pem", resp.Data["bundle_source"])
	_, hasRawPEM := resp.Data["bundle_pem"]
	assert.False(t, hasRawPEM, "raw bundle must not be echoed")

	// List.
	listResp, err := b.handleTrustDomainList(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Contains(t, listResp.Data["keys"], "prod.example.org")

	// Delete, then it is gone from storage.
	resp, err = b.handleTrustDomainDelete(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got, err := b.getTrustDomain(ctx, "prod.example.org")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestTrustDomain_RejectedInX509Mode(t *testing.T) {
	b, ctx := createTestBackend(t) // config nil -> x509 mode

	resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"name": "example.org", "bundle_pem": "x"},
		Schema: b.pathSPIFFETrustDomain().Fields,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "mode=spiffe")
}

func TestTrustDomainWrite_Validation(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))
	tdSchema := b.pathSPIFFETrustDomain().Fields

	t.Run("invalid name", func(t *testing.T) {
		resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
			Raw:    map[string]any{"name": "Bad.Domain", "bundle_pem": caPEM},
			Schema: tdSchema,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid bundle", func(t *testing.T) {
		resp, err := b.handleTrustDomainWrite(ctx, &logical.Request{}, &framework.FieldData{
			Raw:    map[string]any{"name": "example.org", "bundle_pem": "garbage"},
			Schema: tdSchema,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// =============================================================================
// role validation gating
// =============================================================================

func TestValidateRole_ModeGating(t *testing.T) {
	b, ctx := createTestBackend(t)

	// x509 mode (default): SPIFFE-only fields are rejected.
	err := b.validateRole(&CertRole{Name: "r", TrustDomain: "example.org"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid in spiffe mode")

	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	// spiffe mode: trust_domain required.
	err = b.validateRole(&CertRole{Name: "r"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust_domain is required")

	// spiffe mode: valid role.
	require.NoError(t, b.validateRole(&CertRole{
		Name:             "r",
		TrustDomain:      "example.org",
		AllowedSPIFFEIDs: []string{"spiffe://example.org/ns/*"},
	}))

	// spiffe mode: PKI fields rejected.
	err = b.validateRole(&CertRole{Name: "r", TrustDomain: "example.org", AllowedCommonNames: []string{"x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid in spiffe mode")
}

// =============================================================================
// enforcement gate (PR3: spiffe data plane not yet enabled)
// =============================================================================

func TestHandleLogin_SpiffeModeGated(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	clientCert := testClientCert(t, caCert, caKey, "agent")
	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)}
	d := &framework.FieldData{Raw: map[string]any{"role": "api"}, Schema: b.pathLogin().Fields}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "not yet enabled")
}

func TestHandleIntrospect_SpiffeModeEmpty(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	clientCert := testClientCert(t, caCert, caKey, "agent")
	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)}

	resp, err := b.handleIntrospectRoles(ctx, req, &framework.FieldData{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

// =============================================================================
// mode-aware read output
// =============================================================================

func TestHandleConfigRead_SpiffeModeOmitsX509Fields(t *testing.T) {
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))

	resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, modeSPIFFE, resp.Data["mode"])
	for _, k := range []string{"trusted_ca_pem", "principal_claim", "trusted_ca_count"} {
		_, present := resp.Data[k]
		assert.False(t, present, "x509-only field %q must not appear in spiffe mode", k)
	}
}

func TestHandleRoleRead_SpiffeModeShowsSpiffeFields(t *testing.T) {
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{"mode": "spiffe"}))
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:             "api",
		TrustDomain:      "example.org",
		AllowedSPIFFEIDs: []string{"spiffe://example.org/api/*"},
		TokenTTL:         "1h",
	}))

	fd := &framework.FieldData{
		Raw:    map[string]any{"name": "api"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	resp, err := b.handleRoleRead(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "example.org", resp.Data["trust_domain"])
	_, hasCN := resp.Data["allowed_common_names"]
	assert.False(t, hasCN, "x509-only field must not appear for a spiffe role")
}
