package cert

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The "spiffe_id" principal claim was removed because it read a spiffe:// URI
// from the certificate without validating it as an SVID. These tests pin the
// migration behavior: persisted/legacy values are coerced to "uri_san", while
// new writes are rejected.

func TestSetupCertConfig_CoercesSpiffeIDToURISAN(t *testing.T) {
	b, ctx := createTestBackend(t)
	err := b.setupCertConfig(ctx, map[string]any{
		"principal_claim": "spiffe_id",
	})
	require.NoError(t, err)
	assert.Equal(t, "uri_san", b.config.PrincipalClaim)
}

func TestInitialize_CoercesPersistedSpiffeID(t *testing.T) {
	b, ctx := createTestBackend(t)

	// Simulate a config persisted by an older version that still allowed spiffe_id.
	entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
		"principal_claim": "spiffe_id",
		"token_ttl":       "1h",
	})
	require.NoError(t, err)
	require.NoError(t, b.storageView.Put(ctx, entry))

	require.NoError(t, b.Initialize(ctx))
	require.NotNil(t, b.config)
	assert.Equal(t, "uri_san", b.config.PrincipalClaim)
}

func TestHandleConfigWrite_RejectsSpiffeID(t *testing.T) {
	b, ctx := createTestBackend(t)

	d := &framework.FieldData{
		Raw:    map[string]any{"principal_claim": "spiffe_id"},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "spiffe_id")
}

// A role persisted before the removal may still carry principal_claim=spiffe_id.
// Login must coerce it to uri_san so the workload keeps authenticating with the
// same principal value (the single SPIFFE URI SAN).
func TestHandleLogin_LegacyRoleSpiffeIDClaimCoerced(t *testing.T) {
	b, ctx := createTestBackend(t)
	caCert, caKey, caPEM := testCA(t)

	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	// setRole bypasses validateRole, mimicking a value stored by an older version.
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:               "legacy",
		AllowedCommonNames: []string{"*"},
		PrincipalClaim:     "spiffe_id",
		TokenTTL:           "1h",
	}))

	clientCert := testClientCert(t, caCert, caKey, "agent", func(tmpl *x509.Certificate) {
		u, _ := url.Parse("spiffe://example.com/ns/default/sa/agent")
		tmpl.URIs = append(tmpl.URIs, u)
	})

	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "legacy"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "spiffe://example.com/ns/default/sa/agent", resp.Auth.PrincipalID)
}
