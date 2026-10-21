package spiffe

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createRole(t *testing.T, b *spiffeAuthBackend, ctx context.Context, raw map[string]any) *logical.Response {
	t.Helper()
	d := &framework.FieldData{Raw: raw, Schema: b.legacyRolePath().Fields}
	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	return resp
}

func TestRoleValidation(t *testing.T) {
	b, ctx := createTestBackend(t)

	t.Run("trust_domain required", func(t *testing.T) {
		resp := createRole(t, b, ctx, map[string]any{"name": "r1"})
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "trust_domain is required")
	})
	t.Run("invalid trust_domain", func(t *testing.T) {
		resp := createRole(t, b, ctx, map[string]any{"name": "r2", "trust_domain": "Bad Domain"})
		require.NotNil(t, resp.Err)
	})
	t.Run("invalid allowed_spiffe_ids pattern", func(t *testing.T) {
		// '*' is only allowed as the last segment.
		resp := createRole(t, b, ctx, map[string]any{"name": "r3", "trust_domain": "example.org", "allowed_spiffe_ids": "spiffe://example.org/*/sa"})
		require.NotNil(t, resp.Err)
	})
	t.Run("valid role", func(t *testing.T) {
		resp := createRole(t, b, ctx, map[string]any{
			"name": "ok", "trust_domain": "example.org",
			"allowed_spiffe_ids": "spiffe://example.org/ns/+/sa/*",
			"bound_audiences":    "warden",
		})
		require.Nil(t, resp.Err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})
}

// A role with no bound_audiences warns that JWT-SVID logins will be refused.
func TestRole_EmptyAudienceWarning(t *testing.T) {
	b, ctx := createTestBackend(t)

	noAud := createRole(t, b, ctx, map[string]any{"name": "x509only", "trust_domain": "example.org"})
	require.Nil(t, noAud.Err)
	assert.NotEmpty(t, noAud.Warnings, "expected a warning about missing bound_audiences")

	withAud := createRole(t, b, ctx, map[string]any{"name": "jwtok", "trust_domain": "example.org", "bound_audiences": "warden"})
	require.Nil(t, withAud.Err)
	assert.Empty(t, withAud.Warnings)
}

func TestRoleCRUD(t *testing.T) {
	b, ctx := createTestBackend(t)
	createRole(t, b, ctx, map[string]any{
		"name": "api", "trust_domain": "example.org", "bound_audiences": "warden",
		"token_policies": "p1,p2", "allowed_spiffe_ids": "spiffe://example.org/sa/*",
	})

	readData := &framework.FieldData{Raw: map[string]any{"name": "api"}, Schema: b.legacyRolePath().Fields}
	resp, err := b.handleRoleRead(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "example.org", resp.Data["trust_domain"])
	assert.Equal(t, []string{"warden"}, resp.Data["bound_audiences"])

	listResp, err := b.handleRoleList(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Contains(t, listResp.Data["keys"], "api")

	_, err = b.handleRoleDelete(ctx, &logical.Request{}, readData)
	require.NoError(t, err)
	got, err := b.getRole(ctx, "api")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestConfigRoundTrip(t *testing.T) {
	b, ctx := createTestBackend(t)
	d := &framework.FieldData{Raw: map[string]any{"token_ttl": 7200, "bound_audiences": "warden"}, Schema: b.pathConfig().Fields}
	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rresp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Equal(t, "2h0m0s", rresp.Data["token_ttl"])
	assert.NotContains(t, rresp.Data, "default_role")
	assert.NotContains(t, rresp.Data, "warnings")
}

// default_role was removed: a stored one is ignored and a read warns about
// it; a write that sets it is refused; any other write removes it.
func TestConfig_RemovedKeys(t *testing.T) {
	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupSPIFFEConfig(ctx, map[string]any{"default_role": "api", "bound_audiences": "warden"}))

	rresp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	warnings, _ := rresp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "default_role was removed and is ignored")
	assert.NotContains(t, rresp.Data, "default_role")

	before := b.config
	resp := writeConfig(b, map[string]any{"default_role": "api", "token_ttl": 600})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "default_role was removed")
	assert.Same(t, before, b.config)

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"token_ttl": 600}).StatusCode)
	assert.Empty(t, b.config.removed)
}
