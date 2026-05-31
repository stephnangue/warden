package kubernetes

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func TestPathConfig_Pattern(t *testing.T) {
	b, _ := newTestBackend(t)
	p := b.pathConfig()
	assert.Equal(t, "config", p.Pattern)
}

func TestPathConfig_FieldsPresent(t *testing.T) {
	b, _ := newTestBackend(t)
	p := b.pathConfig()
	for _, name := range []string{
		"kubernetes_host", "kubernetes_ca_cert", "token_reviewer_jwt",
		"tls_skip_verify", "issuer", "disable_iss_validation",
		"token_ttl", "default_role",
	} {
		_, ok := p.Fields[name]
		assert.True(t, ok, "expected field %q", name)
	}
}

func TestHandleConfigRead_EmptyConfigReturnsEmptyData(t *testing.T) {
	b, ctx := newTestBackend(t)
	// b.config is nil by default for a freshly-constructed backend.
	d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathConfig().Fields}
	resp, err := b.handleConfigRead(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Data)
}

func TestHandleConfigRead_MasksTokenReviewerJWT(t *testing.T) {
	b, ctx := newTestBackend(t)
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host":    "https://kube",
		"tls_skip_verify":    true,
		"token_reviewer_jwt": "super-secret-reviewer-jwt",
	}))

	d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathConfig().Fields}
	resp, err := b.handleConfigRead(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "https://kube", resp.Data["kubernetes_host"])
	assert.Equal(t, maskedSecret, resp.Data["token_reviewer_jwt"],
		"token_reviewer_jwt must be masked, never returned in plaintext")
	assert.NotContains(t, resp.Data["token_reviewer_jwt"], "super-secret",
		"raw secret must not appear in the masked response")
}

func TestHandleConfigRead_EmptyReviewerJWTReturnsEmptyString(t *testing.T) {
	// When token_reviewer_jwt is unset (self-reviewing mode), the field
	// should be empty, not masked — operators need to see that no
	// reviewer JWT is configured.
	b, ctx := newTestBackend(t)
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": "https://kube",
		"tls_skip_verify": true,
	}))

	d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathConfig().Fields}
	resp, err := b.handleConfigRead(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, "", resp.Data["token_reviewer_jwt"])
}

func TestHandleConfigWrite_BasicWriteThenReadRoundTrip(t *testing.T) {
	b, ctx := newTestBackend(t)

	// tls_skip_verify=true so we don't have to mint a real PEM bundle
	// just to exercise the config-roundtrip plumbing.
	d := &framework.FieldData{
		Raw: map[string]any{
			"kubernetes_host":    "https://kube.example.com",
			"tls_skip_verify":    true,
			"token_reviewer_jwt": "reviewer-jwt-value",
			"issuer":             "https://kubernetes.default.svc",
		},
		Schema: b.pathConfig().Fields,
	}
	resp, err := b.handleConfigWrite(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err, "unexpected validation error: %v", resp.Err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read it back.
	rd := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathConfig().Fields}
	rResp, err := b.handleConfigRead(ctx, &logical.Request{}, rd)
	require.NoError(t, err)
	assert.Equal(t, "https://kube.example.com", rResp.Data["kubernetes_host"])
	assert.Equal(t, true, rResp.Data["tls_skip_verify"])
	assert.Equal(t, maskedSecret, rResp.Data["token_reviewer_jwt"])
	assert.Equal(t, "https://kubernetes.default.svc", rResp.Data["issuer"])
}

func TestHandleConfigWrite_RejectsMissingKubernetesHost(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := &framework.FieldData{
		Raw:    map[string]any{"kubernetes_ca_cert": "PEM"},
		Schema: b.pathConfig().Fields,
	}
	resp, err := b.handleConfigWrite(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "kubernetes_host is required")
}

func TestHandleConfigWrite_PartialUpdate_PreservesUnsetFields(t *testing.T) {
	b, ctx := newTestBackend(t)

	// Initial config with all fields set.
	d := &framework.FieldData{
		Raw: map[string]any{
			"kubernetes_host":    "https://initial",
			"tls_skip_verify":    true,
			"token_reviewer_jwt": "reviewer-initial",
			"issuer":             "https://initial-issuer",
		},
		Schema: b.pathConfig().Fields,
	}
	resp, err := b.handleConfigWrite(ctx, nil, d)
	require.NoError(t, err)
	require.Nil(t, resp.Err, "unexpected validation error on initial write: %v", resp.Err)

	// Partial update: only change the host. Reviewer JWT + issuer must persist.
	d2 := &framework.FieldData{
		Raw:    map[string]any{"kubernetes_host": "https://updated"},
		Schema: b.pathConfig().Fields,
	}
	resp2, err := b.handleConfigWrite(ctx, nil, d2)
	require.NoError(t, err)
	require.Nil(t, resp2.Err, "unexpected validation error on partial update: %v", resp2.Err)

	rd := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathConfig().Fields}
	rResp, err := b.handleConfigRead(ctx, &logical.Request{}, rd)
	require.NoError(t, err)
	assert.Equal(t, "https://updated", rResp.Data["kubernetes_host"])
	assert.Equal(t, true, rResp.Data["tls_skip_verify"],
		"unset tls_skip_verify in update should preserve prior value")
	assert.Equal(t, maskedSecret, rResp.Data["token_reviewer_jwt"])
	assert.Equal(t, "https://initial-issuer", rResp.Data["issuer"])
}
