package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSysOIDCIssuerConfig(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	write := func(ctx context.Context, raw map[string]any) *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
		require.NoError(t, err)
		require.NotNil(t, resp)
		return resp
	}
	read := func(ctx context.Context) *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigRead(ctx, createTestRequest(logical.ReadOperation, "oidc-issuer/config", nil), createFieldData(schema, nil))
		require.NoError(t, err)
		require.NotNil(t, resp)
		return resp
	}

	// Disabled by default: read before any config.
	resp := read(ctx)
	assert.Equal(t, false, resp.Data["enabled"])
	assert.Nil(t, core.OIDCIssuer())

	// Enable it: the issuer becomes ready and mints.
	resp = write(ctx, map[string]any{
		"enabled":       true,
		"issuer_url":    "https://warden-oidc.example",
		"assertion_ttl": 300,
	})
	require.False(t, resp.IsError(), "enable should succeed: %+v", resp.Data)
	require.NotNil(t, core.OIDCIssuer())
	assert.True(t, core.OIDCIssuer().Ready())

	// Read back.
	resp = read(ctx)
	assert.Equal(t, true, resp.Data["enabled"])
	assert.Equal(t, "https://warden-oidc.example", resp.Data["issuer_url"])
	assert.Equal(t, true, resp.Data["ready"])

	// Validation: enabled without issuer_url.
	assert.True(t, write(ctx, map[string]any{"enabled": true}).IsError())
	// Validation: non-HTTPS issuer_url.
	assert.True(t, write(ctx, map[string]any{"enabled": true, "issuer_url": "http://insecure"}).IsError())

	// Disable: issuer torn down.
	resp = write(ctx, map[string]any{"enabled": false})
	require.False(t, resp.IsError())
	assert.Nil(t, core.OIDCIssuer())
}

func TestSysOIDCIssuerConfig_RootNamespaceOnly(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	childCtx := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "/child/"})
	raw := map[string]any{"enabled": true, "issuer_url": "https://warden-oidc.example"}

	// A child namespace can neither write nor read the global issuer config.
	resp, err := backend.handleOIDCIssuerConfigWrite(childCtx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, err = backend.handleOIDCIssuerConfigRead(childCtx, createTestRequest(logical.ReadOperation, "oidc-issuer/config", nil), createFieldData(schema, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
