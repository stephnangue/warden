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

func TestSysProtectedResourceConfig(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema := backend.pathProtectedResource()[0].Fields

	write := func(t *testing.T, raw map[string]any) *logical.Response {
		t.Helper()
		resp, err := backend.handleProtectedResourceConfigWrite(ctx,
			createTestRequest(logical.UpdateOperation, "protected-resource/config", raw),
			createFieldData(schema, raw))
		require.NoError(t, err)
		return resp
	}
	read := func(t *testing.T) *logical.Response {
		t.Helper()
		resp, err := backend.handleProtectedResourceConfigRead(ctx,
			createTestRequest(logical.ReadOperation, "protected-resource/config", nil),
			createFieldData(schema, nil))
		require.NoError(t, err)
		return resp
	}

	t.Run("disabled until resource_url is set", func(t *testing.T) {
		resp := read(t)
		require.False(t, resp.IsError())
		assert.Equal(t, false, resp.Data["enabled"], "no resource_url means no document can be named")
	})

	t.Run("rejects a non-https resource_url", func(t *testing.T) {
		resp := write(t, map[string]any{"resource_url": "http://warden.example.com"})
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Err.Error(), "resource_url must be https")
	})

	t.Run("rejects a bad cache_ttl", func(t *testing.T) {
		resp := write(t, map[string]any{"resource_url": "https://w.example.com", "cache_ttl": "soon"})
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Err.Error(), "cache_ttl must be a duration")
	})

	t.Run("an invalid write is not persisted", func(t *testing.T) {
		resp := read(t)
		assert.Equal(t, false, resp.Data["enabled"], "a rejected write must leave the feature off")
	})

	t.Run("enable and read back", func(t *testing.T) {
		resp := write(t, map[string]any{
			"resource_url":           "https://warden.example.com",
			"resource_documentation": "https://docs.example.com/mcp",
			"cache_ttl":              "30m",
		})
		require.False(t, resp.IsError(), "unexpected error: %v", resp.Err)

		resp = read(t)
		assert.Equal(t, true, resp.Data["enabled"])
		assert.Equal(t, "https://warden.example.com", resp.Data["resource_url"])
		assert.Equal(t, "https://docs.example.com/mcp", resp.Data["resource_documentation"])
		assert.Equal(t, int64(1800), resp.Data["cache_ttl"], "durations are reported as seconds")
	})

	t.Run("partial update keeps untouched fields", func(t *testing.T) {
		resp := write(t, map[string]any{"cache_ttl": "5m"})
		require.False(t, resp.IsError())

		resp = read(t)
		assert.Equal(t, "https://warden.example.com", resp.Data["resource_url"],
			"an omitted field must keep its stored value")
		assert.Equal(t, int64(300), resp.Data["cache_ttl"])
	})

	t.Run("merged result is validated, not just the delta", func(t *testing.T) {
		// resource_url is already valid in storage; the write only supplies a
		// bad authorization_servers. Validating the delta alone would let a
		// partial update persist a config that fails as a whole.
		resp := write(t, map[string]any{"authorization_servers": "not-a-url"})
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Err.Error(), "authorization_servers must be https")
	})

	t.Run("clearing resource_url disables the feature", func(t *testing.T) {
		resp := write(t, map[string]any{"resource_url": ""})
		require.False(t, resp.IsError())
		assert.Equal(t, false, read(t).Data["enabled"])
	})

	t.Run("loopback http is allowed for dev", func(t *testing.T) {
		resp := write(t, map[string]any{"resource_url": "http://127.0.0.1:8200"})
		require.False(t, resp.IsError(), "a dev deployment must not need TLS")
	})
}

func TestSysProtectedResourceConfig_RootNamespaceOnly(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)
	schema := backend.pathProtectedResource()[0].Fields
	nsCtx := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "/child/"})

	resp, err := backend.handleProtectedResourceConfigRead(nsCtx,
		createTestRequest(logical.ReadOperation, "protected-resource/config", nil),
		createFieldData(schema, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "root namespace",
		"the external base URL is a deployment-wide property")
}
