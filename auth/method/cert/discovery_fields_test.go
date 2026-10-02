package cert

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// The discovery fields round-trip through create, read and introspection's
// projection; provider_path is normalised and a bad shape is a 400.
func TestRole_DiscoveryFields(t *testing.T) {
	b, ctx := createTestBackend(t)
	fd := func(raw map[string]any) *framework.FieldData {
		return &framework.FieldData{Raw: raw, Schema: b.pathRole().Fields}
	}

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd(map[string]any{
		"name": "reader", "allowed_common_names": "agent-*",
		"skill": "vault", "provider_path": "vault",
	}))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)

	resp, err = b.handleRoleRead(ctx, &logical.Request{}, fd(map[string]any{"name": "reader"}))
	require.NoError(t, err)
	assert.Equal(t, "vault", resp.Data["skill"])
	assert.Equal(t, "vault/", resp.Data["provider_path"])

	resp, err = b.handleRoleCreate(ctx, &logical.Request{}, fd(map[string]any{
		"name": "bad", "allowed_common_names": "agent-*", "provider_path": "/vault",
	}))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
