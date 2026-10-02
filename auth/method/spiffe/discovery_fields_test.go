package spiffe

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// The discovery fields round-trip through create and read; provider_path is
// normalised and a bad shape is a 400.
func TestRole_DiscoveryFields(t *testing.T) {
	b, ctx := createTestBackend(t)

	resp := createRole(t, b, ctx, map[string]any{
		"name": "reader", "trust_domain": "example.org",
		"skill": "vault", "provider_path": "vault/",
	})
	require.Nil(t, resp.Err, "unexpected validation error: %v", resp.Err)

	resp, err := b.handleRoleRead(ctx, &logical.Request{}, &framework.FieldData{
		Raw: map[string]any{"name": "reader"}, Schema: b.pathRole().Fields,
	})
	require.NoError(t, err)
	assert.Equal(t, "vault", resp.Data["skill"])
	assert.Equal(t, "vault/", resp.Data["provider_path"])

	resp = createRole(t, b, ctx, map[string]any{
		"name": "bad", "trust_domain": "example.org", "provider_path": "a/../b",
	})
	require.NotNil(t, resp.Err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
