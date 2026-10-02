package kubernetes

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The discovery fields round-trip through create and read; provider_path is
// normalised and a bad skill name is a 400.
func TestRole_DiscoveryFields(t *testing.T) {
	b, ctx := newTestBackend(t)

	resp, err := b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "myapp",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"skill":                            "mcp-aws",
		"provider_path":                    "team/mcp-aws",
	}))
	require.NoError(t, err)
	require.Nil(t, resp.Err, "unexpected validation error: %v", resp.Err)

	resp, err = b.handleRoleRead(ctx, nil, roleFieldData(t, b, map[string]any{"name": "myapp"}))
	require.NoError(t, err)
	assert.Equal(t, "mcp-aws", resp.Data["skill"])
	assert.Equal(t, "team/mcp-aws/", resp.Data["provider_path"])

	resp, err = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "bad",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"skill":                            "mcp_aws",
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "invalid skill")
}
