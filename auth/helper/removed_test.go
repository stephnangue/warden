package helper

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func TestRemovedRolePaths(t *testing.T) {
	paths := RemovedRolePaths()
	require.Len(t, paths, 2)
	for _, p := range paths {
		for _, op := range []logical.Operation{
			logical.CreateOperation, logical.ReadOperation, logical.UpdateOperation,
			logical.PatchOperation, logical.DeleteOperation, logical.ListOperation,
		} {
			h, ok := p.Operations[op]
			require.True(t, ok, "%s on %s", op, p.Pattern)
			resp, err := h.(*framework.PathOperation).Callback(context.Background(), &logical.Request{}, &framework.FieldData{})
			require.NoError(t, err)
			assert.Equal(t, http.StatusGone, resp.StatusCode)
			assert.EqualError(t, resp.Err, AuthRolesRemovedMessage)
		}
	}
}

func TestRemovedConfigKeys(t *testing.T) {
	conf := map[string]any{
		"default_role":        "reader",
		"groups_claim":        "",  // empty: sets nothing
		"group_policy_prefix": nil, // nothing
		"metadata_claims":     map[string]any{"repo": "repository"},
		"metadata_mappings":   map[string]any{}, // empty map: nothing
		"token_type":          "jwt_role",
		"bound_audiences":     []string{"warden"},
	}
	assert.Equal(t, []string{"default_role", "metadata_claims", "token_type"}, RemovedConfigKeys(conf))
	assert.Nil(t, RemovedConfigKeys(map[string]any{"bound_audiences": []string{"warden"}}))

	warnings := RemovedConfigWarnings([]string{"default_role", "metadata_claims"})
	require.Len(t, warnings, 2)
	assert.Contains(t, warnings[0], "default_role was removed and is ignored")
	assert.Contains(t, warnings[0], "provider")
	assert.Contains(t, warnings[1], "metadata_claims was replaced by facts")
	assert.Nil(t, RemovedConfigWarnings(nil))

	err := RefuseRemovedConfigKeys(conf)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))
	for _, key := range []string{"default_role", "metadata_claims", "token_type"} {
		assert.Contains(t, err.Error(), key+" was removed")
	}
	assert.NoError(t, RefuseRemovedConfigKeys(map[string]any{"default_role": ""}))
	assert.NoError(t, RefuseRemovedConfigKeys(nil))

	data := map[string]any{}
	SetWarnings(data, nil)
	assert.NotContains(t, data, "warnings")
	SetWarnings(data, []string{"w"})
	assert.Equal(t, []string{"w"}, data["warnings"])
}
