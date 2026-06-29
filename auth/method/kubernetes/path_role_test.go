package kubernetes

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// roleFieldData builds a FieldData targeting the role path schema with
// the given raw values. The "name" key is the role name; other keys
// match the field schema in path_role.go.
func roleFieldData(t *testing.T, b *kubernetesAuthBackend, raw map[string]any) *framework.FieldData {
	t.Helper()
	return &framework.FieldData{Raw: raw, Schema: b.pathRole().Fields}
}

func TestExtractK8sMetadata(t *testing.T) {
	t.Run("maps attributes, comma-joins groups, skips empty", func(t *testing.T) {
		// mappings are source (TokenReview attribute) -> target (metadata key)
		md := extractK8sMetadata(map[string]string{
			"service_account_namespace": "ns",
			"service_account_name":      "sa",
			"service_account_uid":       "uid",
			"username":                  "user",
			"groups":                    "groups",
		},
			"prod", "deployer", "uid-123", "system:serviceaccount:prod:deployer",
			[]string{"system:serviceaccounts", "system:serviceaccounts:prod"})
		assert.Equal(t, map[string]string{
			"ns":     "prod",
			"sa":     "deployer",
			"uid":    "uid-123",
			"user":   "system:serviceaccount:prod:deployer",
			"groups": "system:serviceaccounts,system:serviceaccounts:prod",
		}, md)
	})

	t.Run("nil mappings", func(t *testing.T) {
		assert.Nil(t, extractK8sMetadata(nil, "prod", "deployer", "uid", "user", nil))
	})

	t.Run("all empty -> nil", func(t *testing.T) {
		assert.Nil(t, extractK8sMetadata(map[string]string{"groups": "g"}, "prod", "deployer", "uid", "user", nil))
	})
}

func TestHandleRole_MetadataMappings_RoundTrip(t *testing.T) {
	b, ctx := newTestBackend(t)

	d := roleFieldData(t, b, map[string]any{
		"name":                             "meta",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"prod"},
		"metadata_mappings": map[string]any{
			"service_account_namespace": "ns",
			"service_account_name":      "sa",
		},
	})
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.Nil(t, resp.Err, "unexpected validation error: %v", resp.Err)

	role, err := b.getRole(ctx, "meta")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"service_account_namespace": "ns",
		"service_account_name":      "sa",
	}, role.MetadataMappings)
}

func TestHandleRole_MetadataMappings_InvalidField(t *testing.T) {
	b, ctx := newTestBackend(t)

	d := roleFieldData(t, b, map[string]any{
		"name":                             "bad-meta",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"prod"},
		"metadata_mappings":                map[string]any{"not_an_attr": "x"},
	})
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "invalid metadata_mappings field")
}

func TestHandleRoleCreate_Basic(t *testing.T) {
	b, ctx := newTestBackend(t)

	d := roleFieldData(t, b, map[string]any{
		"name":                             "myapp",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"token_policies":                   []string{"default"},
		"token_ttl":                        3600,
	})
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err, "unexpected validation error: %v", resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "myapp", resp.Data["name"])
}

func TestHandleRoleCreate_DuplicateConflicts(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name":                             "dup",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
	})
	_, _ = b.handleRoleCreate(ctx, nil, d)

	// Second create with same name should 409 conflict.
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "already exists")
}

func TestHandleRoleCreate_RefusesBothWildcards(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name":                             "wildwild",
		"bound_service_account_names":      []string{"*"},
		"bound_service_account_namespaces": []string{"*"},
	})
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp.Err, "must refuse */* binding")
	assert.Contains(t, resp.Err.Error(), "at least one of bound_service_account_names")
}

func TestHandleRoleCreate_RefusesBothEmpty(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name": "noboundings",
	})
	resp, err := b.handleRoleCreate(ctx, nil, d)
	require.NoError(t, err)
	require.NotNil(t, resp.Err, "must refuse empty bindings")
	assert.Contains(t, resp.Err.Error(), "at least one of bound_service_account_names")
}

func TestHandleRoleCreate_PinsTokenType(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name":                             "pinned",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
	})
	_, _ = b.handleRoleCreate(ctx, nil, d)

	role, err := b.getRole(ctx, "pinned")
	require.NoError(t, err)
	require.NotNil(t, role)
	assert.Equal(t, "kubernetes_role", role.TokenType,
		"TokenType must always be pinned to kubernetes_role regardless of operator input")
}

func TestHandleRoleCreate_DefaultsTokenTTLToOneHour(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name":                             "defaultttl",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
	})
	_, _ = b.handleRoleCreate(ctx, nil, d)

	role, err := b.getRole(ctx, "defaultttl")
	require.NoError(t, err)
	require.NotNil(t, role)
	ttl, err := role.ParseTokenTTL()
	require.NoError(t, err)
	assert.Equal(t, time.Hour, ttl)
}

func TestHandleRoleRead_Roundtrip(t *testing.T) {
	b, ctx := newTestBackend(t)
	createData := roleFieldData(t, b, map[string]any{
		"name":                             "roundtrip",
		"description":                      "round-trip test",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default", "prod"},
		"audience":                         "api",
		"token_policies":                   []string{"reader", "writer"},
	})
	_, _ = b.handleRoleCreate(ctx, nil, createData)

	resp, err := b.handleRoleRead(ctx, nil, roleFieldData(t, b, map[string]any{"name": "roundtrip"}))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err)
	assert.Equal(t, "roundtrip", resp.Data["name"])
	assert.Equal(t, "round-trip test", resp.Data["description"])
	assert.Equal(t, []string{"myapp"}, resp.Data["bound_service_account_names"])
	assert.Equal(t, []string{"default", "prod"}, resp.Data["bound_service_account_namespaces"])
	assert.Equal(t, "api", resp.Data["audience"])
	assert.Equal(t, []string{"reader", "writer"}, resp.Data["token_policies"])
}

func TestHandleRoleRead_NotFound(t *testing.T) {
	b, ctx := newTestBackend(t)
	resp, err := b.handleRoleRead(ctx, nil, roleFieldData(t, b, map[string]any{"name": "ghost"}))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "not found")
}

func TestHandleRoleUpdate_CreatesIfMissing(t *testing.T) {
	b, ctx := newTestBackend(t)
	d := roleFieldData(t, b, map[string]any{
		"name":                             "upsert",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
	})
	resp, err := b.handleRoleUpdate(ctx, nil, d)
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestHandleRoleUpdate_PatchesExistingFields(t *testing.T) {
	b, ctx := newTestBackend(t)
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "patch",
		"description":                      "before",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
		"token_policies":                   []string{"default"},
	}))

	// Update only the description; SA bindings and policies must persist.
	resp, err := b.handleRoleUpdate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":        "patch",
		"description": "after",
	}))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	role, err := b.getRole(ctx, "patch")
	require.NoError(t, err)
	assert.Equal(t, "after", role.Description)
	assert.Equal(t, []string{"app"}, role.BoundServiceAccountNames)
	assert.Equal(t, []string{"default"}, role.BoundServiceAccountNamespaces)
	assert.Equal(t, []string{"default"}, role.TokenPolicies)
}

func TestHandleRoleDelete(t *testing.T) {
	b, ctx := newTestBackend(t)
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "deleteme",
		"bound_service_account_names":      []string{"app"},
		"bound_service_account_namespaces": []string{"default"},
	}))

	resp, err := b.handleRoleDelete(ctx, nil, roleFieldData(t, b, map[string]any{"name": "deleteme"}))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Confirm gone.
	role, err := b.getRole(ctx, "deleteme")
	require.NoError(t, err)
	assert.Nil(t, role)
}

func TestHandleRoleList(t *testing.T) {
	b, ctx := newTestBackend(t)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
			"name":                             name,
			"bound_service_account_names":      []string{"app"},
			"bound_service_account_namespaces": []string{"default"},
		}))
	}

	resp, err := b.handleRoleList(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok, "list response should contain []string keys")
	assert.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, keys)
}

func TestValidateRole_BadMaxAge(t *testing.T) {
	b, _ := newTestBackend(t)
	tests := []struct {
		max string
		msg string
	}{
		{"not-a-duration", "invalid max_age"},
		{"-5m", "max_age must be a positive duration"},
		{"0s", "max_age must be a positive duration"},
	}
	for _, tc := range tests {
		t.Run(tc.max, func(t *testing.T) {
			err := b.validateRole(&KubernetesRole{
				BoundServiceAccountNames:      []string{"app"},
				BoundServiceAccountNamespaces: []string{"default"},
				MaxAge:                        tc.max,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestValidateRole_AcceptsValidMaxAge(t *testing.T) {
	b, _ := newTestBackend(t)
	err := b.validateRole(&KubernetesRole{
		BoundServiceAccountNames:      []string{"app"},
		BoundServiceAccountNamespaces: []string{"default"},
		MaxAge:                        "5m",
	})
	require.NoError(t, err)
}
