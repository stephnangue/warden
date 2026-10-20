package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const deployersGroupJSON = `{"data":{
	"id":"0f1e",
	"name":"deployers",
	"type":"virtual",
	"description":"CI deployers",
	"roles":["deploy"],
	"rules":[{"mount":["auth/jwt/"],"repo":["acme/*"]}],
	"rule_count":1,
	"selector_count":2,
	"max_age":"10m0s",
	"metadata":{"owner":"platform"},
	"hash":"h1",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["role \"deploy\" does not exist yet; the group grants it once it does"]
}}`

func TestSys_CreateGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusCreated, deployersGroupJSON)

	g, err := client.Sys().CreateGroup("deployers", &GroupInput{
		Type:        "virtual",
		Description: strPtr("CI deployers"),
		Roles:       []string{"deploy"},
		Rules:       []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}},
		MaxAge:      strPtr("10m"),
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/identity/group/deployers", rec.path)
	assert.Equal(t, map[string]any{
		"type":        "virtual",
		"description": "CI deployers",
		"roles":       []any{"deploy"},
		"rules":       []any{map[string]any{"mount": []any{"auth/jwt/"}, "repo": []any{"acme/*"}}},
		"max_age":     "10m",
	}, rec.body, "only the fields the input sets are sent")

	assert.Equal(t, "0f1e", g.ID)
	assert.Equal(t, "virtual", g.Type)
	assert.Equal(t, []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}}, g.Rules)
	assert.Equal(t, 1, g.RuleCount)
	assert.Equal(t, 2, g.SelectorCount)
	assert.Equal(t, "10m0s", g.MaxAge)
	assert.Equal(t, "h1", g.Hash)
	assert.Len(t, g.Warnings, 1)
}

func TestSys_ReadUpdateGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, deployersGroupJSON)

	g, err := client.Sys().ReadGroup("deployers")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "deployers", g.Name)

	_, err = client.Sys().UpdateGroup("deployers", &GroupInput{Roles: []string{}, ExpectedHash: "h1"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, rec.method)
	assert.Equal(t, map[string]any{"roles": []any{}, "expected_hash": "h1"}, rec.body,
		"an empty list clears; type is not sent when unset")
}

func TestSys_DeleteGroup(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"name":"deployers"}}`)
	require.NoError(t, client.Sys().DeleteGroup("deployers", "h1"))
	assert.Equal(t, http.MethodDelete, rec.method)
	assert.Equal(t, "/v1/sys/identity/group/deployers", rec.path)
	assert.Equal(t, "h1", rec.query.Get("expected_hash"))
}

func TestSys_ListGroups(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"keys":["ci","deployers"],
		"groups":[
			{"name":"ci","type":"virtual","roles":["deploy","read"]},
			{"name":"deployers","type":"virtual","roles":["deploy"]}
		]
	}}`)

	groups, err := client.Sys().ListGroups("deploy")
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/identity/group", rec.path)
	assert.Equal(t, "true", rec.query.Get("warden-list"))
	assert.Equal(t, "deploy", rec.query.Get("role"))
	require.Len(t, groups, 2)
	assert.Equal(t, []string{"deploy", "read"}, groups[0].Roles)

	_, err = client.Sys().ListGroups("")
	require.NoError(t, err)
	assert.False(t, rec.query.Has("role"))
}

func TestSys_ListGroups_Empty(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusOK, `{"data":{"keys":[],"groups":[]}}`)
	groups, err := client.Sys().ListGroups("")
	require.NoError(t, err)
	assert.Empty(t, groups)
	assert.NotNil(t, groups)
}

func TestSys_ReadIdentityUsage(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"groups":{
			"total":42,
			"virtual":{"count":42,"max":8000,"selectors":310,"max_selectors":16000}
		}
	}}`)

	u, err := client.Sys().ReadIdentityUsage()
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/v1/sys/identity/usage", rec.path)
	assert.Equal(t, &IdentityUsage{Groups: GroupsUsage{
		Total:   42,
		Virtual: VirtualGroupsUsage{Count: 42, Max: 8000, Selectors: 310, MaxSelectors: 16000},
	}}, u)
}

func TestSys_ReadIdentityUsage_Forbidden(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)
	_, err := client.Sys().ReadIdentityUsage()
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusForbidden, respErr.StatusCode)
}
