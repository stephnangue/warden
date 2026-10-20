package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roleServer answers every request with status and body and records the last
// request's method, path, query and decoded JSON body.
type roleServer struct {
	method, path string
	query        url.Values
	body         map[string]any
}

func newRoleServer(t *testing.T, status int, respBody string) (*Client, *roleServer) {
	t.Helper()
	rec := &roleServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method, rec.path, rec.query = r.Method, r.URL.Path, r.URL.Query()
		rec.body = nil
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &rec.body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.Address = srv.URL
	client, err := NewClient(cfg)
	require.NoError(t, err)
	return client, rec
}

const deployRoleJSON = `{"data":{
	"name":"deploy",
	"description":"Deploys from acme CI",
	"policies":["deploy"],
	"cred_spec_name":"deploy-role",
	"skill":"aws",
	"provider_path":"aws/",
	"metadata":{"team":"platform"},
	"hash":"abc123",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["policy \"deploy\" does not exist yet"]
}}`

func strPtr(s string) *string { return &s }

func TestSys_CreateRole(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusCreated, deployRoleJSON)

	role, err := client.Sys().CreateRole("deploy", &RoleInput{
		Description:  strPtr("Deploys from acme CI"),
		Policies:     []string{"deploy"},
		CredSpecName: strPtr("deploy-role"),
		ProviderPath: strPtr("aws/"),
		Metadata:     map[string]string{"team": "platform"},
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, rec.method)
	assert.Equal(t, "/v1/sys/roles/deploy", rec.path)
	assert.Equal(t, map[string]any{
		"description":    "Deploys from acme CI",
		"policies":       []any{"deploy"},
		"cred_spec_name": "deploy-role",
		"provider_path":  "aws/",
		"metadata":       map[string]any{"team": "platform"},
	}, rec.body, "only the fields the input sets are sent")

	assert.Equal(t, "deploy", role.Name)
	assert.Equal(t, []string{"deploy"}, role.Policies)
	assert.Equal(t, "aws/", role.ProviderPath)
	assert.Equal(t, "aws", role.Skill)
	assert.Equal(t, map[string]string{"team": "platform"}, role.Metadata)
	assert.Equal(t, "abc123", role.Hash)
	assert.Equal(t, 2026, role.CreatedAt.Year())
	assert.Equal(t, []string{`policy "deploy" does not exist yet`}, role.Warnings)
}

func TestSys_ReadRole(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, deployRoleJSON)

	role, err := client.Sys().ReadRole("deploy")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/v1/sys/roles/deploy", rec.path)
	assert.Equal(t, "Deploys from acme CI", role.Description)
	assert.Equal(t, "deploy-role", role.CredSpecName)
}

func TestSys_ReadRole_NotFound(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusNotFound, `{"errors":["role \"deploy\" not found"]}`)

	_, err := client.Sys().ReadRole("deploy")
	require.Error(t, err)
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusNotFound, respErr.StatusCode)
}

func TestSys_UpdateRole(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, deployRoleJSON)

	// An empty, non-nil list and an empty string clear; nil fields are not sent.
	_, err := client.Sys().UpdateRole("deploy", &RoleInput{
		Policies:     []string{},
		CredSpecName: strPtr(""),
		ExpectedHash: "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, rec.method)
	assert.Equal(t, "/v1/sys/roles/deploy", rec.path)
	assert.Equal(t, map[string]any{
		"policies":       []any{},
		"cred_spec_name": "",
		"expected_hash":  "abc123",
	}, rec.body)
}

func TestSys_UpdateRole_Conflict(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusConflict, `{"errors":["role \"deploy\" changed since it was read"]}`)

	_, err := client.Sys().UpdateRole("deploy", &RoleInput{Description: strPtr("x"), ExpectedHash: "stale"})
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusConflict, respErr.StatusCode)
}

func TestSys_DeleteRole(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{"name":"deploy"}}`)

	require.NoError(t, client.Sys().DeleteRole("deploy", ""))
	assert.Equal(t, http.MethodDelete, rec.method)
	assert.Equal(t, "/v1/sys/roles/deploy", rec.path)
	assert.Empty(t, rec.query.Get("expected_hash"))

	require.NoError(t, client.Sys().DeleteRole("deploy", "abc123"))
	assert.Equal(t, "abc123", rec.query.Get("expected_hash"))
}

func TestSys_ListRoles(t *testing.T) {
	client, rec := newRoleServer(t, http.StatusOK, `{"data":{
		"keys":["deploy","read-secrets"],
		"roles":[
			{"name":"deploy","policies":["deploy"],"provider_path":"aws/"},
			{"name":"read-secrets","policies":[],"provider_path":"vault/"}
		]
	}}`)

	roles, err := client.Sys().ListRoles("")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/v1/sys/roles", rec.path)
	assert.Equal(t, "true", rec.query.Get("warden-list"))
	assert.Empty(t, rec.query.Get("provider_path"))
	require.Len(t, roles, 2)
	assert.Equal(t, "deploy", roles[0].Name)
	assert.Equal(t, "vault/", roles[1].ProviderPath)

	_, err = client.Sys().ListRoles("aws/")
	require.NoError(t, err)
	assert.Equal(t, "aws/", rec.query.Get("provider_path"))
}

func TestSys_ListRoles_Empty(t *testing.T) {
	client, _ := newRoleServer(t, http.StatusOK, `{"data":{"keys":[],"roles":[]}}`)

	roles, err := client.Sys().ListRoles("")
	require.NoError(t, err)
	assert.Empty(t, roles)
}
