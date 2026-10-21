package roles

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeWarden stands in for the server: sys/schema answers a small OpenAPI
// document for the role paths, and sys/roles answers the canned role. Every
// sys/roles request is recorded.
type fakeWarden struct {
	mu       sync.Mutex
	requests []recorded
	status   int
	body     string

	// Group listings (the granted-by join) are answered and recorded apart.
	groupRequests []recorded
	groupsStatus  int
	groupsBody    string
}

type recorded struct {
	method, path string
	query        url.Values
	body         map[string]any
}

// roleSchemaDoc mirrors what the server emits: one body under "post" that
// serves both create and update, and no "put".
const roleSchemaDoc = `{"data":{"openapi":{"paths":{"/sys/roles/{name}":{
	"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{
		"description":{"type":"string"},
		"policies":{"type":"array"},
		"cred_spec_name":{"type":"string"},
		"skill":{"type":"string"},
		"provider_path":{"type":"string"},
		"metadata":{"type":"object"},
		"expected_hash":{"type":"string"}
	}}}}}}
}}}}}`

const cannedRole = `{"data":{
	"name":"deploy",
	"description":"Deploys from acme CI",
	"policies":["deploy"],
	"cred_spec_name":"deploy-role",
	"skill":"",
	"provider_path":"aws/",
	"metadata":{"team":"platform"},
	"hash":"abc123",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["policy \"deploy\" does not exist yet"]
}}`

func (f *fakeWarden) last(t *testing.T) recorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests, "no request reached sys/roles")
	return f.requests[len(f.requests)-1]
}

func (f *fakeWarden) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// setupFake installs a fake server, a client for it, JSON output and captured
// writers, and resets the package state afterwards.
func setupFake(t *testing.T, status int, body string) (*fakeWarden, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	f := &fakeWarden{status: status, body: body,
		groupsStatus: http.StatusOK, groupsBody: `{"data":{"keys":[],"groups":[]}}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/sys/schema" {
			_, _ = w.Write([]byte(roleSchemaDoc))
			return
		}
		rec := recorded{method: r.Method, path: r.URL.Path, query: r.URL.Query()}
		if r.URL.Path == "/v1/sys/identity/group" {
			f.mu.Lock()
			f.groupRequests = append(f.groupRequests, rec)
			status, body := f.groupsStatus, f.groupsBody
			f.mu.Unlock()
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
		}
		f.mu.Lock()
		f.requests = append(f.requests, rec)
		f.mu.Unlock()
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}))

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetMaxRetries(0)
	helpers.SetTestClient(client)
	helpers.ResetSchemaCache()
	helpers.SetOutputFormat("json")

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(stderr)

	t.Cleanup(func() {
		srv.Close()
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.SetFields("")
		helpers.SetDryRun(false)
		helpers.ResetWriters()
		helpers.ResetSchemaCache()
		createJSON, updateJSON, updateExpectedHash = "", "", ""
		createFlags.reset()
		updateFlags.reset()
		deleteForce, deleteExpectedHash = false, ""
		listAll, providerPathFilter = false, ""
	})
	return f, stdout, stderr
}

// freshCreateCmd binds the create flags to a new command, so flags set by one
// test are not seen as changed by the next.
func freshCreateCmd() *cobra.Command {
	cmd := &cobra.Command{}
	createFlags.bind(cmd)
	cmd.Flags().StringVarP(&createJSON, "json", "j", "", "")
	return cmd
}

func freshUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{}
	updateFlags.bind(cmd)
	cmd.Flags().StringVar(&updateExpectedHash, "expected-hash", "", "")
	cmd.Flags().StringVarP(&updateJSON, "json", "j", "", "")
	return cmd
}

func decodeOut(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &m), "stdout: %s", out.String())
	return m
}

func TestCreate_JSON(t *testing.T) {
	f, stdout, stderr := setupFake(t, http.StatusCreated, cannedRole)
	cmd := freshCreateCmd()
	createJSON = `{
		"description": "Deploys from acme CI",
		"policies": ["deploy"],
		"cred_spec_name": "deploy-role",
		"provider_path": "aws/"
	}`

	require.NoError(t, runCreate(cmd, []string{"deploy"}))

	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/roles/deploy", req.path)
	assert.Equal(t, map[string]any{
		"description":    "Deploys from acme CI",
		"policies":       []any{"deploy"},
		"cred_spec_name": "deploy-role",
		"provider_path":  "aws/",
	}, req.body, "the -json payload is sent as given")

	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["created"])
	assert.Equal(t, "deploy", out["name"])
	assert.Equal(t, "abc123", out["hash"])
	assert.Contains(t, stderr.String(), `warning: policy "deploy" does not exist yet`,
		"warnings go to stderr, leaving stdout clean JSON")
}

func TestCreate_TypedFlags(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedRole)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("policies", "deploy,audit"))
	require.NoError(t, cmd.Flags().Set("provider-path", "aws/"))
	require.NoError(t, cmd.Flags().Set("metadata", "team=platform"))

	require.NoError(t, runCreate(cmd, []string{"deploy"}))
	assert.Equal(t, map[string]any{
		"policies":      []any{"deploy", "audit"},
		"provider_path": "aws/",
		"metadata":      map[string]any{"team": "platform"},
	}, f.last(t).body, "only the flags that were set are sent")
}

func TestCreate_JSONAndFlagsRejected(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedRole)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("description", "x"))
	createJSON = `{"policies": ["deploy"]}`

	err := runCreate(cmd, []string{"deploy"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Contains(t, err.Error(), "-description")
	assert.Zero(t, f.count(), "nothing is sent")
}

func TestCreate_InvalidName(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedRole)
	err := runCreate(freshCreateCmd(), []string{"de/ploy"})
	require.Error(t, err)
	assert.Zero(t, f.count())
}

func TestCreate_DryRun(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusCreated, cannedRole)
	helpers.SetDryRun(true)

	cmd := freshCreateCmd()
	createJSON = `{"policies": ["deploy"], "provider_path": "aws/"}`
	require.NoError(t, runCreate(cmd, []string{"deploy"}))
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["dry_run"])
	assert.Equal(t, true, out["validated"])
	assert.Zero(t, f.count(), "a dry run sends nothing to sys/roles")

	cmd = freshCreateCmd()
	createJSON = `{"polices": ["deploy"]}`
	err := runCreate(cmd, []string{"deploy"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `did you mean "policies"`)
	assert.Zero(t, f.count())
}

func TestUpdate_TypedFlagsClearAndCAS(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedRole)
	cmd := freshUpdateCmd()
	require.NoError(t, cmd.Flags().Set("cred-spec-name", ""))
	require.NoError(t, cmd.Flags().Set("expected-hash", "abc123"))

	require.NoError(t, runUpdate(cmd, []string{"deploy"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPut, req.method)
	assert.Equal(t, map[string]any{
		"cred_spec_name": "",
		"expected_hash":  "abc123",
	}, req.body, "an empty flag clears its field; -expected-hash rides along")
	assert.Equal(t, true, decodeOut(t, stdout)["updated"])
}

// TestUpdate_DryRun: an update's body is documented under "post"; the dry run
// must still find it and catch a misspelled field.
func TestUpdate_DryRun(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedRole)
	helpers.SetDryRun(true)

	cmd := freshUpdateCmd()
	updateJSON = `{"description": "x"}`
	require.NoError(t, runUpdate(cmd, []string{"deploy"}))
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["validated"])
	assert.Nil(t, out["note"], "the body schema was found, not soft-passed")

	cmd = freshUpdateCmd()
	updateJSON = `{"polices": ["deploy"]}`
	err := runUpdate(cmd, []string{"deploy"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `did you mean "policies"`)
	assert.Zero(t, f.count(), "a dry run sends nothing to sys/roles")
}

func TestUpdate_NothingToUpdate(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, cannedRole)
	err := runUpdate(freshUpdateCmd(), []string{"deploy"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Zero(t, f.count())
}

func TestUpdate_JSON(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, cannedRole)
	cmd := freshUpdateCmd()
	updateJSON = `{
		"policies": [],
		"expected_hash": "abc123"
	}`
	require.NoError(t, runUpdate(cmd, []string{"deploy"}))
	assert.Equal(t, map[string]any{
		"policies":      []any{},
		"expected_hash": "abc123",
	}, f.last(t).body)
}

func TestUpdate_ConflictSurfaces(t *testing.T) {
	setupFake(t, http.StatusConflict, `{"errors":["role \"deploy\" changed since it was read"]}`)
	cmd := freshUpdateCmd()
	updateJSON = `{"description": "x", "expected_hash": "stale"}`
	err := runUpdate(cmd, []string{"deploy"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed since it was read")
}

func TestRead_JSON(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedRole)
	require.NoError(t, runRead(ReadCmd, []string{"deploy"}))
	assert.Equal(t, http.MethodGet, f.last(t).method)
	out := decodeOut(t, stdout)
	assert.Equal(t, "deploy-role", out["cred_spec_name"])
	assert.Equal(t, "abc123", out["hash"])
}

func TestDelete_ForceWithExpectedHash(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, `{"data":{"name":"deploy"}}`)
	deleteForce, deleteExpectedHash = true, "abc123"

	require.NoError(t, runDelete(DeleteCmd, []string{"deploy"}))
	req := f.last(t)
	assert.Equal(t, http.MethodDelete, req.method)
	assert.Equal(t, "/v1/sys/roles/deploy", req.path)
	assert.Equal(t, "abc123", req.query.Get("expected_hash"))
	assert.Equal(t, true, decodeOut(t, stdout)["deleted"])
}

func TestListAll(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, `{"data":{
		"keys":["deploy","read-secrets"],
		"roles":[
			{"name":"deploy","description":"Deploys from acme CI","policies":["deploy"],"provider_path":"aws/","metadata":{"team":"platform"}},
			{"name":"read-secrets","policies":["read"],"provider_path":"vault/","skill":"vault"}
		]
	}}`)
	listAll, providerPathFilter = true, "aws/"

	require.NoError(t, runList(ListCmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/roles", req.path)
	assert.Equal(t, "true", req.query.Get("warden-list"))
	assert.Equal(t, "aws/", req.query.Get("provider_path"))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items))
	require.Len(t, items, 2)
	assert.Equal(t, "deploy", items[0]["name"])
	assert.Equal(t, []any{"deploy"}, items[0]["policies"])
	assert.Equal(t, map[string]any{"team": "platform"}, items[0]["metadata"])
	assert.Equal(t, map[string]any{}, items[1]["metadata"], "a role without metadata lists an empty object")
	assert.Equal(t, "vault", items[1]["skill"])
}

const twoGroups = `{"data":{
	"keys":["admins","ci"],
	"groups":[
		{"name":"admins","type":"virtual","roles":["deploy","read-secrets"]},
		{"name":"ci","type":"virtual","roles":["deploy"]}
	]
}}`

// TestListAll_GrantedBy: the inventory fills granted_by from one unfiltered
// group listing, whatever the number of roles.
func TestListAll_GrantedBy(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, `{"data":{
		"keys":["deploy","read-secrets","unused"],
		"roles":[{"name":"deploy"},{"name":"read-secrets"},{"name":"unused"}]
	}}`)
	f.groupsBody = twoGroups
	listAll = true

	require.NoError(t, runList(ListCmd, nil))
	require.Len(t, f.groupRequests, 1, "one group listing, not one per role")
	assert.False(t, f.groupRequests[0].query.Has("role"), "the listing is unfiltered and inverted client-side")
	assert.Equal(t, "true", f.groupRequests[0].query.Get("warden-list"))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items))
	require.Len(t, items, 3)
	assert.Equal(t, []any{"admins", "ci"}, items[0]["granted_by"])
	assert.Equal(t, []any{"admins"}, items[1]["granted_by"])
	assert.Equal(t, []any{}, items[2]["granted_by"], "a role no group lists shows an empty list")
}

// TestListAll_GrantedByUnavailable: without access to the groups the inventory
// still lists the roles, warns, and leaves granted_by out.
func TestListAll_GrantedByUnavailable(t *testing.T) {
	f, stdout, stderr := setupFake(t, http.StatusOK, `{"data":{"keys":["deploy"],"roles":[{"name":"deploy"}]}}`)
	f.groupsStatus, f.groupsBody = http.StatusForbidden, `{"errors":["permission denied"]}`
	listAll = true

	require.NoError(t, runList(ListCmd, nil))
	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items))
	require.Len(t, items, 1)
	assert.NotContains(t, items[0], "granted_by")
	assert.Contains(t, stderr.String(), "cannot list groups to fill granted_by")
}

func TestRead_GrantedBy(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedRole)
	f.groupsBody = `{"data":{"keys":["ci"],"groups":[{"name":"ci","roles":["deploy"]}]}}`

	require.NoError(t, runRead(ReadCmd, []string{"deploy"}))
	require.Len(t, f.groupRequests, 1)
	assert.Equal(t, "deploy", f.groupRequests[0].query.Get("role"), "one listing filtered to the role")
	assert.Equal(t, []any{"ci"}, decodeOut(t, stdout)["granted_by"])
}

func TestDelete_WarnsNamingGroups(t *testing.T) {
	_, stdout, stderr := setupFake(t, http.StatusOK, `{"data":{"name":"deploy","warnings":[
		"groups still list \"deploy\": ci (they grant nothing until the role is re-created)"
	]}}`)
	deleteForce = true

	require.NoError(t, runDelete(DeleteCmd, []string{"deploy"}))
	assert.Contains(t, stderr.String(), `warning: groups still list "deploy": ci`)
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["deleted"])
	assert.Equal(t, []any{`groups still list "deploy": ci (they grant nothing until the role is re-created)`}, out["warnings"])
}

func TestListAll_FlagCombinations(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, `{"data":{}}`)

	listAll, providerPathFilter = false, "aws/"
	err := runList(ListCmd, nil)
	assert.True(t, errors.Is(err, helpers.ErrUsage), "-provider-path needs -all")
	assert.Zero(t, f.count())
}

// TestPrintRoleTable checks the key/value table: empty optional fields are left
// out, lists are comma-joined and metadata renders as sorted key=value pairs.
func TestPrintRoleTable(t *testing.T) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	printRoleTable(map[string]any{
		"name":           "deploy",
		"description":    "",
		"policies":       []any{"audit", "deploy"},
		"cred_spec_name": "deploy-role",
		"skill":          "",
		"provider_path":  "aws/",
		"metadata":       map[string]any{"team": "platform", "env": "prod"},
		"hash":           "abc123",
	})
	_ = w.Close()
	os.Stdout = orig
	raw, _ := io.ReadAll(r)
	out := string(raw)

	for _, want := range []string{"deploy", "audit, deploy", "deploy-role", "aws/", "env=prod team=platform", "abc123"} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "Description")
	assert.NotContains(t, out, "Skill")
	assert.True(t, strings.Contains(out, "Cred Spec"))
}
