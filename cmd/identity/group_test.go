package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recorded struct {
	method, path string
	query        url.Values
	body         map[string]any
}

// fakeWarden answers sys/schema with the group path's body schema and every
// other request with the canned status and body, recording it.
type fakeWarden struct {
	mu       sync.Mutex
	requests []recorded
	status   int
	body     string
}

const groupSchemaDoc = `{"data":{"openapi":{"paths":{"/sys/identity/group/{name}":{
	"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{
		"type":{"type":"string"},
		"description":{"type":"string"},
		"roles":{"type":"array"},
		"selectors":{"type":"array"},
		"max_age":{"type":"integer","format":"seconds"},
		"metadata":{"type":"object"},
		"members":{"type":"array"},
		"link":{"type":"object"},
		"expected_hash":{"type":"string"}
	}}}}}}
}}}}}`

const cannedGroup = `{"data":{
	"id":"0f1e",
	"name":"ci-deployers",
	"type":"virtual",
	"description":"CI deployers",
	"roles":["deploy"],
	"selectors":[
		{"mount":["auth/github-oidc/"],"repo":["acme/*"],"ref":["refs/heads/main"]},
		{"mount":["auth/kubernetes/"],"workload":["a","b"]}
	],
	"max_age":"10m0s",
	"metadata":{},
	"hash":"h1",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["selectors[1]: no auth mount the rule lists produces fact \"workload\"; the rule cannot match until one maps it"]
}}`

func (f *fakeWarden) last(t *testing.T) recorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests)
	return f.requests[len(f.requests)-1]
}

func (f *fakeWarden) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func setupFake(t *testing.T, status int, body string) (*fakeWarden, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	f := &fakeWarden{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/sys/schema" {
			_, _ = w.Write([]byte(groupSchemaDoc))
			return
		}
		rec := recorded{method: r.Method, path: r.URL.Path, query: r.URL.Query()}
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
		listRole = ""
	})
	return f, stdout, stderr
}

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

func TestGroupCreate_JSON(t *testing.T) {
	f, stdout, stderr := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	createJSON = `{
		"type": "virtual",
		"roles": ["deploy"],
		"selectors": [
			{
				"mount": ["auth/github-oidc/"],
				"repo": ["acme/*"]
			}
		],
		"max_age": "10m"
	}`

	require.NoError(t, runGroupCreate(cmd, []string{"ci-deployers"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/group/ci-deployers", req.path)
	assert.Equal(t, map[string]any{
		"type":      "virtual",
		"roles":     []any{"deploy"},
		"selectors": []any{map[string]any{"mount": []any{"auth/github-oidc/"}, "repo": []any{"acme/*"}}},
		"max_age":   "10m",
	}, req.body)

	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["created"])
	assert.Equal(t, "h1", out["hash"])
	assert.Contains(t, stderr.String(), `warning: selectors[1]: no auth mount the rule lists produces fact "workload"`)
}

func TestGroupCreate_TypedFlags(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("type", "virtual"))
	require.NoError(t, cmd.Flags().Set("roles", "deploy,read"))
	require.NoError(t, cmd.Flags().Set("selector", `{"mount": ["auth/k8s/"], "workload": ["a"]}`))
	require.NoError(t, cmd.Flags().Set("selector", `{"mount": ["auth/cert/"], "cn": ["x,y"]}`))
	require.NoError(t, cmd.Flags().Set("max-age", "5m"))
	require.NoError(t, cmd.Flags().Set("metadata", "owner=platform"))

	require.NoError(t, runGroupCreate(cmd, []string{"g"}))
	assert.Equal(t, map[string]any{
		"type":  "virtual",
		"roles": []any{"deploy", "read"},
		"selectors": []any{
			map[string]any{"mount": []any{"auth/k8s/"}, "workload": []any{"a"}},
			map[string]any{"mount": []any{"auth/cert/"}, "cn": []any{"x,y"}},
		},
		"max_age":  "5m",
		"metadata": map[string]any{"owner": "platform"},
	}, f.last(t).body, "each -selector is one rule; a comma inside a value stays")
}

// TestGroupSelectorFlag_ScalarValue: a -selector value written as one string
// is sent as written, which the server takes as a one-element list, on create
// and on update.
func TestGroupSelectorFlag_ScalarValue(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("type", "virtual"))
	require.NoError(t, cmd.Flags().Set("selector", `{"mount": "auth/k8s/", "workload": ["a", "b"]}`))
	require.NoError(t, runGroupCreate(cmd, []string{"g"}))
	assert.Equal(t, []any{map[string]any{"mount": "auth/k8s/", "workload": []any{"a", "b"}}},
		f.last(t).body["selectors"])

	cmd = freshUpdateCmd()
	require.NoError(t, cmd.Flags().Set("selector", `{"mount": "auth/jwt/", "sub": "x"}`))
	require.NoError(t, runGroupUpdate(cmd, []string{"g"}))
	assert.Equal(t, []any{map[string]any{"mount": "auth/jwt/", "sub": "x"}}, f.last(t).body["selectors"])
}

func TestGroupCreate_BadSelectorFlag(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("selector", `mount=auth/k8s/`))
	err := runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Zero(t, f.count())
}

func TestGroupCreate_JSONAndFlagsRejected(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("roles", "deploy"))
	createJSON = `{"type": "virtual"}`
	err := runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Contains(t, err.Error(), "-roles")
	assert.Zero(t, f.count())
}

func TestGroupCreate_InvalidName(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	require.Error(t, runGroupCreate(freshCreateCmd(), []string{"a/b"}))
	assert.Zero(t, f.count())
}

func TestGroupCreate_DryRun(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusCreated, cannedGroup)
	helpers.SetDryRun(true)

	cmd := freshCreateCmd()
	createJSON = `{"type": "virtual", "roles": ["deploy"], "max_age": "10m"}`
	require.NoError(t, runGroupCreate(cmd, []string{"g"}), "a duration string passes as the server takes it")
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["validated"])
	assert.Zero(t, f.count())

	cmd = freshCreateCmd()
	createJSON = `{"type": "virtual", "selector": []}`
	err := runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `did you mean "selectors"`)
	assert.Zero(t, f.count())
}

func TestGroupUpdate_TypedFlagsAndCAS(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedGroup)
	cmd := freshUpdateCmd()
	require.NoError(t, cmd.Flags().Set("roles", ""))
	require.NoError(t, cmd.Flags().Set("expected-hash", "h1"))

	require.NoError(t, runGroupUpdate(cmd, []string{"ci-deployers"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPut, req.method)
	assert.Equal(t, map[string]any{"roles": []any{}, "expected_hash": "h1"}, req.body,
		"an empty -roles clears the roles; -expected-hash rides along")
	assert.Equal(t, true, decodeOut(t, stdout)["updated"])
}

func TestGroupUpdate_NothingToUpdate(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, cannedGroup)
	err := runGroupUpdate(freshUpdateCmd(), []string{"g"})
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Zero(t, f.count())
}

func TestGroupUpdate_DryRun(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedGroup)
	helpers.SetDryRun(true)
	cmd := freshUpdateCmd()
	updateJSON = `{"description": "x"}`
	require.NoError(t, runGroupUpdate(cmd, []string{"g"}))
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["validated"])
	assert.Nil(t, out["note"], "the body schema was found, not soft-passed")
	assert.Zero(t, f.count())
}

func TestGroupUpdate_TypeChangeSurfaces(t *testing.T) {
	setupFake(t, http.StatusBadRequest, `{"errors":["type cannot change; create a new group"]}`)
	cmd := freshUpdateCmd()
	updateJSON = `{"type": "internal"}`
	err := runGroupUpdate(cmd, []string{"g"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type cannot change; create a new group")
}

func TestGroupRead_JSON(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, cannedGroup)
	require.NoError(t, runGroupRead(GroupReadCmd, []string{"ci-deployers"}))
	assert.Equal(t, http.MethodGet, f.last(t).method)
	assert.Equal(t, "/v1/sys/identity/group/ci-deployers", f.last(t).path)
	out := decodeOut(t, stdout)
	assert.Equal(t, "virtual", out["type"])
	assert.Equal(t, "h1", out["hash"])
}

func TestGroupDelete(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, `{"data":{"name":"g"}}`)
	deleteForce, deleteExpectedHash = true, "h1"
	require.NoError(t, runGroupDelete(GroupDeleteCmd, []string{"g"}))
	req := f.last(t)
	assert.Equal(t, http.MethodDelete, req.method)
	assert.Equal(t, "/v1/sys/identity/group/g", req.path)
	assert.Equal(t, "h1", req.query.Get("expected_hash"))
	assert.Equal(t, true, decodeOut(t, stdout)["deleted"])
}

func TestGroupList_RoleFilter(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, `{"data":{
		"keys":["ci-deployers"],
		"groups":[{"name":"ci-deployers","type":"virtual","roles":["deploy"],
			"selectors":[{"mount":["auth/k8s/"],"workload":["a"]}],"max_age":"","hash":"h1"}]
	}}`)
	listRole = "deploy"
	require.NoError(t, runGroupList(GroupListCmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/group", req.path)
	assert.Equal(t, "true", req.query.Get("warden-list"))
	assert.Equal(t, "deploy", req.query.Get("role"))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items))
	require.Len(t, items, 1)
	assert.Equal(t, "ci-deployers", items[0]["name"])
	assert.Equal(t, []any{map[string]any{"mount": []any{"auth/k8s/"}, "workload": []any{"a"}}}, items[0]["selectors"])
}

// TestPrintGroupTable: one row per selector, "mount" first, values joined
// with "|".
func TestPrintGroupTable(t *testing.T) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	printGroupTable(map[string]any{
		"name":  "ci-deployers",
		"type":  "virtual",
		"roles": []any{"deploy"},
		"selectors": []any{
			map[string]any{"repo": []any{"acme/*"}, "mount": []any{"auth/github-oidc/"}, "ref": []any{"refs/heads/main"}},
			map[string]any{"mount": []any{"auth/k8s/", "auth/spiffe/"}, "workload": []any{"a", "b"}},
		},
		"max_age": "10m0s",
	})
	_ = w.Close()
	os.Stdout = orig
	raw, _ := io.ReadAll(r)
	out := string(raw)

	assert.Contains(t, out, "#0  mount=auth/github-oidc/  ref=refs/heads/main  repo=acme/*")
	assert.Contains(t, out, "#1  mount=auth/k8s/|auth/spiffe/  workload=a|b")
	assert.Contains(t, out, "10m0s")
	assert.NotContains(t, out, "Description")
}
