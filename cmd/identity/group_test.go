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
	"strings"
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
		"rules":{"type":"array"},
		"valid_until":{"type":"string"},
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
	"rules":[
		{"mount":["auth/github-oidc/"],"repo":["acme/*"],"ref":["refs/heads/main"]},
		{"mount":["auth/kubernetes/"],"workload":["a","b"]}
	],
	"rule_count":2,
	"selector_count":5,
	"valid_until":"2026-12-31T23:59:59Z",
	"metadata":{},
	"hash":"h1",
	"created_at":"2026-10-20T10:00:00Z",
	"updated_at":"2026-10-20T10:00:00Z",
	"warnings":["rules[1]: no auth mount the rule lists produces fact \"workload\"; its selector cannot match until one maps it"]
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
		"rules": [
			{
				"mount": ["auth/github-oidc/"],
				"repo": ["acme/*"]
			}
		],
		"valid_until": "2026-12-31T23:59:59Z"
	}`

	require.NoError(t, runGroupCreate(cmd, []string{"ci-deployers"}))
	req := f.last(t)
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "/v1/sys/identity/group/ci-deployers", req.path)
	assert.Equal(t, map[string]any{
		"type":        "virtual",
		"roles":       []any{"deploy"},
		"rules":       []any{map[string]any{"mount": []any{"auth/github-oidc/"}, "repo": []any{"acme/*"}}},
		"valid_until": "2026-12-31T23:59:59Z",
	}, req.body)

	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["created"])
	assert.Equal(t, "h1", out["hash"])
	assert.Equal(t, float64(2), out["rule_count"])
	assert.Equal(t, float64(5), out["selector_count"])
	assert.Contains(t, stderr.String(), `warning: rules[1]: no auth mount the rule lists produces fact "workload"`)
}

func TestGroupCreate_TypedFlags(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("type", "virtual"))
	require.NoError(t, cmd.Flags().Set("roles", "deploy,read"))
	require.NoError(t, cmd.Flags().Set("rule", `{"mount": ["auth/k8s/"], "workload": ["a"]}`))
	require.NoError(t, cmd.Flags().Set("rule", `{"mount": ["auth/cert/"], "cn": ["x,y"]}`))
	require.NoError(t, cmd.Flags().Set("valid-until", "2026-12-31T23:59:59Z"))
	require.NoError(t, cmd.Flags().Set("metadata", "owner=platform"))

	require.NoError(t, runGroupCreate(cmd, []string{"g"}))
	assert.Equal(t, map[string]any{
		"type":  "virtual",
		"roles": []any{"deploy", "read"},
		"rules": []any{
			map[string]any{"mount": []any{"auth/k8s/"}, "workload": []any{"a"}},
			map[string]any{"mount": []any{"auth/cert/"}, "cn": []any{"x,y"}},
		},
		"valid_until": "2026-12-31T23:59:59Z",
		"metadata":    map[string]any{"owner": "platform"},
	}, f.last(t).body, "each -rule is one rule; a comma inside a value stays")
	assert.Nil(t, cmd.Flags().Lookup("selector"), "the flag is -rule; -selector is gone")
	assert.Nil(t, cmd.Flags().Lookup("max-age"), "-max-age is gone")
}

// TestGroupUpdate_ClearValidUntil: an empty -valid-until is sent, to clear it.
func TestGroupUpdate_ClearValidUntil(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, cannedGroup)
	cmd := freshUpdateCmd()
	require.NoError(t, cmd.Flags().Set("valid-until", ""))
	require.NoError(t, runGroupUpdate(cmd, []string{"g"}))
	assert.Equal(t, map[string]any{"valid_until": ""}, f.last(t).body)
}

// TestGroupRuleFlag_ScalarValue: a -rule selector value written as one string
// is sent as written, which the server takes as a one-element list, on create
// and on update.
func TestGroupRuleFlag_ScalarValue(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("type", "virtual"))
	require.NoError(t, cmd.Flags().Set("rule", `{"mount": "auth/k8s/", "workload": ["a", "b"]}`))
	require.NoError(t, runGroupCreate(cmd, []string{"g"}))
	assert.Equal(t, []any{map[string]any{"mount": "auth/k8s/", "workload": []any{"a", "b"}}},
		f.last(t).body["rules"])

	cmd = freshUpdateCmd()
	require.NoError(t, cmd.Flags().Set("rule", `{"mount": "auth/jwt/", "sub": "x"}`))
	require.NoError(t, runGroupUpdate(cmd, []string{"g"}))
	assert.Equal(t, []any{map[string]any{"mount": "auth/jwt/", "sub": "x"}}, f.last(t).body["rules"])
}

func TestGroupCreate_BadRuleFlag(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusCreated, cannedGroup)
	cmd := freshCreateCmd()
	require.NoError(t, cmd.Flags().Set("rule", `mount=auth/k8s/`))
	err := runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.Contains(t, err.Error(), "-rule #1 is not a JSON object")
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
	createJSON = `{"type": "virtual", "roles": ["deploy"], "valid_until": "2026-12-31T23:59:59Z"}`
	require.NoError(t, runGroupCreate(cmd, []string{"g"}))
	out := decodeOut(t, stdout)
	assert.Equal(t, true, out["validated"])
	assert.Zero(t, f.count())

	// max_age is no field of the group: a dry run flags it.
	cmd = freshCreateCmd()
	createJSON = `{"type": "virtual", "max_age": "10m"}`
	err := runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `"max_age"`)
	assert.Zero(t, f.count())

	cmd = freshCreateCmd()
	createJSON = `{"type": "virtual", "rule": []}`
	err = runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `did you mean "rules"`)
	assert.Zero(t, f.count())

	// The old field name is no field of the path: a dry run flags it.
	cmd = freshCreateCmd()
	createJSON = `{"type": "virtual", "selectors": []}`
	err = runGroupCreate(cmd, []string{"g"})
	require.Error(t, err)
	assert.True(t, helpers.IsValidationError(err))
	assert.Contains(t, err.Error(), `"selectors"`)
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

const listedGroups = `{"data":{
	"keys":["ci-deployers"],
	"groups":[{"name":"ci-deployers","type":"virtual","roles":["deploy"],
		"rules":[{"mount":["auth/k8s/"],"workload":["a"]}],"rule_count":1,"selector_count":2,
		"valid_until":"2026-12-31T23:59:59Z","hash":"h1"}]
}}`

// TestGroupList_JSON: -o json is a plain array of groups; -role filters.
func TestGroupList_JSON(t *testing.T) {
	f, stdout, _ := setupFake(t, http.StatusOK, listedGroups)
	listRole = "deploy"
	require.NoError(t, runGroupList(GroupListCmd, nil))
	req := f.last(t)
	assert.Equal(t, "/v1/sys/identity/group", req.path)
	assert.Equal(t, "true", req.query.Get("warden-list"))
	assert.Equal(t, "deploy", req.query.Get("role"))

	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items), "an array: %s", stdout.String())
	require.Len(t, items, 1)
	assert.Equal(t, "ci-deployers", items[0]["name"])
	assert.Equal(t, "2026-12-31T23:59:59Z", items[0]["valid_until"])
	assert.NotContains(t, items[0], "max_age")
	assert.Equal(t, []any{map[string]any{"mount": []any{"auth/k8s/"}, "workload": []any{"a"}}}, items[0]["rules"])
	assert.Equal(t, float64(1), items[0]["rule_count"])
	assert.Equal(t, float64(2), items[0]["selector_count"])
}

// TestGroupList_NDJSON: one group per line.
func TestGroupList_NDJSON(t *testing.T) {
	_, stdout, _ := setupFake(t, http.StatusOK, listedGroups)
	helpers.SetOutputFormat("ndjson")
	require.NoError(t, runGroupList(GroupListCmd, nil))
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
	require.Len(t, lines, 1)
	var item map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &item))
	assert.Equal(t, "ci-deployers", item["name"])
}

// captureStdout runs fn with os.Stdout redirected, as the table printers
// write there, and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	raw, _ := io.ReadAll(r)
	return string(raw)
}

// TestGroupList_Table: the table lists the groups and nothing after them.
func TestGroupList_Table(t *testing.T) {
	setupFake(t, http.StatusOK, listedGroups)
	helpers.SetOutputFormat("table")
	out := captureStdout(t, func() { require.NoError(t, runGroupList(GroupListCmd, nil)) })
	assert.Contains(t, out, "ci-deployers")
	assert.Contains(t, strings.ToUpper(out), "VALID UNTIL")
	assert.Contains(t, out, "2026-12-31T23:59:59Z")
	assert.NotContains(t, strings.ToUpper(out), "MAX AGE")
	assert.NotContains(t, out, "groups ")
}

const usageJSON = `{"data":{
	"groups":{
		"total":42,
		"virtual":{"count":42,"max":8000,"selectors":310,"max_selectors":16000}
	}
}}`

// TestUsage_Table: one section per kind, counts against their caps.
func TestUsage_Table(t *testing.T) {
	f, _, _ := setupFake(t, http.StatusOK, usageJSON)
	helpers.SetOutputFormat("table")
	out := captureStdout(t, func() { require.NoError(t, runUsage(UsageCmd, nil)) })
	assert.Equal(t, "/v1/sys/identity/usage", f.last(t).path)
	assert.Equal(t, http.MethodGet, f.last(t).method)
	assert.Equal(t, strings.Join([]string{
		"GROUPS",
		"  TYPE      COUNT     SELECTORS",
		"  virtual   42/8000   310/16000",
		"  total     42",
		"",
	}, "\n"), out)
}

// TestUsage_JSON: -o json prints the server's data as is.
func TestUsage_JSON(t *testing.T) {
	_, stdout, _ := setupFake(t, http.StatusOK, usageJSON)
	require.NoError(t, runUsage(UsageCmd, nil))
	assert.JSONEq(t, `{
		"groups": {
			"total": 42,
			"virtual": {"count": 42, "max": 8000, "selectors": 310, "max_selectors": 16000}
		}
	}`, stdout.String())
}

// TestUsage_Forbidden: a refusal surfaces as an error.
func TestUsage_Forbidden(t *testing.T) {
	setupFake(t, http.StatusForbidden, `{"errors":["permission denied"]}`)
	err := runUsage(UsageCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestPrintGroupTable: one row per rule, a selector at a time with "mount"
// first and values joined with "|", then the counts.
func TestPrintGroupTable(t *testing.T) {
	out := captureStdout(t, func() {
		printGroupTable(map[string]any{
			"name":  "ci-deployers",
			"type":  "virtual",
			"roles": []any{"deploy"},
			"rules": []any{
				map[string]any{"repo": []any{"acme/*"}, "mount": []any{"auth/github-oidc/"}, "ref": []any{"refs/heads/main"}},
				map[string]any{"mount": []any{"auth/k8s/", "auth/spiffe/"}, "workload": []any{"a", "b"}},
			},
			"rule_count":     float64(2),
			"selector_count": float64(5),
			"valid_until":    "2026-12-31T23:59:59Z",
		})
	})

	assert.Contains(t, out, "#0  mount=auth/github-oidc/  ref=refs/heads/main  repo=acme/*")
	assert.Contains(t, out, "#1  mount=auth/k8s/|auth/spiffe/  workload=a|b")
	assert.Contains(t, out, "Rule Count")
	assert.Contains(t, out, "Selector Count")
	assert.Contains(t, out, "Valid Until")
	assert.Contains(t, out, "2026-12-31T23:59:59Z")
	assert.NotContains(t, out, "Description")
}
