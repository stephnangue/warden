package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/internal/playground"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDevPlayground records what it is asked to mint.
type fakeDevPlayground struct {
	minted    []playground.Identity
	err       error
	auditPath string
}

func (f *fakeDevPlayground) MintIdentity(id playground.Identity) (string, error) {
	f.minted = append(f.minted, id)
	if f.err != nil {
		return "", f.err
	}
	return "minted-" + id.Subject, nil
}
func (f *fakeDevPlayground) Scenarios() []playground.Scenario { return playground.Scenarios() }
func (f *fakeDevPlayground) AuditPath() string                { return f.auditPath }

// The sys/dev paths exist only on a playground server.
func TestPathDev_OnlyOnAPlayground(t *testing.T) {
	backend, _, c := setupTestSystemBackend(t)
	assert.Empty(t, backend.pathDev())

	c.devPlayground = &fakeDevPlayground{}
	paths := backend.pathDev()
	require.Len(t, paths, 3)
	var patterns []string
	for _, p := range paths {
		patterns = append(patterns, p.Pattern)
	}
	assert.ElementsMatch(t, []string{"dev/jwt", "dev/scenarios", "dev/audit"}, patterns)
}

func TestHandleDevJWT(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	fake := &fakeDevPlayground{}
	c.devPlayground = fake
	schema := backend.pathDev()[0].Fields

	resp, err := backend.handleDevJWT(ctx, nil, createFieldData(schema, map[string]any{
		"kind": "user", "sub": "alice", "may_act": "agent-1", "claims": map[string]any{"team": "payments"}, "ttl": "2h",
	}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "%v", resp.Error())
	assert.Equal(t, "minted-alice", resp.Data["token"])
	require.Len(t, fake.minted, 1)
	got := fake.minted[0]
	assert.Equal(t, "user", got.Kind)
	assert.Equal(t, "agent-1", got.MayAct)
	assert.Equal(t, "payments", got.Claims["team"])
	assert.Equal(t, "2h0m0s", got.TTL.String())

	fake.err = errors.New("kind must be agent or user")
	resp, err = backend.handleDevJWT(ctx, nil, createFieldData(schema, map[string]any{"kind": "robot", "sub": "x"}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(resp.Error()))
}

func auditLine(t *testing.T, entry map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(entry)
	require.NoError(t, err)
	return string(raw)
}

func TestReadDevAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	entries := []map[string]any{
		{"type": "request", "timestamp": "t1", "request": map[string]any{"path": "role/atm/gateway", "mount_point": "bank/", "mount_class": "provider"},
			"auth": map[string]any{"principal_id": "agent-1", "role_name": "atm", "policy_results": map[string]any{"allowed": true}}},
		{"type": "response", "timestamp": "t1"},
		// The operator's own call is not playground traffic.
		{"type": "request", "timestamp": "t1b", "request": map[string]any{"path": "sys/dev/audit", "mount_class": "system"},
			"auth": map[string]any{"principal_id": "root", "policy_results": map[string]any{"allowed": true}}},
		{"type": "request", "timestamp": "t2", "request": map[string]any{"path": "role/atm/gateway", "mount_point": "bank/", "mount_class": "provider"},
			"auth": map[string]any{"principal_id": "agent-1", "role_name": "atm", "policy_results": map[string]any{
				"allowed": true,
				"mcp_decision": map[string]any{"decision": "deny", "name": "withdraw", "rule_type": "condition",
					"condition": map[string]any{"expression": "call.tool != 'withdraw' || (has(call.args.amount) && call.args.amount <= 100)"}},
			}}},
		{"type": "request", "timestamp": "t3", "request": map[string]any{"path": "role/assistant/gateway", "mount_point": "bank-me/", "mount_class": "provider"},
			"auth": map[string]any{"principal_id": "agent-2", "role_name": "assistant", "user": map[string]any{"subject": "alice"},
				"policy_results": map[string]any{"allowed": false, "condition": map[string]any{"expression": "user.metadata.may_act_sub == agent.principal"}}}},
	}
	var lines []string
	for _, e := range entries {
		lines = append(lines, auditLine(t, e))
	}
	lines = append(lines, "not json")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	all, err := readDevAudit(path, 10, devAuditFilter{})
	require.NoError(t, err)
	require.Len(t, all, 3, "provider request entries only; sys calls and malformed lines skipped")
	assert.Equal(t, "t3", all[0]["time"], "newest first")
	assert.Equal(t, "bank-me/role/assistant/gateway", all[0]["path"], "the mount is prefixed")
	assert.Equal(t, "alice", all[0]["user"])
	assert.Equal(t, "deny", all[0]["decision"])
	assert.Contains(t, all[0]["reason"], "may_act_sub")
	assert.Equal(t, "withdraw", all[1]["tool"])
	assert.Equal(t, "deny", all[1]["decision"], "an MCP deny counts even when the path was allowed")
	assert.Contains(t, all[1]["reason"], "mcp policy: condition")
	assert.Equal(t, "allow", all[2]["decision"])
	assert.NotNil(t, all[2]["entry"], "the raw entry is kept")

	denied, err := readDevAudit(path, 10, devAuditFilter{decision: "deny"})
	require.NoError(t, err)
	assert.Len(t, denied, 2)

	alice, err := readDevAudit(path, 10, devAuditFilter{user: "alice"})
	require.NoError(t, err)
	assert.Len(t, alice, 1)

	atm, err := readDevAudit(path, 1, devAuditFilter{role: "atm"})
	require.NoError(t, err)
	require.Len(t, atm, 1, "n bounds the result")
	assert.Equal(t, "t2", atm[0]["time"])

	missing, err := readDevAudit(filepath.Join(t.TempDir(), "none.log"), 10, devAuditFilter{})
	require.NoError(t, err)
	assert.Empty(t, missing, "no log yet is an empty answer, not an error")
}

// A tail that starts mid-file drops the partial first line.
func TestReadFileTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("first line\nsecond\nthird\n"), 0o600))
	tail, err := readFileTail(path, 10)
	require.NoError(t, err)
	assert.Equal(t, "third\n", string(tail))
	whole, err := readFileTail(path, 1000)
	require.NoError(t, err)
	assert.Equal(t, "first line\nsecond\nthird\n", string(whole))

	// A last line still being written is kept as it stands; readDevAudit skips
	// it as malformed JSON rather than failing.
	require.NoError(t, os.WriteFile(path, []byte("first\n{\"type\":\"req"), 0o600))
	tail, err = readFileTail(path, 1000)
	require.NoError(t, err)
	assert.Equal(t, "first\n{\"type\":\"req", string(tail))
}

// One line longer than the whole tail leaves nothing to show, and is not an
// error: the reader answers with what it can parse.
func TestReadDevAudit_LineLongerThanTheTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", devAuditTailBytes+10)), 0o600))
	entries, err := readDevAudit(path, 10, devAuditFilter{})
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// Filters asking for the same value are each checked: a map keyed by the
// wanted value collapsed them into one.
func TestDevAuditFilter_SameValueTwice(t *testing.T) {
	summary := map[string]any{"agent": "agent-1", "role": "atm", "user": "", "decision": "allow"}
	assert.False(t, devAuditFilter{principal: "atm", role: "atm"}.matches(summary), "the agent is not atm")
	assert.True(t, devAuditFilter{principal: "agent-1", role: "atm"}.matches(summary))
	assert.False(t, devAuditFilter{role: "allow", decision: "allow"}.matches(summary), "the role is not allow")
}

func TestHandleDevAudit_Validation(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.devPlayground = &fakeDevPlayground{auditPath: filepath.Join(t.TempDir(), "none.log")}
	schema := backend.pathDev()[2].Fields

	for name, raw := range map[string]map[string]any{
		"n of zero":        {"n": 0},
		"n over 1000":      {"n": 1001},
		"unknown decision": {"decision": "maybe"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := backend.handleDevAudit(ctx, nil, createFieldData(schema, raw))
			require.NoError(t, err)
			require.True(t, resp.IsError())
			assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(resp.Error()))
		})
	}

	resp, err := backend.handleDevAudit(ctx, nil, createFieldData(schema, map[string]any{"decision": "deny"}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "%v", resp.Error())
	assert.Equal(t, []map[string]any{}, resp.Data["entries"], "an empty list, not null")
}

func TestHandleDevScenarios(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.devPlayground = &fakeDevPlayground{}
	resp, err := backend.handleDevScenarios(ctx, nil, nil)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	assert.Equal(t, playground.SetupCommands, resp.Data["setup"])
	assert.Len(t, resp.Data["scenarios"], 7)
}

// The playground is global: a namespace's own sys mount serves the dev paths
// too, and every handler refuses there, so a namespace admin cannot mint
// identities or read the root's audit log.
func TestDevHandlers_RefuseSubNamespaces(t *testing.T) {
	backend, _, c := setupTestSystemBackend(t)
	fake := &fakeDevPlayground{auditPath: filepath.Join(t.TempDir(), "none.log")}
	c.devPlayground = fake
	child := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child-id", Path: "child/"})
	paths := backend.pathDev()

	for name, call := range map[string]func() (*logical.Response, error){
		"jwt": func() (*logical.Response, error) {
			return backend.handleDevJWT(child, nil, createFieldData(paths[0].Fields, map[string]any{"kind": "agent", "sub": "a"}))
		},
		"scenarios": func() (*logical.Response, error) { return backend.handleDevScenarios(child, nil, nil) },
		"audit": func() (*logical.Response, error) {
			return backend.handleDevAudit(child, nil, createFieldData(paths[2].Fields, map[string]any{}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := call()
			require.NoError(t, err)
			require.True(t, resp.IsError())
			assert.Equal(t, http.StatusForbidden, logical.GetErrorCode(resp.Error()))
		})
	}
	assert.Empty(t, fake.minted, "nothing was minted")
}

// The bootstrap goes through HandleRequest as the root token, with a JSON body,
// and stops at the first failing step, naming it.
func TestRunDevBootstrap(t *testing.T) {
	c := createTestCore(t)
	rootToken, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	policy := func(name string) playground.Step {
		return playground.Step{
			Path: "sys/policies/cbp/" + name, Operation: "create",
			Data: map[string]any{"policy": `path "secret/*" { capabilities = ["read"] }`},
		}
	}
	exists := func(name string) bool {
		httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/policies/cbp/"+name, nil)
		httpReq.Header.Set("X-Warden-Token", rootToken)
		resp, err := c.HandleRequest(ctx, &logical.Request{Path: "sys/policies/cbp/" + name, Operation: logical.ReadOperation, HTTPRequest: httpReq})
		return err == nil && resp != nil && !resp.IsError() && resp.Data["policy"] != nil
	}

	require.NoError(t, c.RunDevBootstrap(ctx, rootToken, []playground.Step{policy("pg-one"), policy("pg-two")}))
	assert.True(t, exists("pg-one"))
	assert.True(t, exists("pg-two"))

	bad := playground.Step{Path: "sys/policies/cbp/pg-bad", Operation: "create", Data: map[string]any{"policy": "not hcl {"}}
	err = c.RunDevBootstrap(ctx, rootToken, []playground.Step{bad, policy("pg-after")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sys/policies/cbp/pg-bad", "the failing step is named")
	assert.False(t, exists("pg-after"), "the first failure stops the bootstrap")

	err = c.RunDevBootstrap(ctx, "not-the-root-token", []playground.Step{policy("pg-unauth")})
	require.Error(t, err)
	assert.False(t, exists("pg-unauth"))
}

func TestCheckDevPlaygroundDiscovery_OnlyOnAPlayground(t *testing.T) {
	c := createTestCore(t)
	err := c.CheckDevPlaygroundDiscovery(context.Background(), []string{"atm"})
	assert.ErrorContains(t, err, "not a dev playground")

	c.devPlayground = &fakeDevPlayground{err: errors.New("no IdP")}
	err = c.CheckDevPlaygroundDiscovery(context.Background(), []string{"atm"})
	assert.ErrorContains(t, err, "mint a self-check identity")
}
