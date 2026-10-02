package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
					"condition": map[string]any{"expression": "call.args.?amount.orValue(0) <= 100"}},
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
}
