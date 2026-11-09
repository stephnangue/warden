// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// discoveryEnv is a discovery env with one jwt mount, one granted role and a
// recorded audit, for the request-path tests of sys/mcp.
func discoveryEnv(t *testing.T) (*discEnv, *admitStubMount, *auditCapture) {
	t.Helper()
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	seedTestSkill(t, e.c, e.ctx, "vault")
	e.createRole(&logical.Role{Name: "deploy", Description: "the deploy role", ProviderPath: "vault/", Skill: "vault"})
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	rec := &auditCapture{}
	e.c.auditManager = rec
	return e, m, rec
}

// sysMCPEntry returns the last request audit entry for sys/mcp. A streamed
// request is audited under its path relative to the mount.
func sysMCPEntry(t *testing.T, rec *auditCapture) *audit.LogEntry {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i := len(rec.requests) - 1; i >= 0; i-- {
		if e := rec.requests[i]; e.Request != nil && e.Request.Path == "mcp" {
			return e
		}
	}
	t.Fatalf("no request audit entry for sys/mcp among %d", len(rec.requests))
	return nil
}

const toolsListCall = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// A call whose answer is the same for every caller runs anonymously: no
// admission, a refusal of nothing, and an audit entry that claims no token and
// says a presented credential went unchecked.
func TestSysMCP_AnonymousCallsAdmitNothing(t *testing.T) {
	e, m, rec := discoveryEnv(t)

	for name, bearer := range map[string]string{"no credential": "", "a bearer, unchecked": "eyJ.any.token"} {
		t.Run(name, func(t *testing.T) {
			before := m.admits.Load()
			status, raw := e.postDiscoveryRaw(bearer, "2025-11-25", toolsListCall)
			require.Equal(t, http.StatusOK, status, "body: %s", raw)
			assert.Contains(t, string(raw), "list_roles")
			assert.Equal(t, before, m.admits.Load(), "no admission")

			entry := sysMCPEntry(t, rec)
			require.NotNil(t, entry.Auth)
			assert.Empty(t, entry.Auth.TokenType)
			assert.Empty(t, entry.Auth.TokenID)
			assert.Empty(t, entry.Auth.PrincipalID)
			assert.Equal(t, []string{builtinCBPPolicy, builtinMCPPolicy, builtinSponsorPolicy}, entry.Auth.Policies)
			require.NotNil(t, entry.Auth.Discovery)
			assert.True(t, entry.Auth.Discovery.Anonymous)
			assert.Equal(t, bearer != "", entry.Auth.Discovery.CredentialUnverified)
		})
	}
}

// One call that needs the caller's identity makes the whole body need it.
func TestSysMCP_MixedBatchNeedsIdentity(t *testing.T) {
	e, m, _ := discoveryEnv(t)
	batch := `[` + toolsListCall + `,{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}]`

	status, raw := e.postDiscoveryRaw("", "2025-03-26", batch)
	assert.Equal(t, http.StatusUnauthorized, status, "body: %s", raw)
	assert.Zero(t, m.admits.Load())

	status, raw = e.postDiscoveryRaw("eyJ.any.token", "2025-03-26", batch)
	assert.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, int64(1), m.admits.Load())
}

// A method the discovery server does not classify needs the caller's identity:
// a new method is closed until it is classified.
func TestSysMCP_UnclassifiedMethodNeedsIdentity(t *testing.T) {
	e, _, _ := discoveryEnv(t)
	status, raw := e.postDiscoveryRaw("", "2025-11-25", `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	assert.Equal(t, http.StatusUnauthorized, status, "body: %s", raw)
}

// The classification: the lifecycle methods and the four calls whose answer is
// the same for every caller are anonymous; every call answering from the
// caller's identity is not.
func TestDiscoveryMethodClassification(t *testing.T) {
	for _, m := range []string{"initialize", "ping", "server/discover", "notifications/initialized",
		"tools/list", "resources/templates/list", "logging/setLevel", "subscriptions/listen", "TOOLS/LIST"} {
		assert.True(t, discoveryMethodIsAnonymous(m), m)
	}
	for _, m := range []string{"tools/call", "resources/list", "resources/read", "skills/list", "skills/get",
		"prompts/list", "completion/complete", ""} {
		assert.False(t, discoveryMethodIsAnonymous(m), m)
	}
	for m := range discoveryAnonymousMethods {
		assert.Equal(t, strings.ToLower(m), m, "kept lowercased: lookups lowercase the method")
	}
}

// A batch over the cap is refused whole, before any admission, as the
// transport refuses a body it cannot serve, and the refusal is audited.
func TestSysMCP_BatchOverCapRefusedBeforeAdmission(t *testing.T) {
	e, m, rec := discoveryEnv(t)
	calls := make([]string, maxSysMCPBatch+1)
	for i := range calls {
		calls[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}`, i+1)
	}

	status, raw := e.postDiscoveryRaw("eyJ.any.token", "2025-03-26", "["+strings.Join(calls, ",")+"]")
	require.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
	assert.Contains(t, string(raw), fmt.Sprintf("JSON-RPC batch exceeds %d messages", maxSysMCPBatch))
	assert.Zero(t, m.admits.Load(), "refused before any admission")

	entry := sysMCPEntry(t, rec)
	require.NotNil(t, entry.Auth)
	require.NotNil(t, entry.Auth.PolicyResults)
	require.NotNil(t, entry.Auth.PolicyResults.MCPDecision)
	assert.Equal(t, logical.MCPParseKindBatchTooLarge, entry.Auth.PolicyResults.MCPDecision.RuleType)
}

// Lists are filtered per call, inside a batch too, by the caller's MCP
// policy: what is listed is what may be called. Narrowing default-mcp to
// list_roles and one skill drops the rest from both lists of one batch.
func TestSysMCP_ListsFilteredPerCallInBatch(t *testing.T) {
	e, _, _ := discoveryEnv(t)
	seedTestSkill(t, e.c, e.ctx, "slack")
	e.createRole(&logical.Role{Name: "chat", Description: "the chat role", ProviderPath: "vault/", Skill: "slack"})
	e.group("chatters", []string{"chat"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))

	narrowed := mustParseMCP(t, namespace.RootNamespace, `path "sys/mcp" {
  methods {
    allowed = ["tools/list", "tools/call", "skills/list", "skills/get", "resources/read"]
  }
  tools {
    allowed = ["list_roles"]
  }
  resources {
    allowed = ["skill://vault/*"]
  }
}
`)
	narrowed.Name, narrowed.Type = builtinMCPPolicy, PolicyTypeMCP
	require.NoError(t, e.c.policyStore.SetPolicy(rootCtx(), narrowed, nil))

	out := e.postDiscovery("eyJ.any.token", "2025-03-26", `[
		{"jsonrpc":"2.0","id":1,"method":"tools/list"},
		{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{}}
	]`)
	require.Len(t, out, 2)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	var answers []struct {
		ID     int `json:"id"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			Skills []struct {
				URI string `json:"uri"`
			} `json:"skills"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &answers))
	var tools, skills []string
	for _, a := range answers {
		for _, tl := range a.Result.Tools {
			tools = append(tools, tl.Name)
		}
		for _, s := range a.Result.Skills {
			skills = append(skills, s.URI)
		}
	}
	assert.Equal(t, []string{"list_roles"}, tools, "a tool the policy refuses is not listed")
	assert.Equal(t, []string{"skill://vault/SKILL.md"}, skills, "a skill the policy refuses is not listed")
}

// The server announces no list as changing, so a client opens no
// notification stream to wait for one.
func TestSysMCP_AnnouncesNoChangingList(t *testing.T) {
	e, _, _ := discoveryEnv(t)
	session := connectMCPWithHeaders(t, e.server(), e.headers(""))
	caps := session.InitializeResult().Capabilities
	require.NotNil(t, caps.Tools)
	assert.False(t, caps.Tools.ListChanged)
	if caps.Resources != nil {
		assert.False(t, caps.Resources.ListChanged)
	}
}

// The built-ins are what authorize discovery: emptying default-cbp refuses
// every call, and a condition on agent.present refuses the anonymous ones,
// which present no agent, while identity calls still pass.
func TestSysMCP_GatedByBuiltins(t *testing.T) {
	setCBP := func(t *testing.T, e *discEnv, body string) {
		p := testParsePolicy(t, body)
		p.Name, p.Type = builtinCBPPolicy, PolicyTypeCBP
		require.NoError(t, e.c.policyStore.SetPolicy(rootCtx(), p, nil))
	}

	t.Run("emptied", func(t *testing.T) {
		e, _, _ := discoveryEnv(t)
		setCBP(t, e, `path "sys/introspect/roles" { capabilities = ["read"] }`)
		status, raw := e.postDiscoveryRaw("", "2025-11-25", toolsListCall)
		assert.Equal(t, http.StatusForbidden, status, "body: %s", raw)
	})

	t.Run("agent.present", func(t *testing.T) {
		e, _, _ := discoveryEnv(t)
		setCBP(t, e, `path "sys/mcp" {
  capabilities = ["create", "read", "delete"]
  condition    = "agent.present == true"
}`)
		status, raw := e.postDiscoveryRaw("", "2025-11-25", toolsListCall)
		assert.Equal(t, http.StatusForbidden, status, "an anonymous call presents no agent: %s", raw)

		status, raw = e.postDiscoveryRaw("eyJ.any.token", "2025-11-25",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}`)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
	})
}

// The discovery endpoint answers in a child namespace by path as by header,
// for identity calls and anonymous ones alike: the role-less leg sees the
// path relative to the namespace.
func TestSysMCP_NamespaceByPath(t *testing.T) {
	e := newDiscEnv(t, "team/", "auth/jwt/")
	m := e.mountAuth("jwt/")
	srv := startMCPTestServer(t, e.c, nil)

	post := func(bearer, body string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/team/sys/mcp", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, post("eyJ.any.token",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}`))
	admits := m.admits.Load()
	assert.Equal(t, http.StatusOK, post("", toolsListCall), "anonymous in a child namespace too")
	assert.Equal(t, admits, m.admits.Load(), "and admitting nothing")
	assert.Equal(t, http.StatusUnauthorized, post("",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}`))
}

// Anonymous notification streams are capped per node: once every slot is
// held, in whatever namespace, the next is refused rather than parked.
func TestSysMCP_AnonymousListensCapped(t *testing.T) {
	e, _, _ := discoveryEnv(t)
	slots := e.c.anonymousListenSlots()
	for range maxAnonymousListens {
		slots <- struct{}{}
	}
	t.Cleanup(func() {
		for range maxAnonymousListens {
			<-slots
		}
	})

	status, raw := e.postDiscoveryRaw("", "2025-11-25",
		`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{}}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status, "body: %s", raw)
}

// A request on sys/mcp that is not over HTTP is refused, not served.
func TestSysMCP_RequiresHTTP(t *testing.T) {
	c := createTestCore(t)
	resp, err := c.systemBackend.handleMCPStream(context.Background(), &logical.Request{Path: "mcp"}, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Error(t, resp.Err)
}
