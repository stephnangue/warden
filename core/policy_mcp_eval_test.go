// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMCPRequest builds a logical.Request with a JSON-RPC body and the
// matching MCPDescriptor produced by running the body through the same
// pipeline the production extractor uses (ParseJSONRPCStrict +
// classifyArgs). Every test exercises the strict parser and the matcher
// together, which is the contract that ships in production.
//
// For malformed-body inputs the returned descriptor has ParseErr
// populated and Calls nil — the matcher / decideMCP / AllowOperation
// path then sees the same state production would on adversarial input.
// Accepts testing.TB so the same builder works from both tests and
// benchmarks.
func newMCPRequest(tb testing.TB, path, body string) *logical.Request {
	tb.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/"+path, strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	req := &logical.Request{
		Path:        path,
		Operation:   logical.UpdateOperation,
		HTTPRequest: httpReq,
	}
	req.MCPDescriptor = synthesizeMCPDescriptorFromBody([]byte(body))
	return req
}

// synthesizeMCPDescriptorFromBody mirrors what extractMCPDescriptor
// does on the production streaming branch: strict-parse the body,
// then map every parsed JSONRPCRequest to an MCPCall. Lives next to
// the matcher tests so they exercise the real pipeline without
// dragging in the request_handler extractor's I/O concerns.
func synthesizeMCPDescriptorFromBody(body []byte) *logical.MCPRequestDescriptor {
	desc := &logical.MCPRequestDescriptor{}
	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		desc.ParseErr = &logical.MCPParseError{
			Kind: string(perr.Kind),
			Msg:  perr.Msg,
		}
		return desc
	}
	desc.Calls = make([]logical.MCPCall, len(reqs))
	for i, r := range reqs {
		desc.Calls[i] = logical.MCPCall{
			Method:     r.Method,
			Name:       r.Name,
			MatchArgs:  classifyArgs(r.Arguments),
			BatchIndex: i,
		}
	}
	return desc
}

// mustCBP builds a CBP from raw policy HCL, failing the test on any
// parse or build error. Keeps every test case to a four-line setup.
func mustCBP(t testing.TB, rules string) *CBP {
	t.Helper()
	policy := testParsePolicy(t, rules)
	cbp, err := NewCBP(testContext(), []*Policy{policy})
	require.NoError(t, err)
	return cbp
}

// mustCBPWithMCP compiles one capability document and one MCP document into a
// single CBP, which is how a governed mount is configured: the first grants the
// path, the second constrains what may be called on it.
func mustCBPWithMCP(t testing.TB, cbpRules, mcpRules string) *CBP {
	t.Helper()
	policies := []*Policy{testParsePolicy(t, cbpRules)}
	if mcpRules != "" {
		mcp := testParseMCPPolicy(t, mcpRules)
		mcp.Name = "mcp-contract"
		policies = append(policies, mcp)
	}
	cbp, err := NewCBP(testContext(), policies)
	require.NoError(t, err)
	return cbp
}

// mustMCPGateway is the shape almost every MCP test needs: the standard gateway
// grant paired with a tool contract on the same path. body is the inside of the
// MCP stanza.
func mustMCPGateway(t testing.TB, body string) *CBP {
	t.Helper()
	return mustCBPWithMCP(t,
		"path \"mcp/gateway/*\" {\n  capabilities = [\"update\"]\n}\n",
		"path \"mcp/gateway/*\" {\n"+body+"\n}\n")
}

// =============================================================================
// Method gate
// =============================================================================

func TestMCPEval_AllowedMethods_Match(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "tools/list", res.MCPDecision.Method)
	assert.Equal(t, "tools/list", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_AllowedMethods_NoMatch(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.Method)
	assert.Equal(t, "", res.MCPDecision.MatchedRule, "no allow-list entry matched")
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType)
}

// =============================================================================
// Deny-by-default + lifecycle exemption
// =============================================================================

func TestMCPEval_LifecycleMethods_ExemptFromMethodGate(t *testing.T) {
	// initialize / ping / notifications/* must pass even though the block
	// allow-lists only data-plane methods — otherwise the MCP handshake
	// breaks. The exemption skips the allowed_methods gate for them.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
  tools { allowed = ["*"] }
}
`)
	for _, method := range []string{"initialize", "ping", "notifications/initialized"} {
		body := `{"jsonrpc":"2.0","method":"` + method + `","id":1}`
		if strings.HasPrefix(method, "notifications/") {
			body = `{"jsonrpc":"2.0","method":"` + method + `"}` // notification, no id
		}
		req := newMCPRequest(t, "mcp/gateway/", body)
		res := cbp.AllowOperation(testContext(), req, nil, false)
		assert.True(t, res.Allowed, "lifecycle method %q must be allowed", method)
		require.NotNil(t, res.MCPDecision)
		assert.Equal(t, "allow", res.MCPDecision.Decision, "method %q", method)
		assert.Equal(t, "(lifecycle)", res.MCPDecision.MatchedRule, "method %q", method)
	}
}

func TestMCPEval_LifecycleMethod_ExplicitDenyStillBlocks(t *testing.T) {
	// The deny gate runs before the exemption: an operator can still block
	// a lifecycle method by naming it in denied_methods.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods {
    allowed = ["tools/list"]
    denied = ["ping"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{"jsonrpc":"2.0","method":"ping","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, mcpRuleTypeDeniedMethods, res.MCPDecision.RuleType)
	assert.Equal(t, "ping", res.MCPDecision.MatchedRule)
}

func TestMCPEval_ToolsCall_NeedsBothMethodAndToolAllow(t *testing.T) {
	// Deny-by-default: allowing tools/call as a method is not enough — the
	// tool name must also match allowed_tools. Empty allowed_tools ⇒ deny.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_StarOpensEverything(t *testing.T) {
	// allowed_* = ["*"] restores fully-open behavior for a data-plane call.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["*"] }
  tools { allowed = ["*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
}

func TestMCPEval_DeniedMethods_Match(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { denied = ["tools/call"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_NoMCPPolicy_Denies(t *testing.T) {
	// A capability grant with no contract in scope refuses MCP-shaped traffic.
	// The grant says the caller may reach the mount; nothing says which calls
	// are permitted on it, so none are. (Was a clean pass-through before the
	// absence flip — that default was indistinguishable from an operator
	// forgetting to attach the contract.)
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeNoMCPPolicy, res.MCPDecision.RuleType)
	assert.Empty(t, res.MCPDecision.MatchedRule, "no rule-set was chosen")
	assert.Empty(t, res.MCPDecision.PolicyName, "no policy to name")
}

func TestMCPEval_NoMCPPolicy_NonMCPTrafficUnaffected(t *testing.T) {
	// The absence deny keys on an MCP-shaped body, not on the path. A request
	// with no descriptor at all — every non-MCP mount — is untouched.
	cbp := mustCBP(t, `
path "secret/data/*" {
  capabilities = ["read"]
}
`)
	res := cbp.AllowOperation(testContext(), &logical.Request{
		Path:      "secret/data/app",
		Operation: logical.ReadOperation,
	}, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, res.MCPDecision)
}

// =============================================================================
// Name gate
// =============================================================================

func TestMCPEval_AllowedTools_WildcardMatch(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_*", "list_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "get_repository", res.MCPDecision.Name)
	assert.Equal(t, "get_*", res.MCPDecision.MatchedRule, "wildcard pattern, not literal")
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_AllowedPrompts_BareStar(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["prompts/get"] }
  prompts { allowed = ["*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  {"name": "code-review"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "*", res.MCPDecision.MatchedRule)
}

func TestMCPEval_DeniedTools_Match(t *testing.T) {
	// allowed_methods admits tools/call so the request reaches the name
	// gate; denied_tools then fires. (Under deny-by-default a set without
	// allowed_methods would deny at the method gate before the name gate.)
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { denied = ["delete_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_DeniedResources_Match(t *testing.T) {
	// resources/read with a denied_resources pattern that matches the
	// requested URI → deny with rule_type denied_resources. Mirrors
	// denied_tools but on the resources/read name gate.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/read"] }
  resources { denied = ["github://secrets/*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://secrets/api-key"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "github://secrets/*", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedResources, res.MCPDecision.RuleType)
}

func TestMCPEval_DeniedPrompts_Match(t *testing.T) {
	// prompts/get with a denied_prompts pattern that matches → deny
	// with rule_type denied_prompts.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["prompts/get"] }
  prompts { denied = ["sudo_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  {"name": "sudo_admin"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "sudo_*", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedPrompts, res.MCPDecision.RuleType)
}

// denied_resources alone (no allowed_resources) — a name that does
// NOT match the deny pattern passes through the name gate.
// Pre-Phase-5 the matcher returned (nil, allowList) for resources/read
// so this code path didn't exist; pinning it here.
func TestMCPEval_DeniedResources_NoAllowList_Denies(t *testing.T) {
	// Deny-by-default: allowed_methods admits resources/read, but with no
	// allowed_resources every uri is denied — even one matching no
	// denied_resources pattern. (Was allowed under allow-by-default.)
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/read"] }
  resources { denied = ["github://secrets/*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://repo/readme.md"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeAllowedResources, res.MCPDecision.RuleType)
}

// Deny-list precedence on resources/read: when the same name matches
// both allow and deny lists, the deny wins per evaluateMCPSetForCall
// step (d) (deny-list scanned before allow-list).
func TestMCPEval_DeniedResources_BeatsAllowedResources(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/read"] }
  resources {
    allowed = ["github://*"]
    denied = ["github://secrets/*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://secrets/api-key"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDeniedResources, res.MCPDecision.RuleType)
}

func TestMCPEval_NameNotRequired_ListMethod(t *testing.T) {
	// tools/list is name-less; allowed_tools is irrelevant for it
	// even when configured. The method gate runs, the name gate is
	// skipped per Semantics.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["get_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed, "tools/list passes — name gate doesn't fire for name-less method")
	assert.Equal(t, "tools/list", res.MCPDecision.Method)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType,
		"name gate didn't fire for name-less method")
}

func TestMCPEval_EmptyBlock_DeniesByDefault(t *testing.T) {
	// Deny-by-default: an MCP stanza with no family blocks allow-lists nothing,
	// so a data-plane method is denied at the method gate (an empty allowed
	// list matches nothing). (Was allow-any before the flip.)
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType)
}

// =============================================================================
// Multi-set merge (OR-of-rule-sets across stanzas at the same path)
// =============================================================================

func TestMCPEval_MultiSet_FirstAllows(t *testing.T) {
	// Two stanzas at the same path: set 1 allows the request, set 2
	// would deny it. OR semantics: any allow wins, and audit records
	// the first allowing set.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}

path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_repository"] }
}
path "mcp/gateway/*" {
  methods { denied = ["tools/call"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed, "set 1 allows, OR wins")
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_MultiPolicy_AdditiveMerge(t *testing.T) {
	// An MCP contract bound to the same effective path as a bare capability
	// grant. The contract still applies: a policy that says nothing about MCP
	// does NOT lift it. MCP differs from CEL conditions (where "absent clears")
	// because adding a broader catch-all grant shouldn't accidentally free the
	// tools an existing contract narrowed.
	contract := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_*"] }
}
`)
	contract.Name = "contract"
	bareGrant := testParsePolicy(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	bareGrant.Name = "grant"
	cbp, err := NewCBP(testContext(), []*Policy{contract, bareGrant})
	require.NoError(t, err)

	// Forbidden tool: MCP gate from the first policy denies, the
	// second policy's silence on MCP doesn't lift the restriction.
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed, "additive merge: MCP restriction from one policy still applies even with un-mcp'd policy alongside")
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_MultiSet_StrongestReasonDenyList(t *testing.T) {
	// Both sets deny: set 1 via not-in-allow-list (weaker reason),
	// set 2 via explicit deny-list (stronger reason). Audit should
	// record the deny-list reason.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}

path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_repository"] }
}
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { denied = ["delete_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType,
		"strongest-reason picks the deny-list match over not-in-allow-list")
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
}

// =============================================================================
// Batch bodies — JSON-RPC array. End-to-end through the strict parser.
// =============================================================================

func TestMCPEval_Batch_AllAllowed(t *testing.T) {
	// Three calls in a batch, all pass. Body goes through the real
	// ParseJSONRPCStrict (producing 3 MCPCalls with BatchIndex 0/1/2)
	// and then through the matcher; the decision is the last allow
	// and BatchIndex stays nil because no element denied. No list method
	// is present, so the response-filter batch guard does not fire.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["search_repos", "get_repo"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_repo"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed, "every batch call must allow → batch allows")
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Nil(t, res.MCPDecision.BatchIndex,
		"BatchIndex stamped only on denies")
}

func TestMCPEval_Batch_WithListMethod_Denied(t *testing.T) {
	// A batch that contains a list method is denied even when every call
	// would otherwise pass: a batched JSON-RPC list response can't be
	// pruned per element, so the response-filter guard fails closed.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["search_repos"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 1},
		{"jsonrpc": "2.0", "method": "tools/list", "id": 2}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeBatchListUnfilterable, res.MCPDecision.RuleType)
	assert.Nil(t, req.MCPListFilter, "no filter attached for a denied batch")
}

func TestMCPEval_Batch_OneDeniedFailsBatch(t *testing.T) {
	// A batch where the third element denies — the entire batch
	// denies (single-fail-all-fail) with the denying call's
	// MCPDecision stamped including BatchIndex.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["search_repos"]
    denied = ["delete_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType)
	assert.Equal(t, "delete_repo", res.MCPDecision.Name)
	require.NotNil(t, res.MCPDecision.BatchIndex,
		"batch deny stamps BatchIndex")
	assert.Equal(t, 2, *res.MCPDecision.BatchIndex,
		"third call (index 2) was the denying one")
}

func TestMCPEval_Batch_TwoDenies_FirstWins(t *testing.T) {
	// A batch where elements 1 AND 2 both deny — evaluateMCPDescriptor
	// short-circuits at the FIRST denying call, so BatchIndex == 1.
	// Pins the first-deny-wins contract independently from
	// Batch_OneDeniedFailsBatch (which puts the only deny last).
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { denied = ["delete_*", "drop_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drop_database"}, "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	require.NotNil(t, res.MCPDecision.BatchIndex)
	assert.Equal(t, 1, *res.MCPDecision.BatchIndex,
		"first denying call (index 1) wins; the third call's deny is never reached")
	assert.Equal(t, "delete_repo", res.MCPDecision.Name)
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
}

// A JSON-RPC array body with a single element exercises the batch
// code path BUT doesn't stamp BatchIndex — the matcher only stamps
// for genuinely batched bodies (len > 1). Pins the boundary.
func TestMCPEval_Batch_SingleElement_NoBatchIndex(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { denied = ["delete_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 1}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType)
	assert.Nil(t, res.MCPDecision.BatchIndex,
		"single-element array body is not a batch for BatchIndex purposes")
}

func TestMCPEval_Batch_Empty_Denies(t *testing.T) {
	// An empty batch body `[]` is rejected by the strict parser with
	// batch_empty. The matcher never runs; decideMCP maps the
	// ParseErr.Kind 1:1 to MCPDecision.RuleType.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeBatchEmpty, res.MCPDecision.RuleType)
}

func TestMCPEval_Batch_DuplicateKey_Denies(t *testing.T) {
	// A batch where one element has a duplicate key fails the WHOLE
	// batch at parse time (strict-parser single-pass bail).
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "method": "tools/list", "params": {"name": "x"}, "id": 2}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDuplicateKey, res.MCPDecision.RuleType)
}

// =============================================================================
// Canonicalisation: case-insensitive matching
// =============================================================================

func TestMCPEval_BodyCaseInsensitive(t *testing.T) {
	// Operator wrote lowercase in policy; client sends mixed-case
	// method and tool name in the body. The matcher lowercases
	// descriptor method/name once at the boundary so the comparison
	// succeeds and the decision records the lowercased form.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "Tools/CALL",
		"params":  {"name": "GET_Repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Equal(t, "tools/call", res.MCPDecision.Method)
	assert.Equal(t, "get_repository", res.MCPDecision.Name)
}

// =============================================================================
// Typed-error wrap (request_handler integration is end-to-end; unit-test
// the typed-error shape directly to verify the Unwrap contract).
// =============================================================================

func TestErrMCPPolicyDenied_UnwrapsToPermissionDenied(t *testing.T) {
	err := &ErrMCPPolicyDenied{
		Decision: &logical.MCPDecision{Decision: "deny", RuleType: mcpRuleTypeDeniedTools},
	}
	// errors.Is should resolve through Unwrap.
	require.NotNil(t, err)
	assert.Equal(t, "permission denied", err.Error())

	// Verify the Unwrap returns the sdklogical sentinel that the HTTP
	// status mapper keys off.
	type unwrapper interface{ Unwrap() error }
	var u unwrapper = err
	assert.NotNil(t, u.Unwrap())
}

// =============================================================================
// Helper unit tests
// =============================================================================

func TestMatchMCPGlob(t *testing.T) {
	cases := []struct {
		value, pattern string
		want           bool
	}{
		{"get_repository", "get_*", true},
		{"get_repository", "get_repository", true},
		{"get_repository", "*", true},
		{"get_repository", "get", false},
		{"get_repository", "set_*", false},
		{"", "*", true},
		{"", "", true},
	}
	for _, c := range cases {
		t.Run(c.pattern+"_vs_"+c.value, func(t *testing.T) {
			assert.Equal(t, c.want, matchMCPGlob(c.value, c.pattern))
		})
	}
}

func TestBuildMCPDenyDescription_PerRuleType(t *testing.T) {
	cases := []struct {
		ruleType string
		decision *logical.MCPDecision
		want     string
	}{
		{mcpRuleTypeDeniedMethods,
			&logical.MCPDecision{Method: "tools/call", RuleType: mcpRuleTypeDeniedMethods},
			"Method 'tools/call' not allowed."},
		{mcpRuleTypeAllowedMethods,
			&logical.MCPDecision{Method: "tools/call", RuleType: mcpRuleTypeAllowedMethods},
			"Method 'tools/call' not allowed."},
		{mcpRuleTypeDeniedTools,
			&logical.MCPDecision{Name: "delete_repository", RuleType: mcpRuleTypeDeniedTools},
			"Tool 'delete_repository' not allowed."},
		{mcpRuleTypeAllowedTools,
			&logical.MCPDecision{Name: "create_pr", RuleType: mcpRuleTypeAllowedTools},
			"Tool 'create_pr' not allowed."},
		{mcpRuleTypeAllowedResources,
			&logical.MCPDecision{Name: "github://repo/B/x", RuleType: mcpRuleTypeAllowedResources},
			"Resource 'github://repo/B/x' not allowed."},
		{mcpRuleTypeDeniedResources,
			&logical.MCPDecision{Name: "github://secrets/api-key", RuleType: mcpRuleTypeDeniedResources},
			"Resource 'github://secrets/api-key' not allowed."},
		{mcpRuleTypeAllowedPrompts,
			&logical.MCPDecision{Name: "code-review", RuleType: mcpRuleTypeAllowedPrompts},
			"Prompt 'code-review' not allowed."},
		{mcpRuleTypeDeniedPrompts,
			&logical.MCPDecision{Name: "sudo_admin", RuleType: mcpRuleTypeDeniedPrompts},
			"Prompt 'sudo_admin' not allowed."},
		{mcpRuleTypeDeniedParams,
			&logical.MCPDecision{ParamName: "path", ParamValue: ".env", RuleType: mcpRuleTypeDeniedParams},
			"Parameter 'path'='.env' not allowed."},
		{mcpRuleTypeAllowedParams + "_missing",
			&logical.MCPDecision{ParamName: "region", RuleType: mcpRuleTypeAllowedParams},
			"Parameter 'region' required."},
		{mcpRuleTypeAllowedParams + "_mismatch",
			&logical.MCPDecision{ParamName: "region", ParamValue: "ap-south1", RuleType: mcpRuleTypeAllowedParams},
			"Parameter 'region'='ap-south1' not allowed."},
		{mcpRuleTypeMissingMethod,
			&logical.MCPDecision{RuleType: mcpRuleTypeMissingMethod},
			"Request method required."},
		{mcpRuleTypeMissingBody,
			&logical.MCPDecision{RuleType: mcpRuleTypeMissingBody},
			"Request body required."},
		{mcpRuleTypeMalformedJSONRPC,
			&logical.MCPDecision{RuleType: mcpRuleTypeMalformedJSONRPC},
			"Request body is not a valid JSON-RPC request."},
		{mcpRuleTypeDuplicateKey,
			&logical.MCPDecision{RuleType: mcpRuleTypeDuplicateKey},
			"Request body contains duplicate keys."},
		{mcpRuleTypeOversizedBody,
			&logical.MCPDecision{RuleType: mcpRuleTypeOversizedBody},
			"Request body exceeds maximum size."},
		{mcpRuleTypeBatchEmpty,
			&logical.MCPDecision{RuleType: mcpRuleTypeBatchEmpty},
			"Request batch is empty."},
		{mcpRuleTypeMalformedParams,
			&logical.MCPDecision{RuleType: mcpRuleTypeMalformedParams},
			"Request params have unexpected shape."},
		{mcpRuleTypeBatchListUnfilterable,
			&logical.MCPDecision{RuleType: mcpRuleTypeBatchListUnfilterable},
			"Batched list requests are not supported."},
	}
	for _, c := range cases {
		t.Run(c.ruleType, func(t *testing.T) {
			assert.Equal(t, c.want, BuildMCPDenyDescription(c.decision))
		})
	}

	// Identical-message invariant: denied_tools and allowed_tools-no-match
	// for the same tool name must produce identical strings. Prevents
	// client-side enumeration of policy shape from the response.
	deniedToolsMsg := BuildMCPDenyDescription(&logical.MCPDecision{
		Name: "x", RuleType: mcpRuleTypeDeniedTools,
	})
	allowedToolsMsg := BuildMCPDenyDescription(&logical.MCPDecision{
		Name: "x", RuleType: mcpRuleTypeAllowedTools,
	})
	assert.Equal(t, deniedToolsMsg, allowedToolsMsg,
		"deny-vs-not-in-allow indistinguishable to client")
}

func TestBuildMCPDenyDescription_StripsCTLs(t *testing.T) {
	d := &logical.MCPDecision{
		Name:     "evil\x00name\x1f\r\n",
		RuleType: mcpRuleTypeDeniedTools,
	}
	got := BuildMCPDenyDescription(d)
	assert.Equal(t, "Tool 'evilname' not allowed.", got,
		"CTL bytes stripped before interpolation")
}

func TestBuildMCPDenyDescription_UnknownRuleType_GenericFallback(t *testing.T) {
	d := &logical.MCPDecision{RuleType: "future_unknown_gate"}
	assert.Equal(t, "Request denied by policy.", BuildMCPDenyDescription(d))
}

// =============================================================================
// Benchmarks — validate the performance claims from the Defense-in-depth
// section of the plan. Targets:
//
//	BenchmarkAllowOperation_NoMCP       — baseline (existing perf preserved)
//	BenchmarkAllowOperation_TypicalMCP  — overhead < 2 µs (expect ~300–500 ns)
//	BenchmarkAllowOperation_StressMCP   — overhead < 20 µs at pathological scale
//
// Run: go test -bench BenchmarkAllowOperation -benchmem ./core/
// =============================================================================

func BenchmarkAllowOperation_NoMCP(b *testing.B) {
	cbp := buildBenchCBP(b, `
path "secret/*" {
  capabilities = ["read"]
}
`)
	req := &logical.Request{Path: "secret/foo", Operation: logical.ReadOperation}
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

func BenchmarkAllowOperation_TypicalMCP(b *testing.B) {
	cbp := buildBenchCBPWithMCP(b, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call", "resources/list", "resources/read", "prompts/get"] }
  tools { allowed = [
      "get_repository", "get_pull_request", "list_issues", "list_pull_requests",
      "search_code", "search_issues", "search_repositories", "list_workflows",
      "list_commits", "get_file_contents",
    ] }
  condition = "(!has(call.args.path) || call.args.path.startsWith('docs/')) && (!has(call.args.mode) || call.args.mode == '0644') && (!has(call.args.region) || call.args.region == 'us-west1')"
}
`)
	req := newMCPRequest(b, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name": "get_repository",
			"arguments": {
				"path":   "docs/api.md",
				"mode":   "0644",
				"region": "us-west1"
			}
		},
		"id": 1
	}`)
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

func BenchmarkAllowOperation_StressMCP(b *testing.B) {
	// 5 stanzas at the same path, each with ~50 patterns across
	// methods/tools/params. Operators shouldn't aim for this shape,
	// but the bench bounds the cliff.
	cbp := buildBenchCBPWithMCP(b, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, buildStressPolicy(5, 50))
	req := newMCPRequest(b, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository_47"},
		"id":      1
	}`)
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

func buildBenchCBP(b *testing.B, rules string) *CBP {
	b.Helper()
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	cbp, err := NewCBP(testContext(), []*Policy{policy})
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	return cbp
}

// buildBenchCBPWithMCP is buildBenchCBP for the two-document shape a governed
// MCP mount uses.
func buildBenchCBPWithMCP(b *testing.B, cbpRules, mcpRules string) *CBP {
	b.Helper()
	cbpPolicy, err := ParseCBPPolicy(namespace.RootNamespace, cbpRules)
	if err != nil {
		b.Fatalf("parse cbp: %v", err)
	}
	mcpPolicy, err := ParseMCPPolicy(namespace.RootNamespace, mcpRules)
	if err != nil {
		b.Fatalf("parse mcp: %v", err)
	}
	mcpPolicy.Name = "contract"
	cbp, err := NewCBP(testContext(), []*Policy{cbpPolicy, mcpPolicy})
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	return cbp
}

// buildStressPolicy emits an MCP document with `sets` stanzas at the same path,
// which the index merges into that many rule-sets.
func buildStressPolicy(sets, patternsPerList int) string {
	var sb strings.Builder
	for s := 0; s < sets; s++ {
		sb.WriteString(`path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools {
    allowed = [`)
		for i := 0; i < patternsPerList; i++ {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, `"get_repository_%d"`, i)
		}
		sb.WriteString("]\n  }\n}\n")
	}
	return sb.String()
}

// BenchmarkAllowOperation_MCPNoContract measures the absence deny: an
// MCP-shaped request on a granted path with no contract in scope. This is the
// cost of the second index lookup missing, which every ungoverned MCP request
// now pays before being refused.
func BenchmarkAllowOperation_MCPNoContract(b *testing.B) {
	cbp := buildBenchCBP(b, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := newMCPRequest(b, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_MCPNoCondition isolates the contract's structural
// gates from CEL. Paired with TypicalMCP — same shape, minus the condition —
// it says how much of an MCP request's cost is the condition rather than the
// method and name matching.
func BenchmarkAllowOperation_MCPNoCondition(b *testing.B) {
	cbp := buildBenchCBPWithMCP(b, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call", "resources/list", "resources/read", "prompts/get"] }
  tools { allowed = [
      "get_repository", "get_pull_request", "list_issues", "list_pull_requests",
      "search_code", "search_issues", "search_repositories", "list_workflows",
      "list_commits", "get_file_contents",
    ] }
}
`)
	req := newMCPRequest(b, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name": "get_repository",
			"arguments": {"path": "docs/api.md", "mode": "0644", "region": "us-west1"}
		},
		"id": 1
	}`)
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_NonMCPWithContractAttached measures what a contract
// costs a request it does not govern — a plain path read by a token that also
// carries an MCP policy. The index is built but never consulted for this path.
func BenchmarkAllowOperation_NonMCPWithContractAttached(b *testing.B) {
	cbp := buildBenchCBPWithMCP(b, `
path "secret/data/*" {
  capabilities = ["read"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_repository"] }
}
`)
	req := &logical.Request{Path: "secret/data/app", Operation: logical.ReadOperation}
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}
