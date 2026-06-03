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
func mustCBP(t *testing.T, rules string) *CBP {
	t.Helper()
	policy := testParsePolicy(t, rules)
	cbp, err := NewCBP(testContext(), []*Policy{policy})
	require.NoError(t, err)
	return cbp
}

// =============================================================================
// Method gate
// =============================================================================

func TestMCPEval_AllowedMethods_Match(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "tools/list", res.MCPDecision.Method)
	assert.Equal(t, "tools/list", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_AllowedMethods_NoMatch(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.Method)
	assert.Equal(t, "", res.MCPDecision.MatchedRule, "no allow-list entry matched")
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_DeniedMethods_Match(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_methods = ["tools/call"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_NoMCPBlock_PassesThrough(t *testing.T) {
	// A policy with no mcp { } block leaves MCPDecision nil — the
	// MCP gate doesn't run, the request goes through to the proxy.
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
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, res.MCPDecision, "no mcp block → no decision recorded")
}

// =============================================================================
// Name gate
// =============================================================================

func TestMCPEval_AllowedTools_WildcardMatch(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_*", "list_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "get_repository", res.MCPDecision.Name)
	assert.Equal(t, "get_*", res.MCPDecision.MatchedRule, "wildcard pattern, not literal")
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_AllowedPrompts_BareStar(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["prompts/get"]
    allowed_prompts = ["*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  {"name": "code-review"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "*", res.MCPDecision.MatchedRule)
}

func TestMCPEval_DeniedTools_Match(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_tools = ["delete_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods   = ["resources/read"]
    denied_resources  = ["github://secrets/*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://secrets/api-key"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "github://secrets/*", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedResources, res.MCPDecision.RuleType)
}

func TestMCPEval_DeniedPrompts_Match(t *testing.T) {
	// prompts/get with a denied_prompts pattern that matches → deny
	// with rule_type denied_prompts.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["prompts/get"]
    denied_prompts  = ["sudo_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  {"name": "sudo_admin"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

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
func TestMCPEval_DeniedResources_Only_NonMatchingAllowed(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods  = ["resources/read"]
    denied_resources = ["github://secrets/*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://repo/readme.md"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
}

// Deny-list precedence on resources/read: when the same name matches
// both allow and deny lists, the deny wins per evaluateMCPSetForCall
// step (d) (deny-list scanned before allow-list).
func TestMCPEval_DeniedResources_BeatsAllowedResources(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods   = ["resources/read"]
    allowed_resources = ["github://*"]
    denied_resources  = ["github://secrets/*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  {"uri": "github://secrets/api-key"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDeniedResources, res.MCPDecision.RuleType)
}

func TestMCPEval_NameNotRequired_ListMethod(t *testing.T) {
	// tools/list is name-less; allowed_tools is irrelevant for it
	// even when configured. The method gate runs, the name gate is
	// skipped per Semantics.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["get_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed, "tools/list passes — name gate doesn't fire for name-less method")
	assert.Equal(t, "tools/list", res.MCPDecision.Method)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType,
		"name gate didn't fire for name-less method")
}

func TestMCPEval_EmptyBlock_AllowsAnyMethod(t *testing.T) {
	// Empty mcp { } block doesn't impose any restriction beyond
	// "body must parse." A tools/call with arguments still passes.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {}
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
}

// =============================================================================
// Param gate
// =============================================================================

func TestMCPEval_AllowedParams_Match(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["write_file"]
    allowed_params = {
      path = ["docs/*"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name":      "write_file",
			"arguments": {"path": "docs/api.md"}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
}

func TestMCPEval_DeniedParams_Match(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["write_file"]
    denied_params = {
      path = [".env*"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name":      "write_file",
			"arguments": {"path": ".env.production"}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeDeniedParams, res.MCPDecision.RuleType)
	assert.Equal(t, "path", res.MCPDecision.ParamName)
	assert.Equal(t, ".env.production", res.MCPDecision.ParamValue)
	assert.Equal(t, ".env*", res.MCPDecision.MatchedRule)
}

func TestMCPEval_AllowedParams_MissingArgument(t *testing.T) {
	// allowed_params configured, body's arguments omit the gated
	// key → request passes. allowed_params is a conditional check
	// ("IF this argument is present, its value must match"), not a
	// required-argument check. Matches Vault's allowed_parameters
	// convention and lets one mcp{} block cover a server with
	// multiple tools that share a JSON-RPC method but take different
	// argument shapes — a tool that doesn't take `region` at all
	// shouldn't be blocked because the policy mentions `region`.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["write_file"]
    allowed_params = {
      region = ["us-west1"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name":      "write_file",
			"arguments": {}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed,
		"missing argument is not a constraint violation under conditional semantics")
}

func TestMCPEval_DeniedParams_MissingArgument_NoDeny(t *testing.T) {
	// denied_params only, no allow-list: a missing argument isn't a
	// match (we don't deny something we never saw), so the request
	// passes.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_params = {
      env = ["prod"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name":      "do_thing",
			"arguments": {}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
}

func TestMCPEval_MultiKeyParams_AllPass(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["write_file"]
    allowed_params = {
      path = ["docs/*"]
      mode = ["0644"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name": "write_file",
			"arguments": {
				"path": "docs/api.md",
				"mode": "0644"
			}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)
	assert.True(t, res.Allowed, "both keys satisfied → allow")
}

func TestMCPEval_MultiKeyParams_OneFails(t *testing.T) {
	// Same policy, but mode argument carries a disallowed value.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["write_file"]
    allowed_params = {
      path = ["docs/*"]
      mode = ["0644"]
    }
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": {
			"name": "write_file",
			"arguments": {
				"path": "docs/api.md",
				"mode": "0755"
			}
		},
		"id": 1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed, "AND across keys: any failing key denies")
	assert.Equal(t, "mode", res.MCPDecision.ParamName)
	assert.Equal(t, "0755", res.MCPDecision.ParamValue)
}

// =============================================================================
// Multi-set merge (OR-of-rule-sets across stanzas at the same path)
// =============================================================================

func TestMCPEval_MultiSet_FirstAllows(t *testing.T) {
	// Two stanzas at the same path: set 1 allows the request, set 2
	// would deny it. OR semantics: any allow wins, and audit records
	// the first allowing set.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_repository"]
  }
}

path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_methods = ["tools/call"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed, "set 1 allows, OR wins")
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_MultiPolicy_AdditiveMerge(t *testing.T) {
	// Two separate Policy objects bound to the same effective path,
	// merged at NewCBP time. The MCP slice grows additively — the
	// presence of a policy WITHOUT an mcp block does NOT clear
	// enforcement contributed by the policy WITH one. This is the
	// design call documented next to the merge code: MCP differs
	// from ConditionSets (where "absent clears") because adding a
	// broader catch-all policy shouldn't accidentally lift an
	// existing MCP restriction.
	policyWithMCP := testParsePolicy(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_*"]
  }
}
`)
	policyWithoutMCP := testParsePolicy(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	cbp, err := NewCBP(testContext(), []*Policy{policyWithMCP, policyWithoutMCP})
	require.NoError(t, err)

	// Forbidden tool: MCP gate from the first policy denies, the
	// second policy's silence on MCP doesn't lift the restriction.
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)
	assert.False(t, res.Allowed, "additive merge: MCP restriction from one policy still applies even with un-mcp'd policy alongside")
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_MultiSet_StrongestReasonDenyList(t *testing.T) {
	// Both sets deny: set 1 via not-in-allow-list (weaker reason),
	// set 2 via explicit deny-list (stronger reason). Audit should
	// record the deny-list reason.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_repository"]
  }
}

path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_tools = ["delete_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	// and BatchIndex stays nil because no element denied.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["search_repos"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/list", "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed, "every batch call must allow → batch allows")
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Nil(t, res.MCPDecision.BatchIndex,
		"BatchIndex stamped only on denies")
}

func TestMCPEval_Batch_OneDeniedFailsBatch(t *testing.T) {
	// A batch where the third element denies — the entire batch
	// denies (single-fail-all-fail) with the denying call's
	// MCPDecision stamped including BatchIndex.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["search_repos"]
    denied_tools    = ["delete_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    denied_tools    = ["delete_*", "drop_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drop_database"}, "id": 3}
	]`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    denied_tools    = ["delete_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 1}
	]`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[]`)
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeBatchEmpty, res.MCPDecision.RuleType)
}

func TestMCPEval_Batch_DuplicateKey_Denies(t *testing.T) {
	// A batch where one element has a duplicate key fails the WHOLE
	// batch at parse time (strict-parser single-pass bail).
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "method": "tools/list", "params": {"name": "x"}, "id": 2}
	]`)
	res := cbp.AllowOperation(testContext(), req, false)

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
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "Tools/CALL",
		"params":  {"name": "GET_Repository"},
		"id":      1
	}`)
	res := cbp.AllowOperation(testContext(), req, false)

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
		_ = cbp.AllowOperation(ctx, req, false)
	}
}

func BenchmarkAllowOperation_TypicalMCP(b *testing.B) {
	cbp := buildBenchCBP(b, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call", "resources/list", "resources/read", "prompts/get"]
    allowed_tools = [
      "get_repository", "get_pull_request", "list_issues", "list_pull_requests",
      "search_code", "search_issues", "search_repositories", "list_workflows",
      "list_commits", "get_file_contents",
    ]
    allowed_params = {
      path = ["docs/*"]
      mode = ["0644"]
      region = ["us-west1"]
    }
  }
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
		_ = cbp.AllowOperation(ctx, req, false)
	}
}

func BenchmarkAllowOperation_StressMCP(b *testing.B) {
	// 5 stanzas at the same path, each with ~50 patterns across
	// methods/tools/params. Operators shouldn't aim for this shape,
	// but the bench bounds the cliff.
	stress := buildStressPolicy(5, 50)
	cbp := buildBenchCBP(b, stress)
	req := newMCPRequest(b, "mcp/gateway/", `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "get_repository_47"},
		"id":      1
	}`)
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, false)
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

func buildStressPolicy(sets, patternsPerList int) string {
	var sb strings.Builder
	for s := 0; s < sets; s++ {
		sb.WriteString(`path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools = [`)
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
