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

// newMCPRequest builds a logical.Request with an MCP-shaped HTTPRequest
// carrying the supplied headers. Mcp-* headers go through net/http's
// canonical-case normalisation just like real requests would. Accepts
// testing.TB so the same builder works from both tests and benchmarks.
func newMCPRequest(tb testing.TB, path string, headers map[string]string) *logical.Request {
	tb.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/"+path, nil)
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	return &logical.Request{
		Path:        path,
		Operation:   logical.UpdateOperation, // MCP traffic is POST → update
		HTTPRequest: httpReq,
	}
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{"Mcp-Method": "tools/list"})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{"Mcp-Method": "tools/call"})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{"Mcp-Method": "tools/call"})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedMethods, res.MCPDecision.RuleType)
}

func TestMCPEval_MissingMethodHeader(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{}) // no Mcp-Method
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "", res.MCPDecision.Method)
	assert.Equal(t, mcpRuleTypeMissingMethod, res.MCPDecision.RuleType)
}

func TestMCPEval_NoMCPBlock_PassesThrough(t *testing.T) {
	// A policy with no mcp { } block leaves MCPDecision nil — the
	// MCP gate doesn't run, the request goes through to the proxy.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{}) // no headers at all
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "get_repository",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "get_repository", res.MCPDecision.Name)
	assert.Equal(t, "get_*", res.MCPDecision.MatchedRule, "wildcard pattern, not literal")
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
}

func TestMCPEval_AllowedTools_BareStar(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["prompts/get"]
    allowed_prompts = ["*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "prompts/get",
		"Mcp-Name":   "code-review",
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "delete_repository",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType)
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/list", // no Mcp-Name; name-less method
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed, "tools/list passes even without Mcp-Name")
	assert.Equal(t, "tools/list", res.MCPDecision.Method)
	assert.Equal(t, mcpRuleTypeAllowedMethods, res.MCPDecision.RuleType,
		"name gate didn't fire for name-less method")
}

func TestMCPEval_NameRequiredButMissing(t *testing.T) {
	// tools/call with allowed_tools configured and no Mcp-Name →
	// empty value can't match any allow-list entry → deny.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_repository"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		// no Mcp-Name
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeAllowedTools, res.MCPDecision.RuleType)
	assert.Equal(t, "", res.MCPDecision.MatchedRule)
}

func TestMCPEval_EmptyBlock_AllowsAnyMethod(t *testing.T) {
	// Empty mcp { } block requires Mcp-Method to be present (per
	// Semantics) but doesn't impose any other restriction. A
	// tools/call with no Mcp-Name should still pass since the name
	// gate isn't configured.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {}
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": "docs/api.md",
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": ".env.production",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeDeniedParams, res.MCPDecision.RuleType)
	assert.Equal(t, "path", res.MCPDecision.ParamName)
	assert.Equal(t, ".env.production", res.MCPDecision.ParamValue)
	assert.Equal(t, ".env*", res.MCPDecision.MatchedRule)
}

func TestMCPEval_AllowedParams_MissingHeader(t *testing.T) {
	// allowed_params configured, request omits the header → deny.
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "write_file",
		// no Mcp-Param-Region
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeAllowedParams, res.MCPDecision.RuleType)
	assert.Equal(t, "region", res.MCPDecision.ParamName)
	assert.Equal(t, "", res.MCPDecision.ParamValue,
		"missing-header case records empty value")
}

func TestMCPEval_DeniedParams_MissingHeader_NoDeny(t *testing.T) {
	// denied_params only, no allow-list: a missing header isn't a
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "do_thing",
		// no Mcp-Param-Env
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
}

func TestMCPEval_ParamValue_Base64Decoded(t *testing.T) {
	// Mcp-Param-Path: =?base64?ZG9jcy9yZWFkbWUubWQ=?= decodes to
	// "docs/readme.md" which matches docs/*.
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": "=?base64?ZG9jcy9yZWFkbWUubWQ=?=",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.True(t, res.Allowed)
}

func TestMCPEval_ParamValue_MalformedBase64_FallsBackToLiteral(t *testing.T) {
	// Malformed envelope (invalid base64 inside the wrapper) falls
	// back to the raw value. The raw value matches no allow-list
	// entry, so the request is denied with the raw bytes recorded
	// (not the decoded ones — there's no decoded form).
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": "=?base64?!!!not_valid_base64!!!?=",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, "=?base64?!!!not_valid_base64!!!?=", res.MCPDecision.ParamValue,
		"malformed envelope: raw bytes recorded so audit shows what was actually compared")
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": "docs/api.md",
		"Mcp-Param-Mode": "0644",
	})
	res := cbp.AllowOperation(testContext(), req, false)
	assert.True(t, res.Allowed, "both keys satisfied → allow")
}

func TestMCPEval_MultiKeyParams_OneFails(t *testing.T) {
	// Same policy, but mode header carries a disallowed value.
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "write_file",
		"Mcp-Param-Path": "docs/api.md", // passes
		"Mcp-Param-Mode": "0755",        // fails
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "get_repository",
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "delete_repository",
	})
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
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "delete_repository",
	})
	res := cbp.AllowOperation(testContext(), req, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType,
		"strongest-reason picks the deny-list match over not-in-allow-list")
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
}

// =============================================================================
// Canonicalisation: case-insensitive matching
// =============================================================================

func TestMCPEval_HeaderCaseInsensitive(t *testing.T) {
	// Operator wrote lowercase in policy; client sends mixed case
	// header values. Should still match because evaluateMCP
	// lowercases the request values before comparing.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/", map[string]string{
		"Mcp-Method": "Tools/CALL",  // mixed case
		"Mcp-Name":   "GET_Repository", // mixed case
	})
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

func TestDecodeMCPParamValue(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain ASCII", "docs/readme.md", "docs/readme.md"},
		{"base64 envelope decodes", "=?base64?ZG9jcy9yZWFkbWUubWQ=?=", "docs/readme.md"},
		{"malformed base64 inside envelope falls back to raw",
			"=?base64?!!!?=", "=?base64?!!!?="},
		{"prefix only without suffix is literal",
			"=?base64?ZG9jcw==", "=?base64?ZG9jcw=="},
		{"empty input", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, decodeMCPParamValue(c.raw))
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
		{mcpRuleTypeAllowedPrompts,
			&logical.MCPDecision{Name: "code-review", RuleType: mcpRuleTypeAllowedPrompts},
			"Prompt 'code-review' not allowed."},
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
			"Mcp-Method header required."},
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
	req := newMCPRequest(b, "mcp/gateway/", map[string]string{
		"Mcp-Method":       "tools/call",
		"Mcp-Name":         "get_repository",
		"Mcp-Param-Path":   "docs/api.md",
		"Mcp-Param-Mode":   "0644",
		"Mcp-Param-Region": "us-west1",
	})
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
	req := newMCPRequest(b, "mcp/gateway/", map[string]string{
		"Mcp-Method": "tools/call",
		"Mcp-Name":   "get_repository_47", // matches one of the allow patterns
	})
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
