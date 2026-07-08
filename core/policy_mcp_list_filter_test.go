// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// filterKeeps runs an allowed list request through AllowOperation and returns
// the resulting Keep predicate. It asserts the request was allowed and a
// filter for listMethod was attached.
func filterKeeps(t *testing.T, cbp *CBP, path, body, listMethod string) func(string) bool {
	t.Helper()
	req := newMCPRequest(t, path, body)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	require.True(t, res.Allowed, "list request must be allowed to attach a filter")
	require.NotNil(t, req.MCPListFilter, "filter must be attached for a list method")
	assert.Equal(t, listMethod, req.MCPListFilter.ListMethod)
	return req.MCPListFilter.Keep
}

func TestListFilter_ToolsList_KeepsOnlyCallableTools(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["get_*"]
    denied_tools    = ["get_secret"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("get_repo"), "allowed tool kept")
	assert.True(t, keep("GET_REPO"), "match is case-insensitive")
	assert.False(t, keep("delete_repo"), "not in allowed_tools → dropped")
	assert.False(t, keep("get_secret"), "denied_tools → dropped even though get_* matches")
}

func TestListFilter_NoAllowedTools_KeepsNothing(t *testing.T) {
	// Deny-by-default: tools/list is permitted as a method, but with no
	// allowed_tools every item is filtered out — the list comes back empty.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.False(t, keep("get_repo"))
	assert.False(t, keep("anything"))
}

func TestListFilter_StarKeepsEverything(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("delete_everything"))
}

func TestListFilter_ToolsListAllowedButNotToolsCall_EmptyList(t *testing.T) {
	// allowed_methods permits tools/list but not tools/call, so nothing is
	// callable → the filter keeps nothing. "Visible == callable."
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
    allowed_tools   = ["get_*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.False(t, keep("get_repo"), "tools/call not allowed → nothing is callable")
}

func TestListFilter_ResourcesList_MatchesByUri(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods   = ["resources/list", "resources/read"]
    allowed_resources = ["github://repo/*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"resources/list","id":1}`, "resources/list")

	assert.True(t, keep("github://repo/readme"))
	assert.False(t, keep("github://secrets/token"))
}

func TestListFilter_PromptsList_MatchesByName(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["prompts/list", "prompts/get"]
    allowed_prompts = ["safe_*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"prompts/list","id":1}`, "prompts/list")

	assert.True(t, keep("safe_summary"))
	assert.False(t, keep("sudo_reset"))
}

func TestListFilter_CrossSetOR(t *testing.T) {
	// Two stanzas: one allows get_*, the other allows list_*. A tool is kept
	// if either set would allow the call (cross-set OR).
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["get_*"]
  }
}

path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["list_*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("get_repo"))
	assert.True(t, keep("list_issues"))
	assert.False(t, keep("delete_repo"))
}

func TestListFilter_ConditionGatedToolStaysListed(t *testing.T) {
	// A set with a per-call CEL condition still contributes its name gate to
	// the list filter; the condition (which needs call args) is skipped at
	// list time and enforced at call time. The condition is scoped with
	// call.method so it doesn't deny the argument-less tools/list request
	// itself (a set-wide call.args condition would — see docs/concepts/mcp.md).
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "call.method != 'tools/call' || call.args.amount <= 1500"
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("create_payment"), "name-allowed tool stays listed despite a CEL condition")
}

func TestListFilter_NotAttachedForToolsCall(t *testing.T) {
	// A non-list call gets no filter — only list methods are filtered.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["get_repo"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_repo"},"id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, req.MCPListFilter, "tools/call is not a list method")
}

func TestListFilter_NotAttachedOnCapCheckOnly(t *testing.T) {
	// The cap-check-only pass must not leave a filter behind.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["*"]
  }
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	_ = cbp.AllowOperation(testContext(), req, nil, true) // capCheckOnly

	assert.Nil(t, req.MCPListFilter, "cap-check-only must not attach a filter")
}

func TestListFilter_NotAttachedWithoutMCPBlock(t *testing.T) {
	// A path without an mcp{} block imposes no MCP governance (opt-in), so a
	// tools/list request streams through unfiltered.
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, req.MCPListFilter, "no mcp{} block → no filter")
}
