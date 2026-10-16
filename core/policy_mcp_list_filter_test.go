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
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["get_*"]
    denied = ["get_secret"]
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
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.False(t, keep("get_repo"))
	assert.False(t, keep("anything"))
}

// TestListFilter_WildcardContractAttachesNoFilter covers the deliberately
// unrestricted mount. A keep-everything predicate is not free — the gateway
// buffers the whole upstream response to rewrite it, and fails closed above
// max_body_size — so the wildcard contract must leave the response streaming
// exactly as an ungoverned path used to.
func TestListFilter_WildcardContractAttachesNoFilter(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, req.MCPListFilter,
		"a filter that keeps everything is skipped, not attached")
}

// TestListFilter_PartialWildcardStillFilters is the other half: a deny entry
// anywhere in the family means some name can be excluded, so the filter stays.
func TestListFilter_PartialWildcardStillFilters(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["*"]
    denied  = ["delete_everything"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("get_repository"))
	assert.False(t, keep("delete_everything"))
}

// TestListFilter_WildcardWithConditionAttachesNoFilter pins that a per-call
// condition does not by itself keep the filter.
//
// It is tempting to reason that a condition can refuse a call, so the listing
// should be pruned — but list filtering deliberately skips CEL, because a
// listing carries no call arguments to evaluate against. A condition-gated tool
// stays listed either way and is refused at call time. Keeping the filter here
// would buffer the whole response to prune nothing.
func TestListFilter_WildcardWithConditionAttachesNoFilter(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["*"] }
  condition = "call.args.?env.orValue('') != 'prod'"
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, req.MCPListFilter,
		"the keep-predicate ignores conditions, so this filter would prune nothing")
}

// TestListFilter_UnrelatedDeniedMethodStillSkips pins the other refinement: a
// denied_methods entry that cannot match the mapped call method cannot exclude
// a name either, so it does not force the filter back on.
func TestListFilter_UnrelatedDeniedMethodStillSkips(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods {
    allowed = ["tools/list", "tools/call"]
    denied  = ["prompts/get"]
  }
  tools { allowed = ["*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, req.MCPListFilter,
		"a deny on an unrelated method cannot exclude a tool name")
}

// TestListFilter_DeniedCallMethodKeepsFilter is the boundary of the above: when
// the deny entry does match the mapped call method, nothing is callable, so the
// filter stays and empties the listing.
func TestListFilter_DeniedCallMethodKeepsFilter(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods {
    allowed = ["tools/list", "tools/call"]
    denied  = ["tools/call"]
  }
  tools { allowed = ["*"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.False(t, keep("anything"), "tools/call is denied, so no tool is callable")
}

func TestListFilter_ToolsListAllowedButNotToolsCall_EmptyList(t *testing.T) {
	// allowed_methods permits tools/list but not tools/call, so nothing is
	// callable → the filter keeps nothing. "Visible == callable."
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
  tools { allowed = ["get_*"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.False(t, keep("get_repo"), "tools/call not allowed → nothing is callable")
}

func TestListFilter_ResourcesList_MatchesByUri(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/list", "resources/read"] }
  resources { allowed = ["github://repo/*"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"resources/list","id":1}`, "resources/list")

	assert.True(t, keep("github://repo/readme"))
	assert.False(t, keep("github://secrets/token"))
}

func TestListFilter_PromptsList_MatchesByName(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["prompts/list", "prompts/get"] }
  prompts { allowed = ["safe_*"] }
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
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}

path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["get_*"] }
}
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["list_*"] }
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
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["create_payment"] }
  condition = "call.method != 'tools/call' || call.args.amount <= 1500"
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`, "tools/list")

	assert.True(t, keep("create_payment"), "name-allowed tool stays listed despite a CEL condition")
}

func TestListFilter_NotAttachedForToolsCall(t *testing.T) {
	// A non-list call gets no filter — only list methods are filtered.
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["get_repo"] }
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
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["*"] }
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	_ = cbp.AllowOperation(testContext(), req, nil, true) // capCheckOnly

	assert.Nil(t, req.MCPListFilter, "cap-check-only must not attach a filter")
}

func TestListFilter_NoMCPPolicyDeniesTheListing(t *testing.T) {
	// A path with no contract in scope refuses the listing outright rather than
	// streaming it unfiltered. An agent gets an explicit misconfiguration
	// signal instead of a catalog it was never meant to see. (Before the
	// absence flip this passed through with no filter attached.)
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, mcpRuleTypeNoMCPPolicy, res.MCPDecision.RuleType)
	assert.Nil(t, req.MCPListFilter, "a denied listing never reaches the filter")
}

// A skills/list entry survives iff a skills/get for its SKILL.md uri would
// pass: the resources family governs skills.
func TestListFilter_SkillsList_MatchesBySkillURI(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["skills/list", "skills/get"] }
  resources {
    allowed = ["skill://pdf-processing/*"]
    denied  = ["skill://pdf-processing/internal/*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"skills/list","id":1}`, "skills/list")

	assert.True(t, keep("skill://pdf-processing/SKILL.md"))
	assert.False(t, keep("skill://git-workflow/SKILL.md"))
	assert.False(t, keep("skill://pdf-processing/internal/SKILL.md"))
}

// Visible == fetchable: with skills/get refused, no skill survives the listing.
func TestListFilter_SkillsListAllowedButNotSkillsGet_EmptyList(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["skills/list", "resources/read"] }
  resources { allowed = ["skill://*"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"skills/list","id":1}`, "skills/list")

	assert.False(t, keep("skill://pdf-processing/SKILL.md"), "skills/get not allowed → nothing is fetchable")
}

// The directory URI is gated on the way in; its children are pruned by the
// read gate on the way back.
func TestListFilter_DirectoryRead_PrunesChildren(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/directory/read", "resources/read"] }
  resources {
    allowed = ["skill://pdf-processing/*"]
    denied  = ["skill://pdf-processing/templates/internal*"]
  }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"resources/directory/read","params":{"uri":"skill://pdf-processing/templates"},"id":1}`,
		"resources/directory/read")

	assert.True(t, keep("skill://pdf-processing/templates/invoice.md"))
	assert.True(t, keep("skill://pdf-processing/templates/regional"))
	assert.False(t, keep("skill://pdf-processing/templates/internal.md"))
}

// Children are kept by the read gate, so a browse-only contract lists an
// empty directory, as tools/list without tools/call lists no tools.
func TestListFilter_DirectoryReadAllowedButNotResourcesRead_EmptyList(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["resources/directory/read"] }
  resources { allowed = ["skill://pdf-processing/*"] }
}
`)
	keep := filterKeeps(t, cbp, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"resources/directory/read","params":{"uri":"skill://pdf-processing/templates"},"id":1}`,
		"resources/directory/read")

	assert.False(t, keep("skill://pdf-processing/templates/invoice.md"))
}

// An unrestricted resources grant keeps every skill, so no filter is attached
// and the listing streams — the same fast path tools/list has.
func TestListFilter_WildcardResourcesSkipsSkillsFilter(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["*"] }
  resources { allowed = ["*"] }
}
`)
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"skills/list","id":1}`,
		`{"jsonrpc":"2.0","method":"resources/directory/read","params":{"uri":"skill://pdf"},"id":1}`,
	} {
		req := newMCPRequest(t, "mcp/gateway/", body)
		res := cbp.AllowOperation(testContext(), req, nil, false)
		require.True(t, res.Allowed, body)
		assert.Nil(t, req.MCPListFilter, "a keep-everything filter must not be attached: %s", body)
	}

	// Any deny makes the filter necessary again.
	denying := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["*"] }
  resources {
    allowed = ["*"]
    denied  = ["skill://internal*"]
  }
}
`)
	for _, tc := range []struct{ body, method string }{
		{`{"jsonrpc":"2.0","method":"skills/list","id":1}`, "skills/list"},
		{`{"jsonrpc":"2.0","method":"resources/directory/read","params":{"uri":"skill://pdf"},"id":1}`, "resources/directory/read"},
	} {
		keep := filterKeeps(t, denying, "mcp/gateway/", tc.body, tc.method)
		assert.False(t, keep("skill://internal-tools/SKILL.md"))
		assert.True(t, keep("skill://pdf/SKILL.md"))
	}
}

// A batched list response can't be pruned per element, so a batch carrying
// either new list method fails closed like tools/list does.
func TestListFilter_BatchWithSkillsListFailsClosed(t *testing.T) {
	cbp := mustCBPWithMCP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`, `
path "mcp/gateway/*" {
  methods { allowed = ["*"] }
  resources { allowed = ["skill://pdf-processing/*"] }
}
`)
	for _, body := range []string{
		`[{"jsonrpc":"2.0","method":"ping","id":1},{"jsonrpc":"2.0","method":"skills/list","id":2}]`,
		`[{"jsonrpc":"2.0","method":"ping","id":1},{"jsonrpc":"2.0","method":"resources/directory/read","params":{"uri":"skill://pdf-processing/templates"},"id":2}]`,
	} {
		res := cbp.AllowOperation(testContext(), newMCPRequest(t, "mcp/gateway/", body), nil, false)
		assert.False(t, res.Allowed, body)
		require.NotNil(t, res.MCPDecision)
		assert.Equal(t, mcpRuleTypeBatchListUnfilterable, res.MCPDecision.RuleType)
	}
}
