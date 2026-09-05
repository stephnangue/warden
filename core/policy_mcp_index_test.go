// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// mustMCPIndex compiles the given MCP documents into a CBP and returns it.
func mustMCPIndex(t testing.TB, documents ...string) *CBP {
	t.Helper()
	policies := make([]*Policy, 0, len(documents))
	for i, doc := range documents {
		p := testParseMCPPolicy(t, doc)
		p.Name = fmt.Sprintf("p%d", i)
		policies = append(policies, p)
	}
	cbp, err := NewCBP(testContext(), policies)
	require.NoError(t, err)
	return cbp
}

func toolsOf(sets []*CBPMCPRules) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s.AllowedTools...)
	}
	return out
}

func TestMCPIndex_ExactBeatsPrefix(t *testing.T) {
	cbp := mustMCPIndex(t, `
path "mcp/gateway/tools" {
  tools { allowed = ["exact"] }
}

path "mcp/gateway/*" {
  tools { allowed = ["prefix"] }
}
`)
	assert.Equal(t, []string{"exact"}, toolsOf(cbp.mcpRulesForPath("mcp/gateway/tools")))
	assert.Equal(t, []string{"prefix"}, toolsOf(cbp.mcpRulesForPath("mcp/gateway/other")))
}

// TestMCPIndex_LongestPrefixWinsSingleWinner pins that differently-shaped
// stanzas do NOT union: one wins outright. Unioning would let a broad allow-all
// policy silently widen a deliberately narrow one.
func TestMCPIndex_LongestPrefixWinsSingleWinner(t *testing.T) {
	cbp := mustMCPIndex(t, `
path "mcp/*" {
  tools { allowed = ["broad"] }
}

path "mcp/gateway/*" {
  tools { allowed = ["narrow"] }
}
`)
	got := toolsOf(cbp.mcpRulesForPath("mcp/gateway/call"))
	assert.Equal(t, []string{"narrow"}, got)
	assert.NotContains(t, got, "broad", "a broader stanza must not widen the winner")
}

// TestMCPIndex_SameKeyStanzasMerge is the other half of the rule: stanzas at
// the *same* normalized key are additive, so several documents covering one
// path all contribute and evaluateMCPCall's cross-set OR decides.
func TestMCPIndex_SameKeyStanzasMerge(t *testing.T) {
	cbp := mustMCPIndex(t,
		`
path "mcp/gateway/*" {
  tools { allowed = ["from-first"] }
}
`,
		`
path "mcp/gateway/*" {
  tools { allowed = ["from-second"] }
}
`)
	sets := cbp.mcpRulesForPath("mcp/gateway/call")
	require.Len(t, sets, 2, "same-key stanzas from separate policies both apply")
	assert.ElementsMatch(t, []string{"from-first", "from-second"}, toolsOf(sets))
}

func TestMCPIndex_SegmentWildcard(t *testing.T) {
	cbp := mustMCPIndex(t, `
path "mcp/role/+/gateway/*" {
  tools { allowed = ["role-scoped"] }
}
`)
	assert.Equal(t, []string{"role-scoped"},
		toolsOf(cbp.mcpRulesForPath("mcp/role/analyst/gateway/call")))
	assert.Nil(t, cbp.mcpRulesForPath("mcp/role/analyst/other/call"))
}

func TestMCPIndex_NoMatchReturnsNil(t *testing.T) {
	cbp := mustMCPIndex(t, `
path "mcp/gateway/*" {
  tools { allowed = ["x"] }
}
`)
	assert.Nil(t, cbp.mcpRulesForPath("other/mount/call"))
}

func TestMCPIndex_ExpiredStanzaNotIndexed(t *testing.T) {
	p := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["x"] }
}
`)
	// Expire the stanza after parsing, so the drop is the index's doing rather
	// than the parser's.
	p.Name = "expiring"
	p.Paths[0].Expiration = testPastTime()

	cbp, err := NewCBP(testContext(), []*Policy{p})
	require.NoError(t, err)
	assert.Nil(t, cbp.mcpRulesForPath("mcp/gateway/call"))
}

// TestMCPIndex_DoesNotTouchCapabilityIndex pins the separation: an MCP policy
// contributes no capabilities, so it can never grant on its own.
func TestMCPIndex_DoesNotTouchCapabilityIndex(t *testing.T) {
	cbp := mustMCPIndex(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["x"] }
}
`)
	assert.Nil(t, cbp.CheckAllowedFromNonExactPaths("mcp/gateway/call", false),
		"an MCP policy must contribute nothing to the capability index")

	_, exact := cbp.exactRules.Get("mcp/gateway/call")
	assert.False(t, exact)
}

// TestMCPIndex_MixedPoliciesIndexSeparately compiles a CBP grant and an MCP
// contract together — the normal configuration — and checks each lands in its
// own index, matching the same request path from differently-shaped stanzas.
func TestMCPIndex_MixedPoliciesIndexSeparately(t *testing.T) {
	cbpPolicy := testParsePolicy(t, `
path "mcp/gateway*" {
  capabilities = ["update"]
}
`)
	cbpPolicy.Name = "grant"

	mcpPolicy := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["get_repository"] }
}
`)
	mcpPolicy.Name = "contract"

	cbp, err := NewCBP(testContext(), []*Policy{cbpPolicy, mcpPolicy})
	require.NoError(t, err)

	// Both stanzas cover mcp/gateway/call despite different shapes, because the
	// common key is the request path rather than the stanza text.
	perms := cbp.CheckAllowedFromNonExactPaths("mcp/gateway/call", false)
	require.NotNil(t, perms)
	assert.NotZero(t, perms.CapabilitiesBitmap&UpdateCapabilityInt)
	assert.Empty(t, perms.MCP, "the capability node carries no MCP rules")

	assert.Equal(t, []string{"get_repository"},
		toolsOf(cbp.mcpRulesForPath("mcp/gateway/call")))
}

// TestMCPIndex_AllowOperationUnaffected is the inert-by-design pin for this PR:
// attaching an MCP policy must not change any request-time decision yet.
func TestMCPIndex_AllowOperationUnaffected(t *testing.T) {
	cbpPolicy := testParsePolicy(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	cbpPolicy.Name = "grant"

	mcpPolicy := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["nothing-matches-this"] }
}
`)
	mcpPolicy.Name = "contract"

	withoutMCP, err := NewCBP(testContext(), []*Policy{cbpPolicy})
	require.NoError(t, err)
	withMCP, err := NewCBP(testContext(), []*Policy{cbpPolicy, mcpPolicy})
	require.NoError(t, err)

	req := newMCPRequest(t, "mcp/gateway/",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"anything"},"id":1}`)

	base := withoutMCP.AllowOperation(testContext(), req, nil, false)
	withIndex := withMCP.AllowOperation(testContext(), req, nil, false)

	assert.Equal(t, base.Allowed, withIndex.Allowed)
	assert.Equal(t, base.MCPDecision, withIndex.MCPDecision)
	assert.True(t, base.Allowed, "the capability grant alone still decides in this PR")
}

// TestGetPolicyAnyType_ResolvesBothTypes covers the flat-name resolution that
// lets a token attach a CBP and an MCP policy in one list.
func TestGetPolicyAnyType_ResolvesBothTypes(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	cbpPolicy := testParsePolicy(t, `path "mcp/gateway/*" { capabilities = ["update"] }`)
	cbpPolicy.Name = "grant"
	require.NoError(t, ps.SetPolicy(ctx, cbpPolicy, nil))

	mcpPolicy := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["x"] }
}
`)
	mcpPolicy.Name = "contract"
	require.NoError(t, ps.SetPolicy(ctx, mcpPolicy, nil))

	got, err := ps.getPolicyAnyType(ctx, "grant")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, PolicyTypeCBP, got.Type)

	got, err = ps.getPolicyAnyType(ctx, "contract")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, PolicyTypeMCP, got.Type)

	missing, err := ps.getPolicyAnyType(ctx, "nobody")
	require.NoError(t, err)
	assert.Nil(t, missing, "a dangling name resolves to nothing, as before")
}

// TestGetPolicyAnyType_ResolvesRoot is the regression guard for the trap in
// this resolver: the root policy is synthesized, never stored. A version built
// on direct barrier reads returns nil here, NewCBP never sets a.root, and every
// root token is denied everywhere.
func TestGetPolicyAnyType_ResolvesRoot(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	got, err := ps.getPolicyAnyType(ctx, "root")
	require.NoError(t, err)
	require.NotNil(t, got, "the synthesized root policy must resolve")
	assert.Equal(t, "root", got.Name)
	assert.Equal(t, PolicyTypeCBP, got.Type)

	cbp, err := ps.CBP(ctx, map[string][]string{namespace.RootNamespaceID: {"root"}})
	require.NoError(t, err)
	assert.True(t, cbp.root, "a root token must still get root privileges")

	res := cbp.AllowOperation(ctx, &logical.Request{
		Path:      "any/path/at/all",
		Operation: logical.UpdateOperation,
	}, nil, false)
	assert.True(t, res.Allowed)
	assert.True(t, res.IsRoot)
}

// TestCBP_CompilesAttachedMCPPolicy proves an MCP policy attached by name
// reaches the index through the store, not just through a hand-built CBP.
func TestCBP_CompilesAttachedMCPPolicy(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	cbpPolicy := testParsePolicy(t, `path "mcp/gateway/*" { capabilities = ["update"] }`)
	cbpPolicy.Name = "grant"
	require.NoError(t, ps.SetPolicy(ctx, cbpPolicy, nil))

	mcpPolicy := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["get_repository"] }
}
`)
	mcpPolicy.Name = "contract"
	require.NoError(t, ps.SetPolicy(ctx, mcpPolicy, nil))

	cbp, err := ps.CBP(ctx, map[string][]string{
		namespace.RootNamespaceID: {"grant", "contract"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"get_repository"},
		toolsOf(cbp.mcpRulesForPath("mcp/gateway/call")))
}

// TestCBP_RepeatedCompileDoesNotAccumulate is the regression guard for the
// sharpest hazard in the index: CBP() hands out cached *Policy pointers from
// the LRU, so if the same-key merge appended to a CBPPermissions still owned by
// a cached policy, every compile would grow the rule-sets and corrupt the
// cache. Building the index twice from the same cached policies must be
// idempotent, and the source policies must come back unchanged.
func TestCBP_RepeatedCompileDoesNotAccumulate(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	for i, doc := range []string{
		`
path "mcp/gateway/*" {
  tools { allowed = ["first"] }
}
`,
		`
path "mcp/gateway/*" {
  tools { allowed = ["second"] }
}
`,
	} {
		p := testParseMCPPolicy(t, doc)
		p.Name = fmt.Sprintf("contract-%d", i)
		require.NoError(t, ps.SetPolicy(ctx, p, nil))
	}

	names := map[string][]string{
		namespace.RootNamespaceID: {"contract-0", "contract-1"},
	}

	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	require.Len(t, first.mcpRulesForPath("mcp/gateway/call"), 2)

	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Len(t, second.mcpRulesForPath("mcp/gateway/call"), 2,
		"a second compile over the same cached policies must not accumulate rule-sets")

	// And the cached policies themselves must still hold one rule-set each.
	for _, name := range []string{"contract-0", "contract-1"} {
		cached, err := ps.GetPolicy(ctx, name, PolicyTypeMCP)
		require.NoError(t, err)
		require.Len(t, cached.Paths, 1)
		assert.Len(t, cached.Paths[0].Permissions.MCP, 1,
			"compiling must not mutate the cached policy %q", name)
	}
}

// TestMCPIndex_NamespaceScoped covers the namespace-prefixed path key and the
// child-namespace MCP view, neither of which the root-namespace tests exercise.
func TestMCPIndex_NamespaceScoped(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	rootCtx := testContext()

	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, core.namespaceStore.SetNamespace(rootCtx, child))
	nsCtx := namespace.ContextWithNamespace(context.Background(), child)

	p, err := ParseMCPPolicy(child, `
path "mcp/gateway/*" {
  tools { allowed = ["scoped"] }
}
`)
	require.NoError(t, err)
	p.Name = "ns-contract"
	require.NoError(t, ps.SetPolicy(nsCtx, p, nil))

	// The stanza key carries the namespace path, so it matches only there.
	require.Len(t, p.Paths, 1)
	assert.Equal(t, "team-a/mcp/gateway/", p.Paths[0].Path)

	cbp, err := ps.CBP(nsCtx, map[string][]string{child.ID: {"ns-contract"}})
	require.NoError(t, err)

	assert.Equal(t, []string{"scoped"},
		toolsOf(cbp.mcpRulesForPath("team-a/mcp/gateway/call")))
	assert.Nil(t, cbp.mcpRulesForPath("mcp/gateway/call"),
		"a namespaced contract must not match the unprefixed path")
}

// TestNewCBP_RootWithMCPPolicy pins that an MCP policy alongside root is inert
// rather than fatal. Root bypasses the MCP gate entirely, so counting a
// contract as a competing grant would turn a harmless attachment into a 500 on
// every request the token makes.
func TestNewCBP_RootWithMCPPolicy(t *testing.T) {
	rootPolicy := &Policy{Name: "root", Type: PolicyTypeCBP, namespace: namespace.RootNamespace}

	contract := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  tools { allowed = ["ignored"] }
}
`)
	contract.Name = "contract"

	cbp, err := NewCBP(testContext(), []*Policy{rootPolicy, contract})
	require.NoError(t, err, "an MCP policy must not collide with root")
	assert.True(t, cbp.root)

	// The contract is still indexed; root simply never consults it.
	assert.Equal(t, []string{"ignored"}, toolsOf(cbp.mcpRulesForPath("mcp/gateway/call")))

	res := cbp.AllowOperation(testContext(), &logical.Request{
		Path:      "mcp/gateway/call",
		Operation: logical.UpdateOperation,
	}, nil, false)
	assert.True(t, res.Allowed)
	assert.True(t, res.IsRoot)
}

// TestNewCBP_RootWithAnotherGrantStillRejected proves the exclusivity rule
// still holds for the case it was written for: a second capability policy.
func TestNewCBP_RootWithAnotherGrantStillRejected(t *testing.T) {
	rootPolicy := &Policy{Name: "root", Type: PolicyTypeCBP, namespace: namespace.RootNamespace}

	other := testParsePolicy(t, `path "secret/*" { capabilities = ["read"] }`)
	other.Name = "other"

	_, err := NewCBP(testContext(), []*Policy{rootPolicy, other})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "other policies present along with root")
}

func testPastTime() time.Time {
	return time.Now().Add(-time.Hour)
}
