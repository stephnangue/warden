// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
)

func TestPolicyStore_MCPRoundTrip(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	p := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	p.Name = "gw-tools"
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	got, err := ps.GetPolicy(ctx, "gw-tools", PolicyTypeMCP)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, PolicyTypeMCP, got.Type)
	require.Len(t, got.Paths, 1)
	require.Len(t, got.Paths[0].Permissions.MCP, 1)
	assert.Equal(t, []string{"tools/list"}, got.Paths[0].Permissions.MCP[0].AllowedMethods)

	// The CBP view must not see it: the two types live in separate keyspaces.
	cbpGot, err := ps.GetPolicy(ctx, "gw-tools", PolicyTypeCBP)
	require.NoError(t, err)
	assert.Nil(t, cbpGot)

	names, err := ps.ListPolicies(ctx, PolicyTypeMCP, false)
	require.NoError(t, err)
	assert.Contains(t, names, "gw-tools")

	cbpNames, err := ps.ListPolicies(ctx, PolicyTypeCBP, false)
	require.NoError(t, err)
	assert.NotContains(t, cbpNames, "gw-tools")

	require.NoError(t, ps.DeletePolicy(ctx, "gw-tools", PolicyTypeMCP))
	gone, err := ps.GetPolicy(ctx, "gw-tools", PolicyTypeMCP)
	require.NoError(t, err)
	assert.Nil(t, gone)
}

// TestPolicyStore_CrossTypeNameUniqueness pins the guard that keeps a flat
// token policy list unambiguous: one name can only ever resolve to one policy.
func TestPolicyStore_CrossTypeNameUniqueness(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	cbp := testParsePolicy(t, `path "mcp/gateway/*" { capabilities = ["update"] }`)
	cbp.Name = "shared-name"
	require.NoError(t, ps.SetPolicy(ctx, cbp, nil))

	mcp := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	mcp.Name = "shared-name"
	err := ps.SetPolicy(ctx, mcp, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already in use by a cbp policy")

	// And the same in the other direction.
	other := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	other.Name = "mcp-only"
	require.NoError(t, ps.SetPolicy(ctx, other, nil))

	clash := testParsePolicy(t, `path "mcp/gateway/*" { capabilities = ["update"] }`)
	clash.Name = "mcp-only"
	err = ps.SetPolicy(ctx, clash, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already in use by a mcp policy")
}

// TestPolicyStore_UpdateOwnTypeStillWorks proves the uniqueness guard checks
// the *other* view only — overwriting a policy with itself must not trip it.
func TestPolicyStore_UpdateOwnTypeStillWorks(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	p := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	p.Name = "gw-tools"
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	updated := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/call"] }
}
`)
	updated.Name = "gw-tools"
	require.NoError(t, ps.SetPolicy(ctx, updated, nil))

	got, err := ps.GetPolicy(ctx, "gw-tools", PolicyTypeMCP)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{"tools/call"}, got.Paths[0].Permissions.MCP[0].AllowedMethods)
}

// TestPolicyStore_UnknownTypeErrors covers the delete path that previously
// reported success while deleting nothing.
func TestPolicyStore_UnknownTypeErrors(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	unknown := PolicyType(99)

	require.Error(t, ps.DeletePolicy(ctx, "whatever", unknown))

	_, err := ps.GetPolicy(ctx, "whatever", unknown)
	require.Error(t, err)

	_, err = ps.ListPolicies(ctx, unknown, false)
	require.Error(t, err)

	// Writing an unrouted type must fail rather than land in the CBP view,
	// which is what getBarrierView returning nil used to allow.
	stray := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	stray.Name = "stray"
	stray.Type = unknown
	require.Error(t, ps.SetPolicy(ctx, stray, nil))
}

// TestPolicyStore_CacheKeySeparatesTypes proves two policies of different types
// cannot collide in the shared LRU.
func TestPolicyStore_CacheKeySeparatesTypes(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore

	cbpKey := ps.cacheKey(namespace.RootNamespace, "same", PolicyTypeCBP)
	mcpKey := ps.cacheKey(namespace.RootNamespace, "same", PolicyTypeMCP)
	assert.NotEqual(t, cbpKey, mcpKey)

	// The namespace UUID stays the leading segment so invalidateNamespace's
	// prefix sweep keeps clearing every type at once.
	assert.Contains(t, cbpKey, namespace.RootNamespace.UUID)
	assert.Contains(t, mcpKey, namespace.RootNamespace.UUID)
}

// TestClearNamespaceResources_ClearsBothPolicyTypes guards against MCP policies
// being orphaned in storage. The deletion job clears resources type by type and
// never wipes the namespace barrier prefix wholesale, so a policy type missing
// from that sweep survives its namespace forever.
func TestClearNamespaceResources_ClearsBothPolicyTypes(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := testContext()

	target := &namespace.Namespace{Path: "sweep-test/"}
	require.NoError(t, core.namespaceStore.SetNamespace(ctx, target))
	nsCtx := namespace.ContextWithNamespace(context.Background(), target)

	cbp, err := ParseCBPPolicy(target, `path "mcp/gateway/*" { capabilities = ["update"] }`)
	require.NoError(t, err)
	cbp.Name = "ns-gw-access"
	require.NoError(t, ps.SetPolicy(nsCtx, cbp, nil))

	mcp, err := ParseMCPPolicy(target, `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`)
	require.NoError(t, err)
	mcp.Name = "ns-gw-tools"
	require.NoError(t, ps.SetPolicy(nsCtx, mcp, nil))

	mcpNames, err := ps.ListPolicies(nsCtx, PolicyTypeMCP, false)
	require.NoError(t, err)
	require.Contains(t, mcpNames, "ns-gw-tools")

	// Drive the production sweep, not a local reimplementation of it.
	require.NoError(t, core.namespaceStore.clearNamespaceResources(nsCtx, target))

	remainingMCP, err := ps.ListPolicies(nsCtx, PolicyTypeMCP, false)
	require.NoError(t, err)
	assert.Empty(t, remainingMCP, "MCP policies must not outlive their namespace")

	remainingCBP, err := ps.ListPolicies(nsCtx, PolicyTypeCBP, false)
	require.NoError(t, err)
	assert.Empty(t, remainingCBP, "CBP policies are still swept, as before")
}
