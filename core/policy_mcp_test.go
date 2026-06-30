// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMCP_AllFields(t *testing.T) {
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods   = ["tools/list", "tools/call"]
    denied_methods    = ["tools/dangerous"]
    allowed_tools     = ["get_repository", "list_issues"]
    denied_tools      = ["delete_*", "force_*"]
    allowed_resources = ["github://repo/*"]
    denied_resources  = ["github://secrets/*"]
    allowed_prompts   = ["*"]
    denied_prompts    = ["sudo_*"]
  }
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	require.Len(t, policy.Paths, 1)

	mcp := policy.Paths[0].Permissions.MCP
	require.Len(t, mcp, 1, "one stanza must produce one MCP rule-set")
	r := mcp[0]

	assert.Equal(t, []string{"tools/list", "tools/call"}, r.AllowedMethods)
	assert.Equal(t, []string{"tools/dangerous"}, r.DeniedMethods)
	assert.Equal(t, []string{"get_repository", "list_issues"}, r.AllowedTools)
	assert.Equal(t, []string{"delete_*", "force_*"}, r.DeniedTools)
	assert.Equal(t, []string{"github://repo/*"}, r.AllowedResources)
	assert.Equal(t, []string{"github://secrets/*"}, r.DeniedResources)
	assert.Equal(t, []string{"*"}, r.AllowedPrompts)
	assert.Equal(t, []string{"sudo_*"}, r.DeniedPrompts)
}

func TestParseMCP_EmptyBlock(t *testing.T) {
	// An empty mcp { } block is the minimum opt-in: produces a
	// non-nil rule-set with all empty fields. AllowOperation uses
	// presence to trigger the missing-header check; emptiness means
	// "no further restriction."
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {}
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	require.Len(t, policy.Paths, 1)

	mcp := policy.Paths[0].Permissions.MCP
	require.Len(t, mcp, 1, "empty block must still produce a rule-set entry")
	r := mcp[0]

	assert.Nil(t, r.AllowedMethods)
	assert.Nil(t, r.DeniedMethods)
	assert.Nil(t, r.AllowedTools)
	assert.Nil(t, r.DeniedTools)
	assert.Nil(t, r.AllowedResources)
	assert.Nil(t, r.DeniedResources)
	assert.Nil(t, r.AllowedPrompts)
	assert.Nil(t, r.DeniedPrompts)
}

func TestParseMCP_NoBlock(t *testing.T) {
	// A path stanza without an mcp { } block leaves Permissions.MCP
	// nil — every existing non-MCP policy keeps working unchanged.
	rules := `
path "secret/*" {
  capabilities = ["read"]
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	require.Len(t, policy.Paths, 1)
	assert.Nil(t, policy.Paths[0].Permissions.MCP)
}

func TestParseMCP_Lowercasing(t *testing.T) {
	// Operator-supplied mixed-case patterns are canonicalised at parse
	// time so AllowOperation can do case-insensitive matching via plain
	// string equality.
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["TOOLS/Call", "Tools/LIST"]
    denied_tools    = ["Delete_*", "FORCE_*"]
  }
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	r := policy.Paths[0].Permissions.MCP[0]

	assert.Equal(t, []string{"tools/call", "tools/list"}, r.AllowedMethods)
	assert.Equal(t, []string{"delete_*", "force_*"}, r.DeniedTools)
}

func TestParseMCP_LeadingStarRejected(t *testing.T) {
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_tools = ["*_admin"]
  }
}
`
	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied_tools")
	assert.Contains(t, err.Error(), "*_admin")
	assert.Contains(t, err.Error(), "trailing")
}

func TestParseMCP_InternalStarRejected(t *testing.T) {
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_tools = ["get_*_admin"]
  }
}
`
	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_tools")
	assert.Contains(t, err.Error(), "get_*_admin")
}

func TestParseMCP_TrailingStarAccepted(t *testing.T) {
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    denied_tools = ["delete_*"]
  }
}
`
	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
}

func TestParseMCP_BareStarAccepted(t *testing.T) {
	// The bare `*` is a zero-prefix trailing-star and matches
	// everything. Used to express "any value" without enumerating.
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_prompts = ["*"]
  }
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	assert.Equal(t, []string{"*"}, policy.Paths[0].Permissions.MCP[0].AllowedPrompts)
}

func TestParseMCP_ParamsRejected(t *testing.T) {
	// The removed allowed_params/denied_params are rejected at parse time
	// with a directed error pointing at the CEL call.args equivalent.
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_params = {
      path = ["docs/*"]
    }
  }
}
`
	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_params/denied_params have been removed")
	assert.Contains(t, err.Error(), "call.args")
}

func TestParseMCP_MultipleStanzasSamePath(t *testing.T) {
	// Two `path` stanzas at the same path in one policy each become
	// their own PathRules, each with its own one-entry MCP slice. The
	// OR-of-rule-sets merge into a single CBPPermissions.MCP slice
	// happens at NewCBP time alongside the evaluation logic.
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["resources/read"]
    allowed_resources = ["github://repo/A/*"]
  }
}

path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["resources/list"]
  }
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	require.Len(t, policy.Paths, 2)

	require.Len(t, policy.Paths[0].Permissions.MCP, 1)
	require.Len(t, policy.Paths[1].Permissions.MCP, 1)
	assert.Equal(t, []string{"resources/read"}, policy.Paths[0].Permissions.MCP[0].AllowedMethods)
	assert.Equal(t, []string{"resources/list"}, policy.Paths[1].Permissions.MCP[0].AllowedMethods)
}

func TestCBPMCPRules_Clone_Nil(t *testing.T) {
	var r *CBPMCPRules
	assert.Nil(t, r.Clone())
}

func TestCBPMCPRules_Clone_DeepCopy(t *testing.T) {
	original := &CBPMCPRules{
		AllowedMethods:   []string{"tools/call"},
		DeniedTools:      []string{"delete_*"},
		AllowedResources: []string{"github://repo/A/*"},
		DeniedResources:  []string{"github://repo/A/secrets/*"},
		DeniedPrompts:    []string{"sudo_*"},
	}
	clone := original.Clone()
	require.NotNil(t, clone)
	assert.Equal(t, original, clone)

	// Mutating the clone's slices must not affect the original.
	clone.AllowedMethods[0] = "mutated"
	clone.DeniedResources[0] = "mutated"
	clone.DeniedPrompts[0] = "mutated"

	assert.Equal(t, "tools/call", original.AllowedMethods[0])
	assert.Equal(t, "github://repo/A/secrets/*", original.DeniedResources[0])
	assert.Equal(t, "sudo_*", original.DeniedPrompts[0])
}

func TestCBPPermissions_Clone_MCPDeepCopy(t *testing.T) {
	// End-to-end: parse a policy with an mcp block, clone the
	// CBPPermissions, mutate the clone, confirm the original is
	// unaffected.
	rules := `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_tools = ["get_*"]
  }
}
`
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	original := policy.Paths[0].Permissions

	cloned, err := original.Clone()
	require.NoError(t, err)
	require.Len(t, cloned.MCP, 1)

	cloned.MCP[0].AllowedTools[0] = "mutated"

	assert.Equal(t, "get_*", original.MCP[0].AllowedTools[0])
}
