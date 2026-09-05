// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	// End-to-end: parse an MCP policy, clone the CBPPermissions, mutate the
	// clone, confirm the original is unaffected. This is the discipline the
	// index depends on — it clones before inserting so a compile can never
	// mutate the cached policy it compiled from.
	rules := `
path "mcp/gateway/*" {
  tools { allowed = ["get_*"] }
}
`
	policy, err := ParseMCPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	original := policy.Paths[0].Permissions

	cloned, err := original.Clone()
	require.NoError(t, err)
	require.Len(t, cloned.MCP, 1)

	cloned.MCP[0].AllowedTools[0] = "mutated"

	assert.Equal(t, "get_*", original.MCP[0].AllowedTools[0])
}
