// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
)

// testParseMCPPolicy parses an MCP policy document for testing.
func testParseMCPPolicy(t testing.TB, rules string) *Policy {
	t.Helper()
	policy, err := ParseMCPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	return policy
}

func TestParseMCPPolicy_AllFields(t *testing.T) {
	p := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
    methods {
      allowed = ["tools/list", "tools/call"]
      denied  = ["tools/dangerous"]
    }

    tools {
      allowed = ["get_repository", "list_issues"]
      denied  = ["delete_*"]
    }

    resources {
      allowed = ["github://repo/*"]
      denied  = ["github://secrets/*"]
    }

    prompts {
      allowed = ["*"]
      denied  = ["sudo_*"]
    }

    condition = "call.args.?env.orValue('') != 'prod'"
}
`)

	assert.Equal(t, PolicyTypeMCP, p.Type)
	require.Len(t, p.Paths, 1)

	pr := p.Paths[0]
	assert.Equal(t, "mcp/gateway/", pr.Path)
	assert.True(t, pr.IsPrefix)
	assert.False(t, pr.HasSegmentWildcards)

	// An MCP stanza grants nothing: the capability bitmap stays zero.
	assert.Zero(t, pr.Permissions.CapabilitiesBitmap)
	assert.Empty(t, pr.Permissions.Conditions, "path-level conditions are a CBP concept")

	require.Len(t, pr.Permissions.MCP, 1)
	set := pr.Permissions.MCP[0]
	assert.Equal(t, []string{"tools/list", "tools/call"}, set.AllowedMethods)
	assert.Equal(t, []string{"tools/dangerous"}, set.DeniedMethods)
	assert.Equal(t, []string{"get_repository", "list_issues"}, set.AllowedTools)
	assert.Equal(t, []string{"delete_*"}, set.DeniedTools)
	assert.Equal(t, []string{"github://repo/*"}, set.AllowedResources)
	assert.Equal(t, []string{"github://secrets/*"}, set.DeniedResources)
	assert.Equal(t, []string{"*"}, set.AllowedPrompts)
	assert.Equal(t, []string{"sudo_*"}, set.DeniedPrompts)
	require.NotNil(t, set.Condition, "the per-call condition compiles against the MCP env")
}

func TestParseMCPPolicy_LowercasesEntries(t *testing.T) {
	p := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
    methods { allowed = ["Tools/CALL"] }
    tools   { allowed = ["Get_Repository"] }
}
`)
	set := p.Paths[0].Permissions.MCP[0]
	assert.Equal(t, []string{"tools/call"}, set.AllowedMethods)
	assert.Equal(t, []string{"get_repository"}, set.AllowedTools)
}

func TestParseMCPPolicy_EmptyStanzaIsValid(t *testing.T) {
	// An empty stanza is a deliberate lock-down: with no allow lists, the
	// shipped deny-by-default gates refuse every non-lifecycle call.
	p := testParseMCPPolicy(t, `path "mcp/gateway/*" {}`)
	require.Len(t, p.Paths, 1)
	require.Len(t, p.Paths[0].Permissions.MCP, 1)
	assert.Empty(t, p.Paths[0].Permissions.MCP[0].AllowedMethods)
}

// TestParseMCPPolicy_EmptyBlockMatchesOmittedBlock pins that writing a family
// block with nothing in it says the same thing as leaving it out: both leave
// the family's lists nil, which denies everything in that family.
func TestParseMCPPolicy_EmptyBlockMatchesOmittedBlock(t *testing.T) {
	withEmpty := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
    methods { allowed = ["tools/list"] }
    tools {}
}
`)
	omitted := testParseMCPPolicy(t, `
path "mcp/gateway/*" {
    methods { allowed = ["tools/list"] }
}
`)
	assert.Equal(t,
		omitted.Paths[0].Permissions.MCP[0],
		withEmpty.Paths[0].Permissions.MCP[0])
}

func TestParseMCPPolicy_RejectsCBPKeys(t *testing.T) {
	for _, key := range []string{
		`capabilities = ["update"]`,
		`pagination_limit = 10`,
		`allowed_params = { region = ["eu-west-1"] }`,
	} {
		_, err := ParseMCPPolicy(namespace.RootNamespace,
			fmt.Sprintf("path \"mcp/gateway/*\" {\n  %s\n}\n", key))
		require.Error(t, err, "MCP policies must reject the CBP key %q", key)
	}
}

// TestParseMCPPolicy_RejectsMisspelledFamilyKey is the reason this grammar is
// parsed with HCL v2. A typo in `denied` would leave the deny list empty and
// silently widen the policy; the v1 decoder ignores unknown keys, so the
// mistake would never surface.
func TestParseMCPPolicy_RejectsMisspelledFamilyKey(t *testing.T) {
	_, err := ParseMCPPolicy(namespace.RootNamespace, `
path "mcp/gateway/*" {
    tools {
      allowed = ["get_repository"]
      deined  = ["delete_repository"]
    }
}
`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deined", "the diagnostic must name the offending key")
}

func TestParseMCPPolicy_RejectsUnknownFamilyBlock(t *testing.T) {
	_, err := ParseMCPPolicy(namespace.RootNamespace, `
path "mcp/gateway/*" {
    toolz { allowed = ["get_repository"] }
}
`)
	require.Error(t, err)
}

// TestParseMCPPolicy_RejectsDuplicateFamilyBlock pins the other v2 property:
// a repeated block is an error rather than a silent field-wise merge, so an
// operator cannot lose half a rule set without being told.
func TestParseMCPPolicy_RejectsDuplicateFamilyBlock(t *testing.T) {
	_, err := ParseMCPPolicy(namespace.RootNamespace, `
path "mcp/gateway/*" {
    tools { denied = ["alpha"] }
    tools { denied = ["beta"] }
}
`)
	require.Error(t, err)
}

func TestParseMCPPolicy_RejectsBadPatterns(t *testing.T) {
	// Leading and internal wildcards are rejected; only a trailing * is a glob.
	for _, pattern := range []string{`"*_repo"`, `"get_*_repo"`} {
		_, err := ParseMCPPolicy(namespace.RootNamespace,
			fmt.Sprintf("path \"mcp/gateway/*\" {\n  tools { allowed = [%s] }\n}\n", pattern))
		require.Error(t, err, "pattern %s must be rejected", pattern)
	}
}

// TestParseMCPPolicy_JSONDocument covers the "HCL or JSON format" contract the
// policy API advertises, which the v2 parser serves from its own json package.
func TestParseMCPPolicy_JSONDocument(t *testing.T) {
	p := testParseMCPPolicy(t, `{
  "path": {
    "mcp/gateway/*": {
      "methods": { "allowed": ["tools/list"] },
      "tools":   { "allowed": ["get_repository"] }
    }
  }
}`)
	require.Len(t, p.Paths, 1)
	set := p.Paths[0].Permissions.MCP[0]
	assert.Equal(t, []string{"tools/list"}, set.AllowedMethods)
	assert.Equal(t, []string{"get_repository"}, set.AllowedTools)
}

// TestParseMCPPolicy_JSONRejectsMisspelledKey pins that the strictness which
// justifies the v2 parser survives the JSON path too — a document submitted as
// JSON must not be able to smuggle in a silently-ignored `deined`.
func TestParseMCPPolicy_JSONRejectsMisspelledKey(t *testing.T) {
	_, err := ParseMCPPolicy(namespace.RootNamespace, `{
  "path": {
    "mcp/gateway/*": {
      "tools": { "allowed": ["get_repository"], "deined": ["delete_repository"] }
    }
  }
}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deined")
}

func TestParseMCPPolicy_ExpiredStanzaSkipped(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p := testParseMCPPolicy(t, fmt.Sprintf(`
path "mcp/gateway/*" {
    expiration = %q
    methods { allowed = ["tools/list"] }
}
`, past))
	// Dropped at parse, mechanically as in CBP. The direction differs though:
	// this removes a restriction rather than a grant, so a lapsed contract is
	// only safe once absence of a matching stanza denies MCP-shaped requests.
	assert.Empty(t, p.Paths, "an expired stanza is dropped at parse")
}

func TestParseMCPPolicy_FutureExpirationKept(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	p := testParseMCPPolicy(t, fmt.Sprintf(`
path "mcp/gateway/*" {
    expiration = %q
    methods { allowed = ["tools/list"] }
}
`, future))
	require.Len(t, p.Paths, 1)
	assert.False(t, p.Paths[0].Expiration.IsZero())
}

// TestPathNormalizationParity is the guard against the two policy indexes
// disagreeing on a path key. A divergence here would make MCP stanzas silently
// miss the requests they were written for, so both parsers must agree exactly.
func TestPathNormalizationParity(t *testing.T) {
	for _, key := range []string{
		"mcp/gateway/*",
		"/mcp/gateway/*",
		"mcp/gateway",
		"mcp/role/+/gateway*",
		"+/gateway",
	} {
		t.Run(key, func(t *testing.T) {
			cbp := testParsePolicy(t, fmt.Sprintf("path %q {\n  capabilities = [\"update\"]\n}\n", key))
			mcp := testParseMCPPolicy(t, fmt.Sprintf("path %q {\n  methods { allowed = [\"tools/list\"] }\n}\n", key))

			require.Len(t, cbp.Paths, 1)
			require.Len(t, mcp.Paths, 1)
			assert.Equal(t, cbp.Paths[0].Path, mcp.Paths[0].Path)
			assert.Equal(t, cbp.Paths[0].IsPrefix, mcp.Paths[0].IsPrefix)
			assert.Equal(t, cbp.Paths[0].HasSegmentWildcards, mcp.Paths[0].HasSegmentWildcards)
		})
	}
}

func TestPathNormalizationParity_RejectsSameBadWildcard(t *testing.T) {
	_, cbpErr := ParseCBPPolicy(namespace.RootNamespace, `path "mcp/+*" { capabilities = ["update"] }`)
	_, mcpErr := ParseMCPPolicy(namespace.RootNamespace, "path \"mcp/+*\" {\n  methods { allowed = [\"tools/list\"] }\n}\n")
	require.Error(t, cbpErr)
	require.Error(t, mcpErr)
}
