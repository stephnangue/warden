// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"strings"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// putRawPolicy writes a policy entry straight to storage, as a release before
// the reserved names could have left it, bypassing every write-time check.
func putRawPolicy(t *testing.T, c *Core, ns *namespace.Namespace, name string, policyType PolicyType, raw string) {
	t.Helper()
	entry, err := sdklogical.StorageEntryJSON(name, &PolicyEntry{Version: 2, DataVersion: 1, Raw: raw, Type: policyType})
	require.NoError(t, err)
	require.NoError(t, c.policyStore.getBarrierView(ns, policyType).Put(context.Background(), entry))
}

// testMCPBody is an MCP policy allowing one tool on path. Nested blocks need
// lines of their own.
func testMCPBody(path, tool string) string {
	return `path "` + path + `" {
  tools {
    allowed = ["` + tool + `"]
  }
}
`
}

func mustParseMCP(t *testing.T, ns *namespace.Namespace, raw string) *Policy {
	t.Helper()
	p, err := ParseMCPPolicy(ns, raw)
	require.NoError(t, err)
	return p
}

// The built-ins are seeded with bodies that parse, and seeding again never
// overwrites an operator's edit, an emptied body included.
func TestBuiltinPolicies_SeededAndNeverOverwritten(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	cbp, err := c.policyStore.GetPolicy(ctx, builtinCBPPolicy, PolicyTypeCBP)
	require.NoError(t, err)
	require.NotNil(t, cbp)
	assert.Equal(t, builtinCBPBody, cbp.Raw)
	mcp, err := c.policyStore.GetPolicy(ctx, builtinMCPPolicy, PolicyTypeMCP)
	require.NoError(t, err)
	require.NotNil(t, mcp)
	assert.Equal(t, builtinMCPBody, mcp.Raw)

	edited := testParsePolicy(t, `path "sys/introspect/roles" { capabilities = ["read"] }`)
	edited.Name, edited.Type = builtinCBPPolicy, PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, edited, nil))

	require.NoError(t, c.seedNamespacePolicies(ctx))
	got, err := c.policyStore.GetPolicy(ctx, builtinCBPPolicy, PolicyTypeCBP)
	require.NoError(t, err)
	assert.Equal(t, edited.Raw, got.Raw, "reseeding kept the edit")
}

// A namespace gets its own built-ins when it is created.
func TestBuiltinPolicies_SeededInNewNamespace(t *testing.T) {
	c := createTestCore(t)
	ns := &namespace.Namespace{Path: "team-data/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), ns))
	nsCtx := namespace.ContextWithNamespace(context.Background(), ns)

	for _, b := range builtinPolicies {
		p, err := c.policyStore.GetPolicy(nsCtx, b.name, b.policyType)
		require.NoError(t, err)
		require.NotNil(t, p, b.name)
	}
}

// "default" and every "default-" name are reserved in both types; only the
// built-in of the matching type may be written.
func TestReservedPolicyNames(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	cbpBody := `path "secret/*" { capabilities = ["read"] }`
	mcpBody := testMCPBody("mcp/gateway", "x")

	cases := []struct {
		name       string
		policyType PolicyType
		allowed    bool
	}{
		{"default", PolicyTypeCBP, false},
		{"default", PolicyTypeMCP, false},
		{"default-admins", PolicyTypeCBP, false},
		{"Default-Admins", PolicyTypeCBP, false}, // canonicalised, then reserved
		{"default-a2a", PolicyTypeMCP, false},
		{builtinCBPPolicy, PolicyTypeMCP, false},
		{builtinMCPPolicy, PolicyTypeCBP, false},
		{builtinCBPPolicy, PolicyTypeCBP, true},
		{builtinMCPPolicy, PolicyTypeMCP, true},
		{"default_x", PolicyTypeCBP, true},
		{"default.x", PolicyTypeCBP, true},
		{"defaults", PolicyTypeCBP, true},
	}
	for _, tc := range cases {
		t.Run(tc.policyType.String()+"/"+tc.name, func(t *testing.T) {
			var p *Policy
			if tc.policyType == PolicyTypeMCP {
				p = mustParseMCP(t, namespace.RootNamespace, mcpBody)
			} else {
				p = testParsePolicy(t, cbpBody)
			}
			p.Name, p.Type = tc.name, tc.policyType
			err := c.policyStore.SetPolicy(ctx, p, nil)
			if tc.allowed {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if tc.name == builtinCBPPolicy || tc.name == builtinMCPPolicy {
				// The other type holds the name already.
				return
			}
			assert.ErrorIs(t, err, errReservedPolicyName)
		})
	}
}

// The built-ins cannot be deleted, except by a forced delete (namespace
// deletion); a policy left under another reserved name can, to clean it up.
func TestBuiltinPolicies_Delete(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	for _, b := range builtinPolicies {
		err := c.policyStore.DeletePolicy(ctx, b.name, b.policyType)
		require.Error(t, err, b.name)
		assert.Contains(t, err.Error(), "edit it instead")
	}

	putRawPolicy(t, c, namespace.RootNamespace, "default", PolicyTypeCBP, `path "secret/*" { capabilities = ["read"] }`)
	require.NoError(t, c.policyStore.DeletePolicy(ctx, "default", PolicyTypeCBP))
	p, err := c.policyStore.GetPolicy(ctx, "default", PolicyTypeCBP)
	require.NoError(t, err)
	assert.Nil(t, p)

	require.NoError(t, c.policyStore.deletePolicyForce(ctx, builtinCBPPolicy, PolicyTypeCBP))
}

// A built-in whose name a policy of the other type already holds is not
// seeded, and seeding does not fail.
func TestBuiltinPolicies_SeedConflict(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	require.NoError(t, c.policyStore.deletePolicyForce(ctx, builtinCBPPolicy, PolicyTypeCBP))
	putRawPolicy(t, c, namespace.RootNamespace, builtinCBPPolicy, PolicyTypeMCP, testMCPBody("mcp/gateway", "x"))

	require.NoError(t, c.seedNamespacePolicies(ctx))
	p, err := c.policyStore.GetPolicy(ctx, builtinCBPPolicy, PolicyTypeCBP)
	require.NoError(t, err)
	assert.Nil(t, p, "not seeded over the conflict")

	got, err := c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, builtinMCPPolicy, got[0].Name)
}

// A missing built-in is remembered as missing, and forgotten once it is
// written again.
func TestBuiltinPolicies_MissingIsRememberedUntilWritten(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	require.NoError(t, c.policyStore.deletePolicyForce(ctx, builtinCBPPolicy, PolicyTypeCBP))

	got, err := c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	key := c.policyStore.cacheKey(namespace.RootNamespace, builtinCBPPolicy, PolicyTypeCBP)
	seen, ok := c.policyStore.missingBuiltins.Load(key)
	require.True(t, ok)
	assert.Equal(t, c.policyStore.builtinGen.Load(), seen.(uint64))

	require.NoError(t, c.seedNamespacePolicies(ctx))
	got, err = c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, got, 2, "the reseeded built-in is attached again")
}

// buildCBP attaches the built-ins to every request that is not a root
// request, never twice, and never pulls in a legacy reserved-space policy.
// The built-ins change no decision outside the discovery paths.
func TestBuildCBP_AttachesBuiltins(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	p := testParsePolicy(t, `path "secret/*" { capabilities = ["read"] }`)
	p.Name, p.Type = "reader", PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, p, nil))
	putRawPolicy(t, c, namespace.RootNamespace, "default", PolicyTypeCBP, `path "kv/*" { capabilities = ["read"] }`)

	te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{"reader"}}
	cbp, err := c.buildCBP(ctx, te)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"create", "read", "delete"}, cbp.Capabilities(ctx, "sys/mcp"))
	assert.Equal(t, []string{"read"}, cbp.Capabilities(ctx, "sys/introspect/roles"))
	assert.Equal(t, []string{"read"}, cbp.Capabilities(ctx, "secret/x"))
	assert.Len(t, cbp.mcpRulesForPath("sys/mcp"), 1)
	assert.Empty(t, cbp.mcpRulesForPath("mcp/gateway"), "no MCP contract leaks onto a provider path")
	assert.Equal(t, []string{"deny"}, cbp.Capabilities(ctx, "sys/mcpx"), "an exact key is no prefix")

	t.Run("reserved names on the token", func(t *testing.T) {
		shared := []string{"reader", "default", builtinCBPPolicy, builtinMCPPolicy}
		te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: shared}
		cbp, err := c.buildCBP(ctx, te)
		require.NoError(t, err)
		assert.Equal(t, []string{"deny"}, cbp.Capabilities(ctx, "kv/x"), "legacy default is given to no request")
		assert.Len(t, cbp.mcpRulesForPath("sys/mcp"), 1, "a built-in is attached once")
		assert.Equal(t, []string{"reader", "default", builtinCBPPolicy, builtinMCPPolicy}, shared, "token slice untouched")
	})

	t.Run("root", func(t *testing.T) {
		te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{"root"}}
		cbp, err := c.buildCBP(ctx, te)
		require.NoError(t, err)
		assert.Equal(t, []string{"root"}, cbp.Capabilities(ctx, "sys/mcp"))
	})
}

// A role is stored without reserved names, with a warning for each.
func TestRoleWrite_DropsReservedPolicyNames(t *testing.T) {
	c := createTestCore(t)
	role := &logical.Role{Name: "deploy", Policies: []string{"deploy", builtinCBPPolicy, "default"}}
	warnings, err := c.roleStore.Create(rootCtx(), role)
	require.NoError(t, err)
	assert.Equal(t, []string{"deploy"}, role.Policies)

	var reserved int
	for _, w := range warnings {
		if strings.Contains(w, "attached to every request already") || strings.Contains(w, "reserved for built-in policies") {
			reserved++
		}
	}
	assert.Equal(t, 2, reserved, "%v", warnings)
}

// BenchmarkBuildCBP_Builtins measures what the built-ins add to every
// request's CBP: two cached lookups and two small stanzas. "missing" is the
// floor, with the built-ins absent and remembered as such.
func BenchmarkBuildCBP_Builtins(b *testing.B) {
	for _, missing := range []bool{false, true} {
		name := "with-builtins"
		if missing {
			name = "builtins-missing"
		}
		b.Run(name, func(b *testing.B) {
			c := createTestCore(b)
			ctx := rootCtx()
			p, err := ParseCBPPolicy(namespace.RootNamespace, `path "prov/role/+/gateway*" { capabilities = ["read", "create"] }`)
			if err != nil {
				b.Fatal(err)
			}
			p.Name, p.Type = "reader", PolicyTypeCBP
			if err := c.policyStore.SetPolicy(ctx, p, nil); err != nil {
				b.Fatal(err)
			}
			if missing {
				for _, bp := range builtinPolicies {
					if err := c.policyStore.deletePolicyForce(ctx, bp.name, bp.policyType); err != nil {
						b.Fatal(err)
					}
				}
			}
			te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{"reader"}}
			if _, err := c.buildCBP(ctx, te); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.buildCBP(ctx, te); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The write-time warnings: a built-in reaching beyond the discovery paths,
// and another policy trying to narrow discovery with a condition or an MCP
// contract the merge would erase.
func TestBuiltinPolicyWarnings(t *testing.T) {
	ns := &namespace.Namespace{ID: "ns1", Path: "ns1/"}
	parseCBP := func(raw string) *Policy {
		p, err := ParseCBPPolicy(ns, raw)
		require.NoError(t, err)
		return p
	}

	widened := parseCBP(`path "sys/mcp" { capabilities = ["create"] }
		path "secret/*" { capabilities = ["read"] }`)
	widened.Name, widened.Type = builtinCBPPolicy, PolicyTypeCBP
	w := builtinPolicyWarnings(widened)
	require.Len(t, w, 1)
	assert.Contains(t, w[0], `"secret/*"`)

	plain := parseCBP(`path "sys/mcp" { capabilities = ["create"] }`)
	plain.Name, plain.Type = "ops", PolicyTypeCBP
	assert.Empty(t, builtinPolicyWarnings(plain))

	conditional := parseCBP(`path "sys/mcp" {
		capabilities = ["create"]
		condition    = "true"
	}`)
	conditional.Name, conditional.Type = "ops", PolicyTypeCBP
	assert.Len(t, builtinPolicyWarnings(conditional), 1)

	contract := mustParseMCP(t, ns, testMCPBody("sys/mcp", "list_roles"))
	contract.Name, contract.Type = "ops-mcp", PolicyTypeMCP
	assert.Len(t, builtinPolicyWarnings(contract), 1)

	elsewhere := mustParseMCP(t, ns, testMCPBody("mcp/gateway", "x"))
	elsewhere.Name, elsewhere.Type = "ops-mcp", PolicyTypeMCP
	assert.Empty(t, builtinPolicyWarnings(elsewhere))
}
