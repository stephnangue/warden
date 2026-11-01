// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"fmt"
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
	require.Len(t, got, 2)
	assert.Equal(t, builtinMCPPolicy, got[0].Name)
	assert.Equal(t, builtinSponsorPolicy, got[1].Name)
}

// A missing built-in is remembered as missing, and forgotten once it is
// written again.
func TestBuiltinPolicies_MissingIsRememberedUntilWritten(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	require.NoError(t, c.policyStore.deletePolicyForce(ctx, builtinCBPPolicy, PolicyTypeCBP))

	got, err := c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	require.Len(t, got, 2)
	key := c.policyStore.cacheKey(namespace.RootNamespace, builtinCBPPolicy, PolicyTypeCBP)
	seen, ok := c.policyStore.missingBuiltins.Load(key)
	require.True(t, ok)
	assert.Equal(t, c.policyStore.builtinGen.Load(), seen.(uint64))

	require.NoError(t, c.seedNamespacePolicies(ctx))
	got, err = c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, got, 3, "the reseeded built-in is attached again")
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
	cbp, err := c.buildCBP(ctx, te, true)
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
		cbp, err := c.buildCBP(ctx, te, true)
		require.NoError(t, err)
		assert.Equal(t, []string{"deny"}, cbp.Capabilities(ctx, "kv/x"), "legacy default is given to no request")
		assert.Len(t, cbp.mcpRulesForPath("sys/mcp"), 1, "a built-in is attached once")
		assert.Equal(t, []string{"reader", "default", builtinCBPPolicy, builtinMCPPolicy}, shared, "token slice untouched")
	})

	t.Run("root", func(t *testing.T) {
		for _, name := range []string{"root", "Root", " root "} {
			te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{name}}
			cbp, err := c.buildCBP(ctx, te, true)
			require.NoError(t, err, "%q is root by its canonical name", name)
			assert.Equal(t, []string{"root"}, cbp.Capabilities(ctx, "sys/mcp"))
		}
	})
}

// A refused role grant keeps no policy, the built-ins included, so the CBP
// refuses it even on the paths the built-ins grant to everyone else.
func TestBuildCBP_RefusedGrantGetsNoBuiltins(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	// An admission token presented explicitly is refused its grant.
	te := &logical.TokenEntry{
		ID:            "wdi_explicit",
		Type:          TypeIdentityToken,
		NamespaceID:   namespace.RootNamespaceID,
		MountAccessor: "auth_jwt_x",
	}
	req := &logical.Request{Path: "sys/mcp", Operation: logical.CreateOperation, ClientToken: te.ID}
	req.SetTokenEntry(te)

	cbp, got, err := c.fetchCBPAndTokenEntry(ctx, req, false)
	require.NoError(t, err)
	require.NotNil(t, req.RoleGrant())
	require.False(t, req.RoleGrant().Granted())
	assert.Empty(t, got.Policies)
	assert.Equal(t, []string{"deny"}, cbp.Capabilities(ctx, "sys/mcp"), "no built-in authorizes a refused grant")
	assert.Equal(t, []string{"deny"}, cbp.Capabilities(ctx, "sys/introspect/roles"))
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
			if _, err := c.buildCBP(ctx, te, true); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.buildCBP(ctx, te, true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// storeTestPolicy parses raw as a policy of the given type and stores it under
// name in the root namespace.
func storeTestPolicy(tb testing.TB, c *Core, name string, typ PolicyType, raw string) {
	tb.Helper()
	var p *Policy
	var err error
	if typ == PolicyTypeMCP {
		p, err = ParseMCPPolicy(namespace.RootNamespace, raw)
	} else {
		p, err = ParseCBPPolicy(namespace.RootNamespace, raw)
	}
	require.NoError(tb, err)
	p.Name, p.Type = name, typ
	require.NoError(tb, c.policyStore.SetPolicy(rootCtx(), p, nil))
}

// BenchmarkBuildCBP measures a request's compile for the token shapes that
// matter: an agent with a capability policy and an MCP contract, an operator
// with a 40-stanza policy, root, a token with no policy of its own, and a
// namespace whose default-cbp is emptied to turn discovery off. The built-ins
// join every case but root.
func BenchmarkBuildCBP(b *testing.B) {
	c := createTestCore(b)
	ctx := rootCtx()

	storeTestPolicy(b, c, "agent-cbp", PolicyTypeCBP, `
path "mcp/github/*" { capabilities = ["create", "read"] }
path "mcp/jira" { capabilities = ["create"] }
path "prov/role/+/gateway*" { capabilities = ["read"] }
path "secret/team/data" {
  capabilities = ["read"]
  condition = "request.client_ip != ''"
}
`)
	storeTestPolicy(b, c, "agent-mcp", PolicyTypeMCP, `
path "mcp/github/*" {
  methods {
    allowed = ["tools/list", "tools/call"]
  }
  tools {
    allowed = ["get_repository", "list_issues"]
    denied  = ["delete_*"]
  }
}
path "mcp/jira" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["*"]
  }
}
`)
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&sb, "path \"svc%d/config\" { capabilities = [\"read\", \"list\"] }\n", i)
	}
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&sb, "path \"svc%d/data/*\" { capabilities = [\"read\", \"create\", \"update\"] }\n", i)
	}
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&sb, "path \"svc%d/+/items\" { capabilities = [\"read\"] }\n", i)
	}
	storeTestPolicy(b, c, "ops-large", PolicyTypeCBP, sb.String())

	run := func(name string, policies []string) {
		b.Run(name, func(b *testing.B) {
			te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: policies}
			if _, err := c.buildCBP(ctx, te, true); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.buildCBP(ctx, te, true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	run("agent-2-policies", []string{"agent-cbp", "agent-mcp"})
	run("ops-40-stanzas", []string{"ops-large"})
	run("root", []string{"root"})
	run("no-policies", nil)

	// Last: it rewrites a built-in the cases above compile with.
	storeTestPolicy(b, c, builtinCBPPolicy, PolicyTypeCBP, "# discovery off\n")
	run("default-cbp-emptied", nil)
}

// TestCBP_AllocationBudget holds the request path to its measured allocations,
// so a regression fails a test instead of drifting a benchmark: one for a
// capability check on an exact or a prefix path (the result itself), and
// eleven for a compile with the built-ins of BenchmarkBuildCBP_Builtins's
// token. Raise a budget only with the benchmark that justifies it.
func TestCBP_AllocationBudget(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	storeTestPolicy(t, c, "reader", PolicyTypeCBP, `path "prov/role/+/gateway*" { capabilities = ["read", "create"] }`)
	te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{"reader"}}

	build := func() {
		if _, err := c.buildCBP(ctx, te, true); err != nil {
			t.Fatal(err)
		}
	}
	build()
	assert.Equal(t, 11.0, testing.AllocsPerRun(200, build), "buildCBP with the built-ins")

	prefixOnly, err := ParseCBPPolicy(namespace.RootNamespace, `
path "secret/x" { capabilities = ["read"] }
path "pre/*" { capabilities = ["read"] }
`)
	require.NoError(t, err)
	prefixOnly.Name, prefixOnly.Type = "prefix-only", PolicyTypeCBP
	prefixOnly.finalize()
	cbp, err := NewCBP(ctx, []*Policy{prefixOnly})
	require.NoError(t, err)
	for _, path := range []string{"secret/x", "pre/zz"} {
		req := &logical.Request{Operation: logical.ReadOperation, Path: path}
		require.True(t, cbp.AllowOperation(ctx, req, nil, false).Allowed, path)
		assert.Equal(t, 1.0, testing.AllocsPerRun(200, func() { cbp.AllowOperation(ctx, req, nil, false) }), "AllowOperation on %s", path)
	}

	// With the built-ins attached, as on every request: their "+" sponsor
	// shapes cost a path outside them nothing.
	builtins, err := c.policyStore.appendDefaultPolicies(ctx, nil)
	require.NoError(t, err)
	withBuiltins, err := NewCBP(ctx, append([]*Policy{prefixOnly}, builtins...))
	require.NoError(t, err)
	req := &logical.Request{Operation: logical.ReadOperation, Path: "pre/foo/bar"}
	require.True(t, withBuiltins.AllowOperation(ctx, req, nil, false).Allowed)
	assert.Equal(t, 1.0, testing.AllocsPerRun(200, func() { withBuiltins.AllowOperation(ctx, req, nil, false) }),
		"AllowOperation on a prefix path beside the sponsor shapes")
	sponsor := &logical.Request{Operation: logical.ReadOperation, Path: "sys/identity/sponsor/billing-agent"}
	assert.True(t, withBuiltins.AllowOperation(ctx, sponsor, nil, false).Allowed, "the sponsor shape still matches")
	deeper := &logical.Request{Operation: logical.ReadOperation, Path: "sys/identity/sponsor/billing-agent/x/y"}
	assert.False(t, withBuiltins.AllowOperation(ctx, deeper, nil, false).Allowed)
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
