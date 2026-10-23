package core

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// TestCanonicalPolicyName_MatchesPolicyRoutes keeps the store's name rule and
// the policy routes' path pattern in step: a name the routes accept always has
// a canonical form, and a name with one always routes.
func TestCanonicalPolicyName_MatchesPolicyRoutes(t *testing.T) {
	route := regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")
	corpus := []string{
		"admin", "Admin", "deploy-1", "a", "_", "a_b", "a.b", "a..b", "a-.-b",
		"", ".", "..", "-", "a-", "-a", ".a", "a.", "a/b", "a b", "x/../admin",
		"../../00000000-0000-0000-0000-000000000000/cbp/admin", "a%2fb", "a\\b",
		"é", "ADMİN", "\u212Aey", "a\x00b",
	}
	for _, name := range corpus {
		canonical, ok := logical.CanonicalPolicyName(name)
		assert.Equal(t, route.MatchString(name), ok, "route and canonical rule disagree on %q", name)
		if ok {
			assert.Equal(t, strings.ToLower(name), canonical)
			assert.True(t, route.MatchString(canonical))
		}
	}
}

// policyNameEnv is a core with an "admin" policy granting everything in the
// root namespace, one in a child namespace "team-a", and both warm in the
// policy cache.
type policyNameEnv struct {
	c       *Core
	rootCtx context.Context
	child   *namespace.Namespace
	nsCtx   context.Context
}

func newPolicyNameEnv(t *testing.T) *policyNameEnv {
	t.Helper()
	c := createTestCore(t)
	e := &policyNameEnv{c: c, rootCtx: rootCtx()}

	e.child = &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, c.namespaceStore.SetNamespace(e.rootCtx, e.child))
	e.nsCtx = namespace.ContextWithNamespace(context.Background(), e.child)

	for _, ctx := range []context.Context{e.rootCtx, e.nsCtx} {
		ns, err := namespace.FromContext(ctx)
		require.NoError(t, err)
		p, err := ParseCBPPolicy(ns, `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`)
		require.NoError(t, err)
		p.Name = "admin"
		require.NoError(t, c.policyStore.SetPolicy(ctx, p, nil))
		got, err := c.policyStore.GetPolicy(ctx, "admin", PolicyTypeCBP)
		require.NoError(t, err)
		require.NotNil(t, got)
	}
	// The synthesized root policy is cached on first resolve, as a root token's
	// first request does.
	root, err := c.policyStore.GetPolicy(e.rootCtx, "root", PolicyTypeCBP)
	require.NoError(t, err)
	require.NotNil(t, root)
	return e
}

// TestPolicyStore_TraversalNameReachesNoOtherPolicy pins the namespace
// traversal fix: a policy name spelled with "/" and ".." resolves to nothing,
// even while the policy it spells out is warm in the cache.
func TestPolicyStore_TraversalNameReachesNoOtherPolicy(t *testing.T) {
	e := newPolicyNameEnv(t)
	ps := e.c.policyStore
	rootUUID := namespace.RootNamespace.UUID

	for _, name := range []string{
		"../../" + rootUUID + "/cbp/admin", // the root namespace's admin, from team-a
		"../../" + rootUUID + "/cbp/root",  // the synthesized root policy, from team-a
		"x/../admin",                       // the namespace's own admin, past any prefix
		"group-/../../../" + rootUUID + "/cbp/admin",
	} {
		got, err := ps.getPolicyAnyType(e.nsCtx, name)
		require.NoError(t, err)
		assert.Nil(t, got, "%q must resolve to nothing", name)

		got, err = ps.GetPolicy(e.nsCtx, name, PolicyTypeCBP)
		require.NoError(t, err)
		assert.Nil(t, got, "%q must resolve to nothing", name)
	}

	// Through the CBP a token's policies are compiled with, the name grants
	// nothing and compiles without error.
	cbp, err := ps.CBP(e.nsCtx, map[string][]string{
		e.child.ID: {"../../" + rootUUID + "/cbp/admin", "../../" + rootUUID + "/cbp/root"},
	})
	require.NoError(t, err)
	res := cbp.AllowOperation(e.nsCtx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}, &logical.TokenEntry{}, false)
	assert.False(t, res.Allowed)
	assert.False(t, res.IsRoot)
}

// TestPolicyStore_CanonicalNamesResolve: a name in any case and with
// surrounding space still resolves to its canonical policy, as before.
func TestPolicyStore_CanonicalNamesResolve(t *testing.T) {
	e := newPolicyNameEnv(t)
	for _, name := range []string{"admin", "Admin", " ADMIN "} {
		got, err := e.c.policyStore.getPolicyAnyType(e.nsCtx, name)
		require.NoError(t, err)
		require.NotNil(t, got, "%q", name)
		assert.Equal(t, "admin", got.Name)
		assert.Equal(t, e.child.UUID, got.namespace.UUID, "resolved in its own namespace")
	}
}

func TestPolicyStore_WritesRefuseNonCanonicalNames(t *testing.T) {
	e := newPolicyNameEnv(t)
	ps := e.c.policyStore

	p, err := ParseCBPPolicy(e.child, `path "x" { capabilities = ["read"] }`)
	require.NoError(t, err)
	p.Name = "x/../admin"
	err = ps.SetPolicy(e.nsCtx, p, nil)
	require.Error(t, err)
	assertBadRequest(t, err)

	err = ps.DeletePolicy(e.nsCtx, "x/../admin", PolicyTypeCBP)
	require.Error(t, err)
	assertBadRequest(t, err)

	got, err := ps.GetPolicy(e.nsCtx, "admin", PolicyTypeCBP)
	require.NoError(t, err)
	assert.NotNil(t, got, "the policy the name spelled out is untouched")
}

// BenchmarkGetPolicyAnyTypeCached measures the per-policy cost every request
// pays to resolve a token's policies.
func BenchmarkGetPolicyAnyTypeCached(b *testing.B) {
	c := createTestCore(b)
	ctx := rootCtx()
	p, err := ParseCBPPolicy(namespace.RootNamespace, `path "secret/*" { capabilities = ["read"] }`)
	require.NoError(b, err)
	p.Name = "deploy"
	require.NoError(b, c.policyStore.SetPolicy(ctx, p, nil))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := c.policyStore.getPolicyAnyType(ctx, "deploy")
		if err != nil || got == nil {
			b.Fatal("policy not resolved")
		}
	}
}
