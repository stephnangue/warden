package core

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinRoles_Names(t *testing.T) {
	for _, name := range []string{"warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"} {
		assert.True(t, isBuiltinRoleName(name), name)
		assert.True(t, isReservedRoleName(name), name)
		r := builtinRoleValue(name)
		require.NotNil(t, r, name)
		assert.Equal(t, name, r.Name)
		assert.NotEmpty(t, r.Description, name)
		assert.Nil(t, r.Policies, "%s: the body is the whole grant", name)
		assert.Empty(t, r.CredSpecName, "%s: a built-in mints nothing", name)
		assert.False(t, r.GovernedOnly, "%s: built-ins are for humans through virtual groups", name)
		assert.True(t, r.GrantedThrough(logical.GroupTypeVirtual), name)
		assert.True(t, r.GrantedThrough(logical.GroupTypeStatic), name)
	}

	for _, name := range []string{"Warden-Admin", "WARDEN-ADMIN", "warden-ops", "warden-"} {
		assert.False(t, isBuiltinRoleName(name), name)
		assert.True(t, isReservedRoleName(name), name)
		assert.Nil(t, builtinRoleValue(name), name)
	}
	for _, name := range []string{"warden", "wardenadmin", "admin", "my-warden-admin", "ward"} {
		assert.False(t, isBuiltinRoleName(name), name)
		assert.False(t, isReservedRoleName(name), name)
	}

	assert.Zero(t, testing.AllocsPerRun(1000, func() {
		_ = isBuiltinRoleName("warden-viewer")
		_ = isReservedRoleName("Warden-Viewer")
	}))
}

// builtinRoleCBP compiles the built-in named role beside the built-in
// policies of tokenNS, as a request under it would.
func builtinRoleCBP(t *testing.T, c *Core, role string, tokenNS *namespace.Namespace) *CBP {
	t.Helper()
	i := builtinRoleIndex(role)
	require.GreaterOrEqual(t, i, 0, role)
	body, err := c.builtinRolePolicies.policy(tokenNS, i)
	require.NoError(t, err)
	tokenCtx := namespace.ContextWithNamespace(context.Background(), tokenNS)
	defaults, err := c.policyStore.appendDefaultPolicies(tokenCtx, nil)
	require.NoError(t, err)
	require.Len(t, defaults, 3, "the built-in policies of %q", tokenNS.Path)
	cbp, err := NewCBP(tokenCtx, append([]*Policy{body}, defaults...))
	require.NoError(t, err)
	return cbp
}

type builtinCase struct {
	path      string
	op        logical.Operation
	class     string
	dataPlane bool
	sudo      bool // a Root path: the grant must carry sudo
	allowed   map[string]bool
}

// The four roles over the paths they are meant to cover and the ones they
// are meant to miss, with sudo exactly where a Root path needs it.
var builtinRoleCases = []builtinCase{
	{"sys/roles/x", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/roles/x", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-security-admin")},
	{"sys/roles", logical.ListOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/rolesx", logical.ReadOperation, "system", false, false, roles("warden-admin")},
	{"sys/policies/cbp/x", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/policies/cbp/x", logical.UpdateOperation, "system", false, false, roles("warden-admin", "warden-security-admin")},
	{"sys/identity/group/x", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/identity/group/x", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-security-admin")},
	{"sys/identity/entity/x", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/identity/config", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/identity/config", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-security-admin")},
	{"sys/identity/usage", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/auth", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/auth/jwt", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/auth/jwt", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-security-admin")},
	{"auth/jwt/config", logical.ReadOperation, "auth", false, false, roles("warden-admin", "warden-security-admin")},
	{"auth/jwt/config", logical.UpdateOperation, "auth", false, false, roles("warden-admin", "warden-security-admin")},
	{"sys/audit", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/audit/file", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/audit/file", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-security-admin")},
	{"sys/audit-hash/file", logical.UpdateOperation, "system", false, true, roles("warden-admin")},
	{"sys/providers/aws", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-provider-admin", "warden-viewer")},
	{"sys/providers/aws", logical.UpdateOperation, "system", false, false, roles("warden-admin", "warden-provider-admin")},
	{"sys/providers", logical.ListOperation, "system", false, false, roles("warden-admin", "warden-provider-admin", "warden-viewer")},
	{"sys/providersx", logical.ReadOperation, "system", false, false, roles("warden-admin")},
	{"aws/config", logical.ReadOperation, "provider", false, false, roles("warden-admin", "warden-provider-admin")},
	{"aws/config", logical.UpdateOperation, "provider", false, false, roles("warden-admin", "warden-provider-admin")},
	{"cloud/aws/config", logical.UpdateOperation, "provider", false, false, roles("warden-admin", "warden-provider-admin")},
	{"db/grants/g", logical.UpdateOperation, "provider", false, false, roles("warden-admin", "warden-provider-admin")},
	// The data plane: only warden-admin's "*" reaches it in policy; the
	// request handler refuses every built-in there before routing.
	{"aws/gateway/x", logical.ReadOperation, "provider", true, false, roles("warden-admin")},
	{"aws/role/r/gateway/x", logical.ReadOperation, "provider", true, false, roles("warden-admin")},
	{"db/access/g", logical.ReadOperation, "provider", true, false, roles("warden-admin")},
	{"sys/cred/sources/x", logical.ReadOperation, "system", false, true, roles("warden-admin", "warden-provider-admin", "warden-viewer")},
	{"sys/cred/sources/x", logical.UpdateOperation, "system", false, true, roles("warden-admin", "warden-provider-admin")},
	{"sys/cred/specs/x/keyless-plan", logical.CreateOperation, "system", false, true, roles("warden-admin", "warden-provider-admin")},
	{"sys/skills", logical.ListOperation, "system", false, false, roles("warden-admin", "warden-provider-admin", "warden-viewer")},
	{"sys/skills/x", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-provider-admin", "warden-viewer")},
	{"sys/skills/x", logical.UpdateOperation, "system", false, false, roles("warden-admin", "warden-provider-admin")},
	{"sys/namespaces", logical.ListOperation, "system", false, false, roles("warden-admin", "warden-viewer")},
	{"sys/namespaces/x", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-viewer")},
	{"sys/namespaces/x", logical.UpdateOperation, "system", false, false, roles("warden-admin")},
	{"sys/oidc-issuer/config", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/oidc-issuer/config", logical.UpdateOperation, "system", false, false, roles("warden-admin", "warden-security-admin")},
	{"sys/protected-resource/config", logical.ReadOperation, "system", false, false, roles("warden-admin", "warden-security-admin", "warden-viewer")},
	{"sys/step-down", logical.UpdateOperation, "system", false, true, roles("warden-admin")},
}

func roles(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestBuiltinRoles_Capabilities(t *testing.T) {
	c := createTestCore(t)
	acme := &namespace.Namespace{Path: "acme/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), acme))
	dev := &namespace.Namespace{Path: "acme/dev/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), dev))

	// A body compiled in the token's namespace governs alike there and in a
	// namespace below it.
	for _, layout := range []struct {
		name           string
		tokenNS, reqNS *namespace.Namespace
	}{
		{"root", namespace.RootNamespace, namespace.RootNamespace},
		{"acme", acme, acme},
		{"acme token in acme/dev", acme, dev},
	} {
		t.Run(layout.name, func(t *testing.T) {
			reqCtx := namespace.ContextWithNamespace(context.Background(), layout.reqNS)
			for _, r := range builtinRoles {
				name := r.role.Name
				cbp := builtinRoleCBP(t, c, name, layout.tokenNS)
				for _, tc := range builtinRoleCases {
					req := &logical.Request{Path: tc.path, Operation: tc.op, MountClass: tc.class, DataPlane: tc.dataPlane}
					res := cbp.AllowOperation(reqCtx, req, nil, false)
					want := tc.allowed[name]
					assert.Equal(t, want, res.Allowed, "%s: %s %s", name, tc.op, tc.path)
					if want && tc.sudo {
						assert.True(t, res.RootPrivs, "%s: %s %s is a Root path and needs sudo", name, tc.op, tc.path)
					}
					if want {
						require.NotEmpty(t, res.GrantingPolicies, "%s: %s %s", name, tc.op, tc.path)
					}
				}
			}
		})
	}
}

// A body is compiled in the token's namespace, as any policy is, and reaches
// that namespace and every one below it, never the parent or a sibling: the
// policy's prefix fences it, whatever its condition admits.
func TestBuiltinRoles_CompiledInTheTokenNamespace(t *testing.T) {
	c := createTestCore(t)
	acme := &namespace.Namespace{Path: "acme/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), acme))
	dev := &namespace.Namespace{Path: "acme/dev/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), dev))
	other := &namespace.Namespace{Path: "acme-other/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), other))

	req := &logical.Request{Path: "sys/roles/x", Operation: logical.ReadOperation, MountClass: "system"}
	in := func(ns *namespace.Namespace) context.Context {
		return namespace.ContextWithNamespace(context.Background(), ns)
	}
	for _, role := range []string{"warden-admin", "warden-viewer"} {
		cbp := builtinRoleCBP(t, c, role, acme)
		for _, ns := range []*namespace.Namespace{acme, dev} {
			res := cbp.AllowOperation(in(ns), req, nil, false)
			require.True(t, res.Allowed, "%s in %q", role, ns.Path)
			require.Len(t, res.GrantingPolicies, 1)
			assert.Equal(t, role, res.GrantingPolicies[0].Name)
			assert.Equal(t, acme.Path, res.GrantingPolicies[0].NamespacePath, "%s in %q", role, ns.Path)
		}
		for _, ns := range []*namespace.Namespace{namespace.RootNamespace, other} {
			assert.False(t, cbp.AllowOperation(in(ns), req, nil, false).Allowed, "%s compiled in acme/, in %q", role, ns.Path)
		}
	}
}

// Every Root path of the system backend, and the roles that reach it. A body
// holds sudo across its whole condition, so a Root path a role does not
// administer must stay outside the condition: a new Root path fails here until
// it is placed.
func TestBuiltinRoles_RootPaths(t *testing.T) {
	c := createTestCore(t)
	reach := map[string]map[string]bool{
		"auth/*":            roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"cred/*":            roles("warden-admin", "warden-provider-admin", "warden-viewer"),
		"audit/*":           roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"audit-hash/*":      roles("warden-admin"),
		"dev/*":             roles("warden-admin"),
		"roles":             roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"roles/*":           roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/group":    roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/group/*":  roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/entity":   roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/entity/*": roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/lookup":   roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"identity/config":   roles("warden-admin", "warden-security-admin", "warden-viewer"),
		"step-down":         roles("warden-admin"),
	}
	root := c.systemBackend.SpecialPaths().Root
	require.Len(t, root, len(reach), "every Root path is placed: %v", root)
	for _, pattern := range root {
		want, ok := reach[pattern]
		require.True(t, ok, "Root path %q is not placed", pattern)
		path := "sys/" + strings.TrimSuffix(pattern, "*") + strings.Repeat("x", strings.Count(pattern, "*"))
		for _, r := range builtinRoles {
			cbp := builtinRoleCBP(t, c, r.role.Name, namespace.RootNamespace)
			// Read: the one operation every role that reaches a path has.
			res := cbp.AllowOperation(rootCtx(), &logical.Request{Path: path, Operation: logical.ReadOperation, MountClass: "system"}, nil, false)
			assert.Equal(t, want[r.role.Name], res.Allowed, "%s on %s", r.role.Name, path)
			if res.Allowed {
				assert.True(t, res.RootPrivs, "%s on %s", r.role.Name, path)
			}
		}
	}
}

// The sponsor paths: in the token's own namespace the default-sponsor stanza
// outranks a body's prefix, so every role gets the sponsor capabilities there;
// in a child, the sponsor stanza does not match and the body decides. Either
// way the sponsor handlers, not the role, decide who acts.
func TestBuiltinRoles_SponsorPaths(t *testing.T) {
	c := createTestCore(t)
	acme := &namespace.Namespace{Path: "acme/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), acme))
	dev := &namespace.Namespace{Path: "acme/dev/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), dev))
	in := func(ns *namespace.Namespace) context.Context {
		return namespace.ContextWithNamespace(context.Background(), ns)
	}
	read := &logical.Request{Path: "sys/identity/sponsor/billing-agent", Operation: logical.ReadOperation, MountClass: "system"}
	suspend := &logical.Request{Path: "sys/identity/sponsor/billing-agent/suspend", Operation: logical.UpdateOperation, MountClass: "system"}

	for _, r := range builtinRoles {
		same := builtinRoleCBP(t, c, r.role.Name, acme)
		assert.True(t, same.AllowOperation(in(acme), read, nil, false).Allowed, "%s: sponsor read in acme", r.role.Name)
		assert.True(t, same.AllowOperation(in(acme), suspend, nil, false).Allowed, "%s: sponsor suspend in acme", r.role.Name)
	}

	child := map[string]bool{"warden-admin": true, "warden-security-admin": true, "warden-viewer": true}
	for _, r := range builtinRoles {
		cbp := builtinRoleCBP(t, c, r.role.Name, acme)
		assert.Equal(t, child[r.role.Name], cbp.AllowOperation(in(dev), read, nil, false).Allowed, "%s: sponsor read in acme/dev", r.role.Name)
	}
}

// The measured cost of a capability check under each built-in: the one
// allocation of every check, and for a conditional body seven more to build
// and audit the CEL activation, plus one for each request field the condition
// reads beyond the first (provider-admin's and security-admin's mount_class).
// Request strings are boxed once per evaluation and a condition's source is
// stripped for audit once at compile, so a multi-line condition naming
// request.path on every line costs no more than one naming it once. Allowed or
// denied costs the same. Operator traffic is control plane, and a data-plane
// request under a built-in is refused anyway. Raise a budget only with the
// measurement that justifies it.
func TestBuiltinRoles_AllowOperationBudget(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	sysRoles := &logical.Request{Path: "sys/roles/x", Operation: logical.ReadOperation, MountClass: "system"}
	awsConfig := &logical.Request{Path: "aws/config", Operation: logical.ReadOperation, MountClass: "provider"}
	jwtConfig := &logical.Request{Path: "auth/jwt/config", Operation: logical.ReadOperation, MountClass: "auth"}
	budgets := map[string]map[*logical.Request]float64{
		"warden-admin":          {sysRoles: 1, awsConfig: 1, jwtConfig: 1},
		"warden-provider-admin": {sysRoles: 9, awsConfig: 9, jwtConfig: 9},
		"warden-security-admin": {sysRoles: 9, awsConfig: 9, jwtConfig: 9},
		"warden-viewer":         {sysRoles: 8, awsConfig: 8, jwtConfig: 8},
	}
	for _, r := range builtinRoles {
		cbp := builtinRoleCBP(t, c, r.role.Name, namespace.RootNamespace)
		for req, budget := range budgets[r.role.Name] {
			cbp.AllowOperation(ctx, req, nil, false)
			assert.Equal(t, budget, testing.AllocsPerRun(200, func() { cbp.AllowOperation(ctx, req, nil, false) }), "%s on %s", r.role.Name, req.Path)
		}
	}
}

func TestBuiltinRolePolicies_Index(t *testing.T) {
	var b builtinRolePolicies
	acme := &namespace.Namespace{UUID: "acme-uuid", Path: "acme/"}
	dev := &namespace.Namespace{UUID: "dev-uuid", Path: "acme/dev/"}

	p, err := b.policy(acme, 0)
	require.NoError(t, err)
	again, err := b.policy(acme, 0)
	require.NoError(t, err)
	assert.Same(t, p, again, "compiled once per namespace and role")
	assert.Equal(t, "warden-admin", p.Name)
	assert.Equal(t, PolicyTypeCBP, p.Type)
	assert.NotNil(t, p.info, "finalized before it is shared")

	other, err := b.policy(dev, 0)
	require.NoError(t, err)
	assert.NotSame(t, p, other)

	assert.Zero(t, testing.AllocsPerRun(1000, func() { _, _ = b.policy(acme, 0) }), "a hit allocates nothing")

	b.drop(acme.UUID)
	recompiled, err := b.policy(acme, 0)
	require.NoError(t, err)
	assert.NotSame(t, p, recompiled, "dropped with its namespace")
	kept, err := b.policy(dev, 0)
	require.NoError(t, err)
	assert.Same(t, other, kept, "another namespace keeps its bodies")

	// The root namespace: "*" compiles to the empty prefix and matches
	// everything.
	root, err := b.policy(namespace.RootNamespace, 0)
	require.NoError(t, err)
	cbp, err := NewCBP(rootCtx(), []*Policy{root})
	require.NoError(t, err)
	for _, path := range []string{"sys/roles/x", "aws/config", "a"} {
		assert.True(t, cbp.AllowOperation(rootCtx(), &logical.Request{Path: path, Operation: logical.UpdateOperation}, nil, false).Allowed, path)
	}
}

func TestBuiltinRolePolicies_Concurrent(t *testing.T) {
	var b builtinRolePolicies
	nss := make([]*namespace.Namespace, 8)
	for i := range nss {
		nss[i] = &namespace.Namespace{UUID: string(rune('a' + i)), Path: string(rune('a'+i)) + "/"}
	}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ns := nss[(g+i)%len(nss)]
				p, err := b.policy(ns, i%len(builtinRoles))
				if err != nil || p == nil {
					t.Errorf("policy: %v", err)
					return
				}
				if i%50 == 0 {
					b.drop(ns.UUID)
				}
			}
		}(g)
	}
	wg.Wait()
}

// Every body parses in every namespace shape.
func TestBuiltinRoles_BodiesParse(t *testing.T) {
	for _, ns := range []*namespace.Namespace{namespace.RootNamespace, {UUID: "u1", Path: "acme/"}, {UUID: "u2", Path: "acme/dev/"}} {
		for i := range builtinRoles {
			p, err := compileBuiltinRole(ns, i)
			require.NoError(t, err, "%s in %q", builtinRoles[i].role.Name, ns.Path)
			// Audit records a condition with its newlines stripped, so a CEL
			// comment there would run into the next clause: comments go
			// outside the condition, as HCL comments.
			for _, pc := range p.Paths {
				if cond := pc.Permissions.Condition; cond != nil {
					assert.NotContains(t, cond.Source, "//", builtinRoles[i].role.Name)
				}
			}
		}
	}
}
