package core

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roleRead(t *testing.T, c *Core, ctx context.Context, name string) *logical.Response {
	t.Helper()
	b := c.systemBackend
	raw := map[string]any{"name": name}
	resp, err := b.handleRoleRead(ctx, createTestRequest(logical.ReadOperation, "roles/"+name, raw), createFieldData(b.pathRoles()[0].Fields, raw))
	require.NoError(t, err)
	return resp
}

func roleList(t *testing.T, c *Core, ctx context.Context, providerPath string) *logical.Response {
	t.Helper()
	b := c.systemBackend
	raw := map[string]any{"provider_path": providerPath}
	resp, err := b.handleRoleList(ctx, createTestRequest(logical.ListOperation, "roles", raw), createFieldData(b.pathRoles()[1].Fields, raw))
	require.NoError(t, err)
	return resp
}

// sys/roles reads and lists the built-ins where the namespace has them,
// marked, the read with the body they grant; a built-in wins over a role
// stored under its name; a namespace without them lists none.
func TestBuiltinSurfaces_RoleReadList(t *testing.T) {
	e := newBuiltinEnv(t)
	_, err := e.c.roleStore.Create(e.acmeCtx, &logical.Role{Name: "deploy", Description: "Deploys", ProviderPath: "aws/"})
	require.NoError(t, err)

	for _, ctx := range []context.Context{rootCtx(), e.acmeCtx} {
		resp := roleRead(t, e.c, ctx, "warden-viewer")
		require.Nil(t, resp.Error())
		assert.Equal(t, true, resp.Data["builtin"])
		assert.Equal(t, false, resp.Data["governed_only"])
		assert.Equal(t, []string{}, resp.Data["policies"])
		assert.Contains(t, resp.Data["policy_document"], `request.path.startsWith("sys/namespaces/")`)
		assert.NotEmpty(t, resp.Data["hash"])
	}

	list := roleList(t, e.c, e.acmeCtx, "")
	assert.Equal(t, []string{"deploy", "warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"}, list.Data["keys"])
	for _, item := range list.Data["roles"].([]map[string]any) {
		_, builtin := item["builtin"]
		assert.Equal(t, strings.HasPrefix(item["name"].(string), "warden-"), builtin, item["name"])
	}
	assert.Equal(t, []string{"deploy"}, roleList(t, e.c, e.acmeCtx, "aws/").Data["keys"], "a provider_path filter leaves the built-ins out")

	betaCtx := namespace.ContextWithNamespace(context.Background(), e.beta)
	assert.Empty(t, roleList(t, e.c, betaCtx, "").Data["keys"])
	assert.NotNil(t, roleRead(t, e.c, betaCtx, "warden-admin").Error(), "not found where the namespace has none")

	// A legacy record under a built-in's name: the built-in reads and lists in
	// its place where enabled, and the list still names the record in its
	// warning; where not, the legacy record is what is there.
	e.storeLegacyRole(e.acme, &logical.Role{Name: "warden-admin", Description: "legacy", Policies: []string{"x"}})
	e.storeLegacyRole(e.beta, &logical.Role{Name: "warden-admin", Description: "legacy", Policies: []string{"x"}})
	assert.Equal(t, true, roleRead(t, e.c, e.acmeCtx, "warden-admin").Data["builtin"])
	assert.Len(t, roleList(t, e.c, e.acmeCtx, "").Data["keys"], 5, "listed once")
	legacy := roleRead(t, e.c, betaCtx, "warden-admin")
	require.Nil(t, legacy.Error())
	assert.Equal(t, "legacy", legacy.Data["description"])
	assert.NotContains(t, legacy.Data, "builtin")
	want := "stored under a name reserved for built-in roles, so it grants nothing; delete it: warden-admin"
	assert.Equal(t, []string{want}, legacy.Data["warnings"], "a legacy record says it grants nothing")
	assert.Equal(t, []string{want}, roleList(t, e.c, betaCtx, "").Data["warnings"])
	assert.Equal(t, []string{want}, roleList(t, e.c, e.acmeCtx, "").Data["warnings"], "named even where the built-in stands in for it")
	assert.NotContains(t, roleRead(t, e.c, e.acmeCtx, "warden-admin").Data, "warnings")
}

// Discovery lists the built-ins a ticket is granted, and list_roles says why
// they have no url and no skill. A ticket of acme/ asking from
// acme/dev/ lists the built-ins of acme/, where its roles resolve.
func TestBuiltinSurfaces_Discovery(t *testing.T) {
	e := newTicketRequestEnv(t)
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "operators", Type: logical.GroupTypeVirtual, Roles: []string{"warden-admin"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}, "roles": {"Warden.Operator"}}},
	})
	require.NoError(t, err)

	resp, _, err := e.do("sys/introspect/roles", wardenToken(e.value))
	require.NoError(t, err)
	roles := resp.Data["roles"].([]admittedRole)
	require.Len(t, roles, 2)
	assert.Equal(t, admittedRole{Name: "operator", Description: "day-to-day operations"}, roles[0])
	assert.Equal(t, admittedRole{Name: "warden-admin", Description: builtinRoleValue("warden-admin").Description}, roles[1])

	srv := startMCPTestServer(t, e.c, nil)
	session := connectMCPWithHeaders(t, srv, wardenToken(e.value))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	out := decodeListRoles(t, res)
	require.Len(t, out.Roles, 2)
	admin := out.Roles[1]
	assert.Equal(t, "warden-admin", admin.Name)
	assert.Empty(t, admin.URL)
	assert.Empty(t, admin.Skill)
	assert.Contains(t, out.Warnings, `role "warden-admin": built-in operator role; it is used on Warden's own API with ?role= or X-Warden-Role, not through a provider`)

	// A parent's ticket, in a child: the parent's built-ins.
	b := newBuiltinEnv(t)
	resp, _, err = b.do(logical.ReadOperation, "acme/dev/sys/introspect/roles", b.acmeTicket, "")
	require.NoError(t, err)
	var names []string
	for _, r := range resp.Data["roles"].([]admittedRole) {
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"}, names)
}

// The group write: a static group listing a built-in raises no warning; a
// virtual one trusting an agent mount warns that an unclaimed agent would hold
// it; one trusting a human mount does not; a namespace without built-in roles
// says so; a reserved name that is no built-in says it names none. None is
// told the role "does not exist yet".
func TestBuiltinSurfaces_GroupWarnings(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	en := governedAgent(t, c, "terraform-runner")

	write := func(ctx context.Context, g *logical.Group) []string {
		t.Helper()
		w, err := c.identityStore.CreateGroup(ctx, g)
		require.NoError(t, err)
		for _, s := range w {
			assert.NotContains(t, s, "does not exist yet", g.Name)
		}
		return w
	}

	w := write(ctx, &logical.Group{Name: "terraform-runners", Type: logical.GroupTypeStatic,
		Roles: []string{"warden-provider-admin"}, Members: []logical.GroupMember{{ID: en.ID}}})
	assert.Empty(t, w, "a static group is the accountable route")

	w = write(ctx, &logical.Group{Name: "ci-admins", Type: logical.GroupTypeVirtual, Roles: []string{"warden-admin"},
		Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}, "sub": {"repo:acme/*"}}}})
	assert.Contains(t, w, `rules[0]: mount "auth/jwt/" admits agents; an unclaimed agent would hold the operator role "warden-admin" through this rule — list a governed entity in a static group instead`)

	w = write(ctx, &logical.Group{Name: "admins", Type: logical.GroupTypeVirtual, Roles: []string{"warden-admin"},
		Rules: []logical.GroupRule{{"mount": {"auth/humans/"}, "kind": {"human"}}}})
	for _, s := range w {
		assert.NotContains(t, s, "admits agents")
	}

	w = write(ctx, &logical.Group{Name: "odd", Type: logical.GroupTypeVirtual, Roles: []string{"warden-ops"},
		Rules: []logical.GroupRule{{"mount": {"auth/humans/"}}}})
	assert.Contains(t, w, `role name "warden-ops" is reserved for built-in roles and names none; the group grants nothing through it`)

	beta := &namespace.Namespace{Path: "beta/"}
	require.NoError(t, c.namespaceStore.SetNamespace(ctx, beta))
	beta, err := c.namespaceStore.GetNamespaceByPath(ctx, "beta")
	require.NoError(t, err)
	w = write(namespace.ContextWithNamespace(context.Background(), beta), &logical.Group{Name: "later", Type: logical.GroupTypeStatic, Roles: []string{"warden-viewer"}})
	assert.Contains(t, w, `role "warden-viewer" is a built-in role and built-in roles are not enabled in this namespace (enable_builtin_roles=false); the group grants it once they are`)
}

// A locked namespace's read and list carry no unlock key: warden-viewer reads
// sys/namespaces.
func TestBuiltinSurfaces_NamespaceReadNoUnlockKey(t *testing.T) {
	b, ctx, c := setupTestSystemBackend(t)
	nsWrite(t, b, ctx, logical.CreateOperation, "acme", map[string]any{})
	key, err := c.namespaceStore.LockNamespace(ctx, "acme")
	require.NoError(t, err)
	require.NotEmpty(t, key)

	read, err := b.handleNamespaceRead(ctx, createTestRequest(logical.ReadOperation, "namespaces/acme", nil),
		createFieldData(b.pathNamespaces()[0].Fields, map[string]any{"path": "acme"}))
	require.NoError(t, err)
	assert.Equal(t, true, read.Data["locked"])
	assert.NotContains(t, read.Data, "unlock_key")
	list, err := b.handleNamespaceList(ctx, createTestRequest(logical.ListOperation, "namespaces", nil),
		createFieldData(b.pathNamespaces()[1].Fields, map[string]any{}))
	require.NoError(t, err)
	for _, info := range list.Data["namespaces"].([]map[string]any) {
		assert.NotContains(t, info, "unlock_key")
		for _, v := range info {
			assert.NotEqual(t, key, v)
		}
	}
}
