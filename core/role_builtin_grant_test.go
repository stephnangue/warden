package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// builtinEnv is a core with namespaces acme/ (built-in roles on), acme/dev/
// and beta/ (off), an oidc mount in acme/ whose group "operators" grants every
// built-in to the humans it admits with the app role Warden.Operator, and one
// live acme ticket.
type builtinEnv struct {
	*ticketEnv
	audit            *accessAuditRecorder
	acme, dev, beta  *namespace.Namespace
	acmeCtx          context.Context
	acmeTicket       string
	acmeIssuerAccess string
}

func newBuiltinEnv(t *testing.T) *builtinEnv {
	t.Helper()
	e := &builtinEnv{ticketEnv: newTicketEnv(t), audit: &accessAuditRecorder{}}
	e.c.auditManager = e.audit
	e.acme = e.namespace("acme/", true)
	e.dev = e.namespace("acme/dev/", false)
	e.beta = e.namespace("beta/", false)
	e.acmeCtx = namespace.ContextWithNamespace(context.Background(), e.acme)

	b, me := e.mountIssuer(e.acmeCtx, "oidc/")
	e.acmeIssuerAccess = me.Accessor
	e.grantBuiltins(e.acmeCtx)
	e.acmeTicket, _ = e.login(e.acmeCtx, b, me, time.Hour)
	return e
}

func (e *builtinEnv) namespace(path string, builtins bool) *namespace.Namespace {
	e.t.Helper()
	require.NoError(e.t, e.c.namespaceStore.SetNamespace(rootCtx(), &namespace.Namespace{Path: path, EnableBuiltinRoles: builtins}))
	ns, err := e.c.namespaceStore.GetNamespaceByPath(rootCtx(), path)
	require.NoError(e.t, err)
	require.NotNil(e.t, ns)
	return ns
}

// grantBuiltins writes, in ctx's namespace, the virtual group granting every
// built-in to the humans auth/oidc/ admits as Warden.Operator.
func (e *builtinEnv) grantBuiltins(ctx context.Context) {
	e.t.Helper()
	_, err := e.c.identityStore.CreateGroup(ctx, &logical.Group{
		Name: "operators", Type: logical.GroupTypeVirtual,
		Roles: []string{"warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}, "roles": {"Warden.Operator"}}},
	})
	require.NoError(e.t, err)
}

// do runs op on path (namespace prefix included) with the ticket and role.
func (e *builtinEnv) do(op logical.Operation, path, ticket, role string) (*logical.Response, *logical.Request, error) {
	e.t.Helper()
	method := map[logical.Operation]string{logical.ReadOperation: http.MethodGet, logical.ListOperation: "LIST",
		logical.UpdateOperation: http.MethodPut, logical.CreateOperation: http.MethodPost, logical.DeleteOperation: http.MethodDelete}[op]
	hr := httptest.NewRequest(method, "/v1/"+path, nil)
	hr.Header.Set(logical.HeaderWardenToken, ticket)
	req := &logical.Request{Path: path, Operation: op, HTTPRequest: hr, RequestID: "req-builtin",
		Data: map[string]any{"role": role}}
	resp, err := e.c.HandleRequest(context.Background(), req)
	return resp, req, err
}

func status(resp *logical.Response) int {
	if resp == nil {
		return 0
	}
	if resp.StatusCode != 0 {
		return resp.StatusCode
	}
	return http.StatusOK
}

// A human ticket of acme/ granted warden-admin is the admin of acme/ and of
// every namespace below it, sudo included, and of nothing else: not root, not
// a sibling, not the root-only paths.
func TestBuiltinGrant_TenantAdmin(t *testing.T) {
	e := newBuiltinEnv(t)

	for _, path := range []string{"acme/sys/roles/x", "acme/dev/sys/roles/x"} {
		resp, req, err := e.do(logical.ReadOperation, path, e.acmeTicket, "warden-admin")
		require.NotNil(t, req.RoleGrant(), path)
		assert.True(t, req.RoleGrant().Granted(), "%s: %s", path, req.RoleGrant().DeniedReason)
		assert.Equal(t, http.StatusNotFound, status(resp), "%s: authorized (sudo on a Root path), the role does not exist: %v", path, err)
	}
	resp, _, _ := e.do(logical.ReadOperation, "acme/sys/namespaces/dev", e.acmeTicket, "warden-admin")
	assert.Equal(t, http.StatusOK, status(resp))

	// Root and a sibling: the token store refuses the ticket before any role.
	for _, path := range []string{"sys/roles/x", "beta/sys/roles/x"} {
		resp, req, _ := e.do(logical.ReadOperation, path, e.acmeTicket, "warden-admin")
		assert.Equal(t, http.StatusForbidden, status(resp), path)
		assert.Nil(t, req.TokenEntry(), "%s: refused before any role", path)
	}

	// The root-only paths stay root-only.
	for _, tc := range []struct {
		op   logical.Operation
		path string
	}{{logical.ListOperation, "acme/sys/audit"}, {logical.UpdateOperation, "acme/sys/step-down"}} {
		resp, _, _ := e.do(tc.op, tc.path, e.acmeTicket, "warden-admin")
		assert.Equal(t, http.StatusBadRequest, status(resp), tc.path)
		require.NotNil(t, resp.Err, tc.path)
		assert.Contains(t, resp.Err.Error(), "operation unavailable in namespaces", tc.path)
	}
}

// The audit names the built-in as the role and as the granting policy, the
// virtual group behind a human's grant, and no stored policy.
func TestBuiltinGrant_Audit(t *testing.T) {
	e := newBuiltinEnv(t)
	_, _, _ = e.do(logical.ReadOperation, "acme/dev/sys/roles/x", e.acmeTicket, "warden-admin")

	entry := e.audit.requestFor(t, "sys/roles/x")
	require.NotNil(t, entry.Auth)
	assert.Equal(t, "warden-admin", entry.Auth.RoleName)
	assert.Equal(t, "virtual", entry.Auth.RoleGroupType)
	assert.Empty(t, entry.Auth.Policies, "a built-in grants through its body, not stored policies")
	require.NotNil(t, entry.Auth.PolicyResults)
	assert.Equal(t, []string{"warden-admin"}, entry.Auth.PolicyResults.GrantingPolicies)
	raw, err := json.Marshal(entry.Auth)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"policies":`, "omitted, not an empty list")
}

// A built-in resolves only where its namespace has them: never in a namespace
// without enable_builtin_roles, even for a ticket of a parent that has them.
func TestBuiltinGrant_OnlyWhereEnabled(t *testing.T) {
	e := newBuiltinEnv(t)

	// beta/ is off: its own oidc mount and group grant nothing built in.
	betaCtx := namespace.ContextWithNamespace(context.Background(), e.beta)
	b, me := e.mountIssuer(betaCtx, "oidc/")
	e.grantBuiltins(betaCtx)
	betaTicket, _ := e.login(betaCtx, b, me, time.Hour)
	resp, req, err := e.do(logical.ReadOperation, "beta/sys/roles/x", betaTicket, "warden-admin")
	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, status(resp))
	assert.Equal(t, logical.RoleDeniedNotFound, req.RoleGrant().DeniedReason)

	// acme/dev/ is off too: a ticket issued there gets nothing, though acme/
	// has them.
	devCtx := namespace.ContextWithNamespace(context.Background(), e.dev)
	b, me = e.mountIssuer(devCtx, "oidc/")
	e.grantBuiltins(devCtx)
	devTicket, _ := e.login(devCtx, b, me, time.Hour)
	_, req, err = e.do(logical.ReadOperation, "acme/dev/sys/roles/x", devTicket, "warden-admin")
	require.Error(t, err)
	assert.Equal(t, logical.RoleDeniedNotFound, req.RoleGrant().DeniedReason)

	// Turned on, the next request of the same ticket is granted.
	_, err = e.c.namespaceStore.ModifyNamespaceByPath(rootCtx(), "beta", func(_ context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.EnableBuiltinRoles = true
		return ns, nil
	})
	require.NoError(t, err)
	resp, req, _ = e.do(logical.ReadOperation, "beta/sys/roles/x", betaTicket, "warden-admin")
	assert.True(t, req.RoleGrant().Granted())
	assert.Equal(t, http.StatusNotFound, status(resp))
}

// The narrower built-ins hold to their bodies through the whole request path.
func TestBuiltinGrant_NarrowerRoles(t *testing.T) {
	e := newBuiltinEnv(t)
	for _, tc := range []struct {
		role string
		op   logical.Operation
		path string
		want int
	}{
		{"warden-viewer", logical.ReadOperation, "acme/sys/roles/x", http.StatusNotFound},
		{"warden-viewer", logical.ReadOperation, "acme/sys/namespaces/dev", http.StatusOK},
		{"warden-viewer", logical.ReadOperation, "acme/sys/identity/config", http.StatusOK},
		{"warden-viewer", logical.DeleteOperation, "acme/sys/roles/x", http.StatusForbidden},
		{"warden-viewer", logical.ReadOperation, "acme/auth/oidc/config", http.StatusForbidden},
		{"warden-provider-admin", logical.ReadOperation, "acme/sys/roles/x", http.StatusForbidden},
		{"warden-provider-admin", logical.ReadOperation, "acme/sys/identity/group/operators", http.StatusForbidden},
		{"warden-provider-admin", logical.ListOperation, "acme/sys/providers", http.StatusOK},
		{"warden-security-admin", logical.ReadOperation, "acme/sys/identity/group/operators", http.StatusOK},
		{"warden-security-admin", logical.ListOperation, "acme/sys/providers", http.StatusForbidden},
	} {
		resp, _, _ := e.do(tc.op, tc.path, e.acmeTicket, tc.role)
		assert.Equal(t, tc.want, status(resp), "%s: %s %s", tc.role, tc.op, tc.path)
	}
}

// No built-in reaches a data plane: a gateway path and an access path, whose
// backend mints its grant's spec, are refused before anything is routed or
// minted, whatever the role's policy body allows there.
func TestBuiltinGrant_NoDataPlane(t *testing.T) {
	e := newTicketRequestEnv(t)
	backend := mountAccessTestBackend(t, e.c, "")
	_ = backend
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "operators", Type: logical.GroupTypeVirtual,
		Roles: []string{"warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}, "roles": {"Warden.Operator"}}},
	})
	require.NoError(t, err)

	for _, role := range []string{"warden-admin", "warden-provider-admin", "warden-security-admin", "warden-viewer"} {
		for _, path := range []string{"db/access/ro?role=" + role, "fakegw/role/" + role + "/gateway/x"} {
			resp, req, _ := e.do(path, wardenToken(e.value))
			require.NotNil(t, resp, "%s %s", role, path)
			assert.True(t, req.DataPlane, "%s %s", role, path)
			if role == "warden-admin" {
				// Only warden-admin's body allows the path; the refusal is the
				// data-plane check's, not the policy's.
				assert.Equal(t, http.StatusBadRequest, status(resp), "%s %s", role, path)
				require.NotNil(t, resp.Err)
				assert.Contains(t, resp.Err.Error(), `role "warden-admin" is a built-in operator role and has no data plane`)
			} else {
				assert.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, status(resp), "%s %s", role, path)
			}
			assert.NotContains(t, resp.Data, "secret", "%s %s: nothing minted", role, path)
		}
	}
}

// The reserved space: no stored role can take a name starting "warden-", in
// any case, in any namespace; a built-in is read only; a role stored under a
// reserved name before the space was reserved loads, grants nothing (the
// built-in wins), and can be deleted.
func TestBuiltinGrant_ReservedNames(t *testing.T) {
	e := newBuiltinEnv(t)
	for _, ctx := range []context.Context{rootCtx(), e.acmeCtx} {
		for _, name := range []string{"warden-ops", "Warden-Admin", "warden-admin", "WARDEN-viewer"} {
			_, err := e.c.roleStore.Create(ctx, &logical.Role{Name: name})
			require.Error(t, err, name)
			assert.Regexp(t, `reserved for built-in roles|is built-in and read-only`, err.Error(), name)
		}
	}

	b := e.c.systemBackend
	fields := b.pathRoles()[0].Fields
	update := func(name string) *logical.Response {
		raw := map[string]any{"name": name, "governed_only": true}
		resp, err := b.handleRoleUpdate(e.acmeCtx, createTestRequest(logical.UpdateOperation, "roles/"+name, raw), createFieldData(fields, raw))
		require.NoError(t, err)
		return resp
	}
	resp := update("warden-admin")
	require.NotNil(t, resp.Error())
	assert.Equal(t, `role "warden-admin" is built-in and read-only; copy policy_document to a policy and a role of your own`, resp.Error().Error())
	resp = update("warden-ops")
	require.NotNil(t, resp.Error())
	assert.Equal(t, `role names starting "warden-" are reserved for built-in roles; choose another name`, resp.Error().Error())

	raw := map[string]any{"name": "warden-admin"}
	resp, err := b.handleRoleDelete(e.acmeCtx, createTestRequest(logical.DeleteOperation, "roles/warden-admin", raw), createFieldData(fields, raw))
	require.NoError(t, err)
	require.NotNil(t, resp.Error())
	assert.Contains(t, resp.Error().Error(), "is built-in and read-only")
	betaCtx := namespace.ContextWithNamespace(context.Background(), e.beta)
	resp, err = b.handleRoleDelete(betaCtx, createTestRequest(logical.DeleteOperation, "roles/warden-admin", raw), createFieldData(fields, raw))
	require.NoError(t, err)
	require.NotNil(t, resp.Error())
	assert.Contains(t, resp.Error().Error(), `role "warden-admin" not found`, "nothing built in where the namespace has none")

	// A legacy record, written before the space was reserved: its policies
	// are never granted, the built-in is.
	e.storeLegacyRole(e.acme, &logical.Role{Name: "warden-admin", Policies: []string{"legacy-everything"}})
	resp2, req, _ := e.do(logical.ReadOperation, "acme/sys/roles/x", e.acmeTicket, "warden-admin")
	assert.Equal(t, http.StatusNotFound, status(resp2))
	assert.Nil(t, req.RoleGrant().Role.Policies, "the built-in, not the legacy record")
	resp, err = b.handleRoleDelete(e.acmeCtx, createTestRequest(logical.DeleteOperation, "roles/warden-admin", raw), createFieldData(fields, raw))
	require.NoError(t, err)
	assert.Nil(t, resp.Error(), "the legacy record is deleted")
	_, _, err = e.c.roleStore.Get(e.acmeCtx, "warden-admin")
	assert.ErrorIs(t, err, ErrRoleNotFound)
}

// storeLegacyRole writes role into ns's storage, past validation, and reloads
// the role store, as a role written by an earlier release would load.
func (e *builtinEnv) storeLegacyRole(ns *namespace.Namespace, role *logical.Role) {
	e.t.Helper()
	s := e.c.roleStore
	data, err := json.Marshal(&StoredRole{Version: storedRoleVersion, Role: role, Hash: role.Hash()})
	require.NoError(e.t, err)
	require.NoError(e.t, s.storage.Put(context.Background(), &sdklogical.StorageEntry{Key: roleStorageKey(ns.UUID, role.Name), Value: data}))
	s.mu.Lock()
	snap, _, err := s.loadAllLocked(context.Background())
	if err == nil {
		s.snapshot.Store(snap)
	}
	s.mu.Unlock()
	require.NoError(e.t, err)
	_, _, err = s.Get(namespace.ContextWithNamespace(context.Background(), ns), role.Name)
	require.NoError(e.t, err, "the legacy record loaded")
}

// An agent reaches a built-in through a static group only, once it is claimed:
// granted while its entity is governed and listed, with the static group on
// the grant; refused when only a virtual group lists it, and when the entity is
// suspended. An unclaimed agent is granted through a virtual group.
func TestBuiltinGrant_Agents(t *testing.T) {
	e := newIdentityEnv(t)
	g, hash, err := e.c.identityStore.GetGroup(e.ctx, "deployers")
	require.NoError(t, err)
	g.Roles = append(g.Roles, "warden-admin")
	_, err = e.c.identityStore.UpdateGroup(e.ctx, g, hash)
	require.NoError(t, err)

	req, _, te, err := e.check("warden-admin")
	requireGrantedBy(t, req, te, err, "warden-admin", "group:deployers", logical.GroupTypeVirtual)

	e.claim("terraform-runner")
	e.govern("terraform-runner")
	req, _, _, err = e.check("warden-admin")
	requireDenied(t, req, err, logical.RoleDeniedNotAssumable)

	en, _, err := e.c.identityStore.GetEntity(e.ctx, "terraform-runner")
	require.NoError(t, err)
	_, err = e.c.identityStore.CreateGroup(e.ctx, &logical.Group{Name: "terraform-runners", Type: logical.GroupTypeStatic,
		Roles: []string{"warden-admin"}, Members: []logical.GroupMember{{ID: en.ID}}})
	require.NoError(t, err)
	req, _, te, err = e.check("warden-admin")
	requireGrantedBy(t, req, te, err, "warden-admin", "group:terraform-runners", logical.GroupTypeStatic)
	assert.Nil(t, te.Policies)
	assert.Empty(t, te.CredentialSpec)

	e.setState("terraform-runner", logical.EntityStateSuspended)
	req, _, _, err = e.check("warden-admin")
	requireDenied(t, req, err, logical.RoleDeniedEntitySuspended)
}

// A built-in grant allocates nothing in the grant itself, like every other;
// compiling the CBP adds no allocation for the body once it is cached.
func TestBuiltinGrant_Allocations(t *testing.T) {
	e := newIdentityEnv(t)
	g, hash, err := e.c.identityStore.GetGroup(e.ctx, "deployers")
	require.NoError(t, err)
	g.Roles = append(g.Roles, "warden-admin")
	_, err = e.c.identityStore.UpdateGroup(e.ctx, g, hash)
	require.NoError(t, err)

	req := mustTransparent(e, e.token, "warden-admin")
	te := req.TokenEntry()
	now := time.Now()
	e.c.resolveRoleGrant(req, te, namespace.RootNamespace, now)
	require.True(t, req.RoleGrant().Granted(), req.RoleGrant().DeniedReason)
	assert.Zero(t, testing.AllocsPerRun(1000, func() { e.c.resolveRoleGrant(req, te, namespace.RootNamespace, now) }))

	plain := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID, Policies: []string{"deploy"}}
	build := func(role int) func() {
		return func() {
			if _, err := e.c.buildCBP(e.ctx, plain, namespace.RootNamespace, true, role); err != nil {
				t.Fatal(err)
			}
		}
	}
	build(-1)()
	build(0)()
	without := testing.AllocsPerRun(200, build(-1))
	with := testing.AllocsPerRun(200, build(0))
	assert.LessOrEqual(t, with-without, 2.0, "warden-admin's one stanza: measured %v without, %v with", without, with)
}
