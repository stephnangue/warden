package core

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// Every cell of the identity verdict: rows A–D under observe and deny, with
// and without an exempt mount, and a human admission, never judged.
func TestIdentityVerdict_Rows(t *testing.T) {
	agent := &logical.MountNaming{Kind: logical.EntityKindAgent}
	human := &logical.MountNaming{Kind: logical.EntityKindHuman}
	governed := &logical.Entity{Name: "a", Description: "x", State: logical.EntityStateActive,
		Sponsor: &logical.EntitySponsor{Type: logical.SponsorTypeGroup}}
	ungoverned := &logical.Entity{Name: "a", State: logical.EntityStateActive}
	suspended := &logical.Entity{Name: "a", Description: "x", State: logical.EntityStateSuspended, Sponsor: governed.Sponsor}
	retired := &logical.Entity{Name: "a", State: logical.EntityStateRetired}

	deny := &identityConfig{UnknownAliases: unknownAliasesDeny}
	denyExempt := &identityConfig{UnknownAliases: unknownAliasesDeny, ExemptMounts: []string{"acc"}}
	type row struct {
		alias  string
		entity *logical.Entity
	}
	rows := map[string]row{
		"A no native identity":  {"", nil},
		"B unclaimed":           {"repo:x", nil},
		"C suspended":           {"repo:x", suspended},
		"C retired":             {"repo:x", retired},
		"D claimed, ungoverned": {"repo:x", ungoverned},
		"governed and active":   {"repo:x", governed},
	}
	want := map[string]map[string]string{ // row -> config -> reason
		"A no native identity":  {"observe": "", "deny": logical.RoleDeniedIdentityNone, "deny+exempt": ""},
		"B unclaimed":           {"observe": "", "deny": logical.RoleDeniedIdentityUnclaimed, "deny+exempt": ""},
		"C suspended":           {"observe": logical.RoleDeniedEntitySuspended, "deny": logical.RoleDeniedEntitySuspended, "deny+exempt": logical.RoleDeniedEntitySuspended},
		"C retired":             {"observe": logical.RoleDeniedEntityRetired, "deny": logical.RoleDeniedEntityRetired, "deny+exempt": logical.RoleDeniedEntityRetired},
		"D claimed, ungoverned": {"observe": "", "deny": logical.RoleDeniedEntityNotGoverned, "deny+exempt": ""},
		"governed and active":   {"observe": "", "deny": "", "deny+exempt": ""},
	}
	configs := map[string]*identityConfig{"observe": nil, "deny": deny, "deny+exempt": denyExempt}
	for name, r := range rows {
		for cname, cfg := range configs {
			adm := &logical.Admission{MountAccessor: "acc", AliasName: r.alias}
			got := identityVerdict(cfg, adm, &logical.Membership{Naming: agent, Entity: r.entity})
			assert.Equal(t, want[name][cname], got, "%s under %s", name, cname)

			// A human is never judged, in any mode.
			assert.Empty(t, identityVerdict(cfg, adm, &logical.Membership{Naming: human, Entity: r.entity}), "human, %s under %s", name, cname)
			humanAdm := &logical.Admission{MountAccessor: "acc", AliasName: r.alias, Kind: logical.EntityKindHuman}
			assert.Empty(t, identityVerdict(cfg, humanAdm, &logical.Membership{Naming: agent, Entity: r.entity}), "ticket, %s under %s", name, cname)
		}
	}
	assert.Zero(t, testing.AllocsPerRun(100, func() {
		identityVerdict(deny, &logical.Admission{AliasName: "x"}, &logical.Membership{Naming: agent, Entity: suspended})
	}))
}

// identityEnv is a grantEnv whose admission presents the native identity
// (auth/jwt/, agent-1).
func newIdentityEnv(t *testing.T) *grantEnv {
	t.Helper()
	e := newGrantEnv(t)
	e.adm.AliasName, e.adm.MountAccessor = "agent-1", grantAccessor
	return e
}

func (e *grantEnv) claim(name string) {
	e.t.Helper()
	require.NoError(e.t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{
		Name: name, Aliases: []logical.EntityAlias{{MountAccessor: grantAccessor, Name: "agent-1"}},
	}))
}

func (e *grantEnv) govern(name string) {
	e.t.Helper()
	ent, _, err := e.c.identityStore.GetEntity(e.ctx, name)
	require.NoError(e.t, err)
	ent.Description = "Deploys acme/infra"
	require.NoError(e.t, e.c.identityStore.UpdateEntity(e.ctx, name, ent, ""))
	proposeSponsor(e.t, e.c, e.ctx, e.ctx, name, "infra-leads", true)
}

func (e *grantEnv) setState(name string, st logical.EntityState) {
	e.t.Helper()
	require.NoError(e.t, e.c.identityStore.SetEntityState(e.ctx, name, st, nil, ""))
}

func (e *grantEnv) setConfig(cfg *identityConfig) {
	e.t.Helper()
	require.NoError(e.t, e.c.identityStore.SetIdentityConfig(e.ctx, cfg))
}

// Through CheckToken, with the cached admission: the entity resolves on the
// next request after every identity write, the kill switch refuses in every
// mode, and deny refuses the unknown and the ungoverned unless exempt.
func TestIdentityResolution_RequestPath(t *testing.T) {
	e := newIdentityEnv(t)

	// Unclaimed, default config: granted, no entity.
	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	assert.Nil(t, te.Entity)

	// Claimed: the entity resolves on the next request. It keeps its virtual
	// grant (the claim rule comes with static groups).
	e.claim("infra-agent")
	req, _, te, err = e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	require.NotNil(t, te.Entity)
	assert.Equal(t, "infra-agent", te.Entity.Name)

	// The kill switch, in the default mode.
	e.setState("infra-agent", logical.EntityStateSuspended)
	req, _, _, err = e.check("deploy")
	rerr := requireDenied(t, req, err, logical.RoleDeniedEntitySuspended)
	assert.Equal(t, `native identity (auth/jwt/, agent-1) belongs to entity "infra-agent", which is suspended`, rerr.Message)
	e.setState("infra-agent", logical.EntityStateActive)
	req, _, te, err = e.check("deploy")
	requireGranted(t, req, te, err, "deploy")

	// deny: a claimed, ungoverned caller is refused, naming why.
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
	req, _, _, err = e.check("deploy")
	rerr = requireDenied(t, req, err, logical.RoleDeniedEntityNotGoverned)
	assert.Equal(t, `native identity (auth/jwt/, agent-1) belongs to entity "infra-agent", which is not governed; unknown_aliases=deny`,
		rerr.Message, "the agent is not told what its entity lacks")

	// Governed: granted.
	e.govern("infra-agent")
	req, _, te, err = e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	assert.Equal(t, "warden", te.Entity.GovernedBy())

	// The suspension beats every exemption.
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny, ExemptMounts: []string{grantAccessor}})
	e.setState("infra-agent", logical.EntityStateSuspended)
	req, _, _, err = e.check("deploy")
	requireDenied(t, req, err, logical.RoleDeniedEntitySuspended)

	// Unclaimed under deny: refused; through an exempt mount, granted.
	_, err = e.c.identityStore.DeleteEntity(e.ctx, "infra-agent", "", false)
	require.NoError(t, err)
	req, _, te, err = e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	assert.Nil(t, te.Entity, "a deleted entity resolves no more")
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
	req, _, _, err = e.check("deploy")
	rerr = requireDenied(t, req, err, logical.RoleDeniedIdentityUnclaimed)
	assert.Equal(t, "native identity (auth/jwt/, agent-1) is unclaimed; unknown_aliases=deny", rerr.Message)

	// No native identity under deny.
	e.adm.AliasName = ""
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny}) // a new generation: the membership computes again
	req, _, _, err = e.check("deploy")
	rerr = requireDenied(t, req, err, logical.RoleDeniedIdentityNone)
	assert.Contains(t, rerr.Message, "presents no native identity through auth/jwt/")

	// Back to the defaults: granted.
	e.setConfig(nil)
	req, _, te, err = e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
}

// An identity refusal fails closed by construction: the refused grant leaves
// the token no policies and the CBP no built-ins, so with the role verdict
// skipped the CBP alone still refuses.
func TestIdentityResolution_FailsClosedWithoutVerdict(t *testing.T) {
	e := newIdentityEnv(t)
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
	testHookSkipRoleVerdict = true
	defer func() { testHookSkipRoleVerdict = false }()
	req, _, te, err := e.check("deploy")
	require.Error(t, err)
	assert.False(t, req.RoleGrant().Granted())
	assert.Equal(t, logical.RoleDeniedIdentityUnclaimed, req.RoleGrant().DeniedReason)
	assert.Empty(t, te.Policies, "no policies to authorize with")
	assert.Empty(t, te.RoleName)
}

// A retired entity refuses in every mode; the refusal is the identity's, ahead
// of any role, even one that does not exist.
func TestIdentityResolution_RetiredBeforeRole(t *testing.T) {
	e := newIdentityEnv(t)
	e.claim("old-agent")
	e.setState("old-agent", logical.EntityStateRetired)
	for _, role := range []string{"deploy", "nope", ""} {
		req, _, _, err := e.check(role)
		requireDenied(t, req, err, logical.RoleDeniedEntityRetired)
	}
}

// The verdict changes nothing for a token no mount issued, nor for a human
// admission: a ticket's role is its groups' alone, whatever unknown_aliases
// says.
func TestIdentityResolution_HumansAndRootUntouched(t *testing.T) {
	e := newTicketRequestEnv(t)
	require.NoError(t, e.c.identityStore.SetIdentityConfig(e.ctx, &identityConfig{UnknownAliases: unknownAliasesDeny}))
	resp, req, err := e.do("sys/providers?role=operator", wardenToken(e.value))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy)
	assert.Empty(t, e.audit.requestFor(t, "sys/providers").Auth.EntityID, "a human is never resolved to an entity")
}

// Resolving the entity and judging it allocate nothing on a steady
// membership, granted or refused.
func TestIdentityResolution_DoesNotAllocate(t *testing.T) {
	for name, setup := range map[string]func(e *grantEnv){
		"claimed and governed, deny": func(e *grantEnv) {
			e.claim("a")
			e.govern("a")
			e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
		},
		"suspended": func(e *grantEnv) {
			e.claim("a")
			e.setState("a", logical.EntityStateSuspended)
		},
		"unclaimed, deny": func(e *grantEnv) {
			e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newIdentityEnv(t)
			setup(e)
			req := mustTransparent(e, e.token, "deploy")
			te := req.TokenEntry()
			now := time.Now()
			e.c.resolveRoleGrant(req, te, now)
			assert.Zero(t, testing.AllocsPerRun(1000, func() { e.c.resolveRoleGrant(req, te, now) }))
		})
	}
}

// A condition reads the agent's entity and native identity; one reading an
// entity the caller does not have fails closed.
func TestIdentityResolution_CEL(t *testing.T) {
	e := newIdentityEnv(t)
	e.setPolicy("deploy", `path "secret/*" {
  capabilities = ["read"]
  condition    = "agent.entity.name == 'infra-agent' && agent.entity.state == 'active' && agent.alias == 'agent-1'"
}`)
	_, _, _, err := e.check("deploy")
	require.Error(t, err, "no entity: the condition fails closed")

	e.claim("infra-agent")
	_, _, _, err = e.check("deploy")
	require.NoError(t, err)

	in := celAgentInput(&logical.Request{}, &logical.TokenEntry{
		Admission: &logical.Admission{AliasName: "agent-1"},
		Entity: &logical.Entity{ID: "e1", Name: "infra-agent", Kind: "agent", State: logical.EntityStateActive,
			Profile: &logical.AgentProfile{Runtime: "langgraph"}},
	}, time.Now())
	m := buildPrincipalNS(in, fieldSet{all: true}, legAgent)
	assert.Equal(t, "agent-1", m["alias"])
	ent := m["entity"].(map[string]any)
	assert.Equal(t, "infra-agent", ent["name"])
	assert.Equal(t, "", ent["governed_by"])
	assert.Equal(t, map[string]string{"runtime": "langgraph"}, ent["profile"])
	assert.NotContains(t, buildPrincipalNS(celPrincipalInput{}, fieldSet{all: true}, legAgent), "entity")
	assert.NotContains(t, buildPrincipalNS(in, fieldSet{all: true}, legUser), "entity", "the agent's alone")
}

// The audit names the entity a request resolved.
func TestIdentityResolution_Audit(t *testing.T) {
	ent := &logical.Entity{ID: "e1", Name: "infra-agent", Description: "x", Sponsor: &logical.EntitySponsor{Type: logical.SponsorTypeGroup}}
	a := buildAuditAuth(nil, &logical.TokenEntry{ID: "t", Entity: ent})
	assert.Equal(t, "e1", a.EntityID)
	assert.Equal(t, "infra-agent", a.EntityName)
	assert.Equal(t, "warden", a.GovernedBy)
	a = buildAuditAuth(nil, &logical.TokenEntry{ID: "t"})
	assert.Empty(t, a.EntityID)
}

// Discovery applies the verdict per admitted mount: a refused identity is
// admitted but granted nothing, so its menu is empty, and the menu says
// nothing about why.
func TestIdentityResolution_Discovery(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	n := testNaming(t, "", map[string]string{"repository": "repo"})
	n.AliasSource = "sub"
	m.mf.Publish(n)
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
	unclaimed := e.introspectJSON()

	accessor := accessorOf(t, e.c, "jwt/")
	ent := &logical.Entity{Name: "infra-agent", Aliases: []logical.EntityAlias{{MountAccessor: accessor, Name: "agent-1"}}}
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, ent))
	require.NotEmpty(t, ent.ID)
	rec := &auditCapture{}
	e.c.auditManager = rec
	assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()), "claimed keeps its virtual grants for now")
	entry := introspectEntry(t, rec)
	require.NotNil(t, entry.Auth.Discovery)
	require.Len(t, entry.Auth.Discovery.AdmittedBy, 1)
	assert.Equal(t, ent.ID, entry.Auth.Discovery.AdmittedBy[0].EntityID, "admitted_by names the claiming entity")

	require.NoError(t, e.c.identityStore.SetEntityState(e.ctx, "infra-agent", logical.EntityStateSuspended, nil, ""))
	assert.Empty(t, e.introspectRoles(), "a suspended entity's menu is empty")

	require.NoError(t, e.c.identityStore.SetEntityState(e.ctx, "infra-agent", logical.EntityStateActive, nil, ""))
	require.NoError(t, e.c.identityStore.SetIdentityConfig(e.ctx, &identityConfig{UnknownAliases: unknownAliasesDeny}))
	assert.Empty(t, e.introspectRoles(), "claimed and ungoverned, under deny")

	_, err := e.c.identityStore.DeleteEntity(e.ctx, "infra-agent", "", false)
	require.NoError(t, err)
	refused := e.introspectJSON()
	assert.Empty(t, e.introspectRoles(), "unclaimed, under deny")

	require.NoError(t, e.c.identityStore.SetIdentityConfig(e.ctx, &identityConfig{UnknownAliases: unknownAliasesDeny, ExemptMounts: []string{accessor}}))
	assert.Equal(t, unclaimed, e.introspectJSON(), "an exempt mount lists as before")

	// An empty menu reads the same whatever the cause.
	e.group("deployers-2", nil, time.Time{}, discRule([]string{"auth/jwt/"}, "nobody/*"))
	require.NoError(t, e.c.identityStore.SetIdentityConfig(e.ctx, nil))
	_, err = e.c.identityStore.DeleteGroup(e.ctx, "deployers", "", "", false)
	require.NoError(t, err)
	assert.Equal(t, refused, e.introspectJSON(), "refused and no-match menus are byte-identical")
}

// sys/identity/config: defaults, a write of the fields it names, exempt mounts
// by path in and accessor stored, warnings, reset, reload, namespace clear.
func TestIdentityConfig_Paths(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	cfgReq := func(op logical.Operation, data map[string]any) *logical.Response {
		return tokenRequest(t, c, ctx, rootEntry, op, "identity/config", data)
	}
	resp := cfgReq(logical.ReadOperation, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "observe", resp.Data["unknown_aliases"])
	assert.Empty(t, resp.Data["exempt_mounts"])

	resp = cfgReq(logical.UpdateOperation, map[string]any{"unknown_aliases": "deny", "exempt_mounts": []string{"auth/jwt/", "auth/humans/"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "deny", resp.Data["unknown_aliases"])
	assert.Len(t, resp.Data["exempt_mounts"], 2)
	assert.Equal(t, []string{"exempt mount auth/humans/ admits humans, whom unknown_aliases never refuses; it has no effect"},
		respWarnings(resp))

	// A field left out keeps its value.
	resp = cfgReq(logical.UpdateOperation, map[string]any{"exempt_mounts": []string{"auth/jwt/"}})
	assert.Equal(t, "deny", resp.Data["unknown_aliases"])
	assert.Equal(t, []map[string]any{{"mount": "auth/jwt/", "mount_accessor": accessorOf(t, c, "jwt/")}}, resp.Data["exempt_mounts"])

	for name, body := range map[string]map[string]any{
		"bad mode":       {"unknown_aliases": "ignore"},
		"no such mount":  {"exempt_mounts": []string{"auth/nope/"}},
		"not auth mount": {"exempt_mounts": []string{"sys/"}},
	} {
		assert.Equal(t, http.StatusBadRequest, cfgReq(logical.UpdateOperation, body).StatusCode, name)
	}

	// Stored: a reload keeps it.
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(ctx))
	cfg, err := c.identityStore.IdentityConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, unknownAliasesDeny, cfg.mode())
	assert.True(t, cfg.exempt(accessorOf(t, c, "jwt/")))

	// A mount disabled since is shown by accessor and warned about.
	require.Equal(t, http.StatusOK, roleRequest(t, c, ctx, logical.DeleteOperation, "auth/jwt", nil).StatusCode)
	resp = cfgReq(logical.ReadOperation, nil)
	assert.Equal(t, "", resp.Data["exempt_mounts"].([]map[string]any)[0]["mount"])
	assert.Contains(t, respWarnings(resp)[0], "names no auth mount any more")

	// Reset removes the stored record.
	resp = cfgReq(logical.DeleteOperation, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "observe", resp.Data["unknown_aliases"])
	entry, err := c.identityStore.storage.Get(ctx, identityConfigKey(namespace.RootNamespace.UUID))
	require.NoError(t, err)
	assert.Nil(t, entry)

	// ClearNamespace removes it too.
	cfgReq(logical.UpdateOperation, map[string]any{"unknown_aliases": "deny"})
	require.NoError(t, c.identityStore.ClearNamespace(ctx))
	entry, err = c.identityStore.storage.Get(ctx, identityConfigKey(namespace.RootNamespace.UUID))
	require.NoError(t, err)
	assert.Nil(t, entry)
	assert.Same(t, emptyNSIndex, c.identityStore.namespaceIndex(namespace.RootNamespaceID))

	assert.True(t, c.router.RootPath(ctx, "sys/identity/config"), "sudo")
}

// A namespace that only has a config is published, and keeps it across group
// and entity publishes.
func TestIdentityConfig_SurvivesPublishes(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.SetIdentityConfig(ctx, &identityConfig{UnknownAliases: unknownAliasesDeny}))
	assert.Equal(t, unknownAliasesDeny, c.identityStore.namespaceIndex(namespace.RootNamespaceID).config.mode())
	_, err := c.identityStore.CreateGroup(ctx, humanGroup("g"))
	require.NoError(t, err)
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	_, err = c.identityStore.DeleteGroup(ctx, "g", "", "", false)
	require.NoError(t, err)
	_, err = c.identityStore.DeleteEntity(ctx, "a", "", false)
	require.NoError(t, err)
	assert.Equal(t, unknownAliasesDeny, c.identityStore.namespaceIndex(namespace.RootNamespaceID).config.mode(),
		"the config outlives every group and entity")
}

// The lockout guard: a config that would refuse its writer, and a write on the
// writer's own entity, need force; root is never guarded.
func TestIdentityResolution_LockoutGuard(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{
		Name: "ops-agent", Aliases: []logical.EntityAlias{{MountAccessor: jwt, Name: "ops"}},
	}))
	ent, _, err := c.identityStore.GetEntity(ctx, "ops-agent")
	require.NoError(t, err)
	mf := &logical.MountFacts{}
	mf.Publish(testNaming(t, "", nil))
	writer := &logical.TokenEntry{ID: "w", PrincipalID: "ops", MountAccessor: jwt, NamespaceID: namespace.RootNamespaceID,
		Admission: &logical.Admission{MountAccessor: jwt, AliasName: "ops", Mount: mf}, Entity: ent}

	// deny would refuse the writer (its entity is ungoverned).
	resp := tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/config", map[string]any{"unknown_aliases": "deny"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "would refuse the writer's own requests (entity not governed)")
	resp = tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/config", map[string]any{"unknown_aliases": "deny", "force": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp)[0], "forced")
	resp = tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/config", map[string]any{"unknown_aliases": "observe"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "root is never guarded")

	// The writer's own entity.
	for path, body := range map[string]map[string]any{
		"identity/entity/ops-agent/state":          {"state": "suspended"},
		"identity/entity/ops-agent":                {"description": ""},
		"identity/entity/ops-agent/alias/remove":   {"mount": "auth/jwt/", "name": "ops"},
		"identity/entity/ops-agent/sponsor/remove": {},
	} {
		resp := tokenRequest(t, c, ctx, writer, logical.UpdateOperation, path, body)
		assert.Equal(t, http.StatusConflict, resp.StatusCode, path)
		assert.Contains(t, resp.Err.Error(), "is the writer's own", path)
	}
	resp = tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/entity/ops-agent/state", map[string]any{"state": "suspended", "force": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), `forced: entity "ops-agent" is the writer's own`)

	// Another entity, and root, are not guarded.
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "other"}))
	resp = tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/entity/other/state", map[string]any{"state": "active"})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	resp = tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/ops-agent/state", map[string]any{"state": "active"})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)

	// Moving the writer's own native identity to another entity is guarded
	// too, though the target is not the writer's.
	move := map[string]any{"mount": "auth/jwt/", "name": "ops", "move": true}
	resp = tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/entity/other/alias", move)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "is the writer's own")
	move["force"] = true
	resp = tokenRequest(t, c, ctx, writer, logical.UpdateOperation, "identity/entity/other/alias", move)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), "forced: native identity (auth/jwt/, ops) is the writer's own")

	// Deleting the writer's own entity is guarded.
	resp = tokenRequest(t, c, ctx, writer, logical.DeleteOperation, "identity/entity/ops-agent", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = tokenRequest(t, c, ctx, writer, logical.DeleteOperation, "identity/entity/ops-agent", map[string]any{"force": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
}

// A parent namespace's token writing a child's config is judged by its own
// namespace's config, so the child's deny never needs force from it.
func TestIdentityConfig_ParentWriterNotJudgedByChild(t *testing.T) {
	c := setupEntityMounts(t)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), child))
	cctx := namespace.ContextWithNamespace(rootCtx(), child)
	mf := &logical.MountFacts{}
	mf.Publish(testNaming(t, "", nil))
	jwt := accessorOf(t, c, "jwt/")
	parentAgent := &logical.TokenEntry{ID: "w", PrincipalID: "ops", MountAccessor: jwt, NamespaceID: namespace.RootNamespaceID,
		Admission: &logical.Admission{MountAccessor: jwt, AliasName: "ops", Mount: mf}}
	resp := tokenRequest(t, c, cctx, parentAgent, logical.UpdateOperation, "identity/config", map[string]any{"unknown_aliases": "deny"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Empty(t, respWarnings(resp))
	// In its own namespace, the same write would refuse it.
	resp = tokenRequest(t, c, rootCtx(), parentAgent, logical.UpdateOperation, "identity/config", map[string]any{"unknown_aliases": "deny"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// Under deny, an exempt mount's unclaimed caller still meets the role row: the
// exemption is from the identity verdict, never from the role.
func TestIdentityResolution_RoleRowOnExemptMount(t *testing.T) {
	e := newIdentityEnv(t)
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny, ExemptMounts: []string{grantAccessor}})
	req, _, te, err := e.check("deploy")
	requireGranted(t, req, te, err, "deploy")
	req, _, _, err = e.check("other")
	requireDenied(t, req, err, logical.RoleDeniedNotAssumable)
}

// Resolution reads only the published index: thousands of unknown identities
// write nothing and never take the store's lock.
func TestIdentityResolution_NoStorageWrite(t *testing.T) {
	e := newIdentityEnv(t)
	e.setConfig(&identityConfig{UnknownAliases: unknownAliasesDeny})
	spy := &spyStorage{Storage: e.c.identityStore.storage}
	e.c.identityStore.storage = spy
	e.c.identityStore.mu.Lock() // held: a resolution that took it would deadlock the test
	defer e.c.identityStore.mu.Unlock()
	now := time.Now()
	for i := range 10000 {
		adm := e.admission(grantMount)
		adm.MountAccessor, adm.AliasName = grantAccessor, "unknown-"+strconv.Itoa(i)
		te := &logical.TokenEntry{ID: "t", MountAccessor: grantAccessor, NamespaceID: namespace.RootNamespaceID, Admission: adm}
		req := &logical.Request{Transparent: true, RequestedRole: "deploy"}
		e.c.resolveRoleGrant(req, te, now)
		require.Equal(t, logical.RoleDeniedIdentityUnclaimed, req.RoleGrant().DeniedReason)
	}
	assert.Empty(t, spy.puts)
}
