package core

import (
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// governedAgent creates entity name, governed: a description and an accepted
// sponsor team.
func governedAgent(t *testing.T, c *Core, name string) *logical.Entity {
	t.Helper()
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{Name: name, Description: "Deploys " + name}))
	sponsorAccepted(t, c, rootCtx(), name, "leads")
	en, _, err := c.identityStore.GetEntity(rootCtx(), name)
	require.NoError(t, err)
	require.Equal(t, "warden", en.GovernedBy())
	return en
}

func staticBody(roles []any, members ...any) map[string]any {
	return map[string]any{"type": "static", "roles": roles, "members": members}
}

// A static group lists its members by name in and out, stores them by ID,
// follows a rename, hides a member deleted since and drops it on the next
// write; its fields are its own.
func TestStaticGroups_CRUD(t *testing.T) {
	c := setupEntityMounts(t)
	a := governedAgent(t, c, "a-agent")
	b := governedAgent(t, c, "b-agent")
	until := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	resp := groupRequest(t, c, logical.CreateOperation, "group/local-ops",
		staticBody([]any{"deploy", "ops"}, "b-agent", map[string]any{"name": "a-agent", "until": until.Format(time.RFC3339)}))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	members := resp.Data["members"].([]map[string]any)
	require.Len(t, members, 2)
	assert.Equal(t, map[string]any{"name": "a-agent", "id": a.ID, "until": until.Format(time.RFC3339Nano), "expired": false}, members[0])
	assert.Equal(t, map[string]any{"name": "b-agent", "id": b.ID, "until": "", "expired": false}, members[1])
	assert.Empty(t, resp.Data["rules"])

	g, _, err := c.identityStore.GetGroup(rootCtx(), "local-ops")
	require.NoError(t, err)
	ids := []string{g.Members[0].ID, g.Members[1].ID}
	assert.ElementsMatch(t, []string{a.ID, b.ID}, ids, "stored by ID")
	assert.True(t, g.Members[0].ID < g.Members[1].ID, "sorted by ID")

	// Fields of the other type, and unknown members, are refused.
	for name, body := range map[string]map[string]any{
		`"rules" is not valid on a static group`: {"type": "static", "rules": []any{map[string]any{"mount": "auth/jwt/"}}},
		`no entity "ghost" in this namespace`:    staticBody(nil, "ghost"),
		`unknown field "role"`:                   staticBody(nil, map[string]any{"name": "a-agent", "role": "x"}),
		`until must be an RFC 3339 timestamp`:    staticBody(nil, map[string]any{"name": "a-agent", "until": "tomorrow"}),
	} {
		resp = groupRequest(t, c, logical.CreateOperation, "group/bad", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
		assert.Contains(t, resp.Err.Error(), name)
	}
	resp = groupRequest(t, c, logical.CreateOperation, "group/bad", map[string]any{
		"type": "virtual", "members": []any{"a-agent"}, "rules": []any{map[string]any{"mount": "auth/jwt/"}},
	})
	assert.Contains(t, resp.Err.Error(), `"members" is not valid on a virtual group`)

	// A member another namespace holds is unknown here.
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), child))
	cctx := namespace.ContextWithNamespace(rootCtx(), child)
	resp = roleRequest(t, c, cctx, logical.CreateOperation, "identity/group/x", staticBody(nil, "a-agent"))
	assert.Contains(t, resp.Err.Error(), `no entity "a-agent" in this namespace`)

	// A rename shows; a listed entity knows its groups and roles.
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a-agent", map[string]any{"new_name": "a2-agent"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{"local-ops"}, resp.Data["groups"])
	assert.Equal(t, []string{"deploy", "ops"}, resp.Data["roles"])
	resp = groupRequest(t, c, logical.ReadOperation, "group/local-ops", nil)
	assert.Equal(t, "a2-agent", resp.Data["members"].([]map[string]any)[0]["name"])

	// Filters, both ways.
	resp = groupRequest(t, c, logical.ListOperation, "group", map[string]any{"member": "b-agent"})
	assert.Equal(t, []string{"local-ops"}, resp.Data["keys"])
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"group": "local-ops"})
	assert.Equal(t, []string{"a2-agent", "b-agent"}, resp.Data["keys"])
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"group": "leads"})
	assert.Contains(t, resp.Err.Error(), "only a static group lists its members")

	// A deleted member is hidden, then dropped on the group's next write.
	_, err = c.identityStore.DeleteEntity(rootCtx(), "b-agent", "", false)
	require.NoError(t, err)
	resp = groupRequest(t, c, logical.ReadOperation, "group/local-ops", nil)
	assert.Len(t, resp.Data["members"], 1, "hidden on read")
	g, _, _ = c.identityStore.GetGroup(rootCtx(), "local-ops")
	assert.Len(t, g.Members, 2, "still stored")
	resp = groupRequest(t, c, logical.UpdateOperation, "group/local-ops", map[string]any{"type": "static"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	g, _, _ = c.identityStore.GetGroup(rootCtx(), "local-ops")
	assert.Len(t, g.Members, 1, "dropped by a write")

	// It survives a reload.
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(rootCtx()))
	resp = groupRequest(t, c, logical.ReadOperation, "group/local-ops", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "static", resp.Data["type"])
	assert.Len(t, resp.Data["members"], 1)

	// A static group cannot sponsor: its members are agents.
	resp = tokenRequest(t, c, rootCtx(), rootEntry, logical.UpdateOperation, "identity/entity/a2-agent/sponsor",
		map[string]any{"group": "local-ops"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), errStaticSponsor)
}

// A member given by id stays that entity: a read's members written back as
// they were rendered keep their entities, and an entity deleted and created
// again under the same name between the read and the write is not taken for
// the one read.
func TestStaticGroups_MembersByID(t *testing.T) {
	c := setupEntityMounts(t)
	governedAgent(t, c, "a-agent")
	governedAgent(t, c, "b-agent")
	resp := groupRequest(t, c, logical.CreateOperation, "group/g", staticBody([]any{"deploy"}, "a-agent", "b-agent"))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	read := resp.Data["members"].([]map[string]any)

	// b-agent is deleted and created again between the read and the write.
	_, err := c.identityStore.DeleteEntity(rootCtx(), "b-agent", "", false)
	require.NoError(t, err)
	reborn := governedAgent(t, c, "b-agent")

	echoed := make([]any, len(read))
	for i, m := range read {
		echoed[i] = m // verbatim: name, id, until, expired
	}
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", staticBody([]any{"deploy"}, echoed...))
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	names := []string{}
	for _, m := range resp.Data["members"].([]map[string]any) {
		names = append(names, m["name"].(string))
		assert.NotEqual(t, reborn.ID, m["id"], "the new b-agent is not a member")
	}
	assert.Equal(t, []string{"a-agent"}, names, "the old b-agent is gone, and its name does not stand in for it")

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", staticBody(nil, map[string]any{"id": 7}))
	assert.Contains(t, resp.Err.Error(), "members[0]: id must be a string")
}

// An expired member stays stored and shows as expired until a write drops it,
// with a warning naming it; a write cannot add one already expired.
func TestStaticGroups_ExpiredMembers(t *testing.T) {
	c := setupEntityMounts(t)
	a := governedAgent(t, c, "a-agent")
	governedAgent(t, c, "b-agent")

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	resp := groupRequest(t, c, logical.CreateOperation, "group/g",
		staticBody([]any{"deploy"}, "b-agent", map[string]any{"name": "a-agent", "until": past}))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), "dropped 1 members past their until: a-agent")
	assert.Len(t, resp.Data["members"], 1)

	// One stored before it expired (written to storage as an earlier write
	// left it): listed as expired, then pruned by any write.
	g, hash, err := c.identityStore.GetGroup(rootCtx(), "g")
	require.NoError(t, err)
	g.Members = append(g.Members, logical.GroupMember{ID: a.ID, Until: time.Now().Add(-time.Minute).UTC()})
	data, err := json.Marshal(&StoredGroup{Version: storedGroupVersion, Group: g, Hash: hash})
	require.NoError(t, err)
	require.NoError(t, c.identityStore.storage.Put(rootCtx(), &sdklogical.StorageEntry{
		Key: groupStorageKey(namespace.RootNamespaceUUID, g.ID), Value: data,
	}))
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(rootCtx()))
	resp = groupRequest(t, c, logical.ReadOperation, "group/g", nil)
	var expired []any
	for _, m := range resp.Data["members"].([]map[string]any) {
		if m["expired"].(bool) {
			expired = append(expired, m["name"])
		}
	}
	assert.Equal(t, []any{"a-agent"}, expired)
	resp = entityRequest(t, c, logical.ReadOperation, "entity/a-agent", nil)
	assert.Empty(t, resp.Data["groups"], "an expired membership is not in force")
	assert.Equal(t, 2, readUsage(t, c).Static.Members, "expired members count until pruned")

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "static"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), "dropped 1 members past their until: a-agent")
	assert.Equal(t, 1, readUsage(t, c).Static.Members)
}

// The caps: members per group, memberships across the namespace (counted net
// of what a write replaces), and an until the member index cannot hold.
func TestStaticGroups_Caps(t *testing.T) {
	c := setupEntityMounts(t)
	members := make([]any, 0, logical.MaxStaticGroupMembers+1)
	for i := range logical.MaxStaticGroupMembers + 1 {
		name := "agent-" + strconv.Itoa(i)
		require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{Name: name}))
		members = append(members, name)
	}
	resp := groupRequest(t, c, logical.CreateOperation, "group/big", staticBody(nil, members...))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "at most 1000 members")
	resp = groupRequest(t, c, logical.CreateOperation, "group/big", staticBody(nil, members[:logical.MaxStaticGroupMembers]...))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	u := readUsage(t, c)
	assert.Equal(t, 1, u.Static.Count)
	assert.Equal(t, logical.MaxStaticGroupMembers, u.Static.Members)
	assert.Equal(t, logical.MaxStaticMembersPerNamespace, u.Static.MaxMembers)
	assert.Equal(t, logical.MaxStaticGroupMembers, u.Static.MaxGroupMembers)
	assert.Equal(t, 1, u.Total)

	// The namespace's memberships: 1000 now, a cap of 1010.
	c.identityStore.maxStaticMembers.Store(int64(logical.MaxStaticGroupMembers + 10))
	resp = groupRequest(t, c, logical.CreateOperation, "group/small", staticBody(nil, members[:10]...))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/small", staticBody(nil, members[:11]...))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "would make 1011/1010 memberships")
	resp = groupRequest(t, c, logical.UpdateOperation, "group/small", staticBody(nil, members[5:15]...))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a write replacing as many as it adds is net zero: %v", resp.Err)
	resp = groupRequest(t, c, logical.CreateOperation, "group/one-more", staticBody(nil, members[0]))
	assert.Contains(t, resp.Err.Error(), "would make 1011/1010 memberships")

	// Lowered below what the namespace holds: writes that add nothing pass.
	c.identityStore.maxStaticMembers.Store(500)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/small", staticBody([]any{"deploy"}, members[5:15]...))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/small", staticBody(nil, members[5:10]...))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a write removing members always passes: %v", resp.Err)

	resp = groupRequest(t, c, logical.UpdateOperation, "group/small",
		staticBody(nil, map[string]any{"name": "agent-1", "until": "2300-01-01T00:00:00Z"}))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "until must be no later than 2262-04-11T23:47:16.854775806Z")
}

// The grant table of a claimed caller: only a governed, active entity's
// static groups grant, their union, labelled by the first in name order;
// a membership grants through its until, inclusive, and the earliest end
// among the memberships in force bounds the cached membership.
func TestStaticGroups_GrantTable(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	en := governedAgent(t, c, "a-agent")
	_, err := c.identityStore.ClaimAlias(ctx, "a-agent", jwt, "sub-a", false)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	soon, later := now.Add(time.Minute), now.Add(time.Hour)
	_, err = c.identityStore.CreateGroup(ctx, &logical.Group{Name: "b-ops", Type: logical.GroupTypeStatic,
		Roles: []string{"deploy", "ops"}, Members: []logical.GroupMember{{ID: en.ID, Until: soon}}})
	require.NoError(t, err)
	_, err = c.identityStore.CreateGroup(ctx, &logical.Group{Name: "a-read", Type: logical.GroupTypeStatic,
		Roles: []string{"read", "ops"}, ValidUntil: later, Members: []logical.GroupMember{{ID: en.ID}}})
	require.NoError(t, err)
	// A virtual group matching the same credential never applies to it.
	_, err = c.identityStore.CreateGroup(ctx, &logical.Group{Name: "everyone", Type: logical.GroupTypeVirtual,
		Roles: []string{"admin"}, Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}}}})
	require.NoError(t, err)

	mf := &logical.MountFacts{}
	n := testNaming(t, "", nil)
	mf.Publish(n)
	adm := &logical.Admission{MountPath: "auth/jwt/", MountAccessor: jwt, AliasName: "sub-a", Mount: mf}
	m := compute(adm, n, c.identityStore.namespaceIndex(namespace.RootNamespaceID), now)
	assert.Equal(t, []string{"a-read", "b-ops"}, m.Groups)
	assert.Equal(t, logical.GroupGrant{Group: "a-read", Label: "group:a-read", Type: logical.GroupTypeStatic}, m.Roles["ops"],
		"two groups grant ops: the first by name labels it")
	assert.Equal(t, "group:b-ops", m.Roles["deploy"].Label)
	assert.NotContains(t, m.Roles, "admin", "the claim rule: no virtual group")
	assert.Equal(t, soon, m.ValidUntil, "the earliest end among the memberships in force")

	gs := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	m = compute(adm, n, gs, soon)
	assert.Contains(t, m.Groups, "b-ops", "until is inclusive")
	m = compute(adm, n, gs, soon.Add(time.Nanosecond))
	assert.Equal(t, []string{"a-read"}, m.Groups, "and nothing after")
	assert.Equal(t, later, m.ValidUntil)
	m = compute(adm, n, gs, later.Add(time.Nanosecond))
	assert.Empty(t, m.Groups, "the group's valid_until ends it too")

	// Ungoverned, suspended, retired: no group, though listed.
	for _, change := range []func(){
		func() {
			require.NoError(t, c.identityStore.SetEntityState(ctx, "a-agent", logical.EntityStateSuspended, nil, ""))
		},
		func() {
			require.NoError(t, c.identityStore.SetEntityState(ctx, "a-agent", logical.EntityStateRetired, nil, ""))
		},
	} {
		change()
		m = compute(adm, n, c.identityStore.namespaceIndex(namespace.RootNamespaceID), now)
		assert.Empty(t, m.Groups)
		assert.Empty(t, m.Roles)
		require.NotNil(t, m.Entity)
	}
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "u-agent", Aliases: []logical.EntityAlias{{MountAccessor: jwt, Name: "sub-u"}}}))
	u, _, _ := c.identityStore.GetEntity(ctx, "u-agent")
	g, _, _ := c.identityStore.GetGroup(ctx, "a-read")
	g.Members = append(g.Members, logical.GroupMember{ID: u.ID})
	_, err = c.identityStore.UpdateGroup(ctx, g, "")
	require.NoError(t, err)
	adm.AliasName = "sub-u"
	m = compute(adm, n, c.identityStore.namespaceIndex(namespace.RootNamespaceID), now)
	assert.Empty(t, m.Groups, "an ungoverned member holds nothing")
	assert.Equal(t, "u-agent", m.Entity.Name)

	// A remounted auth mount carries a new accessor: its callers are unclaimed
	// again, and virtual groups apply to them.
	adm.AliasName, adm.MountAccessor = "sub-a", "auth_jwt_remounted"
	m = compute(adm, n, c.identityStore.namespaceIndex(namespace.RootNamespaceID), now)
	assert.Nil(t, m.Entity)
	assert.Equal(t, []string{"everyone"}, m.Groups)
}

// Revocation through the request path: the next request after a member's
// removal, a roles edit, the group's delete or the entity's suspension is
// refused; nothing is cached on the token.
func TestStaticGroups_Revocation(t *testing.T) {
	for name, revoke := range map[string]func(e *grantEnv){
		"member removed": func(e *grantEnv) {
			g, _, _ := e.c.identityStore.GetGroup(e.ctx, "local-ops")
			g.Members = nil
			_, err := e.c.identityStore.UpdateGroup(e.ctx, g, "")
			require.NoError(e.t, err)
		},
		"roles edited": func(e *grantEnv) {
			g, _, _ := e.c.identityStore.GetGroup(e.ctx, "local-ops")
			g.Roles = []string{"other"}
			_, err := e.c.identityStore.UpdateGroup(e.ctx, g, "")
			require.NoError(e.t, err)
		},
		"group deleted": func(e *grantEnv) {
			_, err := e.c.identityStore.DeleteGroup(e.ctx, "local-ops", "", "", false)
			require.NoError(e.t, err)
		},
		"sponsor removed": func(e *grantEnv) {
			require.NoError(e.t, e.c.identityStore.ClearSponsor(e.ctx, "infra-agent", ""))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newIdentityEnv(t)
			e.claim("infra-agent")
			e.govern("infra-agent")
			e.staticDeploy("infra-agent")
			req, _, te, err := e.check("deploy")
			requireGrantedBy(t, req, te, err, "deploy", "group:local-ops", logical.GroupTypeStatic)
			revoke(e)
			req, _, _, err = e.check("deploy")
			require.Error(t, err)
			assert.False(t, req.RoleGrant().Granted())
			assert.NotEqual(t, "group:deployers", req.RoleGrant().GrantedBy, "the virtual grant never comes back")
		})
	}
}

// The member index a write updates incrementally is the one a full build
// gives, after every write of a random sequence of static and virtual
// creates, updates and deletes: the same entities, each with the same refs
// (group entry and until) in the same order, and the same counts. A virtual
// write shares the index it was given.
func TestStaticGroups_MemberIndexIncremental(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	byName := map[string]*groupEntry{}
	mi := buildMemberIndex(byName)
	now := time.Now().UTC()
	entry := func(name string, typ logical.GroupType) *groupEntry {
		g := &logical.Group{Name: name, Type: typ, Roles: []string{"r" + strconv.Itoa(rng.IntN(5))}}
		if typ == logical.GroupTypeVirtual {
			g.Rules = []logical.GroupRule{{"mount": {"auth/jwt/"}}}
		} else {
			for _, i := range rng.Perm(40)[:rng.IntN(12)] {
				m := logical.GroupMember{ID: "e" + strconv.Itoa(i)}
				if rng.IntN(3) == 0 {
					m.Until = now.Add(time.Duration(rng.IntN(1000)) * time.Minute)
				}
				g.Members = append(g.Members, m)
			}
			slices.SortFunc(g.Members, func(a, b logical.GroupMember) int { return strings.Compare(a.ID, b.ID) })
			if rng.IntN(4) == 0 {
				g.ValidUntil = now.Add(time.Hour)
			}
		}
		cg, err := compileGroup(g)
		require.NoError(t, err)
		cg.Group = g
		return cg
	}
	type refView struct {
		group *groupEntry
		until int64
	}
	view := func(mi *memberIndex) map[string][]refView {
		out := map[string][]refView{}
		for id, refs := range mi.byEntity {
			for _, r := range refs {
				out[id] = append(out[id], refView(r))
			}
		}
		return out
	}
	for step := range 5000 {
		name := "g" + strconv.Itoa(rng.IntN(30))
		old := byName[name]
		var next *groupEntry
		switch {
		case old != nil && rng.IntN(4) == 0: // delete
		case old != nil:
			next = entry(name, old.Type) // update: the type never changes
		default:
			typ := logical.GroupTypeStatic
			if rng.IntN(3) == 0 {
				typ = logical.GroupTypeVirtual
			}
			next = entry(name, typ)
		}
		if next == nil {
			delete(byName, name)
		} else {
			byName[name] = next
		}
		prev := mi
		mi = mi.with(old, next)
		full := buildMemberIndex(byName)
		require.Equal(t, view(full), view(mi), "step %d", step)
		require.Equal(t, full.groups, mi.groups, "step %d", step)
		require.Equal(t, full.members, mi.members, "step %d", step)
		if (old == nil || old.Type == logical.GroupTypeVirtual) && (next == nil || next.Type == logical.GroupTypeVirtual) {
			require.Same(t, prev, mi, "step %d: a virtual write shares the index", step)
		}
	}
}

// A membership ending at the epoch, as a record could hold one, is expired:
// the member index never reads an end it cannot encode as no end.
func TestStaticGroups_EndEncoding(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		until   time.Time
		inForce bool
	}{
		"no end":       {time.Time{}, true},
		"the epoch":    {time.Unix(0, 0), false},
		"before 1678":  {time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC), false},
		"after 2262":   {time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC), true},
		"now":          {now, true},
		"a second ago": {now.Add(-time.Second), false},
	} {
		g := &logical.Group{Name: "g", Type: logical.GroupTypeStatic, Members: []logical.GroupMember{{ID: "e1", Until: tc.until}}}
		cg, err := compileGroup(g)
		require.NoError(t, err)
		cg.Group = g
		m := &logical.Membership{Groups: noGroups}
		staticMembership(m, buildMemberIndex(map[string]*groupEntry{"g": cg}).byEntity["e1"], now)
		assert.Equal(t, tc.inForce, len(m.Groups) == 1, name)
	}
}

// Claiming warns, every time a native identity is newly claimed; a move
// between entities does not.
func TestStaticGroups_ClaimWarnings(t *testing.T) {
	c := setupEntityMounts(t)
	body := map[string]any{"aliases": []any{map[string]any{"mount": "auth/jwt/", "name": "repo:x"}}}
	resp := entityRequest(t, c, logical.CreateOperation, "entity/a-agent", body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{`native identity (auth/jwt/, repo:x) is now claimed by entity "a-agent": virtual groups no longer ` +
		`grant it roles; it holds only the roles its entity's static groups grant, and none until the entity is governed`},
		respWarnings(resp))

	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{Name: "b-agent"}))
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/b-agent/alias", map[string]any{"mount": "auth/jwt/", "name": "repo:y"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Len(t, respWarnings(resp), 1)
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/b-agent/alias", map[string]any{"mount": "auth/jwt/", "name": "repo:x", "move": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Empty(t, respWarnings(resp), "already claimed: nothing changes for virtual groups")
}
