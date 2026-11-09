package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// humanGroup is a virtual group of the humans the auth/humans/ mount admits.
func humanGroup(name string) *logical.Group {
	return &logical.Group{
		Name:  name,
		Type:  logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/humans/"}, "kind": {"human"}}},
	}
}

// proposeSponsor proposes group, of the namespace in groupCtx, as the sponsor
// of entity, in the namespace in ctx, creating a human group of that name
// when there is none. accepted makes it the sponsor at once, as a member's
// proposal does.
func proposeSponsor(t *testing.T, c *Core, ctx, groupCtx context.Context, entity, group string, accepted bool) *logical.EntitySponsor {
	t.Helper()
	gns, err := namespace.FromContext(groupCtx)
	require.NoError(t, err)
	if _, _, err := c.identityStore.GetGroup(groupCtx, group); err != nil {
		_, err := c.identityStore.CreateGroup(groupCtx, humanGroup(group))
		require.NoError(t, err)
	}
	g := c.identityStore.namespaceIndex(gns.ID).groupsByName[group]
	sp := &logical.EntitySponsor{
		Type: logical.SponsorTypeGroup, Namespace: gns.ID, GroupID: g.ID, Group: group,
		AddedBy: logical.SponsorActor{Principal: "alice"}, AddedAt: time.Now().UTC(),
	}
	_, err = c.identityStore.ProposeSponsor(ctx, entity, sp, accepted, nil, "")
	require.NoError(t, err)
	return sp
}

// sponsorAccepted makes group, of the entity's namespace, the entity's
// accepted sponsor.
func sponsorAccepted(t *testing.T, c *Core, ctx context.Context, entity, group string) *logical.EntitySponsor {
	t.Helper()
	return proposeSponsor(t, c, ctx, ctx, entity, group, true)
}

// rootEntry is the token entry of a root token, which no mount issued.
var rootEntry = &logical.TokenEntry{ID: "root-id", Accessor: "root-accessor", PrincipalID: "root"}

// tokenRequest runs a request on the system backend carrying te, as the
// request path hands one to a handler.
func tokenRequest(t *testing.T, c *Core, ctx context.Context, te *logical.TokenEntry, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	req := &logical.Request{Operation: op, Path: path, Data: data}
	req.SetTokenEntry(te)
	resp, err := c.systemBackend.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func TestEntitySponsor_HashAndClone(t *testing.T) {
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	sp := func(group string, accepted bool) *logical.EntitySponsor {
		s := &logical.EntitySponsor{
			Type: logical.SponsorTypeGroup, Namespace: "root", GroupID: group + "-id", Group: group,
			AddedBy: logical.SponsorActor{MountAccessor: "auth_oidc_1", Alias: "oid-a", Principal: "oid-a"}, AddedAt: at,
		}
		if accepted {
			s.AcceptedBy, s.AcceptedAt = s.AddedBy, at
		}
		return s
	}
	base := &logical.Entity{Name: "a", Kind: logical.EntityKindAgent, State: logical.EntityStateActive}
	seen := map[string]string{base.Hash(): "no sponsor"}
	for name, edit := range map[string]func(e *logical.Entity){
		"sponsor":           func(e *logical.Entity) { e.Sponsor = sp("leads", true) },
		"pending":           func(e *logical.Entity) { e.PendingSponsor = sp("leads", false) },
		"another sponsor":   func(e *logical.Entity) { e.Sponsor = sp("oncall", true) },
		"sponsor + pending": func(e *logical.Entity) { e.Sponsor, e.PendingSponsor = sp("leads", true), sp("oncall", false) },
		"another proposer": func(e *logical.Entity) {
			e.Sponsor = sp("leads", true)
			e.Sponsor.AddedBy.MountAccessor = "auth_oidc_2"
		},
		"another acceptor":   func(e *logical.Entity) { e.Sponsor = sp("leads", true); e.Sponsor.AcceptedBy.Alias = "oid-b" },
		"another namespace":  func(e *logical.Entity) { e.Sponsor = sp("leads", true); e.Sponsor.Namespace = "ns1" },
		"suspended":          func(e *logical.Entity) { e.State = logical.EntityStateSuspended },
		"same group, slot 2": func(e *logical.Entity) { e.PendingSponsor = sp("oncall", false) },
	} {
		e := base.Clone()
		edit(e)
		h := e.Hash()
		prev, dup := seen[h]
		assert.False(t, dup, "%s hashes like %s", name, prev)
		seen[h] = name
	}

	// Timestamps are not part of the hash.
	a, b := base.Clone(), base.Clone()
	a.Sponsor, b.Sponsor = sp("leads", true), sp("leads", true)
	b.Sponsor.AddedAt, b.Sponsor.AcceptedAt = at.Add(time.Hour), at.Add(2*time.Hour)
	assert.Equal(t, a.Hash(), b.Hash())

	// A clone shares neither slot.
	a.PendingSponsor = sp("oncall", false)
	cl := a.Clone()
	cl.Sponsor.Group, cl.PendingSponsor.Group = "x", "y"
	assert.Equal(t, "leads", a.Sponsor.Group)
	assert.Equal(t, "oncall", a.PendingSponsor.Group)
}

func TestEntitySponsor_Governance(t *testing.T) {
	sp := &logical.EntitySponsor{Type: logical.SponsorTypeGroup, Group: "leads"}
	cases := []struct {
		e      logical.Entity
		by     string
		reason string
	}{
		{logical.Entity{}, "", "no sponsor and no description"},
		{logical.Entity{Description: "x"}, "", "no sponsor"},
		{logical.Entity{Description: "x", PendingSponsor: sp}, "", `no sponsor (handover to group "leads" pending)`},
		{logical.Entity{Sponsor: sp}, "", "no description"},
		{logical.Entity{Description: "x", Sponsor: sp}, logical.GovernedByWarden, ""},
		{logical.Entity{Description: "x", Sponsor: sp, PendingSponsor: sp}, logical.GovernedByWarden, ""},
	}
	for i, tc := range cases {
		assert.Equal(t, tc.by, tc.e.GovernedBy(), "case %d", i)
		assert.Equal(t, tc.reason, tc.e.UngovernedReason(), "case %d", i)
	}
}

func TestEntitySponsor_Validation(t *testing.T) {
	at := time.Now().UTC()
	ok := func() *logical.EntitySponsor {
		return &logical.EntitySponsor{
			Type: logical.SponsorTypeGroup, Namespace: "root", GroupID: "g1", Group: "leads",
			AddedBy: logical.SponsorActor{Principal: "alice"}, AddedAt: at,
		}
	}
	accepted := func() *logical.EntitySponsor {
		s := ok()
		s.AcceptedBy, s.AcceptedAt = s.AddedBy, at
		return s
	}
	for name, e := range map[string]*logical.Entity{
		"unknown type":           {Name: "a", Sponsor: func() *logical.EntitySponsor { s := accepted(); s.Type = "user"; return s }()},
		"no group id":            {Name: "a", Sponsor: func() *logical.EntitySponsor { s := accepted(); s.GroupID = ""; return s }()},
		"no proposer":            {Name: "a", PendingSponsor: func() *logical.EntitySponsor { s := ok(); s.AddedBy = logical.SponsorActor{}; return s }()},
		"sponsor not accepted":   {Name: "a", Sponsor: ok()},
		"accepted before":        {Name: "a", Sponsor: func() *logical.EntitySponsor { s := accepted(); s.AcceptedAt = at.Add(-time.Second); return s }()},
		"pending accepted":       {Name: "a", PendingSponsor: accepted()},
		"both slots, same group": {Name: "a", Sponsor: accepted(), PendingSponsor: ok()},
	} {
		assert.Error(t, validateEntity(e), name)
	}
	e := &logical.Entity{Name: "a", Sponsor: accepted(), PendingSponsor: func() *logical.EntitySponsor { s := ok(); s.GroupID = "g2"; return s }()}
	assert.NoError(t, validateEntity(e))
	assert.Error(t, (&IdentityStore{}).CreateEntity(rootCtx(), e), "created without a sponsor")
}

// A record stored before sponsors were groups, with the key "sponsors", loads
// with no sponsor and its native identities still claimed.
func TestEntitySponsor_OldSponsorsKeyLoads(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	raw := fmt.Sprintf(`{"version":1,"hash":"x","entity":{"id":"e1","name":"old-agent","kind":"agent",
		"description":"Reconciles supplier invoices","sponsors":["alice@corp.example"],"state":"active",
		"aliases":[{"mount_accessor":%q,"name":"repo:acme/x"}]}}`, jwt)
	require.NoError(t, c.identityStore.storage.Put(ctx, &sdklogical.StorageEntry{
		Key: entityStorageKey(namespace.RootNamespace.UUID, "e1"), Value: []byte(raw),
	}))
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(ctx))
	e, _, err := c.identityStore.GetEntity(ctx, "old-agent")
	require.NoError(t, err)
	assert.Nil(t, e.Sponsor)
	assert.Equal(t, "no sponsor", e.UngovernedReason())
	assert.NotNil(t, c.identityStore.EntityByAlias(namespace.RootNamespaceID, jwt, "repo:acme/x"), "still claimed")

	// Rewritten, it no longer carries the old key.
	require.NoError(t, c.identityStore.SetEntityState(ctx, "old-agent", logical.EntityStateSuspended, nil, ""))
	entry, err := c.identityStore.storage.Get(ctx, entityStorageKey(namespace.RootNamespace.UUID, "e1"))
	require.NoError(t, err)
	assert.NotContains(t, string(entry.Value), `"sponsors"`)
}

func TestEntitySponsor_ProposeAdmin(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)
	for _, g := range []string{"leads", "oncall"} {
		_, err := c.identityStore.CreateGroup(ctx, humanGroup(g))
		require.NoError(t, err)
	}
	propose := func(body map[string]any) *logical.Response {
		return tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor", body)
	}

	// Root is a member of no group: it proposes, and the entity stays ungoverned.
	resp := propose(map[string]any{"group": "leads"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{"handover to /leads is pending: a member must accept it"}, respWarnings(resp))
	assert.Nil(t, resp.Data["sponsor"])
	assert.Equal(t, `no sponsor (handover to group "leads" pending)`, resp.Data["ungoverned_reason"])
	p := resp.Data["pending_sponsor"].(map[string]any)
	assert.Equal(t, "leads", p["group"])
	assert.Equal(t, "/", p["namespace"], "the root namespace renders as /")
	assert.Equal(t, "pending", p["status"])
	assert.Equal(t, map[string]any{"mount": "", "mount_accessor": "", "alias": "", "principal": "root"}, p["added_by"])
	assert.Nil(t, p["accepted_by"])
	assert.Nil(t, p["accepted_at"])

	// A second proposal replaces the first pending one.
	resp = propose(map[string]any{"group": "oncall", "namespace": "/"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "oncall", resp.Data["pending_sponsor"].(map[string]any)["group"])

	// Proposing the sponsor changes nothing.
	sponsorAccepted(t, c, ctx, "a", "leads")
	before := entityRequest(t, c, logical.ReadOperation, "entity/a", nil).Data["hash"]
	resp = propose(map[string]any{"group": "leads"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Empty(t, respWarnings(resp))
	assert.Equal(t, before, resp.Data["hash"])
	assert.Equal(t, "warden", resp.Data["governed_by"])

	// Refusals.
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		want   string
	}{
		"no group":            {map[string]any{}, http.StatusBadRequest, "group is required"},
		"unknown group":       {map[string]any{"group": "nope"}, http.StatusBadRequest, "group /nope not found"},
		"a sibling":           {map[string]any{"group": "leads", "namespace": "team-b"}, http.StatusBadRequest, "neither this namespace nor one of its ancestors"},
		"stale expected_hash": {map[string]any{"group": "oncall", "expected_hash": "stale"}, http.StatusConflict, "changed since it was read"},
	} {
		resp := propose(tc.body)
		assert.Equal(t, tc.status, resp.StatusCode, name)
		assert.Contains(t, resp.Err.Error(), tc.want, name)
	}
	resp = tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/nope/sponsor", map[string]any{"group": "leads"})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// A retired entity refuses it.
	require.NoError(t, c.identityStore.SetEntityState(ctx, "a", logical.EntityStateRetired, nil, ""))
	resp = propose(map[string]any{"group": "oncall"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "retired")
}

// A group whose namespace admits no humans can never be accepted, and a rule
// trusting an agent mount never lets anyone act for it: both are warned
// about, not refused.
func TestEntitySponsor_ProposeWarnings(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	mountEntityBackend(t, c, "jwt-fake", "jwt/", "", "sub")
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("agents"))
	require.NoError(t, err)
	resp := tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor", map[string]any{"group": "agents"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{
		"handover to /agents is pending: a member must accept it",
		"no auth mount of namespace / admits humans: nobody can accept or act for this sponsor until one is enabled there",
		`group "agents": rules[0] trusts auth/jwt/, which admits agents; only humans act for a sponsor`,
	}, respWarnings(resp))
}

// A group none of whose rules can admit a human, by its "kind" selectors
// alone, is warned about even when it trusts a mount that admits humans.
func TestEntitySponsor_ProposeWarnsNoRuleAdmitsHumans(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	const noHuman = `no rule can admit a human (each rule's "kind" selector excludes "human"); nobody can accept or act for this sponsor`
	for name, tc := range map[string]struct {
		rules []logical.GroupRule
		warns bool
	}{
		"agent only": {[]logical.GroupRule{{"mount": {"auth/humans/"}, "kind": {"agent"}}}, true},
		"every rule excludes humans": {[]logical.GroupRule{
			{"mount": {"auth/humans/"}, "kind": {"agent"}},
			{"mount": {"auth/humans/"}, "kind": {"ag*"}},
		}, true},
		"one rule admits humans": {[]logical.GroupRule{
			{"mount": {"auth/humans/"}, "kind": {"agent"}},
			{"mount": {"auth/humans/"}, "kind": {"human"}},
		}, false},
		"a pattern admits humans": {[]logical.GroupRule{{"mount": {"auth/humans/"}, "kind": {"hum*"}}}, false},
		"no kind selector":        {[]logical.GroupRule{{"mount": {"auth/humans/"}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			group := strings.ReplaceAll(name, " ", "-")
			_, err := c.identityStore.CreateGroup(ctx, &logical.Group{Name: group, Type: logical.GroupTypeVirtual, Rules: tc.rules})
			require.NoError(t, err)
			resp := tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor", map[string]any{"group": group})
			require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
			want := fmt.Sprintf("group %q: %s", group, noHuman)
			if tc.warns {
				assert.Contains(t, respWarnings(resp), want)
			} else {
				assert.NotContains(t, respWarnings(resp), want)
			}
			assert.Len(t, respWarnings(resp), map[bool]int{true: 2, false: 1}[tc.warns], "and the pending handover")
		})
	}
}

// A group of an ancestor namespace can sponsor; a descendant's or a
// sibling's cannot.
func TestEntitySponsor_AncestorNamespace(t *testing.T) {
	c := setupEntityMounts(t)
	teamA := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), teamA))
	actx := namespace.ContextWithNamespace(context.Background(), teamA)
	require.NoError(t, c.identityStore.CreateEntity(actx, &logical.Entity{Name: "a"}))
	_, err := c.identityStore.CreateGroup(rootCtx(), humanGroup("leads"))
	require.NoError(t, err)

	resp := tokenRequest(t, c, actx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor", map[string]any{
		"group": "leads", "namespace": "/",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), "handover to /leads is pending: a member must accept it")
	p := resp.Data["pending_sponsor"].(map[string]any)
	assert.Equal(t, "/", p["namespace"])

	resp = tokenRequest(t, c, actx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor", map[string]any{
		"group": "leads",
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "team-a has no group of that name")
	resp = tokenRequest(t, c, rootCtx(), rootEntry, logical.UpdateOperation, "identity/entity/x/sponsor", map[string]any{
		"group": "leads", "namespace": "team-a/",
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a descendant is refused")
	assert.Contains(t, resp.Err.Error(), "neither this namespace nor one of its ancestors")
}

func TestEntitySponsor_Remove(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)
	remove := func(body map[string]any) *logical.Response {
		return entityRequest(t, c, logical.UpdateOperation, "entity/a/sponsor/remove", body)
	}
	assert.Equal(t, http.StatusNotFound, remove(nil).StatusCode, "no sponsor")
	assert.Equal(t, http.StatusNotFound, remove(map[string]any{"pending": true}).StatusCode, "no handover")

	sponsorAccepted(t, c, ctx, "a", "leads")
	proposeSponsor(t, c, ctx, ctx, "a", "oncall", false)
	resp := remove(nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{"entity is now ungoverned: it has no sponsor"}, respWarnings(resp))
	assert.Nil(t, resp.Data["sponsor"])
	assert.Equal(t, "oncall", resp.Data["pending_sponsor"].(map[string]any)["group"], "the handover stays")
	assert.Equal(t, "", resp.Data["governed_by"])

	resp = remove(map[string]any{"pending": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Nil(t, resp.Data["pending_sponsor"])
	assert.Empty(t, respWarnings(resp))

	sponsorAccepted(t, c, ctx, "a", "leads")
	require.NoError(t, c.identityStore.SetEntityState(ctx, "a", logical.EntityStateRetired, nil, ""))
	assert.Equal(t, http.StatusConflict, remove(nil).StatusCode, "retired")
}

func TestEntitySponsor_ListFilters(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	for _, n := range []string{"none", "sponsored", "pending", "both"} {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: n, Description: "x"}))
	}
	sponsorAccepted(t, c, ctx, "sponsored", "leads")
	proposeSponsor(t, c, ctx, ctx, "pending", "oncall", false)
	sponsorAccepted(t, c, ctx, "both", "oncall")
	proposeSponsor(t, c, ctx, ctx, "both", "leads", false)

	list := func(q map[string]any) any {
		resp := entityRequest(t, c, logical.ListOperation, "entity", q)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
		return resp.Data["keys"]
	}
	assert.Equal(t, []string{"both", "sponsored"}, list(map[string]any{"sponsor_state": "accepted"}))
	assert.Equal(t, []string{"both", "pending"}, list(map[string]any{"sponsor_state": "pending"}))
	assert.Equal(t, []string{"sponsored"}, list(map[string]any{"sponsor": "leads"}), "the sponsor, not the handover")
	assert.Equal(t, []string{"both"}, list(map[string]any{"sponsor": "oncall", "sponsor_state": "pending"}), "filters combine")
	assert.Equal(t, []string{"none", "pending"}, list(map[string]any{"ungoverned": true}))
	resp := entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"sponsor_state": "stale"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Every store method that takes an expected sponsor refuses once the entity's
// sponsor or handover is no longer the one the caller decided on.
func TestEntitySponsor_ExpectRefusesAChangedSponsor(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a", Description: "x"}))
	a := sponsorAccepted(t, c, ctx, "a", "team-a")
	b := proposeSponsor(t, c, ctx, ctx, "a", "team-b", false)

	// What a member of A saw is overtaken: B replaces A.
	sponsorAccepted(t, c, ctx, "a", "team-b")
	err := c.identityStore.SetEntityState(ctx, "a", logical.EntityStateSuspended, a, "")
	assert.ErrorIs(t, err, ErrSponsorChanged, "a member of the old sponsor cannot suspend")
	_, err = c.identityStore.ProposeSponsor(ctx, "a", proposeEntry(t, c, ctx, "team-c"), false, a, "")
	assert.ErrorIs(t, err, ErrSponsorChanged, "nor hand it over")
	proposeSponsor(t, c, ctx, ctx, "a", "team-c", false)
	assert.ErrorIs(t, c.identityStore.CancelPending(ctx, "a", b, ""), ErrSponsorChanged, "nor cancel another team's handover")

	e, _, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, logical.EntityStateActive, e.State)
	assert.True(t, e.Sponsor.Same(b))
	require.NoError(t, c.identityStore.SetEntityState(ctx, "a", logical.EntityStateSuspended, b, ""), "the sponsor it has")
}

// proposeEntry is an unaccepted entry naming group of the namespace in ctx,
// which must exist or is created.
func proposeEntry(t *testing.T, c *Core, ctx context.Context, group string) *logical.EntitySponsor {
	t.Helper()
	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)
	if _, _, err := c.identityStore.GetGroup(ctx, group); err != nil {
		_, err = c.identityStore.CreateGroup(ctx, humanGroup(group))
		require.NoError(t, err)
	}
	g := c.identityStore.namespaceIndex(ns.ID).groupsByName[group]
	return &logical.EntitySponsor{
		Type: logical.SponsorTypeGroup, Namespace: ns.ID, GroupID: g.ID, Group: group,
		AddedBy: logical.SponsorActor{Principal: "bob"}, AddedAt: time.Now().UTC(),
	}
}

// An entry names its group by ID: one deleted and created again under the
// same name, between a read and the write, is refused, not adopted.
func TestEntitySponsor_RecreatedGroupRefused(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	stale := proposeEntry(t, c, ctx, "leads")
	_, err := c.identityStore.DeleteGroup(ctx, "leads", "", "", false)
	require.NoError(t, err)
	_, err = c.identityStore.CreateGroup(ctx, humanGroup("leads"))
	require.NoError(t, err)
	_, err = c.identityStore.ProposeSponsor(ctx, "a", stale, true, nil, "")
	assert.ErrorIs(t, err, ErrSponsorGroupNotFound)
	e, _, _ := c.identityStore.GetEntity(ctx, "a")
	assert.Nil(t, e.Sponsor)
}

func TestEntitySponsor_GroupDeleteGuard(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	teamA := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, c.namespaceStore.SetNamespace(ctx, teamA))
	actx := namespace.ContextWithNamespace(context.Background(), teamA)
	for _, n := range []string{"a", "b"} {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: n, Description: "x"}))
	}
	require.NoError(t, c.identityStore.CreateEntity(actx, &logical.Entity{Name: "etl", Description: "x"}))
	sponsorAccepted(t, c, ctx, "a", "leads")
	proposeSponsor(t, c, ctx, ctx, "b", "leads", false)
	proposeSponsor(t, c, actx, ctx, "etl", "leads", true)
	sponsorAccepted(t, c, ctx, "b", "oncall")

	del := func(force bool) *logical.Response {
		return entityRequest(t, c, logical.DeleteOperation, "group/leads", map[string]any{"type": "virtual", "force": force})
	}
	gen := c.identityStore.gen.Load()
	resp := del(false)
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `group "leads" sponsors 2 entities and is a pending handover for 1; hand them over first, or pass force=true`,
		"counted across namespaces")
	_, _, err := c.identityStore.GetGroup(ctx, "leads")
	require.NoError(t, err, "nothing deleted")
	assert.Equal(t, gen, c.identityStore.gen.Load(), "a refused delete publishes nothing")

	resp = del(true)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, gen+3, c.identityStore.gen.Load(),
		"one entity publish per affected namespace (root, team-a), then the group's")
	assert.Equal(t, []string{
		`forced: group "leads" sponsored 2 entities; their sponsor was removed and they are ungoverned: /a, team-a/etl`,
		`forced: 1 pending sponsor handovers to group "leads" were cancelled`,
	}, respWarnings(resp))
	for _, tc := range []struct {
		ctx  context.Context
		name string
	}{{ctx, "a"}, {actx, "etl"}} {
		e, _, err := c.identityStore.GetEntity(tc.ctx, tc.name)
		require.NoError(t, err)
		assert.Nil(t, e.Sponsor, tc.name)
		assert.Equal(t, "", e.GovernedBy(), tc.name)
	}
	b, _, err := c.identityStore.GetEntity(ctx, "b")
	require.NoError(t, err)
	assert.Nil(t, b.PendingSponsor, "the handover is cancelled")
	assert.Equal(t, "oncall", b.Sponsor.Group, "its other sponsor is untouched")

	// What storage holds is what was published.
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(ctx))
	e, _, err := c.identityStore.GetEntity(actx, "etl")
	require.NoError(t, err)
	assert.Nil(t, e.Sponsor)
	assertEntityIndexMatchesStorage(t, c)

	// A group nothing names deletes as before, with no warning.
	_, err = c.identityStore.CreateGroup(ctx, humanGroup("spare"))
	require.NoError(t, err)
	resp = entityRequest(t, c, logical.DeleteOperation, "group/spare", map[string]any{"type": "virtual"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Empty(t, respWarnings(resp))
}

// A forced delete whose storage fails partway publishes what storage holds:
// the entities written so far without the group, the others still naming it,
// and the group kept, so no entry ever names a group that is gone. Run again,
// it completes.
func TestEntitySponsor_GroupDeleteStorageFailure(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	for _, n := range []string{"a", "b"} {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: n, Description: "x"}))
		sponsorAccepted(t, c, ctx, n, "leads")
	}
	spy := &spyStorage{Storage: c.identityStore.storage, failAt: 2}
	c.identityStore.storage = spy
	_, err := c.identityStore.DeleteGroup(ctx, "leads", "", "", true)
	require.ErrorContains(t, err, "injected storage failure")
	assertEntityIndexMatchesStorage(t, c)
	g := c.identityStore.namespaceIndex(namespace.RootNamespaceID).groupsByName["leads"]
	require.NotNil(t, g, "the group is kept")
	cleared := 0
	for _, n := range []string{"a", "b"} {
		e, _, err := c.identityStore.GetEntity(ctx, n)
		require.NoError(t, err)
		if e.Sponsor == nil {
			cleared++
		} else {
			assert.Equal(t, g.ID, e.Sponsor.GroupID)
		}
	}
	assert.Equal(t, 1, cleared, "the first write stored, the second refused")

	spy.failAt = 0
	warnings, err := c.identityStore.DeleteGroup(ctx, "leads", "", "", true)
	require.NoError(t, err)
	assert.Len(t, warnings, 1)
	assertEntityIndexMatchesStorage(t, c)
}

// expected_hash makes every admin sponsor write conditional: a stale one is
// refused, the current one applies.
func TestEntitySponsor_ExpectedHash(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a", Description: "x"}))
	_, err := c.identityStore.CreateGroup(ctx, humanGroup("leads"))
	require.NoError(t, err)
	hash := func() string {
		return entityRequest(t, c, logical.ReadOperation, "entity/a", nil).Data["hash"].(string)
	}

	h := hash()
	resp := tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor",
		map[string]any{"group": "leads", "expected_hash": h})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	resp = tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor/remove",
		map[string]any{"pending": true, "expected_hash": h})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "the proposal changed the hash")
	resp = tokenRequest(t, c, ctx, rootEntry, logical.UpdateOperation, "identity/entity/a/sponsor/remove",
		map[string]any{"pending": true, "expected_hash": hash()})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Nil(t, resp.Data["pending_sponsor"])
}

// A propose and a delete of its group racing never leave an entry naming a
// group that is gone.
func TestEntitySponsor_ProposeRacingGroupDelete(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	const n = 8
	for i := range n {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: fmt.Sprintf("e%d", i)}))
	}
	for round := range 20 {
		sp := proposeEntry(t, c, ctx, "leads")
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = c.identityStore.ProposeSponsor(ctx, fmt.Sprintf("e%d", i), sp, i%2 == 0, nil, "")
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.identityStore.DeleteGroup(ctx, "leads", "", "", round%2 == 0)
		}()
		wg.Wait()

		g := c.identityStore.namespaceIndex(namespace.RootNamespaceID).groupsByName["leads"]
		for i := range n {
			e, _, err := c.identityStore.GetEntity(ctx, fmt.Sprintf("e%d", i))
			require.NoError(t, err)
			for _, s := range []*logical.EntitySponsor{e.Sponsor, e.PendingSponsor} {
				if s != nil {
					require.NotNil(t, g, "round %d: e%d names a deleted group", round, i)
					require.Equal(t, g.ID, s.GroupID)
				}
			}
		}
		// Start the next round from a clean state.
		if g != nil {
			_, err := c.identityStore.DeleteGroup(ctx, "leads", "", "", true)
			require.NoError(t, err)
		}
	}
}

// A human ticket granted a role proposes on the admin surface: as a member of
// the group the proposal is accepted at once and names the person; as a
// non-member it is a pending handover.
func TestEntitySponsor_ProposeByTicket(t *testing.T) {
	e := newTicketRequestEnv(t)
	p := testParsePolicy(t, `
path "sys/identity/entity/*" { capabilities = ["create", "read", "update", "sudo"] }
`)
	p.Name, p.Type = "identity-admin", PolicyTypeCBP
	require.NoError(t, e.c.policyStore.SetPolicy(e.ctx, p, nil))
	_, err := e.c.roleStore.Create(e.ctx, &logical.Role{Name: "identity-admin", Policies: []string{"identity-admin"}})
	require.NoError(t, err)
	_, err = e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "admins", Type: logical.GroupTypeVirtual, Roles: []string{"identity-admin"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}}},
	})
	require.NoError(t, err)
	// Groups the ticket is not a member of: another app role, another mount.
	for name, rule := range map[string]logical.GroupRule{
		"finance":     {"mount": {"auth/oidc/"}, "roles": {"Finance.Oncall"}},
		"other-mount": {"mount": {"auth/oidc2/"}, "kind": {"human"}},
	} {
		_, err = e.c.identityStore.CreateGroup(e.ctx, &logical.Group{Name: name, Type: logical.GroupTypeVirtual, Rules: []logical.GroupRule{rule}})
		require.NoError(t, err)
	}
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "billing-agent", Description: "x"}))

	propose := func(group string) *logical.Response {
		e.t.Helper()
		hr := httptest.NewRequest(http.MethodPost, "/v1/sys/identity/entity/billing-agent/sponsor", strings.NewReader("{}"))
		hr.Header.Set(logical.HeaderWardenToken, e.value)
		hr.Header.Set("X-Warden-Role", "identity-admin")
		req := &logical.Request{
			Path: "sys/identity/entity/billing-agent/sponsor", Operation: logical.UpdateOperation, HTTPRequest: hr,
			Data: map[string]any{"group": group}, RequestID: "req-sponsor",
		}
		resp, err := e.c.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
		return resp
	}

	resp := propose("humans")
	assert.Empty(t, respWarnings(resp))
	assert.Equal(t, "warden", resp.Data["governed_by"], "accepted at once")
	sp := resp.Data["sponsor"].(map[string]any)
	person := map[string]any{"mount": "auth/oidc/", "mount_accessor": e.mount.Accessor, "alias": "0583-oid", "principal": "0583-oid"}
	assert.Equal(t, person, sp["added_by"])
	assert.Equal(t, person, sp["accepted_by"])
	assert.Equal(t, "accepted", sp["status"])

	// A member replaces the sponsor in one write; governed throughout.
	resp = propose("admins")
	assert.Equal(t, "admins", resp.Data["sponsor"].(map[string]any)["group"])
	assert.Equal(t, "warden", resp.Data["governed_by"])

	for _, g := range []string{"finance", "other-mount"} {
		resp = propose(g)
		assert.Equal(t, "admins", resp.Data["sponsor"].(map[string]any)["group"], "%s: the sponsor stays", g)
		assert.Equal(t, g, resp.Data["pending_sponsor"].(map[string]any)["group"], "%s: not a member, so pending", g)
	}
}

// Membership counts only for a group of the namespace that issued the ticket,
// with the ID the entry names.
func TestEntitySponsor_CallerMatches(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	sp := proposeEntry(t, c, ctx, "leads")
	root := namespace.RootNamespaceID
	assert.True(t, c.callerMatches(sp, []string{"admins", "leads"}, root))
	assert.False(t, c.callerMatches(sp, []string{"admins"}, root), "not a member")
	assert.False(t, c.callerMatches(sp, []string{"leads"}, "child-ns"), "a ticket of another namespace")
	assert.False(t, c.callerMatches(nil, []string{"leads"}, root))
	other := *sp
	other.GroupID = "another-id"
	assert.False(t, c.callerMatches(&other, []string{"leads"}, root), "a group of that name with another ID")
	assert.Zero(t, testing.AllocsPerRun(100, func() { c.callerMatches(sp, []string{"leads"}, root) }))

	assert.False(t, humanTicket(nil))
	assert.False(t, humanTicket(rootEntry))
	assert.False(t, humanTicket(&logical.TokenEntry{Type: logical.TokenTypeTicket}), "no admission")
}

// The sponsor round-trips through storage with every field.
func TestEntitySponsor_Persisted(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	sponsorAccepted(t, c, ctx, "a", "leads")
	proposeSponsor(t, c, ctx, ctx, "a", "oncall", false)
	before, hash, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)
	c.identityStore.Unload()
	require.NoError(t, c.identityStore.Load(ctx))
	after, hash2, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, hash, hash2)
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	assert.JSONEq(t, string(b1), string(b2))
}
