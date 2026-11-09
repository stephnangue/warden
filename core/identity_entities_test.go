package core

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtmethod "github.com/stephnangue/warden/auth/method/jwt"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// mountEntityBackend enables an auth mount at path (relative to auth/) whose
// backend admits kind ("" answers agent) and takes aliases from source.
func mountEntityBackend(t *testing.T, c *Core, typ, path, kind, source string) *factsBackend {
	t.Helper()
	b := &factsBackend{typ: typ, names: []string{"sub"}, kind: kind, aliasSource: source}
	c.authMethods[typ] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) { return b, nil }
	require.NoError(t, c.mount(rootCtx(), &MountEntry{Class: mountClassAuth, Type: typ, Path: path}))
	return b
}

func entityRequest(t *testing.T, c *Core, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	return roleRequest(t, c, rootCtx(), op, "identity/"+path, data)
}

// accessorOf returns the accessor of the auth mount at path (relative to auth/).
func accessorOf(t *testing.T, c *Core, path string) string {
	t.Helper()
	acc, _, err := c.resolveAliasMount(rootCtx(), authRoutePrefix+path)
	require.NoError(t, err)
	return acc
}

func billingAgentBody() map[string]any {
	return map[string]any{
		"kind":        "agent",
		"description": "Reconciles supplier invoices",
		"profile":     map[string]any{"purpose": "billing", "runtime": "langgraph"},
		"metadata":    map[string]any{"team": "billing"},
		"aliases": []any{
			map[string]any{"mount": "auth/k8s/", "name": "system:serviceaccount:billing:agent"},
			map[string]any{"mount": "auth/spiffe/", "name": "spiffe://corp.example/ns/billing/sa/agent"},
		},
	}
}

func setupEntityMounts(t *testing.T) *Core {
	t.Helper()
	c := createTestCore(t)
	mountEntityBackend(t, c, "k8s-fake", "k8s/", "", "username")
	mountEntityBackend(t, c, "spiffe-fake", "spiffe/", "", "spiffe_id")
	mountEntityBackend(t, c, "jwt-fake", "jwt/", "", "sub")
	mountEntityBackend(t, c, "humans-fake", "humans/", logical.EntityKindHuman, "sub")
	return c
}

func TestEntities_CRUD(t *testing.T) {
	c := setupEntityMounts(t)

	resp := entityRequest(t, c, logical.CreateOperation, "entity/billing-agent", billingAgentBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	id := resp.Data["id"].(string)
	assert.NotEmpty(t, id)
	assert.Equal(t, "", resp.Data["governed_by"], "created without a sponsor")
	assert.Equal(t, "no sponsor", resp.Data["ungoverned_reason"])
	assert.Nil(t, resp.Data["sponsor"])
	assert.Nil(t, resp.Data["pending_sponsor"])
	assert.Equal(t, "active", resp.Data["state"])
	assert.Equal(t, "agent", resp.Data["kind"])
	aliases := resp.Data["aliases"].([]map[string]any)
	require.Len(t, aliases, 2)
	assert.Equal(t, "auth/k8s/", aliases[0]["mount"], "rendered by the mount's current path")
	assert.Equal(t, accessorOf(t, c, "k8s/"), aliases[0]["mount_accessor"])
	assert.Equal(t, map[string]string{"purpose": "billing", "runtime": "langgraph"}, resp.Data["profile"])

	resp = entityRequest(t, c, logical.ReadOperation, "entity/billing-agent", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	h1 := resp.Data["hash"].(string)
	resp = entityRequest(t, c, logical.ReadOperation, "entity/id/"+id, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "billing-agent", resp.Data["name"])

	// An update replaces what it names; a rename keeps the ID and the aliases.
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/billing-agent", map[string]any{
		"description": "Reconciles supplier invoices against purchase orders",
		"new_name":    "invoice-agent",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "Reconciles supplier invoices against purchase orders", resp.Data["description"])
	assert.Equal(t, id, resp.Data["id"])
	assert.Len(t, resp.Data["aliases"], 2)
	assert.Equal(t, http.StatusNotFound, entityRequest(t, c, logical.ReadOperation, "entity/billing-agent", nil).StatusCode)
	e, err := c.identityStore.LookupAlias(rootCtx(), accessorOf(t, c, "k8s/"), "system:serviceaccount:billing:agent")
	require.NoError(t, err)
	assert.Equal(t, "invoice-agent", e.Name, "the alias index follows the rename")

	// expected_hash: a stale one is refused.
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/invoice-agent", map[string]any{
		"description": "stale", "expected_hash": h1,
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	resp = entityRequest(t, c, logical.DeleteOperation, "entity/invoice-agent", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = c.identityStore.LookupAlias(rootCtx(), accessorOf(t, c, "k8s/"), "system:serviceaccount:billing:agent")
	assert.ErrorIs(t, err, ErrAliasNotFound, "a delete releases the native identities")
}

func TestEntities_Validation(t *testing.T) {
	c := setupEntityMounts(t)
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"governed_by written", map[string]any{"governed_by": "warden"}, "governed_by is derived"},
		{"human kind", map[string]any{"kind": "human"}, `kind "human" is not supported yet`},
		{"unknown kind", map[string]any{"kind": "robot"}, "unknown entity kind"},
		{"state", map[string]any{"state": "suspended"}, "state changes through sys/identity/entity/<name>/state"},
		{"sponsors", map[string]any{"sponsors": []any{"alice@corp.example"}}, "the sponsor is proposed through"},
		{"sponsor", map[string]any{"sponsor": map[string]any{"group": "billing-leads"}}, "the sponsor is proposed through"},
		{"unknown profile field", map[string]any{"profile": map[string]any{"team": "x"}}, "unknown profile field"},
		{"no such mount", map[string]any{"aliases": []any{map[string]any{"mount": "auth/nope/", "name": "x"}}}, "no auth mount"},
		{"not an auth mount", map[string]any{"aliases": []any{map[string]any{"mount": "sys/", "name": "x"}}}, "no auth mount"},
		{"below a mount", map[string]any{"aliases": []any{map[string]any{"mount": "auth/k8s/config", "name": "x"}}}, "no auth mount"},
		{"human mount", map[string]any{"aliases": []any{map[string]any{"mount": "auth/humans/", "name": "alice"}}}, "admits human entities"},
		{"control character", map[string]any{"aliases": []any{map[string]any{"mount": "auth/jwt/", "name": "a\nb"}}}, "invalid native identity"},
		{"listed twice", map[string]any{"aliases": []any{
			map[string]any{"mount": "auth/jwt/", "name": "a"}, map[string]any{"mount": "auth/jwt/", "name": "a"},
		}}, "listed twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := entityRequest(t, c, logical.CreateOperation, "entity/x", tc.body)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, resp.Err.Error(), tc.want)
		})
	}
	for _, name := range []string{"-x", "a/b", "a b", ""} {
		assert.Error(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{Name: name}), "name %q", name)
	}
}

func TestEntities_Governance(t *testing.T) {
	c := setupEntityMounts(t)
	resp := entityRequest(t, c, logical.CreateOperation, "entity/ci-runner", map[string]any{})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "", resp.Data["governed_by"])
	assert.Equal(t, "no sponsor and no description", resp.Data["ungoverned_reason"])

	sponsorAccepted(t, c, rootCtx(), "ci-runner", "billing-leads")
	resp = entityRequest(t, c, logical.ReadOperation, "entity/ci-runner", nil)
	assert.Equal(t, "no description", resp.Data["ungoverned_reason"])
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/ci-runner", map[string]any{"description": "Builds billing"})
	assert.Equal(t, "warden", resp.Data["governed_by"])
	assert.Equal(t, "", resp.Data["ungoverned_reason"])
	assert.Equal(t, "billing-leads", resp.Data["sponsor"].(map[string]any)["group"], "an update keeps the sponsor")

	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"ungoverned": true})
	assert.Empty(t, resp.Data["keys"])
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"governed_by": "warden"})
	assert.Equal(t, []string{"ci-runner"}, resp.Data["keys"])
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"sponsor": "billing-leads"})
	assert.Equal(t, []string{"ci-runner"}, resp.Data["keys"])

	// Kind never changes.
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/ci-runner", map[string]any{"kind": "human"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEntities_StateLifecycle(t *testing.T) {
	c := setupEntityMounts(t)
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)

	state := func(st string) *logical.Response {
		return entityRequest(t, c, logical.UpdateOperation, "entity/a/state", map[string]any{"state": st})
	}
	for _, st := range []string{"suspended", "active"} {
		resp := state(st)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
		assert.Equal(t, st, resp.Data["state"])
	}

	// An empty or unknown state never lifts a suspension.
	require.Equal(t, http.StatusOK, state("suspended").StatusCode)
	assert.Equal(t, http.StatusBadRequest, state("").StatusCode)
	resp := state("paused")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "unknown entity state")
	e, _, err := c.identityStore.GetEntity(rootCtx(), "a")
	require.NoError(t, err)
	assert.Equal(t, logical.EntityStateSuspended, e.State)
	h := entityRequest(t, c, logical.ReadOperation, "entity/a", nil).Data["hash"].(string)
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a/state", map[string]any{"state": "active", "expected_hash": "stale"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "expected_hash makes it conditional")
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a/state", map[string]any{"state": "active", "expected_hash": h})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.NotEqual(t, h, resp.Data["hash"], "the state is hashed")
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"state": "active"})
	assert.Equal(t, []string{"a"}, resp.Data["keys"])
	assert.Equal(t, http.StatusOK, state("active").StatusCode, "the state it has is no change")

	require.Equal(t, http.StatusOK, state("retired").StatusCode)
	resp = state("active")
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "retired is final")
	assert.Contains(t, resp.Err.Error(), "retired")

	// A retired entity keeps its native identities, which can be moved off it
	// without move.
	k8s := accessorOf(t, c, "k8s/")
	e, err = c.identityStore.LookupAlias(rootCtx(), k8s, "system:serviceaccount:billing:agent")
	require.NoError(t, err)
	assert.Equal(t, "a", e.Name)
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/b", map[string]any{}).StatusCode)
	resp = entityRequest(t, c, logical.CreateOperation, "entity/b/alias", map[string]any{
		"mount": "auth/k8s/", "name": "system:serviceaccount:billing:agent",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "a", resp.Data["moved_from"])
}

func TestEntities_Aliases(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", map[string]any{}).StatusCode)
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/b", map[string]any{}).StatusCode)
	claim := func(entity, name string, move bool) *logical.Response {
		return entityRequest(t, c, logical.CreateOperation, "entity/"+entity+"/alias", map[string]any{
			"mount": "auth/jwt/", "name": name, "move": move,
		})
	}

	require.Equal(t, http.StatusOK, claim("a", "repo:acme/x", false).StatusCode)
	require.Equal(t, http.StatusOK, claim("a", "repo:acme/x", false).StatusCode, "claiming it again changes nothing")
	e, _, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)
	assert.Len(t, e.Aliases, 1)

	resp := claim("b", "repo:acme/x", false)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `native identity "repo:acme/x" on mount auth/jwt/ is already claimed by entity "a"; pass move`,
		"the mount is named by its path")

	resp = claim("b", "repo:acme/x", true)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "a", resp.Data["moved_from"])
	owner, err := c.identityStore.LookupAlias(ctx, jwt, "repo:acme/x")
	require.NoError(t, err)
	assert.Equal(t, "b", owner.Name)
	a, _, _ := c.identityStore.GetEntity(ctx, "a")
	assert.Empty(t, a.Aliases, "taken from the loser")

	resp = entityRequest(t, c, logical.UpdateOperation, "lookup", map[string]any{"mount": "auth/jwt/", "name": "repo:acme/x"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "b", resp.Data["entity"])
	assert.Equal(t, http.StatusNotFound,
		entityRequest(t, c, logical.UpdateOperation, "lookup", map[string]any{"mount": "auth/jwt/", "name": "nobody"}).StatusCode)

	resp = entityRequest(t, c, logical.UpdateOperation, "entity/b/alias/remove", map[string]any{"mount": "auth/jwt/", "name": "repo:acme/x"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	_, err = c.identityStore.LookupAlias(ctx, jwt, "repo:acme/x")
	assert.ErrorIs(t, err, ErrAliasNotFound)
	assert.Equal(t, http.StatusNotFound,
		entityRequest(t, c, logical.UpdateOperation, "entity/b/alias/remove", map[string]any{"mount": "auth/jwt/", "name": "repo:acme/x"}).StatusCode)

	// An update cannot edit aliases; a human mount cannot be claimed by an agent.
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a", map[string]any{"aliases": []any{}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = entityRequest(t, c, logical.CreateOperation, "entity/a/alias", map[string]any{"mount": "auth/humans/", "name": "alice"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "admits human entities")

	// The per-entity cap.
	for i := 0; i < logical.MaxEntityAliases; i++ {
		require.Equal(t, http.StatusOK, claim("a", fmt.Sprintf("id-%d", i), false).StatusCode)
	}
	resp = claim("a", "one-more", false)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "native identities")
}

// A native identity is bound to one entity in a namespace; a mount of another
// namespace cannot be claimed.
func TestEntities_NamespaceScope(t *testing.T) {
	c := setupEntityMounts(t)
	other := namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "ns2", UUID: "ns2-uuid", Path: "ns2/"})
	_, _, err := c.resolveAliasMount(other, "auth/jwt/")
	assert.Error(t, err, "the root namespace's mount is not ns2's")

	require.NoError(t, c.identityStore.CreateEntity(other, &logical.Entity{Name: "a"}))
	_, _, err = c.identityStore.GetEntity(rootCtx(), "a")
	assert.ErrorIs(t, err, ErrEntityNotFound, "entities are per namespace")
}

// Two claims of one native identity racing bind it once.
func TestEntities_ConcurrentClaimsBindOnce(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	const n = 16
	for i := range n {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: fmt.Sprintf("e%d", i)}))
	}
	var wg sync.WaitGroup
	var won sync.Map
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.identityStore.ClaimAlias(ctx, fmt.Sprintf("e%d", i), jwt, "shared", false); err == nil {
				won.Store(i, true)
			}
		}()
	}
	wg.Wait()
	winners := 0
	won.Range(func(any, any) bool { winners++; return true })
	assert.Equal(t, 1, winners)
	holders := 0
	for i := range n {
		e, _, err := c.identityStore.GetEntity(ctx, fmt.Sprintf("e%d", i))
		require.NoError(t, err)
		holders += len(e.Aliases)
	}
	assert.Equal(t, 1, holders, "exactly one entity holds it")
}

// Every entity write publishes the namespace under a new generation, so a
// membership computed before it is recomputed on the next request.
func TestEntities_PublishBumpsGeneration(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	before := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	after := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	assert.Greater(t, after.gen, before.gen)
	assert.Equal(t, 0, before.entities.count(), "a published value is never changed")
	assert.Equal(t, 1, after.entities.count())

	// Groups survive an entity publish, and entities a group publish.
	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("g"))
	require.NoError(t, err)
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "b"}))
	ns := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	assert.NotNil(t, ns.groupsByName["g"])
	assert.Equal(t, 2, ns.entities.count())
	_, err = c.identityStore.DeleteGroup(ctx, "g", "", "", false)
	require.NoError(t, err)
	assert.Equal(t, 2, c.identityStore.namespaceIndex(namespace.RootNamespaceID).entities.count())
}

// Looking a native identity up allocates nothing.
func TestEntities_AliasLookupDoesNotAllocate(t *testing.T) {
	c := setupEntityMounts(t)
	jwt := accessorOf(t, c, "jwt/")
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: jwt, Name: "repo:acme/x"}},
	}))
	allocs := testing.AllocsPerRun(1000, func() {
		if c.identityStore.EntityByAlias(namespace.RootNamespaceID, jwt, "repo:acme/x") == nil {
			t.Fatal("not found")
		}
	})
	assert.Zero(t, allocs)
}

// The claims on a mount are counted by its accessor's keys only: an accessor
// that is a prefix of another counts nothing of the other's.
func TestEntities_AliasesBoundTo(t *testing.T) {
	ents, err := emptyEntities.with(
		entityChange{next: newEntityEntry(&logical.Entity{ID: "1", Name: "a", Aliases: []logical.EntityAlias{
			{MountAccessor: "auth_jwt_1", Name: "x"}, {MountAccessor: "auth_jwt_1", Name: "y"},
		}})},
		entityChange{next: newEntityEntry(&logical.Entity{ID: "2", Name: "b", Aliases: []logical.EntityAlias{
			{MountAccessor: "auth_jwt_12", Name: "x"},
		}})},
	)
	require.NoError(t, err)
	assert.Equal(t, 2, ents.aliasesOn("auth_jwt_1"))
	assert.Equal(t, 1, ents.aliasesOn("auth_jwt_12"))
	assert.Equal(t, 0, ents.aliasesOn("auth_jwt"))
}

// A stored record that conflicts with one loaded before it is left out whole:
// none of its keys is published.
func TestEntities_LoadSkipsConflictsWhole(t *testing.T) {
	alias := func(name string) []logical.EntityAlias {
		return []logical.EntityAlias{{MountAccessor: "acc", Name: name}}
	}
	var skipped []string
	ents := loadEntities([]*entityEntry{
		newEntityEntry(&logical.Entity{ID: "1", Name: "a", Aliases: alias("x")}),
		newEntityEntry(&logical.Entity{ID: "2", Name: "b", Aliases: append(alias("y"), alias("x")...)}),
		newEntityEntry(&logical.Entity{ID: "3", Name: "a"}),
		newEntityEntry(&logical.Entity{ID: "4", Name: "c", Aliases: alias("y")}),
	}, func(en *entityEntry, _ error) { skipped = append(skipped, en.ID) })
	assert.Equal(t, []string{"2", "3"}, skipped)
	assert.Equal(t, 2, ents.count())
	assert.Equal(t, "c", ents.byAlias("acc", "y").Name, "b's alias y was never inserted")
	assert.Same(t, emptyEntities, loadEntities(nil, nil))
}

// The store survives a reload: what was published is what storage holds.
func TestEntities_Reload(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)
	before, hash, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)

	c.identityStore.Unload()
	_, _, err = c.identityStore.GetEntity(ctx, "a")
	assert.ErrorIs(t, err, ErrEntityNotFound)
	require.NoError(t, c.identityStore.Load(ctx))
	after, hash2, err := c.identityStore.GetEntity(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, hash, hash2)
	assert.Equal(t, before.ID, after.ID)
	assert.NotNil(t, c.identityStore.EntityByAlias(namespace.RootNamespaceID, accessorOf(t, c, "k8s/"), "system:serviceaccount:billing:agent"))
	u, err := c.identityStore.Usage(ctx)
	require.NoError(t, err)
	assert.Equal(t, IdentitiesUsage{Entities: 1, MaxEntities: logical.MaxEntitiesPerNamespace, Aliases: 2}, u.Identities)
}

func TestEntities_ClearNamespace(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)
	require.NoError(t, c.identityStore.ClearNamespace(ctx))
	_, _, err := c.identityStore.GetEntity(ctx, "a")
	assert.ErrorIs(t, err, ErrEntityNotFound)
	keys, err := c.identityStore.storage.List(ctx, entityListPrefix(namespace.RootNamespace.UUID))
	require.NoError(t, err)
	assert.Empty(t, keys, "storage swept too")
}

// The trees stay consistent with storage across random sequences of writes,
// and a refused write publishes nothing.
func TestEntities_IndexConsistency(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	rng := rand.New(rand.NewSource(1))
	names := []string{"a", "b", "c", "d"}
	aliases := []string{"x", "y", "z"}
	sponsors := []*logical.EntitySponsor{proposeEntry(t, c, ctx, "leads"), proposeEntry(t, c, ctx, "oncall")}
	states := []logical.EntityState{logical.EntityStateActive, logical.EntityStateSuspended}
	for i := 0; i < 400; i++ {
		before := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
		name := names[rng.Intn(len(names))]
		var err error
		switch rng.Intn(10) {
		case 6:
			_, err = c.identityStore.ProposeSponsor(ctx, name, sponsors[rng.Intn(2)], rng.Intn(2) == 0, nil, "")
		case 7:
			err = c.identityStore.ClearSponsor(ctx, name, "")
		case 8:
			err = c.identityStore.CancelPending(ctx, name, nil, "")
		case 9:
			err = c.identityStore.SetEntityState(ctx, name, states[rng.Intn(2)], nil, "")
		case 0:
			err = c.identityStore.CreateEntity(ctx, &logical.Entity{Name: name})
		case 1:
			_, err = c.identityStore.DeleteEntity(ctx, name, "", false)
		case 2:
			_, err = c.identityStore.ClaimAlias(ctx, name, jwt, aliases[rng.Intn(len(aliases))], rng.Intn(2) == 0)
		case 3:
			err = c.identityStore.RemoveAlias(ctx, name, jwt, aliases[rng.Intn(len(aliases))])
		case 4:
			e, _, gerr := c.identityStore.GetEntity(ctx, name)
			if gerr == nil {
				e.Name = names[rng.Intn(len(names))]
				err = c.identityStore.UpdateEntity(ctx, name, e, "")
			} else {
				err = gerr
			}
		case 5:
			e, _, gerr := c.identityStore.GetEntity(ctx, name)
			if gerr == nil {
				e.Description = fmt.Sprint(i)
				err = c.identityStore.UpdateEntity(ctx, name, e, "")
			} else {
				err = gerr
			}
		}
		if err != nil {
			assert.Same(t, before, c.identityStore.namespaceIndex(namespace.RootNamespaceID), "a refused write publishes nothing")
		}
		assertEntityIndexMatchesStorage(t, c)
	}
}

func assertEntityIndexMatchesStorage(t *testing.T, c *Core) {
	t.Helper()
	ctx := rootCtx()
	ents := c.identityStore.namespaceIndex(namespace.RootNamespaceID).entities
	ids, err := c.identityStore.storage.List(ctx, entityListPrefix(namespace.RootNamespace.UUID))
	require.NoError(t, err)
	require.Equal(t, len(ids), ents.count(), "byID and storage")
	require.Equal(t, len(ids), ents.byName.Len(), "byName and storage")
	aliases := 0
	for _, id := range ids {
		stored, err := c.identityStore.readEntity(ctx, namespace.RootNamespace.UUID, id)
		require.NoError(t, err)
		require.Equal(t, stored.Hash(), ents.get(id).hash, "the cached hash is the entity's")
		require.Same(t, ents.get(id), ents.named(stored.Name))
		for _, a := range stored.Aliases {
			require.Same(t, ents.get(id), ents.byAlias(a.MountAccessor, a.Name))
			aliases++
		}
	}
	require.Equal(t, aliases, ents.aliasCount(), "every alias key belongs to a stored entity")
}

// A config write that changes how a mount derives aliases is refused while
// native identities are claimed on it, unless force; a write deriving them as
// before passes. The derivation itself (kind, fact, raw key) is the auth
// methods' (helper.AliasChange); this fake answers from alias_name_source.
func TestEntities_AliasChangeGuard(t *testing.T) {
	c := setupEntityMounts(t)
	guard := func(op logical.Operation, path string, data map[string]any) (error, map[string]any) {
		req := &logical.Request{Operation: op, Path: path, Data: data}
		_, err := c.refuseAliasChange(rootCtx(), req)
		return err, req.Data
	}
	err, _ := guard(logical.UpdateOperation, "auth/jwt/config", map[string]any{"alias_name_source": "repo"})
	assert.NoError(t, err, "nothing claimed on the mount yet")

	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: accessorOf(t, c, "jwt/"), Name: "x"}},
	}))
	err, _ = guard(logical.UpdateOperation, "auth/jwt/config", map[string]any{"alias_name_source": "repo"})
	require.Error(t, err)
	assert.Equal(t, http.StatusConflict, logical.GetErrorCode(err))
	assert.Contains(t, err.Error(), "after this write auth/jwt/ would derive native identities as from repo (now from sub) while 1 are claimed")

	err, _ = guard(logical.UpdateOperation, "auth/jwt/config", map[string]any{"alias_name_source": "sub"})
	assert.NoError(t, err, "the derivation in effect is no change")
	err, data := guard(logical.UpdateOperation, "auth/jwt/config", map[string]any{"alias_name_source": "repo", "force": true})
	assert.NoError(t, err)
	assert.NotContains(t, data, "force", "force never reaches the backend")
	err, data = guard(logical.UpdateOperation, "auth/jwt/config", map[string]any{"bound_audiences": "x", "force": false})
	assert.NoError(t, err, "a write deriving aliases as before passes")
	assert.NotContains(t, data, "force", "force is taken out of every config write")
	err, _ = guard(logical.ReadOperation, "auth/jwt/config", map[string]any{"alias_name_source": "repo"})
	assert.NoError(t, err, "a read is no change")
	err, _ = guard(logical.UpdateOperation, "auth/jwt/role/x", map[string]any{"alias_name_source": "repo"})
	assert.NoError(t, err, "another path of the mount")
	err, _ = guard(logical.UpdateOperation, "auth/k8s/config", map[string]any{"alias_name_source": "uid"})
	assert.NoError(t, err, "another mount, with nothing claimed")
}

// An auth mount with claimed native identities cannot be disabled, unless
// force.
func TestEntities_MountDisableGuard(t *testing.T) {
	c := setupEntityMounts(t)
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: accessorOf(t, c, "jwt/"), Name: "x"}},
	}))
	resp := roleRequest(t, c, rootCtx(), logical.DeleteOperation, "auth/jwt", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "cannot be disabled while 1 native identities are claimed")

	resp = roleRequest(t, c, rootCtx(), logical.DeleteOperation, "auth/k8s", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "nothing claimed on it")
	resp = roleRequest(t, c, rootCtx(), logical.DeleteOperation, "auth/jwt", map[string]any{"force": true})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	require.Len(t, respWarnings(resp), 1, "a forced disable says what it left behind")
	assert.Contains(t, respWarnings(resp)[0], "1 native identities claimed on auth/jwt/ are orphaned")
}

// The claims left on a mount disabled with force are listed as orphaned, show
// no mount path, and are released by accessor.
func TestEntities_OrphanedClaims(t *testing.T) {
	c := setupEntityMounts(t)
	jwt := accessorOf(t, c, "jwt/")
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: jwt, Name: "x"}},
	}))
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "b", Aliases: []logical.EntityAlias{{MountAccessor: accessorOf(t, c, "k8s/"), Name: "y"}},
	}))
	resp := entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"orphaned": true})
	assert.Empty(t, resp.Data["keys"], "every mount still exists")

	require.Equal(t, http.StatusOK,
		roleRequest(t, c, rootCtx(), logical.DeleteOperation, "auth/jwt", map[string]any{"force": true}).StatusCode)
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"orphaned": true})
	assert.Equal(t, []string{"a"}, resp.Data["keys"])
	aliases := entityRequest(t, c, logical.ReadOperation, "entity/a", nil).Data["aliases"].([]map[string]any)
	assert.Equal(t, "", aliases[0]["mount"], "no mount carries the accessor")
	assert.Equal(t, jwt, aliases[0]["mount_accessor"])

	resp = entityRequest(t, c, logical.UpdateOperation, "lookup", map[string]any{"mount_accessor": jwt, "name": "x"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "a", resp.Data["entity"])
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a/alias/remove", map[string]any{"mount_accessor": jwt, "name": "x"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	resp = entityRequest(t, c, logical.ListOperation, "entity", map[string]any{"orphaned": true})
	assert.Empty(t, resp.Data["keys"])

	for _, body := range []map[string]any{
		{"name": "x"},
		{"mount": "auth/k8s/", "mount_accessor": jwt, "name": "x"},
		{"mount_accessor": "a\x00b", "name": "x"},
	} {
		resp = entityRequest(t, c, logical.UpdateOperation, "lookup", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	}
}

// A retired entity keeps its native identities: they cannot be released, only
// moved, and the entity is deleted only with force.
func TestEntities_RetiredKeepsClaims(t *testing.T) {
	c := setupEntityMounts(t)
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", billingAgentBody()).StatusCode)
	require.Equal(t, http.StatusOK, entityRequest(t, c, logical.UpdateOperation, "entity/a/state", map[string]any{"state": "retired"}).StatusCode)

	resp := entityRequest(t, c, logical.UpdateOperation, "entity/a/alias/remove", map[string]any{
		"mount": "auth/k8s/", "name": "system:serviceaccount:billing:agent",
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "can only be moved")
	resp = entityRequest(t, c, logical.DeleteOperation, "entity/a", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "a delete needs force")
	assert.NotNil(t, c.identityStore.EntityByAlias(namespace.RootNamespaceID, accessorOf(t, c, "k8s/"), "system:serviceaccount:billing:agent"))

	resp = entityRequest(t, c, logical.DeleteOperation, "entity/a", map[string]any{"force": true})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{`forced: retired entity "a" deleted; the 2 native identities it claimed are unclaimed again`},
		respWarnings(resp), "a forced delete says what it released")
	assert.Nil(t, c.identityStore.EntityByAlias(namespace.RootNamespaceID, accessorOf(t, c, "k8s/"), "system:serviceaccount:billing:agent"))
}

// "id" is the path segment that reads an entity by ID, never an entity name.
func TestEntities_ReservedName(t *testing.T) {
	c := setupEntityMounts(t)
	resp := entityRequest(t, c, logical.CreateOperation, "entity/id", map[string]any{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, http.StatusCreated, entityRequest(t, c, logical.CreateOperation, "entity/a", map[string]any{}).StatusCode)
	resp = entityRequest(t, c, logical.UpdateOperation, "entity/a", map[string]any{"new_name": "id"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "is reserved")
}

// spyStorage records the keys written through it and fails the failAt-th Put
// (1-based; 0 never fails).
type spyStorage struct {
	sdklogical.Storage
	puts   []string
	failAt int
}

func (s *spyStorage) Put(ctx context.Context, e *sdklogical.StorageEntry) error {
	s.puts = append(s.puts, e.Key)
	if len(s.puts) == s.failAt {
		return errors.New("injected storage failure")
	}
	return s.Storage.Put(ctx, e)
}

// A move writes the loser first. When the winner's write then fails, what is
// published is what storage holds: the native identity unclaimed, never
// claimed twice, and a reload changes nothing.
func TestEntities_MoveWritesLoserFirst(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: jwt, Name: "x"}},
	}))
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "b"}))
	a, _, _ := c.identityStore.GetEntity(ctx, "a")
	b, _, _ := c.identityStore.GetEntity(ctx, "b")

	spy := &spyStorage{Storage: c.identityStore.storage, failAt: 2}
	c.identityStore.storage = spy
	_, err := c.identityStore.ClaimAlias(ctx, "b", jwt, "x", true)
	require.ErrorContains(t, err, "injected storage failure")
	require.Equal(t, []string{
		entityStorageKey(namespace.RootNamespace.UUID, a.ID),
		entityStorageKey(namespace.RootNamespace.UUID, b.ID),
	}, spy.puts, "the loser is written first")
	assert.Nil(t, c.identityStore.EntityByAlias(namespace.RootNamespaceID, jwt, "x"), "unclaimed, as stored")
	assertEntityIndexMatchesStorage(t, c)

	spy.failAt = 0
	from, err := c.identityStore.ClaimAlias(ctx, "b", jwt, "x", false)
	require.NoError(t, err)
	assert.Empty(t, from, "nobody held it any more")
	assertEntityIndexMatchesStorage(t, c)
}

// An entity publish invalidates every cached membership of the namespace: the
// next request recomputes once, and the one after takes the fast path again.
func TestEntities_PublishRecomputesCachedMembershipOnce(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("g"))
	require.NoError(t, err)
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "x"}, time.Time{})
	now := time.Now()
	first := membership(adm, c.identityStore.namespaceIndex(namespace.RootNamespaceID), now)
	require.Equal(t, []string{"g"}, first.Groups)

	matches := countMatches(t)
	require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: "a"}))
	ns := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	second := membership(adm, ns, now)
	assert.NotSame(t, first, second, "a new generation recomputes")
	assert.Equal(t, first.Groups, second.Groups)
	assert.Equal(t, int64(1), matches.Load())
	assert.Same(t, second, membership(adm, ns, now), "then the fast path again")
	assert.Equal(t, int64(1), matches.Load())
}

// The guard runs on the request path in front of a real jwt mount: a facts
// remap behind the alias fact, or a kind change, is refused while a native
// identity is claimed on the mount; a write deriving aliases as before passes,
// and so does a forced one, whose force never reaches the backend.
func TestEntities_AliasChangeGuardOnRequestPath(t *testing.T) {
	e := newJWTEnv(t, "")
	c := e.c
	c.authMethods["jwt"] = jwtmethod.Factory
	require.NoError(t, c.mount(rootCtx(), &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt/"}))
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	config := func(body map[string]any) *logical.Response {
		return roleHTTP(t, c, root, http.MethodPost, "/v1/auth/jwt/config", body)
	}
	resp := config(map[string]any{
		"jwt_validation_pubkeys": []string{e.pubPEM},
		"bound_audiences":        "warden",
		"facts":                  map[string]any{"repository": "repo"},
		"alias_name_source":      "repo",
	})
	require.Less(t, resp.StatusCode, 300, "%v", resp.Err)
	require.NoError(t, c.identityStore.CreateEntity(rootCtx(), &logical.Entity{
		Name: "a", Aliases: []logical.EntityAlias{{MountAccessor: accessorOf(t, c, "jwt/"), Name: "acme/x"}},
	}))

	resp = config(map[string]any{"facts": map[string]any{"job_workflow_ref": "repo"}})
	require.Equal(t, http.StatusConflict, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, resp.Err.Error(), `as kind agent, fact "repo" (source "job_workflow_ref") `+
		`(now kind agent, fact "repo" (source "repository"))`)
	resp = config(map[string]any{"entity_kind": "human"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a kind change")
	resp = config(map[string]any{"alias_name_source": "sub"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a source change")

	resp = config(map[string]any{"bound_audiences": "warden,other"})
	assert.Less(t, resp.StatusCode, 300, "a write deriving aliases as before passes: %v", resp.Err)
	resp = config(map[string]any{"facts": map[string]any{"repository": "repo"}, "alias_name_source": "repo"})
	assert.Less(t, resp.StatusCode, 300, "resending the same mapping passes: %v", resp.Err)

	resp = config(map[string]any{"facts": map[string]any{"job_workflow_ref": "repo"}, "force": true})
	require.Less(t, resp.StatusCode, 300, "%v", resp.Err)
	require.Len(t, respWarnings(resp), 1, "a forced change says so on its response")
	assert.Contains(t, respWarnings(resp)[0], `forced: auth/jwt/ now derives native identities as kind agent, fact "repo" (source "job_workflow_ref")`)
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/auth/jwt/config", nil)
	assert.Equal(t, map[string]string{"job_workflow_ref": "repo"}, resp.Data["facts"])

	// force as a query parameter, as an HTTP client sends it on any method.
	resp = roleHTTP(t, c, root, http.MethodPost, "/v1/auth/jwt/config", map[string]any{"alias_name_source": "sub"})
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = roleHTTP(t, c, root, http.MethodPost, "/v1/auth/jwt/config?force=true", map[string]any{"alias_name_source": "sub"})
	require.Less(t, resp.StatusCode, 300, "%v", resp.Err)
	assert.Len(t, respWarnings(resp), 1)
}

// Lock-free readers run against writers without a race: every snapshot a
// reader loads is immutable.
func TestEntities_ReadsDuringWrites(t *testing.T) {
	c := setupEntityMounts(t)
	ctx := rootCtx()
	jwt := accessorOf(t, c, "jwt/")
	for _, n := range []string{"a", "b"} {
		require.NoError(t, c.identityStore.CreateEntity(ctx, &logical.Entity{Name: n}))
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if e := c.identityStore.EntityByAlias(namespace.RootNamespaceID, jwt, "x"); e != nil {
					_ = e.Name + e.Aliases[0].Name
				}
				ents, _, err := c.identityStore.ListEntities(ctx, EntityFilter{})
				if err == nil && len(ents) != 2 {
					t.Errorf("listed %d entities", len(ents))
				}
				_ = c.identityStore.AliasesBoundTo(jwt)
			}
		}()
	}
	for i := range 200 {
		_, err := c.identityStore.ClaimAlias(ctx, []string{"a", "b"}[i%2], jwt, "x", true)
		require.NoError(t, err)
	}
	close(stop)
	readers.Wait()
	assertEntityIndexMatchesStorage(t, c)
}

// The entity index uses one package of github.com/cilium/statedb, the
// persistent radix tree in part, and none of the rest: the module also holds
// a full in-memory database whose dependencies (a dependency-injection
// framework, configuration loaders) Warden does not want.
func TestEntities_OnlyStatedbPart(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the module's dependencies")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	out, err := exec.Command(goBin, "list", "-deps", "github.com/stephnangue/warden/...").Output()
	require.NoError(t, err)
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasPrefix(pkg, "github.com/cilium/statedb") && pkg != "github.com/cilium/statedb/part" {
			t.Errorf("%s is imported; only github.com/cilium/statedb/part may be", pkg)
		}
	}
}

// Entity paths need sudo, like the group paths.
func TestEntities_SudoRequired(t *testing.T) {
	c := createTestCore(t)
	for _, p := range []string{"sys/identity/entity", "sys/identity/entity/a", "sys/identity/entity/id/x",
		"sys/identity/entity/a/alias", "sys/identity/entity/a/sponsor", "sys/identity/entity/a/sponsor/remove",
		"sys/identity/entity/a/state", "sys/identity/lookup"} {
		assert.True(t, c.router.RootPath(rootCtx(), p), "%s must require sudo", p)
	}
	assert.False(t, c.router.RootPath(rootCtx(), "sys/identity/usage"))
}
