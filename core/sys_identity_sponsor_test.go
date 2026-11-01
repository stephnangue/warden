package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// sponsorEnv is a ticketRequestEnv with the entity billing-agent, sponsored by
// "humans" (whose members the env's ticket is), and the group "finance",
// whose members it is not.
type sponsorEnv struct {
	*ticketRequestEnv
}

func newSponsorEnv(t *testing.T) *sponsorEnv {
	t.Helper()
	e := &sponsorEnv{newTicketRequestEnv(t)}
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "finance", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "roles": {"Finance.Oncall"}}},
	})
	require.NoError(t, err)
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "billing-agent", Description: "Reconciles invoices"}))
	proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "humans", true)
	return e
}

// sponsorRequest runs a request on a sponsor path (relative to the namespace,
// e.g. "sys/identity/sponsor/billing-agent/suspend") with headers: a read
// when body is nil, a write otherwise.
func (e *sponsorEnv) sponsorRequest(path string, body map[string]any, headers map[string]string) (*logical.Response, *logical.Request) {
	e.t.Helper()
	method, op := http.MethodGet, logical.ReadOperation
	if body != nil {
		method, op = http.MethodPost, logical.UpdateOperation
	}
	hr := httptest.NewRequest(method, "/v1/"+path, strings.NewReader("{}"))
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	req := &logical.Request{Path: path, Operation: op, HTTPRequest: hr, Data: body, RequestID: "req-sponsor"}
	resp, _ := e.c.HandleRequest(context.Background(), req)
	require.NotNil(e.t, resp)
	return resp, req
}

// rootToken returns a root token's value.
func (e *sponsorEnv) rootToken() string {
	e.t.Helper()
	root, err := e.c.tokenStore.GenerateRootToken()
	require.NoError(e.t, err)
	return root
}

// responseFor returns the response audit entry recorded for path, which
// routing records relative to its mount ("identity/sponsor/x" for
// "sys/identity/sponsor/x").
func (m *accessAuditRecorder) responseFor(t *testing.T, path string) *audit.LogEntry {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.responses {
		if e.Request != nil && strings.HasSuffix(path, e.Request.Path) && e.Request.Path != "" {
			return e
		}
	}
	t.Fatalf("no response audit entry for %q", path)
	return nil
}

func (e *sponsorEnv) entity(name string) *logical.Entity {
	e.t.Helper()
	ent, _, err := e.c.identityStore.GetEntity(e.ctx, name)
	require.NoError(e.t, err)
	return ent
}

func TestSponsorSurface_MemberActs(t *testing.T) {
	e := newSponsorEnv(t)
	ticket := wardenToken(e.value)

	resp, req := e.sponsorRequest("sys/identity/sponsor/billing-agent", nil, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "billing-agent", resp.Data["name"])
	assert.Equal(t, "group:humans", req.SponsoredBy)

	// Audit: the person, the built-ins, the mount that admitted them, the group.
	entry := e.audit.responseFor(t, "sys/identity/sponsor/billing-agent")
	require.NotNil(t, entry.Auth)
	assert.Equal(t, TypeTicketToken, entry.Auth.TokenType)
	assert.Equal(t, []string{builtinCBPPolicy, builtinMCPPolicy, builtinSponsorPolicy}, entry.Auth.Policies)
	assert.Equal(t, e.mount.Accessor, entry.Auth.MountAccessor)
	assert.Equal(t, "human", entry.Auth.EntityKind)
	assert.Equal(t, "group:humans", entry.Auth.SponsoredBy)

	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent/suspend", map[string]any{}, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "suspended", resp.Data["state"])
	assert.Equal(t, logical.EntityStateSuspended, e.entity("billing-agent").State)

	// On a bearer too, the same.
	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent", nil, bearer(e.value))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
}

// Every refusal is the same response: a caller with no role learns nothing
// about which entities exist or why.
func TestSponsorSurface_UniformRefusal(t *testing.T) {
	e := newSponsorEnv(t)
	ticket := wardenToken(e.value)
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "unsponsored"}))
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "finance-agent"}))
	proposeSponsor(t, e.c, e.ctx, e.ctx, "finance-agent", "finance", true)
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "retired-agent"}))
	proposeSponsor(t, e.c, e.ctx, e.ctx, "retired-agent", "humans", true)
	require.NoError(t, e.c.identityStore.SetEntityState(e.ctx, "retired-agent", logical.EntityStateRetired, nil, ""))

	cases := []struct {
		name, path string
		body       map[string]any
		headers    map[string]string
	}{
		{"missing entity", "sys/identity/sponsor/nobody", nil, ticket},
		{"no sponsor", "sys/identity/sponsor/unsponsored", nil, ticket},
		{"not a member", "sys/identity/sponsor/finance-agent", nil, ticket},
		{"not a member, suspend", "sys/identity/sponsor/finance-agent/suspend", map[string]any{}, ticket},
		{"not a member, handover", "sys/identity/sponsor/finance-agent/handover", map[string]any{"group": "humans"}, ticket},
		{"no handover to accept", "sys/identity/sponsor/billing-agent/accept", map[string]any{}, ticket},
		{"retired", "sys/identity/sponsor/retired-agent/suspend", map[string]any{}, ticket},
		{"no credential", "sys/identity/sponsor/billing-agent", nil, nil},
		{"an agent bearer", "sys/identity/sponsor/billing-agent", nil, bearer("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")},
		{"a garbage bearer, write", "sys/identity/sponsor/billing-agent/suspend", map[string]any{}, bearer("not-a-token")},
		{"root token", "sys/identity/sponsor/billing-agent", nil, wardenToken(e.rootToken())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, req := e.sponsorRequest(tc.path, tc.body, tc.headers)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.NotNil(t, resp.Err)
			assert.Equal(t, errNoSponsoredAgent, resp.Err.Error())
			assert.Empty(t, req.SponsoredBy)
		})
	}
	assert.Equal(t, logical.EntityStateActive, e.entity("finance-agent").State, "nothing changed")
}

// A request without a ticket on a sponsor path is refused before any auth
// mount is asked about its credential: no 401, no 503 naming a mount.
func TestSponsorSurface_TicketOnlyAdmission(t *testing.T) {
	e := newSponsorEnv(t)
	for _, path := range []string{
		"sys/identity/sponsor/billing-agent",
		"sys/identity/sponsor/billing-agent/suspend",
		"sys/identity/sponsor/billing-agent/handover",
		"sys/identity/sponsor/billing-agent/accept",
	} {
		var body map[string]any
		if path != "sys/identity/sponsor/billing-agent" {
			body = map[string]any{}
		}
		for _, h := range []map[string]string{nil, bearer("eyJhbGciOiJSUzI1NiJ9.e30.c2ln"), bearer("not-a-token")} {
			resp, req := e.sponsorRequest(path, body, h)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, path)
			assert.Equal(t, errNoSponsoredAgent, resp.Err.Error(), path)
			assert.Nil(t, req.Discovery, "%s: the role-less leg never ran", path)
			assert.Nil(t, req.TokenEntry(), path)
		}
	}
	assert.Equal(t, logical.EntityStateActive, e.entity("billing-agent").State)
	// Discovery still admits bearers as before.
	resp, _, err := e.do("sys/introspect/roles", bearer("eyJhbGciOiJSUzI1NiJ9.e30.c2ln"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the role-less leg answers discovery")
}

func TestSponsorSurface_HandoverAndAccept(t *testing.T) {
	e := newSponsorEnv(t)
	ticket := wardenToken(e.value)

	// To a group the caller is not a member of: pending; humans still sponsors.
	resp, req := e.sponsorRequest("sys/identity/sponsor/billing-agent/handover", map[string]any{"group": "finance"}, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), "handover to /finance is pending: a member must accept it")
	assert.Equal(t, "group:humans", req.SponsoredBy)
	ent := e.entity("billing-agent")
	assert.Equal(t, "humans", ent.Sponsor.Group)
	assert.Equal(t, "finance", ent.PendingSponsor.Group)
	assert.Equal(t, "0583-oid", ent.PendingSponsor.AddedBy.Alias)

	// A member of humans cannot accept for finance.
	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent/accept", map[string]any{}, ticket)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent/handover", map[string]any{"cancel": true}, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Nil(t, e.entity("billing-agent").PendingSponsor)
	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent/handover", map[string]any{"cancel": true}, ticket)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "nothing pending, said to the sponsor")

	// One answer for an unknown group; the admin path tells more.
	resp, _ = e.sponsorRequest("sys/identity/sponsor/billing-agent/handover", map[string]any{"group": "nope"}, ticket)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "no such virtual group")

	// Handed over to finance by an admin; then a member of the pending group
	// (the ticket, once finance is humans' twin) reads and accepts.
	proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "admins-to-be", false)
	resp, req = e.sponsorRequest("sys/identity/sponsor/billing-agent", nil, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "group:humans", req.SponsoredBy, "a member of the sponsor reads as the sponsor")

	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "oncall", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}}},
	})
	require.NoError(t, err)
	require.NoError(t, e.c.identityStore.CreateEntity(e.ctx, &logical.Entity{Name: "etl", Description: "x"}))
	proposeSponsor(t, e.c, e.ctx, e.ctx, "etl", "finance", true)
	proposeSponsor(t, e.c, e.ctx, e.ctx, "etl", "oncall", false)

	resp, req = e.sponsorRequest("sys/identity/sponsor/etl", nil, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "group:oncall", req.SponsoredBy, "a member of the pending group may read before accepting")
	resp, _ = e.sponsorRequest("sys/identity/sponsor/etl/suspend", map[string]any{}, ticket)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "only the sponsor's members suspend")

	resp, req = e.sponsorRequest("sys/identity/sponsor/etl/accept", map[string]any{}, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "group:oncall", req.SponsoredBy)
	ent = e.entity("etl")
	assert.Equal(t, "oncall", ent.Sponsor.Group)
	assert.Nil(t, ent.PendingSponsor)
	assert.Equal(t, logical.SponsorActor{MountAccessor: e.mount.Accessor, Alias: "0583-oid", Principal: "0583-oid"}, ent.Sponsor.AcceptedBy)
	assert.Equal(t, "warden", ent.GovernedBy())

	// A member of both hands over and is accepted at once.
	resp, _ = e.sponsorRequest("sys/identity/sponsor/etl/handover", map[string]any{"group": "humans"}, ticket)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Empty(t, respWarnings(resp))
	assert.Equal(t, "humans", e.entity("etl").Sponsor.Group)
}

// Accept re-checks under the lock what the handler matched on a read: a
// proposal that replaced the pending group in between is never accepted by a
// member of the one it replaced.
func TestSponsorSurface_AcceptRefusesAReplacedHandover(t *testing.T) {
	e := newSponsorEnv(t)
	a := proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "finance", false)
	proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "admins-to-be", false)
	err := e.c.identityStore.AcceptSponsor(e.ctx, "billing-agent", a, logical.SponsorActor{Principal: "x"}, "")
	assert.ErrorIs(t, err, ErrSponsorChanged)
	ent := e.entity("billing-agent")
	assert.Equal(t, "humans", ent.Sponsor.Group)
	assert.Equal(t, "admins-to-be", ent.PendingSponsor.Group)

	err = e.c.identityStore.AcceptSponsor(e.ctx, "billing-agent", ent.PendingSponsor, logical.SponsorActor{Principal: "x"}, "")
	require.NoError(t, err)
	ent = e.entity("billing-agent")
	assert.Equal(t, "admins-to-be", ent.Sponsor.Group)
	assert.False(t, ent.Sponsor.AcceptedAt.Before(ent.Sponsor.AddedAt))

	assert.ErrorIs(t, e.c.identityStore.AcceptSponsor(e.ctx, "billing-agent", nil, logical.SponsorActor{Principal: "x"}, ""),
		ErrSponsorNotFound)
}

// Driven through the handler: a proposal that replaces the pending group
// between the accept handler's decision and its write is never accepted by a
// member of the group it replaced.
func TestSponsorSurface_AcceptRaceRefused(t *testing.T) {
	e := newSponsorEnv(t)
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "oncall", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}}},
	})
	require.NoError(t, err)
	proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "oncall", false)
	testHookSponsorDecided = func() {
		proposeSponsor(t, e.c, e.ctx, e.ctx, "billing-agent", "finance", false)
	}
	defer func() { testHookSponsorDecided = nil }()

	resp, req := e.sponsorRequest("sys/identity/sponsor/billing-agent/accept", map[string]any{}, wardenToken(e.value))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, errNoSponsoredAgent, resp.Err.Error())
	assert.Empty(t, req.SponsoredBy)
	ent := e.entity("billing-agent")
	assert.Equal(t, "humans", ent.Sponsor.Group, "the sponsor is unchanged")
	assert.Equal(t, "finance", ent.PendingSponsor.Group, "the replacing proposal stays pending, not accepted")
}

// A ticket of a child namespace is refused in its parent before any handler,
// with one answer whether the entity exists or not.
func TestSponsorSurface_ChildTicketInParentRefused(t *testing.T) {
	e := newSponsorEnv(t)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), child))
	cctx := namespace.ContextWithNamespace(context.Background(), child)
	b, me := e.mountIssuer(cctx, "oidc/")
	childValue, _ := e.login(cctx, b, me, time.Hour)

	var answers []string
	for _, name := range []string{"billing-agent", "nobody"} {
		resp, req := e.sponsorRequest("sys/identity/sponsor/"+name, nil, wardenToken(childValue))
		require.NotNil(t, resp.Err)
		answers = append(answers, http.StatusText(resp.StatusCode)+": "+resp.Err.Error())
		assert.Nil(t, req.TokenEntry())
	}
	assert.Equal(t, answers[0], answers[1], "the same refusal for an existing and a missing entity")
}

// Methods and sub-paths the surface does not serve answer alike whatever the
// entity name.
func TestSponsorSurface_UnservedAnswerAlike(t *testing.T) {
	e := newSponsorEnv(t)
	for _, op := range []logical.Operation{logical.DeleteOperation, logical.ListOperation} {
		var answers []int
		for _, name := range []string{"billing-agent", "nobody"} {
			hr := httptest.NewRequest(http.MethodGet, "/v1/sys/identity/sponsor/"+name, nil)
			hr.Header.Set(logical.HeaderWardenToken, e.value)
			req := &logical.Request{Path: "sys/identity/sponsor/" + name, Operation: op, HTTPRequest: hr}
			resp, _ := e.c.HandleRequest(context.Background(), req)
			require.NotNil(t, resp)
			answers = append(answers, resp.StatusCode)
		}
		assert.Equal(t, answers[0], answers[1], "%s", op)
		assert.Equal(t, http.StatusForbidden, answers[0], "%s is not granted", op)
	}
	assert.Equal(t, logical.EntityStateActive, e.entity("billing-agent").State)
}

// A ticket of the parent acts in a child namespace on an entity there that a
// parent group sponsors, under the child's built-ins.
func TestSponsorSurface_ParentTicketInChild(t *testing.T) {
	e := newSponsorEnv(t)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), child))
	require.NoError(t, e.c.seedNamespacePolicies(namespace.ContextWithNamespace(context.Background(), child)))
	cctx := namespace.ContextWithNamespace(context.Background(), child)
	require.NoError(t, e.c.identityStore.CreateEntity(cctx, &logical.Entity{Name: "etl"}))
	proposeSponsor(t, e.c, cctx, e.ctx, "etl", "humans", true)

	resp, req := e.sponsorRequest("team-a/sys/identity/sponsor/etl/suspend", map[string]any{}, wardenToken(e.value))
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "group:humans", req.SponsoredBy)
	ent, _, err := e.c.identityStore.GetEntity(cctx, "etl")
	require.NoError(t, err)
	assert.Equal(t, logical.EntityStateSuspended, ent.State)
}

// Emptying default-sponsor turns the surface off: the next request is refused
// by the policy, before the handler. The admin paths are untouched.
func TestSponsorSurface_EmptiedBuiltinTurnsItOff(t *testing.T) {
	e := newSponsorEnv(t)
	p := testParsePolicy(t, "# sponsors are off\n")
	p.Name, p.Type = builtinSponsorPolicy, PolicyTypeCBP
	require.NoError(t, e.c.policyStore.SetPolicy(e.ctx, p, nil))

	resp, req := e.sponsorRequest("sys/identity/sponsor/billing-agent", nil, wardenToken(e.value))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotEqual(t, errNoSponsoredAgent, resp.Err.Error(), "the policy refused it, not the handler")
	assert.Empty(t, req.SponsoredBy)
	resp, _, err := e.do("sys/introspect/roles", wardenToken(e.value))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "discovery is untouched")
}

// The built-in grants the four exact shapes and nothing else on the surface.
func TestSponsorSurface_BuiltinGrantsExactShapes(t *testing.T) {
	e := newSponsorEnv(t)
	ticket := wardenToken(e.value)
	for _, path := range []string{
		"sys/identity/sponsor/billing-agent/unknown",
		"sys/identity/sponsor/billing-agent/suspend/x",
	} {
		resp, _ := e.sponsorRequest(path, map[string]any{}, ticket)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, path)
		assert.NotEqual(t, errNoSponsoredAgent, resp.Err.Error(), "%s: refused by the policy", path)
	}
	resp, _ := e.sponsorRequest("sys/identity/sponsor/billing-agent", map[string]any{}, ticket)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a write on the read path is not granted")

	// The seeded body raises no warning; a prefix or another "+" stanza does.
	seeded := testParsePolicy(t, builtinSponsorBody)
	seeded.Name, seeded.Type = builtinSponsorPolicy, PolicyTypeCBP
	assert.Empty(t, builtinPolicyWarnings(seeded))
	for _, body := range []string{
		`path "sys/identity/sponsor/*" { capabilities = ["read"] }`,
		`path "sys/identity/sponsor/+/remove" { capabilities = ["update"] }`,
		`path "sys/identity/entity/+" { capabilities = ["read"] }`,
	} {
		p := testParsePolicy(t, body)
		p.Name, p.Type = builtinSponsorPolicy, PolicyTypeCBP
		assert.Len(t, builtinPolicyWarnings(p), 1, body)
	}
}

// Each sponsor request computes the ticket's membership once, in the hook:
// the handler reads it, it does not match again.
func TestSponsorSurface_MembershipComputedOnce(t *testing.T) {
	e := newSponsorEnv(t)
	matches := countMatches(t)
	resp, _ := e.sponsorRequest("sys/identity/sponsor/billing-agent", nil, wardenToken(e.value))
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	perRequest := matches.Load()
	require.NotZero(t, perRequest)

	te, err := e.c.lookupTicket(e.ctx, e.value)
	require.NoError(t, err)
	matches.Store(0)
	compute(te.Admission, te.Admission.Mount.Load(), e.c.grantIndex(namespace.RootNamespaceID), time.Now())
	assert.Equal(t, matches.Load(), perRequest, "one computation's worth of rule matches")
}

// The sponsor paths are identity paths, not root paths.
func TestSponsorSurface_IsAnIdentityPath(t *testing.T) {
	c := createTestCore(t)
	for _, p := range []string{"sys/identity/sponsor/a", "sys/identity/sponsor/a/accept"} {
		assert.True(t, c.router.IdentityPath(rootCtx(), p), p)
		assert.False(t, c.router.RootPath(rootCtx(), p), p)
	}
	assert.True(t, isSponsorPath("sys/identity/sponsor/a"))
	assert.False(t, isSponsorPath("sys/identity/entity/a/sponsor"))
	assert.False(t, isSponsorPath("sys/introspect/roles"))
}
