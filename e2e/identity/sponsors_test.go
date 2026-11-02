//go:build e2e

package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// People of the sponsors' identity provider: Ada administers agents and leads
// billing, Bob is on the finance on-call rota and holds no Warden role, Carol
// is in neither team.
const (
	sponsorAda   = "ada@sponsors.example"
	sponsorBob   = "bob@sponsors.example"
	sponsorCarol = "carol@sponsors.example"
)

// sponsorEntity is an entity as the sponsor and entity commands print it.
type sponsorEntity struct {
	Name             string        `json:"name"`
	State            string        `json:"state"`
	GovernedBy       string        `json:"governed_by"`
	UngovernedReason string        `json:"ungoverned_reason"`
	Sponsor          *sponsorEntry `json:"sponsor"`
	PendingSponsor   *sponsorEntry `json:"pending_sponsor"`
}

type sponsorEntry struct {
	Group      string        `json:"group"`
	Namespace  string        `json:"namespace"`
	Status     string        `json:"status"`
	AddedBy    *sponsorActor `json:"added_by"`
	AcceptedBy *sponsorActor `json:"accepted_by"`
}

type sponsorActor struct {
	Mount     string `json:"mount"`
	Alias     string `json:"alias"`
	Principal string `json:"principal"`
}

// sponsorsEnv is a child namespace holding the agent, administered centrally
// from the root namespace: an oidc mount there signs people in, its groups are
// the sponsor teams, and a role lets Ada administer the child's entities.
type sponsorsEnv struct {
	t        *testing.T
	port     int
	ns       string // the child namespace, e.g. "e2e-sponsors-1a2b3c4d"
	mount    string // the oidc mount, root namespace
	leads    string // the billing leads' group (Ada)
	oncall   string // the finance on-call group (Bob)
	admin    string // the role administering the child's entities
	homes    map[string]string
	accessor string
}

func newSponsorsEnv(t *testing.T) *sponsorsEnv {
	t.Helper()
	port := h.GetLeaderPort(t)
	e := &sponsorsEnv{
		t:      t,
		port:   port,
		ns:     h.UniqueMount("e2e-sponsors"),
		mount:  h.UniqueMount("oidc-sponsors"),
		leads:  h.UniqueMount("billing-leads"),
		oncall: h.UniqueMount("finance-oncall"),
		admin:  h.UniqueMount("e2e-platform-admin"),
		homes:  map[string]string{},
	}
	// Registered first, so it runs last: deleting the namespace clears its
	// entities and groups.
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+e.ns, "")
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/namespaces/"+e.ns) })

	idp := h.StartHumanIdP(t, map[string]map[string]any{
		sponsorAda:   {"roles": []any{"Warden.Admin", "Billing.Lead"}},
		sponsorBob:   {"roles": []any{"Finance.Oncall"}},
		sponsorCarol: {"roles": []any{}},
	})
	h.EnableAuth(t, port, "", e.mount, "oidc", h.OIDCMountConfig(idp, nil))
	e.accessor = mountAccessor(t, port, e.mount)
	mount := h.AuthMountPath(e.mount)
	for group, appRole := range map[string]string{e.leads: "Billing.Lead", e.oncall: "Finance.Oncall"} {
		h.WriteGroupInNS(t, port, "", group, h.Group{Rules: []map[string][]string{
			{"mount": {mount}, "kind": {"human"}, "roles": {appRole}},
		}})
	}

	policy := e.admin + "-policy"
	h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+policy, h.JSON(t, map[string]any{"policy": fmt.Sprintf(
		"path \"%[1]s/sys/identity/entity\" {\n  capabilities = [\"list\", \"sudo\"]\n}\n"+
			"path \"%[1]s/sys/identity/entity/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n",
		e.ns)}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/cbp/"+policy) })
	h.GrantRole(t, port, e.mount, e.admin, h.Role{Policies: []string{policy}}, h.Rule{"kind": {"human"}, "roles": {"Warden.Admin"}})
	t.Cleanup(func() { h.RevokeRoleBestEffort(port, e.mount, e.admin) })
	return e
}

// login signs person in at the oidc mount, with args, under a home of their
// own, and returns warden login's stderr.
func (e *sponsorsEnv) login(person string, args ...string) string {
	e.t.Helper()
	home := e.t.TempDir()
	e.homes[person] = home
	run := h.OIDCLogin(e.t, e.port, home, person, nil, nil, append([]string{"-path=" + e.mount}, args...)...)
	if run.Err != nil {
		e.t.Fatalf("warden login as %s: %v\n%s", person, run.Err, run.Stderr)
	}
	return run.Stderr
}

// as runs a warden command in the child namespace with person's session.
func (e *sponsorsEnv) as(person string, args ...string) (stdout, stderr string, err error) {
	e.t.Helper()
	return h.SessionCLI(e.t, e.port, e.homes[person], map[string]string{"WARDEN_NAMESPACE": e.ns}, args...)
}

// mustAs is as, failing the test unless the command succeeded, decoding its
// -o json output.
func (e *sponsorsEnv) mustAs(person string, args ...string) (sponsorEntity, string) {
	e.t.Helper()
	stdout, stderr, err := e.as(person, append(args, "-o", "json")...)
	if err != nil {
		e.t.Fatalf("as %s, warden %s: %v\nstdout: %s\nstderr: %s", person, strings.Join(args, " "), err, stdout, stderr)
	}
	var out sponsorEntity
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		e.t.Fatalf("warden %s -o json: %v: %s", strings.Join(args, " "), err, stdout)
	}
	return out, stderr
}

// root runs a warden command in the child namespace with the root token.
func (e *sponsorsEnv) root(args ...string) (stdout, stderr string, err error) {
	e.t.Helper()
	return h.WardenCLISplitWithPort(e.t, e.port, map[string]string{"WARDEN_TOKEN": h.RootToken(e.t), "WARDEN_NAMESPACE": e.ns}, args...)
}

// refused fails the test unless err is a sponsor path's one refusal.
func refused(t *testing.T, what, stderr string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(stderr, "no sponsored agent by that name") {
		t.Fatalf("%s: err %v, stderr %q; want the sponsor refusal", what, err, stderr)
	}
}

// TestSponsors_EndToEnd is Part 4 on a 3-node cluster: an agent's sponsor team
// is a group of people, accepted by one of them, who act on the agent with no
// Warden role, through warden login.
//
// Ada, an admin and a billing lead, creates the agent in a child namespace
// (born ungoverned) and proposes her own team, accepted at once. Proposing
// finance on-call, of which she is not a member, leaves a pending handover.
// Bob, on call and with no Warden role, reads the agent through every node,
// accepts it for his team in one write, and suspends it; only an admin makes
// it active again. Carol, in neither team, the agent's own JWT, a garbage
// bearer and the root token all get the same refusal. Bob offers the agent
// back and cancels. Emptying the child's default-sponsor turns sponsors off
// there and leaves administration alone. A forced delete of the sponsor group
// leaves the agent ungoverned. Root can only propose.
func TestSponsors_EndToEnd(t *testing.T) {
	e := newSponsorsEnv(t)
	start := time.Now()
	const agent = "billing-agent"
	t.Cleanup(func() { h.NSRequestBestEffort(e.port, e.ns, "DELETE", "sys/identity/entity/"+agent+"?force=true") })

	assert := func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Fatalf(format, args...)
		}
	}

	// 1. The agent is created ungoverned: no sponsor.
	if stdout, stderr, err := e.root("identity", "entity", "create", agent,
		"-description", "Reconciles supplier invoices against purchase orders"); err != nil {
		t.Fatalf("create: %v\n%s\n%s", err, stdout, stderr)
	}

	// 2. Ada proposes her own team: accepted at once, by her.
	e.login(sponsorAda, "-role="+e.admin)
	ent, _ := e.mustAs(sponsorAda, "identity", "entity", "sponsor", "propose", agent, "-json",
		h.JSON(t, map[string]string{"group": e.leads, "namespace": "/"}))
	assert(ent.GovernedBy == "warden", "after Ada's proposal: %+v, want governed", ent)
	assert(ent.Sponsor != nil && ent.Sponsor.Group == e.leads && ent.Sponsor.Status == "accepted",
		"sponsor %+v, want %s accepted", ent.Sponsor, e.leads)
	assert(ent.Sponsor.AcceptedBy != nil && ent.Sponsor.AcceptedBy.Mount == h.AuthMountPath(e.mount) &&
		ent.Sponsor.AcceptedBy.Principal != "", "accepted_by %+v, want Ada at %s", ent.Sponsor.AcceptedBy, e.mount)

	// 3. A handover to finance on-call is pending; billing leads still sponsor.
	ent, stderr := e.mustAs(sponsorAda, "identity", "entity", "sponsor", "propose", agent,
		"-group", e.oncall, "-group-namespace", "/")
	assert(strings.Contains(stderr, "handover to /"+e.oncall+" is pending"), "propose stderr %q, want the pending warning", stderr)
	assert(ent.Sponsor.Group == e.leads && ent.PendingSponsor != nil && ent.PendingSponsor.Group == e.oncall,
		"after the handover: %+v", ent)

	// Bob, with no Warden role, reads the agent he is offered through every
	// node, then accepts it for his team.
	stderr = e.login(sponsorBob)
	assert(strings.Contains(stderr, "no group grants you a role"), "Bob's login: %q", stderr)
	bob := h.SessionTicket(t, e.homes[sponsorBob])
	for _, port := range h.NodePorts {
		status, body := h.TicketRequest(t, "GET", "sys/identity/sponsor/"+agent, port, bob, map[string]string{"X-Warden-Namespace": e.ns})
		expectStatus(t, fmt.Sprintf("Bob reads through node %d", port), status, body, http.StatusOK)
	}
	ent, _ = e.mustAs(sponsorBob, "identity", "sponsor", "accept", agent)
	assert(ent.Sponsor.Group == e.oncall && ent.PendingSponsor == nil && ent.GovernedBy == "warden",
		"after Bob's accept: %+v, want %s the sponsor", ent, e.oncall)
	assert(ent.Sponsor.AcceptedBy != nil && ent.Sponsor.AcceptedBy.Principal != ent.Sponsor.AddedBy.Principal,
		"accepted by %+v, proposed by %+v: want Bob, not Ada", ent.Sponsor.AcceptedBy, ent.Sponsor.AddedBy)

	// 4. Bob suspends it. No sponsor path makes it active again; Ada does.
	ent, _ = e.mustAs(sponsorBob, "identity", "sponsor", "suspend", agent)
	assert(ent.State == "suspended", "after Bob's suspend: %+v", ent)
	_, _, err := e.as(sponsorBob, "identity", "entity", "state", agent, "active")
	assert(err != nil, "Bob, with no role, made the agent active")
	ent, _ = e.mustAs(sponsorAda, "identity", "entity", "state", agent, "active")
	assert(ent.State == "active", "after Ada's state change: %+v", ent)

	// Audit: the person, the built-ins, the oidc mount, the team.
	auditEntries(t, e.port, "identity/sponsor/"+agent+"/suspend", start, 1, func(entry audit.LogEntry) bool {
		a := entry.Auth
		return a.SponsoredBy == "group:"+e.oncall && a.TokenType == "ticket_token" && a.EntityKind == "human" &&
			a.MountAccessor == e.accessor && strings.Join(a.Policies, ",") == "default-cbp,default-mcp,default-sponsor"
	})

	// 5. One refusal for everyone else, whatever they present.
	e.login(sponsorCarol)
	for _, args := range [][]string{
		{"identity", "sponsor", "read", agent},
		{"identity", "sponsor", "suspend", agent},
		{"identity", "sponsor", "handover", agent, "-group", e.leads, "-group-namespace", "/"},
		{"identity", "sponsor", "accept", agent},
	} {
		_, stderr, err := e.as(sponsorCarol, args...)
		refused(t, "Carol: "+strings.Join(args, " "), stderr, err)
	}
	nsHeader := map[string]string{"X-Warden-Namespace": e.ns}
	for what, headers := range map[string]map[string]string{
		"the agent's JWT":  {"Authorization": "Bearer " + h.GetDefaultJWT(t)},
		"a garbage bearer": {"Authorization": "Bearer not-a-token"},
		"the root token":   {"X-Warden-Token": h.RootToken(t)},
		"nothing":          {},
	} {
		for k, v := range nsHeader {
			headers[k] = v
		}
		status, body := h.DoRequest(t, "GET", h.NodeURL(e.port)+"/v1/sys/identity/sponsor/"+agent, headers, "")
		assert(status == http.StatusForbidden && strings.Contains(string(body), "no sponsored agent by that name"),
			"%s on the sponsor path: %d %s, want the one refusal", what, status, body)
	}
	ent, _ = e.mustAs(sponsorAda, "identity", "entity", "read", agent)
	assert(ent.State == "active" && ent.Sponsor.Group == e.oncall, "after the refusals: %+v, want unchanged", ent)

	// 6. Bob offers the agent back to billing leads, then thinks better of it.
	ent, stderr = e.mustAs(sponsorBob, "identity", "sponsor", "handover", agent, "-group", e.leads, "-group-namespace", "/")
	assert(strings.Contains(stderr, "handover to /"+e.leads+" is pending"), "handover stderr %q", stderr)
	assert(ent.PendingSponsor != nil && ent.PendingSponsor.Group == e.leads, "after the handover: %+v", ent)
	ent, _ = e.mustAs(sponsorBob, "identity", "sponsor", "handover", agent, "-cancel")
	assert(ent.PendingSponsor == nil && ent.Sponsor.Group == e.oncall, "after the cancel: %+v", ent)

	// A team of the child namespace can never accept: nobody signs in there.
	local := h.UniqueMount("team-local")
	h.WriteGroupInNS(t, e.port, e.ns, local, h.Group{Rules: []map[string][]string{
		{"mount": {"auth/nowhere/"}, "kind": {"human"}},
	}})
	_, stderr = e.mustAs(sponsorBob, "identity", "sponsor", "handover", agent, "-group", local)
	assert(strings.Contains(stderr, "admits humans: nobody can accept"), "handover to a child team: stderr %q", stderr)
	e.mustAs(sponsorBob, "identity", "sponsor", "handover", agent, "-cancel")

	// Emptying the child's default-sponsor turns sponsors off there; Ada
	// still administers the agent.
	seeded := h.JSONString(t, h.MustNS(t, e.port, e.ns, "GET", "sys/policies/cbp/default-sponsor", ""), "data.policy")
	h.MustNS(t, e.port, e.ns, "POST", "sys/policies/cbp/default-sponsor", h.JSON(t, map[string]any{"policy": "# off\n"}))
	_, stderr, err = e.as(sponsorBob, "identity", "sponsor", "read", agent)
	assert(err != nil && !strings.Contains(stderr, "no sponsored agent"), "with default-sponsor emptied: err %v, stderr %q", err, stderr)
	e.mustAs(sponsorAda, "identity", "entity", "read", agent)
	h.MustNS(t, e.port, e.ns, "POST", "sys/policies/cbp/default-sponsor", h.JSON(t, map[string]any{"policy": seeded}))
	e.mustAs(sponsorBob, "identity", "sponsor", "read", agent)

	// 8. Deleting finance on-call is refused while it sponsors the agent;
	// forced, it leaves the agent ungoverned, and Bob no longer reaches it.
	rootCLI := func(args ...string) (string, string, error) {
		return h.WardenCLISplitWithPort(t, e.port, map[string]string{"WARDEN_TOKEN": h.RootToken(t)}, args...)
	}
	_, stderr, err = rootCLI("identity", "group", "delete", e.oncall, "-type", "virtual", "-force")
	assert(err != nil && strings.Contains(stderr, "sponsors 1 entities"), "delete without -sponsored: err %v, stderr %q", err, stderr)
	_, stderr, err = rootCLI("identity", "group", "delete", e.oncall, "-type", "virtual", "-force", "-sponsored")
	assert(err == nil && strings.Contains(stderr, e.ns+"/"+agent), "forced delete: err %v, stderr %q, want the agent named", err, stderr)
	ent, _ = e.mustAs(sponsorAda, "identity", "entity", "read", agent)
	assert(ent.Sponsor == nil && ent.GovernedBy == "", "after the forced delete: %+v, want ungoverned", ent)
	_, stderr, err = e.as(sponsorBob, "identity", "sponsor", "read", agent)
	refused(t, "Bob after his team was deleted", stderr, err)

	// 9. Root creates an agent, ungoverned, and can only propose a team.
	const scratch = "scratch-agent"
	t.Cleanup(func() { h.NSRequestBestEffort(e.port, e.ns, "DELETE", "sys/identity/entity/"+scratch+"?force=true") })
	if _, stderr, err := e.root("identity", "entity", "create", scratch, "-description", "Scratch agent"); err != nil {
		t.Fatalf("root create: %v\n%s", err, stderr)
	}
	stdout, stderr, err := e.root("identity", "entity", "sponsor", "propose", scratch, "-group", e.leads, "-group-namespace", "/", "-o", "json")
	assert(err == nil && strings.Contains(stderr, "is pending"), "root propose: err %v, stderr %q", err, stderr)
	var proposed sponsorEntity
	if err := json.Unmarshal([]byte(stdout), &proposed); err != nil {
		t.Fatalf("root propose -o json: %v: %s", err, stdout)
	}
	assert(proposed.Sponsor == nil && proposed.PendingSponsor != nil && proposed.GovernedBy == "",
		"root's proposal: %+v, want pending only", proposed)
}
