//go:build e2e

package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestGovernance_EndToEnd is Part 2 on a 3-node cluster: an agent's roles
// move from a virtual group to the static groups of its governed entity of
// record, and the namespace's identity config decides who runs at all.
//
// Two Hydra clients reach two jwt mounts, both trusted by a virtual group
// granting deploy. Claiming the agent's native identity takes the virtual
// grant away (the claim rule): ungoverned, it holds no role; governed (a
// description and a sponsor team Ada accepts) but in no static group, still
// none; listed by a static group, it holds deploy and the governed_only
// prod-deploy. Flagging deploy governed_only stops the unclaimed pipeline,
// not the agent. Under unknown_aliases=deny the unclaimed pipeline is refused
// through one mount and admitted through the exempt one. Suspension and the
// loss of the sponsor refuse the agent; a membership's until ends its grant.
func TestGovernance_EndToEnd(t *testing.T) {
	port := h.GetLeaderPort(t)
	var (
		jwtA    = h.UniqueMount("e2e-gov-jwt")
		jwtB    = h.UniqueMount("e2e-gov-ci")
		vaultA  = h.UniqueMount("e2e-gov-vault")
		vaultB  = h.UniqueMount("e2e-gov-vault-ci")
		deploy  = h.UniqueMount("e2e-gov-deploy")
		prod    = h.UniqueMount("e2e-gov-prod")
		ci      = h.UniqueMount("e2e-gov-ci-deployers")
		ops     = h.UniqueMount("e2e-gov-local-ops")
		oidc    = h.UniqueMount("oidc-gov")
		leads   = h.UniqueMount("gov-leads")
		admin   = h.UniqueMount("e2e-gov-admin")
		agent   = h.UniqueMount("billing-agent")
		ada     = "ada@gov.example"
		agentID = "e2e-agent"    // the Hydra client's sub
		pipeID  = "e2e-pipeline" // ditto
	)
	start := time.Now()
	assert := func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Fatalf(format, args...)
		}
	}

	// Mounts, providers, roles and the virtual group that grants deploy to
	// both clients, through either mount.
	h.EnableAuth(t, port, "", jwtA, "jwt", h.HydraJWTConfig(nil))
	h.EnableAuth(t, port, "", jwtB, "jwt", h.HydraJWTConfig(nil))
	deleteEntityAtEnd(t, port, agent)
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/identity/config") })
	policyA := h.VaultProvider(t, port, "", vaultA, jwtA)
	policyB := h.VaultProvider(t, port, "", vaultB, jwtB)
	for _, role := range []string{deploy, prod} {
		h.WriteRoleInNS(t, port, "", role, h.Role{
			Policies: []string{policyA, policyB}, CredSpec: "vault-token-reader", ProviderPath: vaultA + "/",
		})
		t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/roles/"+role) })
	}
	cli(t, port, "role", "update", prod, "-governed-only")
	h.WriteGroupInNS(t, port, "", ci, h.Group{Roles: []string{deploy}, Rules: []map[string][]string{
		{"mount": {h.AuthMountPath(jwtA)}, "sub": {agentID, pipeID}},
		{"mount": {h.AuthMountPath(jwtB)}, "sub": {pipeID}},
	}})
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/identity/group/"+ops+"?type=static") })

	// Ada signs in at an oidc mount: a billing lead, and an admin of the
	// root namespace's entities.
	idp := h.StartHumanIdP(t, map[string]map[string]any{ada: {"roles": []any{"Warden.Admin", "Billing.Lead"}}})
	h.EnableAuth(t, port, "", oidc, "oidc", h.OIDCMountConfig(idp, nil))
	h.WriteGroupInNS(t, port, "", leads, h.Group{Rules: []map[string][]string{
		{"mount": {h.AuthMountPath(oidc)}, "kind": {"human"}, "roles": {"Billing.Lead"}},
	}})
	// Cleanups run last first: the entity goes before the group that
	// sponsors it, whose delete it would otherwise refuse. The earlier
	// registration stays, for a run that fails before this line.
	deleteEntityAtEnd(t, port, agent)
	policy := admin + "-policy"
	h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+policy, h.JSON(t, map[string]any{"policy": "" +
		"path \"sys/identity/entity\" {\n  capabilities = [\"list\", \"sudo\"]\n}\n" +
		"path \"sys/identity/entity/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n"}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/cbp/"+policy) })
	h.GrantRole(t, port, oidc, admin, h.Role{Policies: []string{policy}}, h.Rule{"kind": {"human"}, "roles": {"Warden.Admin"}})
	t.Cleanup(func() { h.RevokeRoleBestEffort(port, oidc, admin) })
	adaHome := t.TempDir()
	if run := h.OIDCLogin(t, port, adaHome, ada, nil, nil, "-path="+oidc, "-role="+admin); run.Err != nil {
		t.Fatalf("warden login as Ada: %v\n%s", run.Err, run.Stderr)
	}
	asAda := func(args ...string) {
		t.Helper()
		if stdout, stderr, err := h.SessionCLI(t, port, adaHome, nil, args...); err != nil {
			t.Fatalf("as Ada, warden %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, stdout, stderr)
		}
	}
	proposeLeads := func() {
		t.Helper()
		asAda("identity", "entity", "sponsor", "propose", agent, "-group", leads, "-group-namespace", "/")
	}

	agentJWT := h.GetDefaultJWT(t)
	pipeJWT := h.GetJWT(t, pipeID, "pipeline-secret")
	call := func(who, jwt, provider, role string, want int, wantBody string) {
		t.Helper()
		status, body := h.DoRequest(t, "GET", gatewayURL(port, provider, role), map[string]string{"Authorization": "Bearer " + jwt}, "")
		expectStatus(t, fmt.Sprintf("%s under %s through %s", who, role, provider), status, body, want)
		if wantBody != "" && !strings.Contains(string(body), wantBody) {
			t.Fatalf("%s under %s through %s: body %s, want it to contain %q", who, role, provider, body, wantBody)
		}
	}
	menu := func(jwt string) []string {
		t.Helper()
		status, body := h.DoRequest(t, "GET", h.NodeURL(port)+"/v1/sys/introspect/roles", map[string]string{"Authorization": "Bearer " + jwt}, "")
		expectStatus(t, "discovery", status, body, http.StatusOK)
		var out struct {
			Data struct {
				Roles []struct {
					Name string `json:"name"`
				} `json:"roles"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode discovery: %v: %s", err, body)
		}
		names := []string{}
		for _, r := range out.Data.Roles {
			if r.Name == deploy || r.Name == prod {
				names = append(names, r.Name)
			}
		}
		slices.Sort(names)
		return names
	}

	// 1. Unclaimed, the default config: the virtual group grants deploy, and
	// a virtual group may not list the governed_only prod.
	call("the agent", agentJWT, vaultA, deploy, 200, "")
	call("the pipeline", pipeJWT, vaultA, deploy, 200, "")
	got := menu(agentJWT)
	assert(slices.Equal(got, []string{deploy}), "unclaimed agent's menu: %v, want [%s]", got, deploy)
	_, stderr, err := cliResult(t, port, "identity", "group", "update", ci, "-type", "virtual", "-roles", deploy+","+prod)
	assert(err != nil && strings.Contains(stderr, "a virtual group cannot grant it"),
		"a virtual group listing prod: err %v, stderr %q", err, stderr)

	// 2. Claimed: the virtual grant stops, and an ungoverned entity holds no
	// role. The claim warns.
	_, stderr, err = cliResult(t, port, "identity", "entity", "create", agent,
		"-description", "Reconciles supplier invoices", "-alias", h.AuthMountPath(jwtA)+"="+agentID)
	assert(err == nil && strings.Contains(stderr, "virtual groups no longer grant it roles"), "claim: err %v, stderr %q", err, stderr)
	call("the claimed agent", agentJWT, vaultA, deploy, 403, `which is not governed; it holds no role until it is`)
	got = menu(agentJWT)
	assert(len(got) == 0, "claimed, ungoverned agent's menu: %v, want empty", got)

	// 3. Governed, in no static group: still nothing, and told why.
	proposeLeads()
	call("the governed agent", agentJWT, vaultA, deploy, 403, "holds no static group granting it")

	// 4. Listed by a static group: deploy, and prod, which only governed
	// membership grants.
	cli(t, port, "identity", "group", "create", ops, "-json", h.JSON(t, map[string]any{
		"type": "static", "description": "Operations agents governed by Warden",
		"members": []string{agent}, "roles": []string{deploy, prod},
	}))
	call("the static member", agentJWT, vaultA, deploy, 200, "")
	call("the static member", agentJWT, vaultA, prod, 200, "")
	got = menu(agentJWT)
	assert(slices.Equal(got, []string{deploy, prod}), "member's menu: %v, want [%s %s]", got, deploy, prod)

	// 5. Flagging deploy governed_only stops the unclaimed pipeline, naming
	// the virtual group in the warning; the governed agent keeps it.
	_, stderr, err = cliResult(t, port, "role", "update", deploy, "-governed-only")
	assert(err == nil && strings.Contains(stderr, "virtual group lists it and no longer grants it: "+ci),
		"flag deploy: err %v, stderr %q", err, stderr)
	call("the pipeline", pipeJWT, vaultA, deploy, 403, "requires governed membership")
	call("the static member", agentJWT, vaultA, deploy, 200, "")
	got = menu(pipeJWT)
	assert(len(got) == 0, "pipeline's menu with deploy governed_only: %v, want empty", got)
	cli(t, port, "role", "update", deploy, "-governed-only=false")
	call("the pipeline", pipeJWT, vaultA, deploy, 200, "")

	// 6. deny, with jwtB exempt: the pipeline's cached admission is refused
	// through jwtA, admitted through jwtB; the governed agent is not judged,
	// nor is Ada, a human, whose menu still lists her role.
	cli(t, port, "identity", "config", "write", "-json", h.JSON(t, map[string]any{
		"unknown_aliases": "deny", "exempt_mounts": []string{h.AuthMountPath(jwtB)},
	}))
	call("the pipeline", pipeJWT, vaultA, deploy, 403, "native identity ("+h.AuthMountPath(jwtA)+", "+pipeID+") is unclaimed; unknown_aliases=deny")
	call("the pipeline", pipeJWT, vaultB, deploy, 200, "")
	got = menu(pipeJWT)
	assert(len(got) == 0, "the refused pipeline's menu: %v, want empty (deploy is used with %s, through jwtA)", got, vaultA)
	call("the static member", agentJWT, vaultA, deploy, 200, "")
	status, body := h.TicketRequest(t, "GET", "sys/introspect/roles", port, h.SessionTicket(t, adaHome), nil)
	expectStatus(t, "Ada's menu under deny", status, body, http.StatusOK)
	assert(strings.Contains(string(body), `"`+admin+`"`), "Ada's menu under deny: %s, want her role %s", body, admin)
	cli(t, port, "identity", "config", "reset")

	// Steps 7 to 10 run under the default config, observe: what refuses the
	// agent there is its entity's state and the claim rule, not deny.

	// 7. Suspension refuses at once; reactivation restores.
	cli(t, port, "identity", "entity", "state", agent, "suspended")
	call("the suspended agent", agentJWT, vaultA, deploy, 403, "which is suspended")
	cli(t, port, "identity", "entity", "state", agent, "active")
	call("the reactivated agent", agentJWT, vaultA, deploy, 200, "")

	// 8. Without its sponsor the entity is ungoverned and holds nothing; a
	// member of the team proposing it again restores it.
	cli(t, port, "identity", "entity", "sponsor", "remove", agent)
	call("the agent without a sponsor", agentJWT, vaultA, deploy, 403, "which is not governed")
	proposeLeads()
	call("the agent sponsored again", agentJWT, vaultA, deploy, 200, "")

	// 9. A membership that ends: granted through its until, then not; a
	// write drops it, naming it. until is written to the second, and the
	// window leaves room for a slow runner before it.
	until := time.Now().Add(15 * time.Second).UTC()
	cli(t, port, "identity", "group", "member", "add", ops, agent, "-until", until.Format(time.RFC3339))
	call("the member until "+until.Format(time.TimeOnly), agentJWT, vaultA, deploy, 200, "")
	time.Sleep(time.Until(until) + 1500*time.Millisecond)
	call("the member past its until", agentJWT, vaultA, deploy, 403, "holds no static group granting it")
	_, stderr, err = cliResult(t, port, "identity", "group", "prune", ops)
	assert(err == nil && strings.Contains(stderr, "past their until: "+agent), "prune: err %v, stderr %q", err, stderr)
	cli(t, port, "identity", "group", "member", "add", ops, agent)
	call("the member added back", agentJWT, vaultA, deploy, 200, "")

	// 10. Retired refuses in every mode; its record is read-only, and the
	// cleanup deletes it with force.
	cli(t, port, "identity", "entity", "state", agent, "retired")
	call("the retired agent", agentJWT, vaultA, deploy, 403, "which is retired")

	// Audit: an unclaimed caller's grant through the virtual group is deny's
	// dry run (identity_status unclaimed, no refusal); the agent's grant
	// names its static group and entity; deny's refusal names its reason.
	jwtAccessor := mountAccessor(t, port, jwtA)
	gateway := "role/" + deploy + "/gateway"
	auditEntries(t, port, gateway, start, 1, func(e audit.LogEntry) bool {
		a := e.Auth
		return a.AliasName != "" && a.RoleGroupType == "virtual" && a.IdentityStatus == "unclaimed" && a.RoleDeniedReason == ""
	})
	auditEntries(t, port, gateway, start, 1, func(e audit.LogEntry) bool {
		a := e.Auth
		return a.RoleGrantedBy == "group:"+ops && a.RoleGroupType == "static" && a.EntityName == agent && a.GovernedBy == "warden"
	})
	auditEntries(t, port, gateway, start, 1, func(e audit.LogEntry) bool {
		a := e.Auth
		return a.RoleDeniedReason == "unclaimed" && a.IdentityStatus == "unclaimed" && a.MountAccessor == jwtAccessor
	})
}
