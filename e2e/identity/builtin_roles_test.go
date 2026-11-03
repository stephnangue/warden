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

// TestBuiltinRoles_EndToEnd drives the built-in operator roles on a 3-node
// cluster, in a tenant namespace whose parent (root) enabled them.
//
// Humans: Ada's identity provider app role makes her warden-admin of the
// tenant and every namespace below it, through the tenant's oidc mount; she
// acts there under a ticket, but not in root, not on a root-only path, and
// never on a provider's data plane. Vera is warden-viewer: she reads, writes
// nothing, and a namespace read carries no unlock key.
//
// Agents: a Hydra agent is granted warden-admin by a virtual group trusting a
// jwt mount, and the write warns it should be a static group. Claimed, it
// holds nothing until its entity is governed and listed by a static group,
// whose write warns of nothing; suspended, it holds nothing again.
//
// Last, the tenant's flag cannot be turned off while groups grant built-ins;
// once they are gone it can, and the next request finds no warden-admin.
func TestBuiltinRoles_EndToEnd(t *testing.T) {
	port := h.GetLeaderPort(t)
	var (
		ns      = h.UniqueMount("e2e-builtin")
		oidc    = h.UniqueMount("oidc-builtin")
		jwt     = h.UniqueMount("e2e-builtin-jwt")
		vault   = h.UniqueMount("e2e-builtin-vault")
		agent   = h.UniqueMount("terraform-runner")
		ada     = "ada@builtin.example"
		vera    = "vera@builtin.example"
		agentID = "e2e-agent" // the Hydra client's sub
	)
	start := time.Now()
	in := func(path string) string { return ns + "/" + path }
	asRole := func(role string) map[string]string { return map[string]string{"X-Warden-Role": role} }
	expectBody := func(what string, status int, body []byte, want int, contains string) {
		t.Helper()
		expectStatus(t, what, status, body, want)
		if contains != "" && !strings.Contains(string(body), contains) {
			t.Fatalf("%s: body %s, want it to contain %q", what, body, contains)
		}
	}

	// The tenant, created from root with built-in roles on and the jwt mount
	// as its auto_auth_path, and a child created from the tenant.
	cli(t, port, "namespace", "create", ns, "-json", h.JSON(t, map[string]any{
		"enable_builtin_roles": true,
		"custom_metadata":      map[string]string{"auto_auth_path": h.AuthMountPath(jwt)},
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/namespaces/"+ns) })
	cli(t, port, "-n", ns, "namespace", "create", "dev")
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/namespaces/dev") })

	idp := h.StartHumanIdP(t, map[string]map[string]any{
		ada:  {"roles": []any{"Warden.Admin"}},
		vera: {"roles": []any{"Warden.Auditor"}},
	})
	h.EnableAuth(t, port, ns, oidc, "oidc", h.OIDCMountConfig(idp, nil))
	h.EnableAuth(t, port, ns, jwt, "jwt", h.HydraJWTConfig(nil))
	h.VaultProvider(t, port, ns, vault, jwt)
	for name, g := range map[string]h.Group{
		"platform-admins": {Roles: []string{"warden-admin"}, Rules: []map[string][]string{
			{"mount": {h.AuthMountPath(oidc)}, "kind": {"human"}, "roles": {"Warden.Admin"}}}},
		"auditors": {Roles: []string{"warden-viewer"}, Rules: []map[string][]string{
			{"mount": {h.AuthMountPath(oidc)}, "kind": {"human"}, "roles": {"Warden.Auditor"}}}},
		"leads": {Rules: []map[string][]string{
			{"mount": {h.AuthMountPath(oidc)}, "kind": {"human"}, "roles": {"Warden.Admin"}}}},
	} {
		for _, w := range h.WriteGroupInNS(t, port, ns, name, g) {
			if strings.Contains(w, "admits agents") || strings.Contains(w, "does not exist yet") {
				t.Fatalf("group %s: unexpected warning %q", name, w)
			}
		}
	}

	// Ada signs in at the tenant and is its warden-admin.
	adaHome := t.TempDir()
	if run := h.OIDCLogin(t, port, adaHome, ada, nil, nil, "-n", ns, "-path="+oidc, "-role=warden-admin"); run.Err != nil {
		t.Fatalf("warden login as Ada: %v\n%s", run.Err, run.Stderr)
	}
	adaTicket := h.SessionTicket(t, adaHome)
	asAda := func(args ...string) (string, string, error) {
		t.Helper()
		return h.SessionCLI(t, port, adaHome, nil, args...)
	}

	// The tenant and its child: sudo paths included, writes included.
	for _, path := range []string{in("sys/roles/nope"), in("dev/sys/roles/nope")} {
		status, body := h.TicketRequest(t, "GET", path, port, adaTicket, asRole("warden-admin"))
		expectBody("Ada reads "+path, status, body, http.StatusNotFound, "")
	}
	status, body := h.DoRequest(t, "POST", h.NodeURL(port)+"/v1/"+in("dev/sys/roles/deploy"),
		map[string]string{"X-Warden-Token": adaTicket, "X-Warden-Role": "warden-admin"}, `{"policies":["deploy"]}`)
	expectBody("Ada writes a role in the child", status, body, http.StatusCreated, "")
	if _, stderr, err := asAda("-n", ns+"/dev", "role", "read", "deploy"); err != nil || !strings.Contains(stderr, "using session from namespace "+ns) {
		t.Fatalf("Ada's CLI in the child: err %v, stderr %q", err, stderr)
	}

	// Not above or beside the tenant, not a root-only path, not a data plane.
	status, body = h.TicketRequest(t, "GET", "sys/roles/nope", port, adaTicket, asRole("warden-admin"))
	expectBody("Ada in root", status, body, http.StatusForbidden, "")
	status, body = h.TicketRequest(t, "PUT", in("sys/step-down"), port, adaTicket, asRole("warden-admin"))
	expectBody("Ada steps down", status, body, http.StatusBadRequest, "operation unavailable in namespaces")
	status, body = h.TicketRequest(t, "GET", in(vault+"/gateway/"+secretPath), port, adaTicket, asRole("warden-admin"))
	expectBody("Ada on the gateway", status, body, http.StatusBadRequest, "is a built-in operator role and has no data plane")

	// Discovery lists her built-in, with no url and no skill, and says why.
	status, body = h.TicketRequest(t, "GET", in("sys/introspect/roles"), port, adaTicket, nil)
	expectBody("Ada's menu", status, body, http.StatusOK, `"warden-admin"`)
	roles, roleWarnings := h.TicketListRolesInNS(t, port, ns, adaTicket)
	var listed bool
	for _, r := range roles {
		if r.Name == "warden-admin" {
			listed = true
			if r.URL != "" || r.Skill != "" || r.Provider != "" {
				t.Fatalf("list_roles: warden-admin has url %q, skill %q, provider %q; want none", r.URL, r.Skill, r.Provider)
			}
		}
	}
	wantWarning := `role "warden-admin": built-in operator role; it is used on Warden's own API with ?role= or X-Warden-Role, not through a provider`
	if !listed || !strings.Contains(strings.Join(roleWarnings, "\n"), wantWarning) {
		t.Fatalf("list_roles: roles %+v, warnings %q; want warden-admin listed with the built-in warning", roles, roleWarnings)
	}

	// Vera reads, writes nothing, and sees no unlock key.
	veraHome := t.TempDir()
	if run := h.OIDCLogin(t, port, veraHome, vera, nil, nil, "-n", ns, "-path="+oidc, "-role=warden-viewer"); run.Err != nil {
		t.Fatalf("warden login as Vera: %v\n%s", run.Err, run.Stderr)
	}
	veraTicket := h.SessionTicket(t, veraHome)
	status, body = h.TicketRequest(t, "GET", in("sys/namespaces/dev"), port, veraTicket, asRole("warden-viewer"))
	expectBody("Vera reads the child", status, body, http.StatusOK, `"path"`)
	if strings.Contains(string(body), "unlock_key") {
		t.Fatalf("Vera's namespace read carries an unlock key: %s", body)
	}
	status, body = h.TicketRequest(t, "DELETE", in("dev/sys/roles/deploy"), port, veraTicket, asRole("warden-viewer"))
	expectBody("Vera deletes a role", status, body, http.StatusForbidden, "")
	status, body = h.TicketRequest(t, "GET", in(h.AuthMountPath(oidc)+"config"), port, veraTicket, asRole("warden-viewer"))
	expectBody("Vera reads the oidc mount's config", status, body, http.StatusForbidden, "")

	// The agent: granted through a virtual group trusting the jwt mount, whose
	// write warns.
	agentJWT := h.GetDefaultJWT(t)
	call := func(what string, want int, contains string) {
		t.Helper()
		status, body := h.DoRequest(t, "GET", h.NodeURL(port)+"/v1/"+in("sys/roles/nope?role=warden-admin"),
			map[string]string{"Authorization": "Bearer " + agentJWT}, "")
		expectBody(what, status, body, want, contains)
	}
	warnings := h.WriteGroupInNS(t, port, ns, "ci-admins", h.Group{Roles: []string{"warden-admin"}, Rules: []map[string][]string{
		{"mount": {h.AuthMountPath(jwt)}, "sub": {agentID}}}})
	if !strings.Contains(strings.Join(warnings, "\n"), "admits agents; an unclaimed agent would hold the operator role \"warden-admin\"") {
		t.Fatalf("virtual group on a jwt mount: warnings %q, want the agent warning", warnings)
	}
	call("the unclaimed agent", http.StatusNotFound, "")

	// Claimed: nothing until governed and listed by a static group.
	deleteEntityAtEnd(t, port, agent)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/identity/entity/"+agent+"?force=true") })
	if _, stderr, err := cliResult(t, port, "-n", ns, "identity", "entity", "create", agent,
		"-description", "Terraform pipeline for the tenant's roles", "-alias", h.AuthMountPath(jwt)+"="+agentID); err != nil ||
		!strings.Contains(stderr, "virtual groups no longer grant it roles") {
		t.Fatalf("claim: err %v, stderr %q", err, stderr)
	}
	call("the claimed agent", http.StatusForbidden, "which is not governed")
	if _, stderr, err := asAda("-n", ns, "identity", "entity", "sponsor", "propose", agent, "-group", "leads"); err != nil {
		t.Fatalf("Ada proposes leads: %v\n%s", err, stderr)
	}
	call("the governed agent", http.StatusForbidden, "holds no static group granting it")
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/identity/group/terraform-runners?type=static") })
	_, stderr, err := cliResult(t, port, "-n", ns, "identity", "group", "create", "terraform-runners", "-json", h.JSON(t, map[string]any{
		"type": "static", "description": "Pipelines that manage the tenant's roles",
		"members": []string{agent}, "roles": []string{"warden-admin"},
	}))
	if err != nil || strings.Contains(stderr, "warning") {
		t.Fatalf("static group: err %v, stderr %q, want no warning", err, stderr)
	}
	call("the static member", http.StatusNotFound, "")
	cli(t, port, "-n", ns, "identity", "entity", "state", agent, "suspended")
	call("the suspended agent", http.StatusForbidden, "which is suspended")

	// The flag stays on while groups grant built-ins.
	_, stderr, err = cliResult(t, port, "namespace", "update", ns, "-enable-builtin-roles=false")
	for _, want := range []string{"platform-admins (virtual, warden-admin)", "auditors (virtual, warden-viewer)",
		"ci-admins (virtual, warden-admin)", "terraform-runners (static, warden-admin)"} {
		if err == nil || !strings.Contains(stderr, want) {
			t.Fatalf("turn off with grants: err %v, stderr %q, want it to name %s", err, stderr, want)
		}
	}
	for _, g := range []struct{ name, typ string }{
		{"platform-admins", "virtual"}, {"auditors", "virtual"}, {"ci-admins", "virtual"}, {"terraform-runners", "static"},
	} {
		h.MustNS(t, port, ns, "DELETE", fmt.Sprintf("sys/identity/group/%s?type=%s", g.name, g.typ), "")
	}
	cli(t, port, "namespace", "update", ns, "-enable-builtin-roles=false")
	status, body = h.TicketRequest(t, "GET", in("sys/roles/nope"), port, adaTicket, asRole("warden-admin"))
	expectBody("Ada once the flag is off", status, body, http.StatusForbidden, "not found")

	// Audit: Ada's grant names the built-in through her virtual group; the
	// agent's names its static group and entity. A response entry carries
	// the path as the system backend routed it, without "sys/".
	auditEntries(t, port, "roles/nope", start, 1, func(e audit.LogEntry) bool {
		a := e.Auth
		return a.RoleName == "warden-admin" && a.RoleGroupType == "virtual" && a.EntityKind == "human" &&
			a.PolicyResults != nil && strings.Join(a.PolicyResults.GrantingPolicies, ",") == "warden-admin"
	})
	auditEntries(t, port, "roles/nope", start, 1, func(e audit.LogEntry) bool {
		a := e.Auth
		return a.RoleName == "warden-admin" && a.RoleGroupType == "static" && a.EntityName == agent
	})

	var read struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(h.MustNS(t, port, "", "GET", "sys/namespaces/"+ns, ""), &read); err != nil {
		t.Fatal(err)
	}
	if read.Data["enable_builtin_roles"] != false {
		t.Fatalf("namespace read after turn-off: %v", read.Data)
	}
}
