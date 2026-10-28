//go:build e2e

package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestNativeIdentities_ClaimedThroughTheCLI is the identity store on a fresh
// install. A Hydra JWT at a jwt mount and a certificate at a cert mount are
// granted one role by a virtual group, and audit records the native identity
// each presented (its alias, the mount's accessor, the entity kind), on the
// gateway requests and on discovery.
//
// One entity claims both through the CLI: created on a standby node, which
// forwards the write, with the JWT's identity, then given the certificate's
// with alias add. Lookup finds it from either. Claiming changes no gateway
// outcome, and neither does suspending the entity: its state is recorded,
// not yet enforced.
//
// While the JWT's identity is claimed, a config write changing how the jwt
// mount derives identities is refused, and so is disabling the mount. A
// forced disable orphans the claim: entity list -orphaned shows the entity,
// lookup and alias remove still reach the claim by the old accessor, and
// once it is removed the entity is no longer orphaned.
func TestNativeIdentities_ClaimedThroughTheCLI(t *testing.T) {
	port := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)
	const (
		jwtMount  = "auth/e2e-identity-jwt/"
		certMount = "auth/e2e-identity-cert/"
		jwtVault  = "e2e-identity-vault-jwt"
		certVault = "e2e-identity-vault-cert"
		role      = "e2e-identity-reader"
		group     = "e2e-identity-reader"
		ent       = "e2e-identity-agent"
		jwtAlias  = "e2e-agent" // the Hydra client's sub
		agentCN   = "e2e-identity-agent-cert"
	)
	caPEM, caKey := h.GenerateTestCA(t)
	h.EnableAuth(t, port, "", jwtMount, "jwt", h.HydraJWTConfig(nil))
	h.EnableAuth(t, port, "", certMount, "cert", h.CertMountConfig([]string{caPEM}, nil))
	deleteEntityAtEnd(t, port, ent)
	jwtPolicy := h.VaultProvider(t, port, "", jwtVault, jwtMount)
	certPolicy := h.VaultProvider(t, port, "", certVault, certMount)
	h.WriteRoleInNS(t, port, "", role, h.Role{
		Policies:     []string{jwtPolicy, certPolicy},
		CredSpec:     "vault-token-reader",
		ProviderPath: jwtVault + "/", // so discovery admits the JWT at jwtMount
	})
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/roles/"+role) })
	h.WriteGroupInNS(t, port, "", group, h.Group{Roles: []string{role}, Rules: []map[string][]string{
		{"mount": {jwtMount}, "sub": {jwtAlias}},
		{"mount": {certMount}, "cn": {agentCN}},
	}})
	jwtAccessor := mountAccessor(t, port, jwtMount)
	certAccessor := mountAccessor(t, port, certMount)

	start := time.Now()
	jwt := h.GetDefaultJWT(t)
	certPEM, _ := h.GenerateClientCert(t, caPEM, caKey, agentCN)
	requests := func(when string) {
		t.Helper()
		status, body := h.DoRequest(t, "GET", gatewayURL(port, jwtVault, role),
			map[string]string{"Authorization": "Bearer " + jwt}, "")
		expectStatus(t, "JWT "+when, status, body, 200)
		status, body = h.DoRequest(t, "GET", gatewayURL(port, certVault, role),
			map[string]string{"X-SSL-Client-Cert": h.URLEncodePEM(certPEM)}, "")
		expectStatus(t, "certificate "+when, status, body, 200)
	}
	requests("before any claim")
	status, body := h.DoRequest(t, "GET", h.NodeURL(port)+"/v1/sys/introspect/roles",
		map[string]string{"Authorization": "Bearer " + jwt}, "")
	expectStatus(t, "discovery with the JWT", status, body, 200)

	// Claim both native identities: the JWT's at creation, through a standby.
	cli(t, standby, "identity", "entity", "create", ent,
		"-description", "Reads the e2e application config",
		"-sponsors", "alice@corp.example",
		"-alias", jwtMount+"="+jwtAlias)
	cli(t, port, "identity", "alias", "add", "-json", h.JSON(t, map[string]string{
		"mount": certMount,
		"name":  agentCN,
		"to":    ent,
	}))

	var byJWT, byCert lookup
	cliJSON(t, port, &byJWT, "identity", "entity", "lookup", "-mount", jwtMount, "-name", jwtAlias)
	cliJSON(t, standby, &byCert, "identity", "entity", "lookup", "-json", h.JSON(t, map[string]string{
		"mount": certMount,
		"name":  agentCN,
	}))
	if byJWT.Entity != ent || byJWT.Kind != "agent" || byJWT.State != "active" || byJWT.GovernedBy != "warden" {
		t.Fatalf("lookup of the JWT's identity = %+v, want active agent %s governed by warden", byJWT, ent)
	}
	if byCert.EntityID != byJWT.EntityID {
		t.Fatalf("the certificate's identity resolves to entity %q, the JWT's to %q: want one entity", byCert.EntityID, byJWT.EntityID)
	}

	requests("after both were claimed")
	cli(t, port, "identity", "entity", "update", ent, "-state", "suspended")
	requests("while their entity is suspended")

	// Audit: every gateway request names the native identity it presented,
	// and discovery names it per admitting mount.
	want := map[string]string{jwtAccessor: jwtAlias, certAccessor: agentCN}
	entries := auditEntries(t, port, "role/"+role+"/gateway", start, 6, nil)
	seen := map[string]int{}
	for _, e := range entries {
		a := e.Auth
		if alias, ok := want[a.MountAccessor]; !ok || a.AliasName != alias || a.EntityKind != "agent" {
			t.Errorf("gateway audit: mount_accessor %q, alias_name %q, entity_kind %q; want one of %v with entity_kind agent",
				a.MountAccessor, a.AliasName, a.EntityKind, want)
		}
		if a.RoleDeniedReason != "" || a.RoleGrantedBy != "group:"+group {
			t.Errorf("gateway audit: role granted by %q, denied for %q; want group:%s", a.RoleGrantedBy, a.RoleDeniedReason, group)
		}
		seen[a.MountAccessor]++
	}
	if seen[jwtAccessor] != 3 || seen[certAccessor] != 3 {
		t.Errorf("gateway audit: %v entries per mount accessor, want 3 for each of %s and %s", seen, jwtAccessor, certAccessor)
	}
	auditEntries(t, port, "introspect/roles", start, 1, func(e audit.LogEntry) bool {
		if e.Auth.Discovery == nil {
			return false
		}
		for _, m := range e.Auth.Discovery.AdmittedBy {
			if m.Mount == strings.TrimPrefix(jwtMount, "auth/") && m.AliasName == jwtAlias {
				return true
			}
		}
		return false
	})

	// The claim guards the jwt mount: how it derives identities, and its
	// existence.
	_, stderr, err := cliResult(t, port, "write", jwtMount+"config", `{"alias_name_source": "iss"}`)
	if err == nil || !strings.Contains(stderr, "claimed on it") || !strings.Contains(stderr, "force=true") {
		t.Fatalf("changing alias_name_source on a mount with a claim: err %v, stderr %q; want refused naming force=true", err, stderr)
	}
	mountArg := strings.TrimPrefix(jwtMount, "auth/")
	_, stderr, err = cliResult(t, port, "auth", "disable", mountArg)
	if err == nil || !strings.Contains(stderr, "cannot be disabled while 1 native identities are claimed") {
		t.Fatalf("disabling a mount with a claim: err %v, stderr %q; want refused", err, stderr)
	}
	stdout, stderr, err := cliResult(t, port, "auth", "disable", mountArg, "-force")
	if err != nil || !strings.Contains(stdout+stderr, "orphaned") {
		t.Fatalf("forced disable: err %v, output %q; want success warning that the claim is orphaned", err, stdout+stderr)
	}

	// The claim outlives its mount, reachable by the old accessor.
	listed := orphanedEntity(t, port, ent)
	if listed == nil || listed.State != "suspended" {
		t.Fatalf("entity list -orphaned lists %s as %+v, want it, suspended", ent, listed)
	}
	for _, a := range listed.Aliases {
		if a.MountAccessor == jwtAccessor && a.Mount != "" {
			t.Errorf("the orphaned claim names mount %q, want none: its mount is gone", a.Mount)
		}
	}
	var byAccessor lookup
	cliJSON(t, port, &byAccessor, "identity", "entity", "lookup", "-mount-accessor", jwtAccessor, "-name", jwtAlias)
	if byAccessor.EntityID != byJWT.EntityID {
		t.Fatalf("lookup by the old accessor = %+v, want entity %s", byAccessor, byJWT.EntityID)
	}
	cli(t, port, "identity", "alias", "remove", "-from", ent, "-mount-accessor", jwtAccessor, "-name", jwtAlias)
	if listed := orphanedEntity(t, port, ent); listed != nil {
		t.Fatalf("entity list -orphaned still lists %s after its orphaned claim was removed: %+v", ent, listed)
	}
	var read entity
	cliJSON(t, port, &read, "identity", "entity", "read", ent)
	if len(read.Aliases) != 1 || read.Aliases[0].Mount != certMount || read.Aliases[0].Name != agentCN {
		t.Fatalf("entity read after the removal: aliases %+v, want only %s on %s", read.Aliases, agentCN, certMount)
	}
}

// orphanedEntity returns entity name as entity list -orphaned prints it, or
// nil when it is not listed.
func orphanedEntity(t *testing.T, port int, name string) *entity {
	t.Helper()
	var listed []entity
	cliJSON(t, port, &listed, "identity", "entity", "list", "-orphaned")
	for i := range listed {
		if listed[i].Name == name {
			return &listed[i]
		}
	}
	return nil
}
