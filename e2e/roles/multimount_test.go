//go:build e2e

package roles

import (
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestMultiMount_OneRoleOneGroup grants one role through one group with two
// rules: one for Hydra JWTs at a jwt mount, on the subject and a mapped
// pointer into the scp claim, and one for certificates at a cert mount, on the
// CN. A provider admits through one auth mount, so the role is reached through
// one provider per mount, the role URL otherwise the same.
//
// Both credentials are granted the role, and audit credits the group on both.
// Editing the jwt rule's selector values refuses the next request on the JWT
// still cached, while the certificate keeps its grant; restoring the values
// allows the JWT again. Neither credential logs in again: every request of
// each runs on one admission (one token accessor).
func TestMultiMount_OneRoleOneGroup(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		jwtMount   = "auth/e2e-roles-jwt/"
		certMount  = "auth/e2e-roles-cert/"
		jwtVault   = "e2e-roles-vault-jwt"
		certVault  = "e2e-roles-vault-cert"
		role       = "e2e-roles-multi"
		group      = "e2e-roles-multi"
		agentCN    = "agent-multi"
		firstScope = "scope0"
	)
	caPEM, caKey := newCA(t)
	h.EnableAuth(t, port, "", jwtMount, "jwt", h.HydraJWTConfig(map[string]any{
		"facts": map[string]string{"/scp/0": firstScope},
	}))
	h.EnableAuth(t, port, "", certMount, "cert", h.CertMountConfig([]string{caPEM}, nil))
	jwtPolicy := h.VaultProvider(t, port, "", jwtVault, jwtMount)
	certPolicy := h.VaultProvider(t, port, "", certVault, certMount)
	writeRole(t, port, "", role, h.Role{Policies: []string{jwtPolicy, certPolicy}, CredSpec: "vault-token-reader"})

	rules := func(scope string) []map[string][]string {
		return []map[string][]string{
			{"mount": {jwtMount}, "sub": {"e2e-agent"}, firstScope: {scope}},
			{"mount": {certMount}, "cn": {agentCN}},
		}
	}
	if warnings := h.WriteGroupInNS(t, port, "", group, h.Group{Roles: []string{role}, Rules: rules("api:read")}); len(warnings) != 0 {
		t.Fatalf("a group whose rules name facts both mounts produce warns: %v", warnings)
	}

	start := time.Now()
	jwt := h.GetDefaultJWT(t)
	certPEM, _ := h.GenerateClientCert(t, caPEM, caKey, agentCN)
	viaJWT := func() (int, []byte) { return get(t, gatewayURL(port, jwtVault, role), bearer(jwt)) }
	viaCert := func() (int, []byte) { return get(t, gatewayURL(port, certVault, role), forwardedCert(certPEM)) }

	status, body := viaJWT()
	expectStatus(t, "JWT through the jwt mount", status, body, 200)
	status, body = viaCert()
	expectStatus(t, "certificate through the cert mount", status, body, 200)

	// The jwt rule stops matching the JWT: its scope is not api:admin.
	h.WriteGroupInNS(t, port, "", group, h.Group{Roles: []string{role}, Rules: rules("api:admin")})
	status, body = viaJWT()
	expectRefused(t, "cached JWT after its rule's values changed", status, body, 403, "not assumable through "+jwtMount)
	status, body = viaCert()
	expectStatus(t, "certificate after the other rule changed", status, body, 200)

	h.WriteGroupInNS(t, port, "", group, h.Group{Roles: []string{role}, Rules: rules("api:read")})
	status, body = viaJWT()
	expectStatus(t, "cached JWT after its rule was restored", status, body, 200)

	// Audit: the JWT's three requests and the certificate's two, each on one
	// identity token of its own, the group credited on every granted one.
	byPrincipal := map[string][]audit.LogEntry{}
	for _, e := range gatewayEntries(t, port, role, start, 5) {
		byPrincipal[e.Auth.PrincipalID] = append(byPrincipal[e.Auth.PrincipalID], e)
	}
	jwtEntries, certEntries := byPrincipal["e2e-agent"], byPrincipal[agentCN]
	if len(jwtEntries) != 3 || len(certEntries) != 2 {
		t.Fatalf("audit: %d entries for the JWT and %d for the certificate, want 3 and 2 (principals %v)",
			len(jwtEntries), len(certEntries), keys(byPrincipal))
	}
	for name, entries := range map[string][]audit.LogEntry{"JWT": jwtEntries, "certificate": certEntries} {
		accessors := map[string]bool{}
		ids := map[string]bool{}
		for _, e := range entries {
			accessors[e.Auth.TokenAccessor] = true
			ids[e.Auth.TokenID] = true
			if !strings.HasPrefix(e.Auth.TokenID, "wdi_") || e.Auth.TokenType != "identity_token" {
				t.Errorf("%s: token %s of type %q, want an identity_token wdi_ ID", name, e.Auth.TokenID, e.Auth.TokenType)
			}
			granted := e.Auth.RoleDeniedReason == ""
			if granted && (e.Auth.RoleGrantedBy != "group:"+group || e.Auth.RoleName != role) {
				t.Errorf("%s: role %q granted by %q, want %s granted by group:%s", name, e.Auth.RoleName, e.Auth.RoleGrantedBy, role, group)
			}
			if !granted && (e.Auth.RoleGrantedBy != "" || e.Auth.RoleDeniedReason != "not assumable") {
				t.Errorf("%s: a refused request credits %q, denied for %q", name, e.Auth.RoleGrantedBy, e.Auth.RoleDeniedReason)
			}
		}
		if len(accessors) != 1 || len(ids) != 1 {
			t.Errorf("%s: %d token accessors and %d token IDs across its requests, want 1 each: it logged in again",
				name, len(accessors), len(ids))
		}
	}
	if jwtEntries[0].Auth.TokenID == certEntries[0].Auth.TokenID {
		t.Errorf("the JWT and the certificate share identity token %s", jwtEntries[0].Auth.TokenID)
	}
	refused := 0
	for _, e := range jwtEntries {
		if e.Auth.RoleDeniedReason != "" {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("audit records %d refused JWT requests, want 1", refused)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
