//go:build e2e

package roles

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestTokenTypes_AuditAndCEL covers the two token types as audit and policy
// conditions see them:
//
//   - a caller admitted by an auth mount runs on an identity_token whose ID
//     starts wdi_; the root token is a service_token whose ID starts wds_;
//   - a CBP condition on agent.token_type == "identity_token" allows the
//     admitted caller, one on "service_token" refuses it;
//   - the same JWT admitted at a jwt mount and at a kubernetes mount (whose API
//     server authenticates it, as a cluster trusting the JWT's issuer does)
//     runs on two distinct identity tokens: the mount is part of the ID.
func TestTokenTypes_AuditAndCEL(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		jwtMount  = "auth/e2e-roles-tt-jwt/"
		k8sMount  = "auth/e2e-roles-tt-k8s/"
		jwtVault  = "e2e-roles-tt-vault-jwt"
		k8sVault  = "e2e-roles-tt-vault-k8s"
		identity  = "e2e-roles-tt-identity"
		service   = "e2e-roles-tt-service"
		probePath = "sys/policies/cbp/e2e-roles-tt-probe"
	)
	start := time.Now()
	jwt := h.GetDefaultJWT(t)

	h.EnableAuth(t, port, "", jwtMount, "jwt", h.HydraJWTConfig(nil))
	reviewer := h.StartTokenReviewer(t)
	reviewer.Register(jwt, h.ServiceAccount{Namespace: "ci", Name: "e2e-agent", UID: "uid-e2e-agent", Audiences: []string{h.HydraAudience}})
	h.EnableKubernetesAuth(t, port, "", k8sMount, reviewer, map[string]any{"bound_audiences": []string{h.HydraAudience}})
	h.VaultProvider(t, port, "", jwtVault, jwtMount)
	h.VaultProvider(t, port, "", k8sVault, k8sMount)

	// Two policies over both gateways, conditioned on the token type.
	for name, tokenType := range map[string]string{identity: "identity_token", service: "service_token"} {
		var rules strings.Builder
		for _, p := range []string{jwtVault, k8sVault} {
			fmt.Fprintf(&rules, "path %q {\n  capabilities = [\"read\"]\n  condition = %q\n}\n",
				p+"/role/+/gateway*", `agent.token_type == "`+tokenType+`"`)
		}
		h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+name, mustJSON(t, map[string]any{"policy": rules.String()}))
		t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/cbp/"+name) })
		writeRole(t, port, "", name, h.Role{Policies: []string{name}, CredSpec: "vault-token-reader"})
		h.WriteGroupInNS(t, port, "", name, h.Group{
			Roles: []string{name},
			Rules: []map[string][]string{{"mount": {jwtMount, k8sMount}}},
		})
	}

	status, body := get(t, gatewayURL(port, jwtVault, identity), bearer(jwt))
	expectStatus(t, `condition agent.token_type == "identity_token", JWT at the jwt mount`, status, body, 200)
	status, body = get(t, gatewayURL(port, k8sVault, identity), bearer(jwt))
	expectStatus(t, `condition agent.token_type == "identity_token", JWT at the kubernetes mount`, status, body, 200)
	status, body = get(t, gatewayURL(port, jwtVault, service), bearer(jwt))
	expectStatus(t, `condition agent.token_type == "service_token", JWT at the jwt mount`, status, body, 403)
	if strings.Contains(h.ErrorText(body), "assumable") {
		t.Fatalf("the role was not granted, so the condition decided nothing: %s", body)
	}

	// A request on the root token, for its audit entry.
	h.APIRequest(t, "GET", probePath, port, "")

	entries := gatewayEntries(t, port, identity, start, 2)
	ids := map[string]string{}
	for _, e := range entries {
		if e.Auth.TokenType != "identity_token" || !strings.HasPrefix(e.Auth.TokenID, "wdi_") {
			t.Errorf("%s: token %q of type %q, want an identity_token wdi_ ID", e.Request.Path, e.Auth.TokenID, e.Auth.TokenType)
		}
		ids[strings.Trim(e.Request.MountPoint, "/")] = e.Auth.TokenID
	}
	if ids[jwtVault] == "" || ids[k8sVault] == "" || ids[jwtVault] == ids[k8sVault] {
		t.Errorf("the same JWT at two mounts: identity tokens %v, want two distinct wdi_ IDs", ids)
	}

	root := h.AwaitAuditEntries(t, h.NodeNumberForPort(port), "e2e-roles-tt-probe", 1, func(e audit.LogEntry) bool {
		return e.Type == string(audit.EntryTypeResponse) && e.Auth != nil && !e.Timestamp.Before(start)
	})[0]
	if root.Auth.TokenType != "service_token" || !strings.HasPrefix(root.Auth.TokenID, "wds_") {
		t.Errorf("root token request: token %q of type %q, want a service_token wds_ ID", root.Auth.TokenID, root.Auth.TokenType)
	}
}
