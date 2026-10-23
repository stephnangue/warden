//go:build e2e

package userleg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const hydraAdmin = "http://localhost:4445"

// hydraClient registers an OAuth client at Hydra allowed to request the given
// audiences, and deletes it when the test ends.
func hydraClient(t *testing.T, id, secret string, audiences ...string) {
	t.Helper()
	del := func() {
		req, _ := http.NewRequest(http.MethodDelete, hydraAdmin+"/admin/clients/"+url.PathEscape(id), nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	del()
	body, _ := json.Marshal(map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"grant_types":                []string{"client_credentials"},
		"response_types":             []string{},
		"scope":                      "api:read api:write",
		"audience":                   audiences,
		"token_endpoint_auth_method": "client_secret_post",
	})
	resp, err := http.Post(hydraAdmin+"/admin/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register Hydra client %s: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register Hydra client %s: status %d: %s", id, resp.StatusCode, b)
	}
	t.Cleanup(del)
}

// TestUserLeg_ResourceIdentifierBindsInNamespace: in a sub-namespace, a user
// auth mount with no bound_audiences of its own, behind a provider with
// protected-resource metadata on. The mount's resource identifier
// (resource_url + /v1/<namespace>/<mount>) binds the user token's audience:
//
//   - a user token issued for that identifier is admitted;
//   - one issued for another resource is refused with a challenge, so the
//     client can fetch a token for this one;
//   - with protected-resource metadata off nothing binds the audience, and
//     every user credential is refused without a challenge.
func TestUserLeg_ResourceIdentifierBindsInNamespace(t *testing.T) {
	ensureEnv(t)
	port := leaderPort
	const (
		ns        = "e2e-ul-rid"
		provider  = "vault-rid"
		agentRole = "rid-agent"
		policy    = "rid-access"
		userID    = "e2e-ul-rid-user"
		secret    = "rid-user-secret"
	)
	resource := h.UserLegResourceURL + "/v1/" + ns + "/" + provider

	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+ns, "")
	t.Cleanup(func() { h.CleanupNamespaces(t, port, ns) })

	// The agent: a certificate.
	caPEM, caKey := h.GenerateTestCA(t)
	h.MustNS(t, port, ns, "POST", "sys/auth/cert", `{"type":"cert"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/auth/cert") })
	h.MustNS(t, port, ns, "PUT", "auth/cert/config", h.JSON(t, map[string]any{"trusted_ca_pem": caPEM}))

	// The user: a human jwt mount binding no audience.
	h.MustNS(t, port, ns, "POST", "sys/auth/people", `{"type":"jwt"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/auth/people") })
	h.MustNS(t, port, ns, "PUT", "auth/people/config", fmt.Sprintf(
		`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q,"user_claim":"sub","entity_kind":"human"}`,
		h.HydraIssuer, h.HydraIssuer))

	h.MustNS(t, port, ns, "POST", "sys/providers/"+provider, `{"type":"vault"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/providers/"+provider) })
	h.MustNS(t, port, ns, "POST", provider+"/config",
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"auto_auth_path":"auth/cert/","user_auth_path":"auth/people/"}`)
	h.MustNS(t, port, ns, "POST", "sys/policies/cbp/"+policy, fmt.Sprintf(
		`{"policy":"path \"%s/gateway*\" {\n  capabilities = [\"read\"]\n}"}`, provider))
	h.MustNS(t, port, ns, "POST", "sys/cred/sources/vault-e2e",
		`{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/cred/sources/vault-e2e") })
	h.MustNS(t, port, ns, "POST", "sys/cred/specs/vault-token-reader",
		`{"type":"vault_token","source":"vault-e2e","config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/cred/specs/vault-token-reader") })
	h.WriteRoleInNS(t, port, ns, agentRole, h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader"})
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/roles/"+agentRole) })
	h.WriteGroupInNS(t, port, ns, agentRole, h.Group{
		Roles: []string{agentRole},
		Rules: []map[string][]string{{"mount": {"auth/cert/"}, "cn": {"agent-rid"}}},
	})

	hydraClient(t, userID, secret, resource, h.HydraAudience)
	forResource := h.GetJWTForAudience(t, userID, secret, resource)
	forOther := h.GetJWTForAudience(t, userID, secret, h.HydraAudience)
	agent, _ := h.GenerateClientCert(t, caPEM, caKey, "agent-rid")

	request := func(user string) (int, []byte, map[string][]string) {
		t.Helper()
		return h.DoRequestWithResponseHeaders(t, "GET",
			h.NodeURL(port)+"/v1/"+provider+"/gateway/v1/secret/data/e2e/app-config",
			map[string]string{
				"X-Warden-Namespace": ns,
				"X-Warden-Role":      agentRole,
				"X-SSL-Client-Cert":  h.URLEncodePEM(agent),
				"Authorization":      "Bearer " + user,
			}, "")
	}

	status, body, _ := request(forResource)
	if status != 200 {
		t.Fatalf("a user token for this resource: status %d: %s", status, body)
	}

	status, body, hdrs := request(forOther)
	if status != 401 || !strings.Contains(h.ErrorText(body), "user token audience does not name this resource") {
		t.Errorf("a user token for another resource: status %d, want 401 naming the audience: %s", status, body)
	}
	if c := strings.Join(hdrs["Www-Authenticate"], " "); !strings.Contains(c, "resource_metadata=") ||
		!strings.Contains(c, `error="invalid_token"`) {
		t.Errorf("a user token for another resource: challenge %q, want one naming the metadata and invalid_token", c)
	}

	h.DisableProtectedResourceMetadata(t, port)
	t.Cleanup(func() { h.EnableProtectedResourceMetadata(t, port) })
	status, body, hdrs = request(forResource)
	if status != 403 || !strings.Contains(h.ErrorText(body), "user token audience is not bound") {
		t.Errorf("with protected-resource metadata off: status %d, want 403 audience not bound: %s", status, body)
	}
	if c := hdrs["Www-Authenticate"]; len(c) != 0 {
		t.Errorf("with protected-resource metadata off: a refusal no credential can pass carries a challenge: %q", c)
	}
}
