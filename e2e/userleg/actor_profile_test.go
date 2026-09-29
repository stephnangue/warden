//go:build e2e

package userleg

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// =============================================================================
// The actor assertion profile, verified by a real Vault
// =============================================================================
//
// The actor profile mints an RFC 8693 delegation token: the USER as sub, the
// AGENT as the current actor in a nested act claim. Unit tests pin the claim map;
// this runs the whole path — two principals authenticated on one request, the
// profile rendering them, Warden signing, and a real verifier parsing the nested
// claim — and reads back what Vault actually bound.
//
// Vault's JWT auth resolves JSON Pointers in bound_claims, claim_mappings and
// user_claim (documented under "Claim specifications and JSON Pointer"), so the
// role here:
//   - binds /act/iss to Warden's issuer URL, so the login fails unless Vault
//     finds the nested act object where the profile puts it;
//   - takes the Vault alias from sub, and maps sub, /act/sub and the claims that
//     qualify them into token metadata, which lookup-self returns — the observable
//     proof of what Vault read.
//
// Hydra issues no act claim, so the user token's own chain (nested beneath the
// agent) and the refusal of an agent token carrying act stay unit-covered.
const (
	actorVaultRole = "warden-e2e-actor"
	actorSpec      = "e2e-actor-vault-token"
	actorAgentRole = "e2e-userleg-actor"

	// wardenIssuerURL is the issuer setup.sh enables; the jwt-warden mount binds it.
	wardenIssuerURL = "https://127.0.0.1:8000"
)

func setupActorProfile(t *testing.T) {
	t.Helper()
	ensureEnv(t)

	mustVault := func(method, path, body, what string) {
		t.Helper()
		status, resp := h.VaultDirectRequest(t, method, path, body)
		if status < 200 || status > 299 {
			t.Fatalf("%s: status %d: %s", what, status, resp)
		}
	}
	mustVault("POST", "auth/jwt-warden/role/"+actorVaultRole, fmt.Sprintf(`{
		"role_type":"jwt",
		"bound_audiences":["https://vault.e2e.warden"],
		"bound_claims":{"/act/iss":%q},
		"user_claim":"sub",
		"claim_mappings":{
			"sub":"delegated_subject","warden_namespace":"subject_namespace",
			"/act/sub":"current_actor","/act/warden_namespace":"actor_namespace",
			"/act/warden_role":"actor_role"},
		"token_policies":["e2e-secrets-reader"],
		"token_type":"batch",
		"token_ttl":"120s"}`, wardenIssuerURL),
		"create the actor role on the Warden-issuer mount")
	t.Cleanup(func() { h.VaultDirectRequest(t, "DELETE", "auth/jwt-warden/role/"+actorVaultRole, "") })

	mustWarden := func(method, path, body, what string) {
		t.Helper()
		status, resp := h.APIRequest(t, method, path, leaderPort, body)
		if status < 200 || status > 299 {
			t.Fatalf("%s: status %d: %s", what, status, resp)
		}
	}
	h.APIRequest(t, "DELETE", "sys/cred/specs/"+actorSpec, leaderPort, "")
	mustWarden("POST", "sys/cred/specs/"+actorSpec, fmt.Sprintf(`{
		"type":"vault_token",
		"source":"vault-warden-fed-e2e",
		"config":{
			"mint_method":"vault_token",
			"jwt_role":%q,
			"subject_token_source":"warden_identity",
			"assertion_profile":"actor",
			"assertion_user_claims":"sub"
		}}`, actorVaultRole),
		"create the actor-profile spec")
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+actorSpec, leaderPort, "") })

	// A JWT agent rather than a certificate: its principal is the Hydra client's
	// sub, which the test reads off the token, so the expected act.sub is exact.
	h.APIRequest(t, "DELETE", "auth/jwt/role/"+actorAgentRole, leaderPort, "")
	mustWarden("POST", "auth/jwt/role/"+actorAgentRole, fmt.Sprintf(`{
		"token_policies":["%s-access"],"cred_spec_name":%q,
		"user_claim":"sub","token_ttl":3600}`, h.UserLegMount, actorSpec),
		"create the actor agent role")
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "auth/jwt/role/"+actorAgentRole, leaderPort, "") })

	h.SetUserLegAgentPath(t, leaderPort, "auth/jwt/", actorAgentRole)
	t.Cleanup(func() { restoreEnv(t) })
}

// TestActorProfile_VaultBindsUserAsSubAndAgentAsAct: Vault accepts the login only
// because /act/iss is where the profile puts it, and the token it issues records
// the USER's raw principal as sub and the AGENT's as the current actor — each the id
// Hydra put in the token that party presented, with no Warden namespace or mount.
func TestActorProfile_VaultBindsUserAsSubAndAgentAsAct(t *testing.T) {
	setupActorProfile(t)

	agentJWT := h.GetDefaultJWT(t)
	userJWT := h.UserJWT(t)
	wantSubject := h.JWTSubject(t, userJWT)
	wantActor := h.JWTSubject(t, agentJWT)

	status, body := h.DoRequest(t, "GET",
		h.NodeURL(leaderPort)+"/v1/"+h.UserLegMount+"/gateway/v1/auth/token/lookup-self",
		map[string]string{
			"X-Warden-Agent-Token": agentJWT,
			"Authorization":        "Bearer " + userJWT,
			"X-Warden-Role":        actorAgentRole,
		}, "")
	if status != http.StatusOK {
		t.Fatalf("lookup-self under the actor profile: status %d: %s", status, body)
	}

	if got := h.JSONString(t, body, "data.meta.delegated_subject"); got != wantSubject {
		t.Errorf("Vault read sub = %q, want the user's raw principal %q", got, wantSubject)
	}
	if got := h.JSONString(t, body, "data.meta.current_actor"); got != wantActor {
		t.Errorf("Vault read /act/sub = %q, want the agent's raw principal %q", got, wantActor)
	}
	if got := h.JSONString(t, body, "data.meta.actor_role"); got != actorAgentRole {
		t.Errorf("Vault read /act/warden_role = %q, want the agent's role %q", got, actorAgentRole)
	}

	// Both principals are in the root namespace, whose path is the empty string. It
	// must reach the verifier as a value to bind, not vanish as an absent claim.
	data := h.ParseJSON(t, body)
	for _, key := range []string{"subject_namespace", "actor_namespace"} {
		got, ok := h.JSONPath(data, "data.meta."+key).(string)
		if !ok {
			t.Errorf("Vault read no %s: the namespace claim was not rendered", key)
		} else if got != "" {
			t.Errorf("Vault read %s = %q, want the root namespace's path \"\"", key, got)
		}
	}
}

// TestActorProfile_NoUserIsRefused: the shape has no subject without a user, so a
// request that presents only the agent is refused rather than minted as some
// other shape — as a 401, so the client knows to authenticate a user and retry.
func TestActorProfile_NoUserIsRefused(t *testing.T) {
	setupActorProfile(t)

	status, body := h.DoRequest(t, "GET",
		h.NodeURL(leaderPort)+"/v1/"+h.UserLegMount+"/gateway/v1/auth/token/lookup-self",
		map[string]string{
			"X-Warden-Agent-Token": h.GetDefaultJWT(t),
			"X-Warden-Role":        actorAgentRole,
		}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("an agent with no user must be challenged for one, got %d: %s", status, body)
	}
	if !strings.Contains(string(body), "a user principal is required") {
		t.Fatalf("refused for the wrong reason: %s", body)
	}
}
