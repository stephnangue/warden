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
// The default assertion profile, verified by a real Vault
// =============================================================================
//
// With a user disclosed (assertion_user_claims), the default profile mints an RFC
// 8693 delegation token: the USER as sub, by its raw id qualified by
// warden_namespace, and the AGENT as the current actor in act, by its composite
// wid:<namespace>:<mount_accessor>:<principal>. With no user it names the agent at
// the top level, by the same composite, and has no act. Unit tests pin the claim
// maps; this runs the whole path — two principals authenticated on one request, the
// profile rendering them, Warden signing, and a real verifier parsing the claims —
// and reads back what Vault actually bound.
//
// Vault's JWT auth resolves JSON Pointers in bound_claims, claim_mappings and
// user_claim (documented under "Claim specifications and JSON Pointer"), so the
// delegation role:
//   - binds /act/iss to Warden's issuer URL, so the login fails unless Vault finds
//     the nested act object where the profile puts it;
//   - takes the Vault alias from sub, and maps sub, /act/sub and the claims that
//     qualify them into token metadata, which lookup-self returns — the observable
//     proof of what Vault read.
//
// Hydra issues no act claim, so the user token's own chain (nested beneath the
// agent) and the refusal of an agent token carrying act stay unit-covered.
const (
	delegationVaultRole = "warden-e2e-delegation"
	delegationSpec      = "e2e-default-delegation"
	agentOnlyVaultRole  = "warden-e2e-agent-only"
	agentOnlySpec       = "e2e-default-agent-only"
	defaultAgentRole    = "e2e-userleg-default"

	// wardenIssuerURL is the issuer setup.sh enables; the jwt-warden mount binds it.
	wardenIssuerURL = "https://127.0.0.1:8000"
)

// setupDefaultProfile creates a Vault role on the Warden-issuer mount, a
// default-profile spec that logs in there (disclosing the user when userClaims is
// set), and a JWT agent role bound to that spec on the user-leg mount.
func setupDefaultProfile(t *testing.T, vaultRole, roleBody, spec, userClaims string) {
	t.Helper()
	ensureEnv(t)

	status, resp := h.VaultDirectRequest(t, "POST", "auth/jwt-warden/role/"+vaultRole, roleBody)
	if status < 200 || status > 299 {
		t.Fatalf("create Vault role %s: status %d: %s", vaultRole, status, resp)
	}
	t.Cleanup(func() { h.VaultDirectRequest(t, "DELETE", "auth/jwt-warden/role/"+vaultRole, "") })

	mustWarden := func(method, path, body, what string) {
		t.Helper()
		status, resp := h.APIRequest(t, method, path, leaderPort, body)
		if status < 200 || status > 299 {
			t.Fatalf("%s: status %d: %s", what, status, resp)
		}
	}
	userClaimsKey := ""
	if userClaims != "" {
		userClaimsKey = fmt.Sprintf(`,"assertion_user_claims":%q`, userClaims)
	}
	h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
	mustWarden("POST", "sys/cred/specs/"+spec, fmt.Sprintf(`{
		"type":"vault_token",
		"source":"vault-warden-fed-e2e",
		"config":{
			"mint_method":"vault_token",
			"jwt_role":%q,
			"subject_token_source":"warden_identity"%s
		}}`, vaultRole, userClaimsKey),
		"create the default-profile spec")
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "") })

	// A JWT agent rather than a certificate: its principal is the Hydra client's
	// sub, which the test reads off the token, so the expected agent sub is exact.
	h.APIRequest(t, "DELETE", "auth/jwt/role/"+defaultAgentRole, leaderPort, "")
	mustWarden("POST", "auth/jwt/role/"+defaultAgentRole, fmt.Sprintf(`{
		"token_policies":["%s-access"],"cred_spec_name":%q,
		"user_claim":"sub","token_ttl":3600}`, h.UserLegMount, spec),
		"create the agent role")
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "auth/jwt/role/"+defaultAgentRole, leaderPort, "") })

	h.SetUserLegAgentPath(t, leaderPort, "auth/jwt/", defaultAgentRole)
	t.Cleanup(func() { restoreEnv(t) })
}

// setupDelegation is setupDefaultProfile for the delegation shape.
func setupDelegation(t *testing.T) {
	t.Helper()
	setupDefaultProfile(t, delegationVaultRole, fmt.Sprintf(`{
		"role_type":"jwt",
		"bound_audiences":["https://vault.e2e.warden"],
		"bound_claims":{"/act/iss":%q},
		"user_claim":"sub",
		"claim_mappings":{
			"sub":"delegated_subject","warden_namespace":"subject_namespace","warden_role":"subject_role",
			"/act/sub":"current_actor","/act/warden_role":"actor_role"},
		"token_policies":["e2e-secrets-reader"],
		"token_type":"batch",
		"token_ttl":"120s"}`, wardenIssuerURL),
		delegationSpec, "sub")
}

// authAccessor reads an auth mount's accessor, the third segment of the agent's
// composite subject. Read live: setup regenerates accessors on every run.
func authAccessor(t *testing.T, mount string) string {
	t.Helper()
	status, body := h.APIRequest(t, "GET", "sys/auth/"+mount, leaderPort, "")
	if status != http.StatusOK {
		t.Fatalf("read sys/auth/%s: status %d: %s", mount, status, body)
	}
	return h.JSONString(t, body, "data.accessor")
}

// lookupSelf makes the gateway request that mints the spec's Vault token and returns
// that token's lookup-self response.
func lookupSelf(t *testing.T, headers map[string]string) (int, []byte) {
	t.Helper()
	headers["X-Warden-Role"] = defaultAgentRole
	return h.DoRequest(t, "GET",
		h.NodeURL(leaderPort)+"/v1/"+h.UserLegMount+"/gateway/v1/auth/token/lookup-self", headers, "")
}

// TestDefaultProfile_VaultBindsDelegation: Vault accepts the login only because
// /act/iss is where the profile puts it, and the token it issues records the USER's
// raw id — what Hydra put in the token the agent presented — as sub, qualified by the
// root namespace's value "root", and the AGENT's composite as the current actor.
func TestDefaultProfile_VaultBindsDelegation(t *testing.T) {
	setupDelegation(t)

	agentJWT := h.GetDefaultJWT(t)
	userJWT := h.UserJWT(t)
	wantSubject := h.JWTSubject(t, userJWT)
	wantActor := fmt.Sprintf("wid:root:%s:%s", authAccessor(t, "jwt"), h.JWTSubject(t, agentJWT))

	status, body := lookupSelf(t, map[string]string{
		"X-Warden-Agent-Token": agentJWT,
		"Authorization":        "Bearer " + userJWT,
	})
	if status != http.StatusOK {
		t.Fatalf("lookup-self under the delegation shape: status %d: %s", status, body)
	}

	for key, want := range map[string]string{
		"delegated_subject": wantSubject,
		"subject_namespace": "root",
		"subject_role":      h.UserLegAuthRole,
		"current_actor":     wantActor,
		"actor_role":        defaultAgentRole,
	} {
		if got := h.JSONString(t, body, "data.meta."+key); got != want {
			t.Errorf("Vault read %s = %q, want %q", key, got, want)
		}
	}
}

// TestDefaultProfile_VaultBindsAgentOnly: with no user disclosed the agent is the
// subject, by the same composite existing trusts already bind — a role globbing only
// the accessor accepts it — and there is no act.
func TestDefaultProfile_VaultBindsAgentOnly(t *testing.T) {
	agentJWT := h.GetDefaultJWT(t)
	agentSub := h.JWTSubject(t, agentJWT)
	setupDefaultProfile(t, agentOnlyVaultRole, fmt.Sprintf(`{
		"role_type":"jwt",
		"bound_audiences":["https://vault.e2e.warden"],
		"bound_claims_type":"glob",
		"bound_claims":{"sub":"wid:root:*:%s"},
		"user_claim":"sub",
		"claim_mappings":{"sub":"agent_subject","warden_role":"agent_role","/act/sub":"current_actor"},
		"token_policies":["e2e-secrets-reader"],
		"token_type":"batch",
		"token_ttl":"120s"}`, agentSub),
		agentOnlySpec, "")

	status, body := lookupSelf(t, map[string]string{"X-Warden-Agent-Token": agentJWT})
	if status != http.StatusOK {
		t.Fatalf("lookup-self under the agent-only shape: status %d: %s", status, body)
	}

	wantSubject := fmt.Sprintf("wid:root:%s:%s", authAccessor(t, "jwt"), agentSub)
	if got := h.JSONString(t, body, "data.meta.agent_subject"); got != wantSubject {
		t.Errorf("Vault read sub = %q, want the agent's composite %q", got, wantSubject)
	}
	if got := h.JSONString(t, body, "data.meta.agent_role"); got != defaultAgentRole {
		t.Errorf("Vault read warden_role = %q, want %q", got, defaultAgentRole)
	}
	if got := h.JSONPath(h.ParseJSON(t, body), "data.meta.current_actor"); got != nil {
		t.Errorf("an agent-only token must carry no act, but Vault read act.sub = %v", got)
	}
}

// TestDefaultProfile_DelegationSpecWithoutUserIsRefused: a spec that discloses a user
// fails closed when the request carries none — as a 401, so the client knows to
// authenticate a user and retry — rather than minting some other shape.
func TestDefaultProfile_DelegationSpecWithoutUserIsRefused(t *testing.T) {
	setupDelegation(t)

	status, body := lookupSelf(t, map[string]string{"X-Warden-Agent-Token": h.GetDefaultJWT(t)})
	if status != http.StatusUnauthorized {
		t.Fatalf("an agent with no user must be challenged for one, got %d: %s", status, body)
	}
	if !strings.Contains(string(body), "a user principal is required") {
		t.Fatalf("refused for the wrong reason: %s", body)
	}
}
