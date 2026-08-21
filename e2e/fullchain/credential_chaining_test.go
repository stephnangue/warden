//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Credential chaining: a spec that stores no secret of its own and names another
// spec that yields one. Here the referenced spec reads a Vault KV secret holding a
// whole multi-field credential, and the consuming spec's source declares which of
// those fields travel beyond api_key.
//
// The driver tests cover the same shape against a hand-built SecretMaterial. What
// only a full chain can show is the rest of it: the reference resolving to a real
// Vault read over federation, the payload reaching MintFromSecret, the declaration
// surviving Parse, and the declared field arriving as an upstream header. Joins
// like those are where a provider ends up reading a credential field nothing can
// supply — each layer correct alone, and unreachable together.
//
// Why this needs its own Vault source: a referenced spec must be minted as the
// session-pinned caller, which forces the exchange path, which on an hvault source
// requires auth_method=oidc_federation. The AppRole source every other suite uses
// cannot back a chained secret at all.

const (
	// Written to secret/data/e2e/datadog-keys by setup.sh. Nothing in any spec
	// config carries these values, so an assertion on them can only pass if the
	// whole chain ran.
	chainedAPIKey = "e2e-dd-chained-not-a-real-key"
	chainedAppKey = "e2e-dd-chained-not-a-real-app-key"

	chainedSecretSpec = "fc-chain-vault-keys"

	// Every resource here is test-local, the source included. Hanging the
	// consuming spec off the datadog mount's own source would be less setup, but a
	// killed run — Ctrl-C, a timeout panic — skips t.Cleanup, and the leftover spec
	// would then block that source from being deleted. The next run's environment
	// setup could not re-create it, would 409, and would fatal every test in the
	// package *before* reaching the cleanup that would have cleared the leftover.
	// Nothing recovers from that without hand-deleting a spec. Test-local
	// resources can only ever strand themselves.
	chainedSource    = "fc-chain-decl-src"
	chainedSpec      = "fc-chain-decl-cred"
	chainedAgentRole = "fc-chain-decl-agent"

	// A second source over the same Vault secret, declaring nothing. It is the
	// control: same payload, same referenced spec, same mount and policy, so the
	// declaration is the only difference between the two rows.
	undeclaredSource    = "fc-chain-nodecl-src"
	undeclaredSpec      = "fc-chain-nodecl-cred"
	undeclaredAgentRole = "fc-chain-nodecl-agent"
)

// setupChainedSpecs builds two chains over one Vault secret, differing only in
// whether their source declares the second field. Both drive the datadog mount,
// which supplies the extractor that turns each carried field into its own header.
//
// Order is load-bearing in both directions. A spec naming a secret_spec that does
// not exist is refused at create, and a referenced spec cannot be deleted while a
// consumer still names it, so cleanup runs consumer-first.
func setupChainedSpecs(t *testing.T) {
	t.Helper()

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	// Consumers first, then what they reference. Same order as cleanup, and for
	// the same reason — this clears anything a killed run left behind, which would
	// otherwise 409 the creates below.
	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+chainedAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+undeclaredAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+chainedSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+undeclaredSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+chainedSecretSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+chainedSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+undeclaredSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// The referenced spec: the whole credential, read from one Vault secret.
	// subject_token_source is not optional here — a chained secret must be minted
	// as the caller, and the store refuses the reference otherwise.
	mustWrite("POST", "sys/cred/specs/"+chainedSecretSpec, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":"e2e/datadog-keys",
			"subject_token_source":"agent_identity"}}`,
		"create the referenced secret spec")

	// The declaring source. api_key travels because it is the credential; the
	// application key travels because this names it.
	mustWrite("POST", "sys/cred/sources/"+chainedSource,
		`{"type":"apikey","config":{"credential_fields":"application_key"}}`,
		"create the declaring source")

	// The consuming spec holds no api_key: it is mutually exclusive with
	// secret_spec. secret_field is explicit — the fallback would find api_key by
	// name anyway, but a test should not lean on a fallback to choose the secret.
	mustWrite("POST", "sys/cred/specs/"+chainedSpec, `{
		"type":"api_key","source":"`+chainedSource+`","config":{
			"secret_spec":"`+chainedSecretSpec+`","secret_field":"api_key"}}`,
		"create the chained consuming spec")

	// The mount's own JWT agent role binds its default spec, so this row needs one
	// bound to the chained spec instead.
	mustWrite("POST", "auth/jwt/role/"+chainedAgentRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+chainedSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained agent role")

	// The control source, identical but for the missing declaration.
	mustWrite("POST", "sys/cred/sources/"+undeclaredSource,
		`{"type":"apikey","config":{}}`,
		"create the undeclaring source")

	mustWrite("POST", "sys/cred/specs/"+undeclaredSpec, `{
		"type":"api_key","source":"`+undeclaredSource+`","config":{
			"secret_spec":"`+chainedSecretSpec+`","secret_field":"api_key"}}`,
		"create the chained spec on the undeclaring source")

	mustWrite("POST", "auth/jwt/role/"+undeclaredAgentRole, `{
		"token_policies":["`+datadogEnv.Policy()+`"],"cred_spec_name":"`+undeclaredSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the undeclared agent role")
}

// TestChaining_VaultBackedCredentialCarriesItsDeclaredField is the row this
// exists for: two secrets living in one Vault entry, arriving as two upstream
// headers.
//
// Both asserted values appear in no spec config anywhere — they exist only inside
// the Vault secret — so the row fails if any link breaks: the federation login,
// the KV read, the material reaching the consuming driver, the declaration
// surviving Parse, or the extractor.
//
// A JWT agent leg rather than the usual certificate, because agent_identity
// forwards the agent's own inbound JWT as the exchange subject and fails closed
// on a cert-authenticated request.
func TestChaining_VaultBackedCredentialCarriesItsDeclaredField(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	setupChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       chainedAgentRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"DD-API-KEY":         chainedAPIKey,
			"DD-APPLICATION-KEY": chainedAppKey,
		},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}

// TestChaining_ReferencedSecretCannotBeDeletedWhileConsumed pins the protection
// this file's own cleanup order depends on.
//
// Deleting the secret-yielding spec out from under its consumers would not fail
// until the next mint, and would fail there as a credential error rather than
// anything naming the spec that went missing. The refusal is what keeps a chain
// from being dismantled halfway.
func TestChaining_ReferencedSecretCannotBeDeletedWhileConsumed(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	setupChainedSpecs(t)

	status, body := h.APIRequest(t, "DELETE", "sys/cred/specs/"+chainedSecretSpec, leaderPort, "")
	if status < 400 {
		t.Fatalf("deleting a referenced secret spec: got status %d, want a failure (body: %s)", status, body)
	}
	if !strings.Contains(string(body), "referenced") {
		t.Errorf("the error should say the spec is still referenced, got: %s", body)
	}

	// Still mintable afterwards — the refusal left the chain intact rather than
	// half-deleted.
	reqStatus, reqBody, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       chainedAgentRole,
	})
	h.AssertChain(t, upstream, reqStatus, reqBody, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": chainedAPIKey},
		UpstreamCalls: 1,
	})
}

// TestChaining_UndeclaredPayloadFieldStaysInTheVault is what makes the row above
// mean something.
//
// It drives the identical chain — same Vault secret, same referenced spec, same
// mount — through a source that declares nothing. The application key is right
// there in the payload, and it must not travel: a fetched secret is a shared blob
// an operator may keep notes, owners or rotation timestamps in, and copying it
// wholesale would send whichever of them a provider happens to read.
//
// The assertion is on DD-APPLICATION-KEY rather than some inert extra key,
// deliberately. An undeclared field that no extractor maps could never appear in a
// header whatever carriage did, so a row asserting *that* absence would pass
// against any implementation — including one that copies the whole payload. Only a
// field the provider would emit if it had it can tell the two apart.
func TestChaining_UndeclaredPayloadFieldStaysInTheVault(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, datadogEnv)
	setupChainedSpecs(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       undeclaredAgentRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		// The primary field always travels: it is the credential.
		Injected: map[string]string{"DD-API-KEY": chainedAPIKey},
		// The second secret is in the same payload and stays there.
		Absent:        h.AlwaysAbsent("Authorization", "DD-APPLICATION-KEY"),
		UpstreamCalls: 1,
	})
}
