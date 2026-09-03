//go:build e2e

package fullchain

import (
	"fmt"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// A grafana source chains the privileged token that authenticates its own
// service-account calls. Grafana's token API has no assertion grant to federate
// against, so as with elastic and ibm, keyless here means removing the token from
// Warden rather than exchanging an identity for one.
//
// Chaining is a SOURCE concern for this driver, and only that. There is one mint
// path and no second reading of the fetched material — every spec issues a fresh
// token rather than serving a stored one — so a spec-level reference means
// nothing and is refused, with the guidance to move it to the source.
//
// What chaining does NOT supply is the account. The fetched token is the one that
// manages tokens; the account they are minted on is still the operator's, still
// named by the spec or its source, and still required — which the last row here
// pins, because it is the one thing a reader might expect chaining to cover.
//
// The inline half of this driver is next door in grafana_source_test.go.

const (
	// Written to secret/data/e2e/grafana-admin-token by setup.sh, under the key
	// the driver looks for by convention.
	grafanaChainedAdminToken = "glsa_e2e-grafana-not-a-real-admin-token"

	// Test-local, the source included, for the reason the other chained suites
	// give: a killed run skips t.Cleanup, and a spec left hanging off a shared
	// source would block that source from being deleted, failing the next run's
	// setup before it reaches the cleanup that would have cleared it.
	grafanaSecretSpec     = "fc-gf-token-from-vault"
	grafanaChainSource    = "fc-gf-keyless-src"
	grafanaChainSpec      = "fc-gf-chain-cred"
	grafanaChainAgentRole = "fc-gf-chain-agent"
)

// setupGrafanaChain stands up one chain: a referenced spec over the Vault secret,
// a source holding no token that names it, an ordinary spec naming the account,
// and a role selecting that spec.
//
// secretField may be empty, which exercises the conventional-name fallback — the
// driver reads admin_token, then api_key, then token, but only when no field was
// resolved.
func setupGrafanaChain(t *testing.T, subj scalewaySubject, secretField string, stub *grafanaStub) {
	t.Helper()

	// The referenced spec is minted as the calling agent, and both subjects derive
	// that agent from an inbound JWT — agent_identity forwards it, warden_identity
	// signs an assertion from the principal it established. This mount's default
	// agent leg is a client certificate, which carries neither.
	useJWTAgentLeg(t, grafanaEnv)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+grafanaChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+grafanaChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+grafanaChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+grafanaSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	grafanaMustWrite(t, "POST", "sys/cred/specs/"+grafanaSecretSpec, fmt.Sprintf(`{
		"type":"key_value","source":%q,"config":{
			"mint_method":"kv2_read","kv2_mount":"secret",
			"secret_path":"e2e/grafana-admin-token","subject_token_source":%q}}`,
		subj.source, subj.name),
		"create the referenced secret spec "+grafanaSecretSpec)

	// No admin_token: validation refuses a source that keeps one while naming a
	// chain. tls_skip_verify because the stub listens on http, the same allowance
	// every other stubbed source in this suite takes.
	sourceCfg := fmt.Sprintf(`"grafana_url":%q,"tls_skip_verify":"true","secret_spec":%q`,
		stub.URL, grafanaSecretSpec)
	if secretField != "" {
		sourceCfg += fmt.Sprintf(`,"secret_field":%q`, secretField)
	}
	grafanaMustWrite(t, "POST", "sys/cred/sources/"+grafanaChainSource,
		fmt.Sprintf(`{"type":"grafana","config":{%s}}`, sourceCfg),
		"create the keyless grafana source")

	// Ordinary but for the account: it inherits the chain from its source and
	// carries no chaining config of its own, which is what source-level chaining
	// means.
	grafanaMustWrite(t, "POST", "sys/cred/specs/"+grafanaChainSpec, fmt.Sprintf(
		`{"type":"api_key","source":%q,"config":{"service_account_id":%q,"token_expiry":"1h"}}`,
		grafanaChainSource, grafanaAccountViewer),
		"create the chained grafana spec")

	grafanaMustWrite(t, "POST", "auth/jwt/role/"+grafanaChainAgentRole, fmt.Sprintf(`{
		"token_policies":[%q],"cred_spec_name":%q,
		"user_claim":"sub","token_ttl":3600}`,
		grafanaEnv.Policy(), grafanaChainSpec),
		"create the chained agent role")
}

// TestGrafanaChaining_SourceFetchesTheTokenPerRequest is the whole feature in one
// row: the source stores no Grafana secret, the referenced spec yields one, and
// the token the gateway injects is the one Grafana issued for exactly that
// privileged token.
//
// Both ways of naming the secret are driven — by secret_field, and by the
// conventional key the driver falls back to when no field is set — because the
// fallback only applies when nothing resolved, and a resolver that fell back on
// an empty result would silently authenticate with some other value.
func TestGrafanaChaining_SourceFetchesTheTokenPerRequest(t *testing.T) {
	ensureEnv(t)

	fields := []struct {
		name  string
		field string
	}{
		{"named_by_secret_field", "admin_token"},
		{"conventional_name", ""},
	}

	for _, subj := range scalewaySubjects {
		for _, f := range fields {
			t.Run(subj.name+"/"+f.name, func(t *testing.T) {
				stub := startGrafanaStub(t)
				setupGrafanaChain(t, subj, f.field, stub)
				stub.reset()
				upstream.Reset()

				status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
					AgentToken: h.GetDefaultJWT(t),
					Bearer:     h.FullChainUserJWT(t),
					Role:       grafanaChainAgentRole,
					Path:       h.ProbePath("grafana-chained-" + f.name),
				})
				if status != 200 {
					t.Fatalf("status %d, body %s", status, string(body))
				}

				// The stub derives what it issues from the token it was handed, so
				// this header is the end-to-end proof that the FETCHED token
				// performed the create — not an inline one a routing regression fell
				// back to.
				h.AssertChain(t, upstream, status, body, h.ChainWant{
					Status:        200,
					Injected:      map[string]string{"Authorization": "Bearer " + grafanaMintedFor(grafanaChainedAdminToken)},
					Absent:        h.AlwaysAbsent(),
					UpstreamCalls: 1,
				})

				// And Grafana's own record agrees, which distinguishes a genuine
				// chain from a header that merely looks right.
				presented := stub.observed()
				if len(presented) == 0 {
					t.Fatal("the Grafana stub saw no token creation at all")
				}
				for _, token := range presented {
					if token != grafanaChainedAdminToken {
						t.Errorf("the create authenticated with %q, want the chained privileged token", token)
					}
				}

				// Chaining supplies the token that manages tokens, not the account.
				for _, c := range stub.createdTokens() {
					if c.AccountID != grafanaAccountViewer {
						t.Errorf("the token was created on account %q, want the account the spec names (%q)",
							c.AccountID, grafanaAccountViewer)
					}
				}
				if deleted := stub.deletedAccounts(); len(deleted) != 0 {
					t.Errorf("Grafana was asked to delete service account(s) %v", deleted)
				}
			})
		}
	}
}

// TestGrafanaChaining_ExpiredTokensAreReclaimed is the sweep on the path where it
// is the only reclamation there is.
//
// A chained source cannot revoke — there is no caller at lease expiry to fetch
// the privileged token as — so nothing but this removes what it mints. It also
// cannot be observed the way the inline row's sweep partly could: a chained spec
// is never test-minted at create, so the only sweep that ever runs is the one a
// real request triggers, authenticating with the token that request fetched.
func TestGrafanaChaining_ExpiredTokensAreReclaimed(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaChain(t, scalewaySubjects[0], "admin_token", stub)

	stub.primeTokens(grafanaAccountViewer,
		grafanaStubToken{ID: 8001, Name: "warden-" + grafanaChainSpec + "-1-aaaaaaaa", HasExpired: true},
		grafanaStubToken{ID: 8002, Name: "warden-" + grafanaChainSpec + "-2-bbbbbbbb", HasExpired: false},
		grafanaStubToken{ID: 8003, Name: "ci-pipeline-token", HasExpired: true},
	)
	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       grafanaChainAgentRole,
		Path:       h.ProbePath("grafana-chained-sweep"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	stub.awaitDeleted(t, "8001", 60*time.Second)
	stub.awaitQuiescent(t, 3*time.Second)

	// The token this very request minted is in the listing too, and live. A sweep
	// that read hasExpired the wrong way round would take it.
	var minted string
	for _, c := range stub.createdTokens() {
		minted = c.MintedID
	}
	for _, id := range stub.deletedTokens() {
		switch id {
		case "8002":
			t.Errorf("the sweep deleted a token that has not expired")
		case "8003":
			t.Errorf("the sweep deleted a token this account's operator issued and Warden did not")
		case minted:
			t.Errorf("the sweep deleted the credential this request had just minted")
		}
	}
}

// TestGrafanaChaining_PlacementAndShapeAreEnforced drives the refusals. A
// reference on the spec would describe a secret the spec never spends, and a
// source keeping a token beside a chain reads as keyless while storing the very
// secret chaining removes.
func TestGrafanaChaining_PlacementAndShapeAreEnforced(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaChain(t, scalewaySubjects[0], "admin_token", stub)

	t.Run("a spec may not carry a reference of its own", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-spec-chained",
			fmt.Sprintf(`{"type":"api_key","source":%q,"config":{"service_account_id":%q,"secret_spec":%q}}`,
				grafanaChainSource, grafanaAccountViewer, grafanaSecretSpec),
			"set secret_spec on the source",
			"a spec naming its own reference")
	})

	t.Run("a chained source may not also store a privileged token", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/sources/fc-gf-half-keyless",
			fmt.Sprintf(`{"type":"grafana","config":{"grafana_url":%q,"tls_skip_verify":"true","secret_spec":%q,"admin_token":"still-here"}}`,
				stub.URL, grafanaSecretSpec),
			"admin_token",
			"a source keeping an inline token beside a reference")
	})

	// A chained source holds no secret of its own, so there is nothing here to
	// rotate — that passes to whoever owns the referenced spec.
	t.Run("a chained source may not carry a rotation period", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/sources/fc-gf-rotating",
			fmt.Sprintf(`{"type":"grafana","rotation_period":3600,"config":{"grafana_url":%q,"tls_skip_verify":"true","secret_spec":%q}}`,
				stub.URL, grafanaSecretSpec),
			"rotation_period",
			"a chained source asking to rotate")
	})

	// The one an operator is most likely to expect chaining to have covered.
	t.Run("a chained spec still has to name an account", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-chain-no-account",
			fmt.Sprintf(`{"type":"api_key","source":%q,"config":{"token_expiry":"1h"}}`, grafanaChainSource),
			"service_account_id is required",
			"a chained spec naming no account")
	})
}

// TestGrafanaChaining_InlineSourceStillNeedsAToken pins the other half of the
// dropped Required(): a source naming no chain must still be refused without a
// token, rather than being accepted and failing at the first mint.
func TestGrafanaChaining_InlineSourceStillNeedsAToken(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	grafanaMustRefuse(t, "sys/cred/sources/fc-gf-no-token",
		fmt.Sprintf(`{"type":"grafana","config":{"grafana_url":%q,"tls_skip_verify":"true"}}`, stub.URL),
		"admin_token",
		"a source with neither a token nor a reference")
}

// TestGrafanaChaining_IncompleteMaterialIsRefusedBeforeAnyGrafanaCall points
// secret_field at a key the payload does not have.
//
// What it asserts is where the failure lands. The resolver refuses on the
// material alone, before authenticating, so Grafana is never called: an
// incomplete secret must not be spent as a credential to find out it was
// incomplete. That is also what separates this from a stale-secret refusal, which
// would have reached Grafana and been told no — and which the minting layer would
// then retry, having evicted a perfectly good cached secret.
//
// It is discriminating for a second reason: the payload DOES carry admin_token,
// the very key the conventional fallback reads. A resolver that fell back after a
// field resolved to nothing would authenticate successfully here and this row
// would go green while secret_field silently meant nothing.
func TestGrafanaChaining_IncompleteMaterialIsRefusedBeforeAnyGrafanaCall(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaChain(t, scalewaySubjects[0], "no_such_field", stub)
	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       grafanaChainAgentRole,
		Path:       h.ProbePath("grafana-chained-incomplete"),
	})
	if status == 200 {
		t.Fatalf("the request succeeded on material the field names nothing in: %s", string(body))
	}
	// Named specifically: any other 500 would pass a bare status check while
	// meaning something entirely different.
	if !strings.Contains(string(body), "chained secret material is incomplete") {
		t.Errorf("the refusal did not name the incomplete material: %s", string(body))
	}

	if creates := stub.createdTokens(); len(creates) != 0 {
		t.Errorf("Grafana was asked to create %d token(s) with material the driver could not resolve: %+v",
			len(creates), creates)
	}
	// And nothing reached the upstream either, since there was no credential to
	// inject.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("the upstream saw %d request(s), want 0", n)
	}
}
