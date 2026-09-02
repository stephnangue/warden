//go:build e2e

package fullchain

import (
	"fmt"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The grafana source driver on its inline path: a source holding its own
// privileged token, issuing a token per request on an account an operator
// provisioned.
//
// Nothing drove this code end to end before — grafana appeared nowhere in this
// suite, which is what e2e/FINDINGS.md records. What these rows pin is the shape
// of the driver rather than any one call: Warden mints a credential ON an
// identity, it does not create the identity. A row asserting only that a token
// came back would pass just as well against the driver that created a fresh
// service account per request, so each one below names the account too.

// grafanaStaticKey backs the mount itself, which serves an ordinary static
// credential. The rows here bind their own specs by role, so this is only what
// makes the mount stand up.
const grafanaStaticKey = "glsa_fc-grafana-not-a-real-token"

var grafanaEnv = h.ProviderEnv{
	Mount:      "fc-grafana",
	Type:       "grafana",
	URLKey:     "grafana_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": grafanaStaticKey},
}

const (
	// The privileged token an inline source holds: able to manage tokens on the
	// provisioned account, and nothing this suite does may create an account
	// with it.
	grafanaInlineAdminToken = "glsa_fc-inline-not-a-real-admin-token"

	// Everything is test-local, the source included. A killed run skips
	// t.Cleanup, and a spec left hanging off a shared source would block that
	// source from being deleted, failing the next run's setup before it reaches
	// the cleanup that would have cleared it.
	grafanaInlineSource    = "fc-gf-inline-src"
	grafanaInlineSpec      = "fc-gf-inline-cred"
	grafanaInlineAgentRole = "fc-gf-inline-agent"

	grafanaRevokeSource    = "fc-gf-revoke-src"
	grafanaRevokeSpec      = "fc-gf-revoke-cred"
	grafanaRevokeAgentRole = "fc-gf-revoke-agent"

	grafanaSweepSource    = "fc-gf-sweep-src"
	grafanaSweepSpec      = "fc-gf-sweep-cred"
	grafanaSweepAgentRole = "fc-gf-sweep-agent"

	// The prefix a spec sets on the names of the tokens it mints. The sweep
	// matches Warden's own default prefix, so this stays under it.
	grafanaSpecNamePrefix = "warden-"
)

func grafanaMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// grafanaMustRefuse asserts a write is rejected and that the reason names what
// the operator has to change. "not 200" would also pass for a 500, which would
// mean something else entirely.
func grafanaMustRefuse(t *testing.T, path, body, wantIn, what string) {
	t.Helper()
	status, resp := h.APIRequest(t, "POST", path, leaderPort, body)
	if status < 400 || status >= 500 {
		t.Fatalf("%s: status %d, want a 4xx refusal (body: %s)", what, status, resp)
	}
	if !strings.Contains(string(resp), wantIn) {
		t.Errorf("%s: refusal did not mention %q: %s", what, wantIn, resp)
	}
	t.Cleanup(func() { h.APIRequest(t, "DELETE", path, leaderPort, "") })
}

// setupGrafanaInlineSource stands up a source holding its own privileged token, a
// spec naming the account to mint on, and a role selecting it.
//
// sourceAccount goes on the source as its default; specAccount on the spec. Either
// may be empty, which is how the rows below tell the two apart.
func setupGrafanaInlineSource(t *testing.T, stub *grafanaStub, source, spec, role string, tokenTTL int, sourceAccount, specAccount, specExtra string) {
	t.Helper()

	useJWTAgentLeg(t, grafanaEnv)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	sourceCfg := fmt.Sprintf(`"grafana_url":%q,"tls_skip_verify":"true","admin_token":%q`,
		stub.URL, grafanaInlineAdminToken)
	if sourceAccount != "" {
		sourceCfg += fmt.Sprintf(`,"service_account_id":%q`, sourceAccount)
	}
	grafanaMustWrite(t, "POST", "sys/cred/sources/"+source,
		fmt.Sprintf(`{"type":"grafana","config":{%s}}`, sourceCfg),
		"create the inline grafana source "+source)

	specCfg := fmt.Sprintf(`"name_prefix":%q`, grafanaSpecNamePrefix)
	if specAccount != "" {
		specCfg += fmt.Sprintf(`,"service_account_id":%q`, specAccount)
	}
	specCfg += specExtra
	grafanaMustWrite(t, "POST", "sys/cred/specs/"+spec,
		fmt.Sprintf(`{"type":"api_key","source":%q,"config":{%s}}`, source, specCfg),
		"create the inline grafana spec "+spec)

	if role != "" {
		grafanaMustWrite(t, "POST", "auth/jwt/role/"+role, fmt.Sprintf(`{
			"token_policies":[%q],"cred_spec_name":%q,
			"user_claim":"sub","token_ttl":%d}`,
			grafanaEnv.Policy(), spec, tokenTTL),
			"create the inline agent role "+role)
	}
}

// TestGrafanaSource_MintIssuesATokenOnTheProvisionedAccount drives the inline
// path end to end, and is the row the whole redesign turns on.
//
// It asserts three things a "a token came back" check would miss: that the token
// was created ON the account the spec names, that no account was created or
// deleted along the way, and that the spec's mint parameters reached Grafana. The
// driver as it stood would fail every one of them — it created a fresh service
// account per request with a role the spec chose.
func TestGrafanaSource_MintIssuesATokenOnTheProvisionedAccount(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaInlineSource(t, stub, grafanaInlineSource, grafanaInlineSpec, grafanaInlineAgentRole,
		3600, "", grafanaAccountViewer, `,"token_expiry":"30m"`)

	// Standing the spec up already cost Grafana a create and a delete: spec
	// validation test-mints and then releases the lease. Start counting here.
	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       grafanaInlineAgentRole,
		Path:       h.ProbePath("grafana-inline-mint"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	// The stub derives what it issues from the token that authenticated the
	// create, so this header names the source's own privileged token specifically.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + grafanaMintedFor(grafanaInlineAdminToken)},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	creates := stub.createdTokens()
	if len(creates) != 1 {
		t.Fatalf("Grafana saw %d token creations, want exactly 1: %+v", len(creates), creates)
	}
	got := creates[0]

	if got.Privileged != grafanaInlineAdminToken {
		t.Errorf("the create authenticated with %q, want the source's own privileged token", got.Privileged)
	}
	if got.AccountID != grafanaAccountViewer {
		t.Errorf("the token was created on account %q, want the account the spec names (%q)",
			got.AccountID, grafanaAccountViewer)
	}
	if ttl, _ := got.Body["secondsToLive"].(float64); ttl != 1800 {
		t.Errorf("secondsToLive reached Grafana as %v, want the spec's 30m as 1800", got.Body["secondsToLive"])
	}
	// The name is what tells one lease from another in Grafana's own view, where
	// every token on the account acts as the same identity.
	name, _ := got.Body["name"].(string)
	if !strings.HasPrefix(name, grafanaSpecNamePrefix+grafanaInlineSpec+"-") {
		t.Errorf("token name %q does not carry the spec's prefix and name", name)
	}

	// The account is the operator's. Nothing here may create or remove one.
	if deleted := stub.deletedAccounts(); len(deleted) != 0 {
		t.Errorf("Grafana was asked to delete service account(s) %v; Warden must only ever delete tokens", deleted)
	}
}

// TestGrafanaSource_SpecAccountWinsOverTheSourceDefault is what spec-level
// placement buys: one source — one Grafana, one privileged token — serving two
// privilege levels, because the account's role is the credential's privilege.
//
// Both halves matter. A driver reading only the source default would fail the
// first; one reading only the spec would fail the second.
func TestGrafanaSource_SpecAccountWinsOverTheSourceDefault(t *testing.T) {
	ensureEnv(t)

	t.Run("the spec's account wins", func(t *testing.T) {
		stub := startGrafanaStub(t)
		setupGrafanaInlineSource(t, stub, grafanaInlineSource+"-a", grafanaInlineSpec+"-a",
			grafanaInlineAgentRole+"-a", 3600, grafanaAccountViewer, grafanaAccountEditor, "")
		stub.reset()
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
			AgentToken: h.GetDefaultJWT(t),
			Bearer:     h.FullChainUserJWT(t),
			Role:       grafanaInlineAgentRole + "-a",
			Path:       h.ProbePath("grafana-account-spec-wins"),
		})
		if status != 200 {
			t.Fatalf("status %d, body %s", status, string(body))
		}
		assertGrafanaMintedOn(t, stub, grafanaAccountEditor)
	})

	t.Run("the source default covers a silent spec", func(t *testing.T) {
		stub := startGrafanaStub(t)
		setupGrafanaInlineSource(t, stub, grafanaInlineSource+"-b", grafanaInlineSpec+"-b",
			grafanaInlineAgentRole+"-b", 3600, grafanaAccountEditor, "", "")
		stub.reset()
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
			AgentToken: h.GetDefaultJWT(t),
			Bearer:     h.FullChainUserJWT(t),
			Role:       grafanaInlineAgentRole + "-b",
			Path:       h.ProbePath("grafana-account-source-default"),
		})
		if status != 200 {
			t.Fatalf("status %d, body %s", status, string(body))
		}
		assertGrafanaMintedOn(t, stub, grafanaAccountEditor)
	})
}

func assertGrafanaMintedOn(t *testing.T, stub *grafanaStub, wantAccount string) {
	t.Helper()
	creates := stub.createdTokens()
	if len(creates) != 1 {
		t.Fatalf("Grafana saw %d token creations, want exactly 1: %+v", len(creates), creates)
	}
	if creates[0].AccountID != wantAccount {
		t.Errorf("the token was created on account %q, want %q", creates[0].AccountID, wantAccount)
	}
}

// TestGrafanaSource_MintedTokenIsDeletedWhenTheSessionEnds pins revocation, which
// the redesign made precise: the lease names one token, so revoking removes that
// token and leaves the account and everything else on it alone.
//
// A minted token is registered for expiry against the SESSION's lifetime, not its
// own — so a role with a short token_ttl brings the revocation forward to where a
// test can watch it. The token here asks for an hour; what ends it is the agent's
// token running out five seconds later.
func TestGrafanaSource_MintedTokenIsDeletedWhenTheSessionEnds(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaInlineSource(t, stub, grafanaRevokeSource, grafanaRevokeSpec, grafanaRevokeAgentRole,
		5, "", grafanaAccountViewer, "")

	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       grafanaRevokeAgentRole,
		Path:       h.ProbePath("grafana-inline-revoke"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}
	creates := stub.createdTokens()
	if len(creates) != 1 {
		t.Fatalf("Grafana saw %d token creations, want exactly 1", len(creates))
	}
	minted := creates[0].MintedID

	// Nothing to synchronise on but the effect: revocation runs on the expiration
	// manager's own timer once the session's five seconds are up.
	stub.awaitDeleted(t, minted, 60*time.Second)

	for _, id := range stub.deletedTokens() {
		if id != minted {
			t.Errorf("Grafana was asked to delete token %q, which this row never minted", id)
		}
	}
	if deleted := stub.deletedAccounts(); len(deleted) != 0 {
		t.Errorf("revocation deleted service account(s) %v; it must only remove the one token", deleted)
	}
}

// TestGrafanaSource_ExpiredTokensAreReclaimed drives the sweep.
//
// Grafana does not remove a token when it expires — it stays listed on the
// account, inert but accumulating — and a revoke that failed for good, or a node
// that died between mint and register, leaves one behind. What the sweep is
// allowed to match is the whole of its safety: the account is the operator's and
// may hold tokens Warden never issued, so a live token and a hand-issued expired
// one are primed alongside, and this row asserts both survived.
func TestGrafanaSource_ExpiredTokensAreReclaimed(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaInlineSource(t, stub, grafanaSweepSource, grafanaSweepSpec, grafanaSweepAgentRole,
		3600, "", grafanaAccountViewer, "")

	// Primed AFTER setup, deliberately. Creating the spec test-mints through a
	// throwaway driver the store builds and discards, and that mint sweeps too —
	// so priming earlier would let this row pass on a sweep the request path never
	// ran. The registry driver serving the request below has swept nothing yet.
	stub.primeTokens(grafanaAccountViewer,
		grafanaStubToken{ID: 9001, Name: "warden-" + grafanaSweepSpec + "-1-aaaaaaaa", HasExpired: true},
		grafanaStubToken{ID: 9002, Name: "warden-" + grafanaSweepSpec + "-2-bbbbbbbb", HasExpired: false},
		grafanaStubToken{ID: 9003, Name: "ci-pipeline-token", HasExpired: true},
	)
	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, grafanaEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       grafanaSweepAgentRole,
		Path:       h.ProbePath("grafana-inline-sweep"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	stub.awaitDeleted(t, "9001", 60*time.Second)

	// The sweep walks the listing in order, so 9003 would be deleted after 9001 if
	// the filter were wrong. Let the sweep finish before concluding it left them.
	stub.awaitQuiescent(t, 3*time.Second)

	for _, id := range stub.deletedTokens() {
		switch id {
		case "9002":
			t.Errorf("the sweep deleted a token that has not expired")
		case "9003":
			t.Errorf("the sweep deleted %q, a token this account's operator issued and Warden did not", "ci-pipeline-token")
		}
	}
	if deleted := stub.deletedAccounts(); len(deleted) != 0 {
		t.Errorf("the sweep deleted service account(s) %v; it may only remove tokens", deleted)
	}
}

// TestGrafanaSource_SpecShapeIsEnforced drives the refusals that moved into the
// credential type, which is the layer that runs for every spec — including a
// chained one, which the store never test-mints or verifies.
func TestGrafanaSource_SpecShapeIsEnforced(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	setupGrafanaInlineSource(t, stub, grafanaInlineSource+"-shape", grafanaInlineSpec+"-shape",
		"", 0, "", grafanaAccountViewer, "")
	source := grafanaInlineSource + "-shape"

	spec := func(config string) string {
		return fmt.Sprintf(`{"type":"api_key","source":%q,"config":{%s}}`, source, config)
	}

	// The privilege boundary this redesign moved. Asking for a role would be
	// asking Warden to create an identity, which it no longer does.
	t.Run("a spec may not choose a role", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-role",
			spec(`"service_account_id":"42","role":"Admin"`),
			"'role' is not settable",
			"a spec asking for a role")
	})

	// The account says which organization; a second answer could only disagree.
	t.Run("a spec may not name an organization", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-org",
			spec(`"service_account_id":"42","org_id":"1"`),
			"'org_id' is not settable",
			"a spec naming an org")
	})

	// Grafana reads a truncated-to-zero lifetime as "never expires", and a zero
	// lease TTL reads to Warden as a static credential.
	for _, expiry := range []string{"0s", "500ms"} {
		t.Run("a sub-second lifetime is refused: "+expiry, func(t *testing.T) {
			grafanaMustRefuse(t, "sys/cred/specs/fc-gf-tiny-"+expiry,
				spec(fmt.Sprintf(`"service_account_id":"42","token_expiry":%q`, expiry)),
				"at least 1s",
				"a spec asking for "+expiry)
		})
	}

	// GetDuration swallows a parse error and returns the default, so an unchecked
	// value here would mint an hour while the spec said something else.
	t.Run("a unitless lifetime is refused", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-unitless",
			spec(`"service_account_id":"42","token_expiry":"60"`),
			"not a duration",
			"a spec asking for a unitless lifetime")
	})

	t.Run("a non-numeric account is refused", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-badaccount",
			spec(`"service_account_id":"my-account"`),
			"positive integer",
			"a spec naming a non-numeric account")
	})
}

// TestGrafanaSource_SpecMustNameAnAccount pins the check that can only live in
// the store: the credential type is handed the source's TYPE but never its
// config, so it cannot see whether a default exists to fall back to.
func TestGrafanaSource_SpecMustNameAnAccount(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	const source = "fc-gf-bare-src"

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/fc-gf-no-account", leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	grafanaMustWrite(t, "POST", "sys/cred/sources/"+source, fmt.Sprintf(
		`{"type":"grafana","config":{"grafana_url":%q,"tls_skip_verify":"true","admin_token":%q}}`,
		stub.URL, grafanaInlineAdminToken),
		"create a grafana source with no default account")

	grafanaMustRefuse(t, "sys/cred/specs/fc-gf-no-account",
		fmt.Sprintf(`{"type":"api_key","source":%q,"config":{"token_expiry":"1h"}}`, source),
		"service_account_id is required",
		"a spec on a source that names no account either")
}

// TestGrafanaSource_VerificationRejectsAnAccountThatCannotServe covers what
// VerifySpec adds over the test mint that runs just before it: an account id
// naming nothing, and one the operator has disabled — whose tokens would mint
// happily and then fail to authenticate.
func TestGrafanaSource_VerificationRejectsAnAccountThatCannotServe(t *testing.T) {
	ensureEnv(t)

	stub := startGrafanaStub(t)
	const source = "fc-gf-verify-src"

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	grafanaMustWrite(t, "POST", "sys/cred/sources/"+source, fmt.Sprintf(
		`{"type":"grafana","config":{"grafana_url":%q,"tls_skip_verify":"true","admin_token":%q}}`,
		stub.URL, grafanaInlineAdminToken),
		"create the verifying grafana source")

	t.Run("an account that does not exist", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-missing-account",
			fmt.Sprintf(`{"type":"api_key","source":%q,"config":{"service_account_id":%q}}`,
				source, grafanaAccountUnknown),
			grafanaAccountUnknown,
			"a spec naming an account Grafana does not have")
	})

	t.Run("an account the operator disabled", func(t *testing.T) {
		grafanaMustRefuse(t, "sys/cred/specs/fc-gf-disabled-account",
			fmt.Sprintf(`{"type":"api_key","source":%q,"config":{"service_account_id":%q}}`,
				source, grafanaAccountDisabled),
			"disabled",
			"a spec naming a disabled account")
	})
}
