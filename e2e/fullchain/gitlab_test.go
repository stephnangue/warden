//go:build e2e

package fullchain

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// gitlab is the second of the two providers whose credential extractor is
// selected per request rather than per mount, and github_test.go notes its REST
// leg had never been driven end to end. It is also the only provider here that
// mints through a driver calling a real API, so the recording upstream stands in
// for GitLab itself: the source's gitlab_address and the mount's both point at
// it, and a handler answers the mint POST.
//
// That is what makes the keyless row below possible at all. Its point is the
// join no driver test can reach — a personal access token that exists only
// inside Vault travelling through federation, a KV read and MintFromSecret to
// authenticate a mint, whose result then comes back out as the credential the
// provider injects. Each half is covered in isolation; only a full chain shows
// them meeting.
//
// Unlike github, gitlab cannot borrow a local source: gitlab_access_token
// validates that its source is a gitlab one, so both rows here mint for real.
// The two differ only in where the driver's token comes from — inline config, or
// the chain — which is exactly the comparison worth drawing.

const (
	// The token the driver authenticates its mint with on the inline row.
	gitlabInlinePAT = "e2e-gl-inline-not-a-real-pat"

	// Written to secret/data/e2e/gitlab-pat by setup.sh, and the token the
	// driver authenticates with on the keyless row. It appears in no spec or
	// source config anywhere, so an assertion on it can only pass if the whole
	// chain ran.
	gitlabChainedPAT = "e2e-gl-chained-not-a-real-pat"

	// What the stand-in API returns from the mint call. Also present in no
	// config: it is minted, not stored.
	gitlabMintedToken = "glpat-e2e-minted-not-a-real-token"

	gitlabProjectID = "42"
	gitlabMintPath  = "/api/v4/projects/" + gitlabProjectID + "/access_tokens"

	// Test-local, the source included, for the reason credential_chaining_test.go
	// gives: a killed run skips t.Cleanup, and a spec left hanging off a shared
	// source would block that source from being deleted, failing the next run's
	// setup before it reaches the cleanup that would have cleared it.
	gitlabChainSecretSpec = "fc-gl-pat-from-vault"
	gitlabChainSource     = "fc-gl-keyless-src"
	gitlabChainSpec       = "fc-gl-keyless-cred"
	gitlabChainAgentRole  = "fc-gl-keyless-agent"
)

// setupGitLabEnv builds the mount and its inline source, per test rather than
// once for the package.
//
// The ordering is the reason. Creating a spec test-mints it, and gitlab's mint is
// a real API call, so the stand-in has to be answering before the spec is
// written — and the handler that answers it belongs to a test, not to the
// package. Every other provider mints from a local source that calls nothing, so
// none of them has this constraint and all of them are set up in ensureEnv.
//
// Recorded traffic is cleared last: setup's own calls — the source's auth check,
// the spec's test-mint — would otherwise be counted against the row's
// expectations.
func setupGitLabEnv(t *testing.T) h.ProviderEnv {
	t.Helper()

	serveGitLabMint(t)

	env := buildGitLabEnv(upstream.URL)
	h.SetupFullChainProvider(t, leaderPort, upstream.URL, env)
	t.Cleanup(func() { h.TeardownFullChainProviderBestEffort(leaderPort, env) })

	upstream.Reset()
	return env
}

// buildGitLabEnv needs the upstream's URL for the source config, not just the
// mount config, since the driver calls it to mint.
func buildGitLabEnv(upstreamURL string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      "fc-gitlab",
		Type:       "gitlab",
		URLKey:     "gitlab_address",
		CredType:   "gitlab_access_token",
		SourceType: "gitlab",
		SourceConfig: map[string]string{
			"gitlab_address":        upstreamURL,
			"auth_method":           "pat",
			"personal_access_token": gitlabInlinePAT,
		},
		CredConfig: map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   gitlabProjectID,
			"token_name":   "warden-e2e",
			"scopes":       "api",
			"access_level": "30",
			"ttl":          "24h",
		},
	}
}

// serveGitLabMint makes the upstream answer the driver's mint call, and leave
// every other path to the default probe response so the proxied request still
// behaves like every other row's.
func serveGitLabMint(t *testing.T) {
	t.Helper()
	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == gitlabMintPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99,"token":"` + gitlabMintedToken + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// findGitLabMint returns the mint call the driver made, failing if it never
// happened — which is the interesting failure on the keyless row, since a chain
// that broke before the driver ran would otherwise present only as a 5xx.
func findGitLabMint(t *testing.T) h.UpstreamRequest {
	t.Helper()
	for _, req := range upstream.Requests() {
		if req.Method == http.MethodPost && req.Path == gitlabMintPath {
			return req
		}
	}
	t.Fatalf("upstream never received the mint call %s %s", http.MethodPost, gitlabMintPath)
	return h.UpstreamRequest{}
}

// TestGitLab_RESTLegInjectsMintedToken drives the REST half of the mount that
// github_test.go records as uncovered, and pins the inline baseline the keyless
// row is measured against: the driver authenticates its mint with the token in
// source config, and the token it mints back comes out as a Bearer credential.
//
// Three upstream calls, where every other provider here makes one. Unlike them
// the mint is itself a request, and an inline source makes two: constructing the
// driver checks the token it was configured with, then the mint spends it, then
// the proxied request goes out. The keyless row below makes two, and the missing
// one is that construction check — a chained source has no token to check yet.
//
// The Bearer value is minted rather than stored, so it can only be right if the
// mint response was actually parsed and carried through.
func TestGitLab_RESTLegInjectsMintedToken(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         gitlabEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 3,
	})

	if got := findGitLabMint(t).Header.Get("PRIVATE-TOKEN"); got != gitlabInlinePAT {
		t.Errorf("mint call authenticated with %q, want the source's inline token %q", got, gitlabInlinePAT)
	}
}

// setupGitLabKeylessChain builds the keyless half: a source holding no token,
// naming a spec that reads one out of Vault.
//
// Order is load-bearing both ways — a source naming a secret_spec that does not
// exist is refused at create, and a referenced spec cannot be deleted while
// something names it — so cleanup runs consumer-first, and the same order clears
// whatever a killed run left behind.
func setupGitLabKeylessChain(t *testing.T, gitlabEnv h.ProviderEnv) {
	t.Helper()

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+gitlabChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+gitlabChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+gitlabChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+gitlabChainSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// The referenced spec. subject_token_source is not optional: a chained secret
	// must be minted as the session-pinned caller, and the store refuses the
	// reference otherwise.
	mustWrite("POST", "sys/cred/specs/"+gitlabChainSecretSpec, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":"e2e/gitlab-pat",
			"subject_token_source":"agent_identity"}}`,
		"create the referenced secret spec")

	// The keyless source: same address as the inline one, but carrying no
	// personal_access_token — validation rejects a source that keeps one while
	// also naming a chain.
	mustWrite("POST", "sys/cred/sources/"+gitlabChainSource, fmt.Sprintf(`{
		"type":"gitlab","config":{
			"gitlab_address":%q,"auth_method":"pat",
			"secret_spec":%q,"secret_field":"pat"}}`, upstream.URL, gitlabChainSecretSpec),
		"create the keyless gitlab source")

	// The consuming spec is ordinary: it inherits the chain from its source and
	// carries no chaining config of its own, which is what source-level chaining
	// means.
	mustWrite("POST", "sys/cred/specs/"+gitlabChainSpec, `{
		"type":"gitlab_access_token","source":"`+gitlabChainSource+`","config":{
			"mint_method":"project_access_token","project_id":"`+gitlabProjectID+`",
			"token_name":"warden-e2e-keyless","scopes":"api","access_level":"30","ttl":"24h"}}`,
		"create the keyless consuming spec")

	// The mount's own role binds its default spec, so this row needs one bound to
	// the keyless spec instead.
	mustWrite("POST", "auth/jwt/role/"+gitlabChainAgentRole, `{
		"token_policies":["`+gitlabEnv.Policy()+`"],"cred_spec_name":"`+gitlabChainSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the keyless agent role")
}

// TestGitLab_KeylessChainMintsWithVaultHeldToken is the row this file exists
// for: a source that stores no token still mints.
//
// Both asserted values are absent from every spec and source config — one lives
// only in Vault, the other only in the mint response — so the row fails if any
// link breaks: the federation login, the KV read, the material reaching
// MintFromSecret, the mint itself, or the extractor.
//
// A JWT agent leg rather than the usual certificate, because agent_identity
// forwards the agent's own inbound JWT as the exchange subject and fails closed
// on a cert-authenticated request.
func TestGitLab_KeylessChainMintsWithVaultHeldToken(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)
	useJWTAgentLeg(t, gitlabEnv)
	setupGitLabKeylessChain(t, gitlabEnv)
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       gitlabChainAgentRole,
	})

	// Two calls, not the inline row's three: no construction-time auth check,
	// because at construction a chained source has nothing to check with.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 2,
	})

	// The half a driver test cannot show: the token the mint authenticated with
	// came out of Vault, not out of config.
	mint := findGitLabMint(t)
	if got := mint.Header.Get("PRIVATE-TOKEN"); got != gitlabChainedPAT {
		t.Errorf("mint call authenticated with %q, want the Vault-held token %q", got, gitlabChainedPAT)
	}
	// And it really was the chained path: a source keeping an inline token
	// alongside a chain is refused at create, so the inline value must be absent.
	if strings.Contains(string(mint.Body), gitlabInlinePAT) {
		t.Errorf("the inline token leaked into the keyless mint body: %s", mint.Body)
	}
}

// TestGitLab_KeylessSourceRefusesConfigThatContradictsIt pins the two shapes a
// keyless source must not take, at the point they are written rather than at
// first use.
//
// Both are cases where the config would read as sensible and behave as neither
// thing: a rotation_period asks Warden to rotate a secret it does not own, on
// behalf of whoever does; an inline token alongside a chain leaves a source that
// presents as keyless while still storing the very secret the chain exists to
// remove.
func TestGitLab_KeylessSourceRefusesConfigThatContradictsIt(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)
	setupGitLabKeylessChain(t, gitlabEnv)

	tests := []struct {
		name   string
		body   string
		errMsg string
	}{
		{
			name: "rotation_period on a source owning no secret",
			body: fmt.Sprintf(`{"type":"gitlab","rotation_period":86400,"config":{
				"gitlab_address":%q,"auth_method":"pat",
				"secret_spec":%q,"secret_field":"pat"}}`, upstream.URL, gitlabChainSecretSpec),
			errMsg: "rotation_period does not apply",
		},
		{
			name: "an inline token kept alongside the chain",
			body: fmt.Sprintf(`{"type":"gitlab","config":{
				"gitlab_address":%q,"auth_method":"pat","personal_access_token":%q,
				"secret_spec":%q,"secret_field":"pat"}}`, upstream.URL, gitlabInlinePAT, gitlabChainSecretSpec),
			errMsg: "must be omitted when secret_spec is set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := "fc-gl-refused-" + strings.ReplaceAll(tt.name, " ", "-")
			t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "") })

			status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, tt.body)
			if status < 400 {
				t.Fatalf("got status %d, want a failure (body: %s)", status, body)
			}
			if !strings.Contains(string(body), tt.errMsg) {
				t.Errorf("error should mention %q, got: %s", tt.errMsg, body)
			}
		})
	}
}
