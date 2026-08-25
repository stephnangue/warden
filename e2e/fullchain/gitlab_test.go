//go:build e2e

package fullchain

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	// The cache row's own chain. It cannot share the keyless row's resources:
	// its source must carry secret_cache_ttl, and it needs two consuming specs
	// where that row needs one.
	gitlabCacheSecretSpec = "fc-gl-cache-pat-from-vault"
	gitlabCacheSource     = "fc-gl-cache-src"
	gitlabCacheSpecA      = "fc-gl-cache-cred-a"
	gitlabCacheSpecB      = "fc-gl-cache-cred-b"
	gitlabCacheAgentRoleA = "fc-gl-cache-agent-a"
	gitlabCacheAgentRoleB = "fc-gl-cache-agent-b"

	// What the Vault secret is rotated to mid-test on the cache row. Like the
	// seeded value, it appears in no config anywhere.
	gitlabRotatedPAT = "e2e-gl-rotated-not-a-real-pat"

	// Where setup.sh seeds the chained token in the harness Vault, as a KV2
	// data path. The cache row writes here to simulate a rotation happening at
	// the source, behind Warden's back.
	gitlabPATVaultPath = "secret/data/e2e/gitlab-pat"

	// --- oauth2 chaining ---

	// The application id a keyless oauth2 source authenticates as. Unlike the
	// secret it pairs with, it is not sensitive and stays in source config.
	gitlabApplicationID = "e2e-gl-app-id"

	// Written to secret/data/e2e/gitlab-app-secret by setup.sh. Where the pat
	// rows' chained value authenticates the mint directly, this one is spent on
	// the token grant, and the bearer that grant returns authenticates the mint.
	gitlabChainedAppSecret = "e2e-gl-app-secret-not-a-real-secret"

	// What the stand-in grants for the seeded secret, and for the rotated one.
	// Neither is in any config: like the minted token, they are issued.
	gitlabAppBearer        = "e2e-gl-bearer-for-seeded-secret"
	gitlabRotatedAppBearer = "e2e-gl-bearer-for-rotated-secret"

	// What the application secret is rotated to mid-test on the oauth2 cache row.
	gitlabRotatedAppSecret = "e2e-gl-rotated-app-secret-not-a-real-secret"

	gitlabTokenPath          = "/oauth/token"
	gitlabAppSecretVaultPath = "secret/data/e2e/gitlab-app-secret"

	// The oauth2 rows' own chains, test-local for the same reason the pat ones are.
	gitlabOAuthSecretSpec = "fc-gl-oauth-secret-from-vault"
	gitlabOAuthSource     = "fc-gl-oauth-keyless-src"
	gitlabOAuthSpec       = "fc-gl-oauth-keyless-cred"
	gitlabOAuthAgentRole  = "fc-gl-oauth-keyless-agent"

	gitlabOAuthCacheSecretSpec = "fc-gl-oauth-cache-secret-from-vault"
	gitlabOAuthCacheSource     = "fc-gl-oauth-cache-src"
	gitlabOAuthCacheSpecA      = "fc-gl-oauth-cache-cred-a"
	gitlabOAuthCacheSpecB      = "fc-gl-oauth-cache-cred-b"
	gitlabOAuthCacheAgentRoleA = "fc-gl-oauth-cache-agent-a"
	gitlabOAuthCacheAgentRoleB = "fc-gl-oauth-cache-agent-b"
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

// gitlabChainConsumer names one consuming spec and the JWT agent role bound to
// it, for setupGitLabChain.
type gitlabChainConsumer struct {
	spec, role string
}

// setupGitLabChain builds a keyless chain: a source holding no token, naming a
// spec that reads one out of Vault, and one consuming spec plus agent role per
// entry in consumers. cacheTTL, when non-empty, becomes the source's
// secret_cache_ttl, so every consumer under it shares the fetched token for
// that long.
//
// Order is load-bearing both ways — a source naming a secret_spec that does not
// exist is refused at create, and a referenced spec cannot be deleted while
// something names it — so cleanup runs consumer-first, and the same order clears
// whatever a killed run left behind.
// gitlabChainMode describes what a keyless source chains and how it spends it.
// The two modes differ only in which secret is fetched and which config keys the
// source carries; everything else about the chain is identical, which is the point
// worth holding constant between the pat rows and the oauth2 ones.
type gitlabChainMode struct {
	secretPath  string // KV2 path setup.sh seeded
	secretField string // which field of that secret holds the value
	authConfig  string // the source's auth keys, as a JSON fragment
}

var (
	gitlabPATChain = gitlabChainMode{
		secretPath:  "e2e/gitlab-pat",
		secretField: "pat",
		authConfig:  `"auth_method":"pat"`,
	}
	gitlabOAuth2Chain = gitlabChainMode{
		secretPath:  "e2e/gitlab-app-secret",
		secretField: "application_secret",
		// The application id is an identifier rather than a secret, so it stays in
		// config; only the secret half is chained.
		authConfig: `"auth_method":"oauth2","application_id":"` + gitlabApplicationID + `"`,
	}
)

func setupGitLabChain(t *testing.T, gitlabEnv h.ProviderEnv, mode gitlabChainMode, secretSpec, source, cacheTTL string, consumers []gitlabChainConsumer) {
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
		for _, c := range consumers {
			h.APIRequest(t, "DELETE", "auth/jwt/role/"+c.role, leaderPort, "")
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+c.spec, leaderPort, "")
		}
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+secretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// The referenced spec. subject_token_source is not optional: a chained secret
	// must be minted as the session-pinned caller, and the store refuses the
	// reference otherwise.
	mustWrite("POST", "sys/cred/specs/"+secretSpec, fmt.Sprintf(`{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":%q,
			"subject_token_source":"agent_identity"}}`, mode.secretPath),
		"create the referenced secret spec")

	// The keyless source: same address as the inline one, but carrying none of the
	// secret its auth method would normally need — validation rejects a source
	// that keeps one while also naming a chain.
	ttlField := ""
	if cacheTTL != "" {
		ttlField = fmt.Sprintf(`,"secret_cache_ttl":%q`, cacheTTL)
	}
	mustWrite("POST", "sys/cred/sources/"+source, fmt.Sprintf(`{
		"type":"gitlab","config":{
			"gitlab_address":%q,%s,
			"secret_spec":%q,"secret_field":%q%s}}`,
		upstream.URL, mode.authConfig, secretSpec, mode.secretField, ttlField),
		"create the keyless gitlab source")

	for _, c := range consumers {
		// The consuming spec is ordinary: it inherits the chain from its source and
		// carries no chaining config of its own, which is what source-level chaining
		// means.
		mustWrite("POST", "sys/cred/specs/"+c.spec, `{
			"type":"gitlab_access_token","source":"`+source+`","config":{
				"mint_method":"project_access_token","project_id":"`+gitlabProjectID+`",
				"token_name":"warden-e2e-keyless","scopes":"api","access_level":"30","ttl":"24h"}}`,
			"create the keyless consuming spec "+c.spec)

		// The mount's own role binds its default spec, so each consumer needs one
		// bound to its own spec instead.
		mustWrite("POST", "auth/jwt/role/"+c.role, `{
			"token_policies":["`+gitlabEnv.Policy()+`"],"cred_spec_name":"`+c.spec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the keyless agent role "+c.role)
	}
}

// setupGitLabKeylessChain builds the single-consumer, uncached chain the
// keyless rows use.
func setupGitLabKeylessChain(t *testing.T, gitlabEnv h.ProviderEnv) {
	t.Helper()
	setupGitLabChain(t, gitlabEnv, gitlabPATChain, gitlabChainSecretSpec, gitlabChainSource, "",
		[]gitlabChainConsumer{{gitlabChainSpec, gitlabChainAgentRole}})
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

// TestGitLab_StaleCachedSecretIsEvictedAndRetried covers the join that makes
// the driver's ErrChainedSecretRejected worth returning at all: the driver's
// unit test stops at the error value, and the minting layer's eviction tests
// reject from a fake driver, so no test anywhere shows a real 401 from the API
// turning into an eviction, a fresh Vault read and a mint that succeeds. Without
// that join, a token rotated at its source would fail every request under it
// until the cache entry aged out on its own.
//
// Two consuming specs on one source, deliberately. A minted credential is
// cached per (caller, spec), so a second request against the same spec would be
// answered from that cache and never reach the mint this row exists to observe;
// a different spec under the same caller misses it while still sharing the
// source-scoped secret cache, whose key carries no spec name.
//
// One JWT for both requests, also deliberately. The secret cache's per-agent
// dimension is the agent's inbound JWT itself, and Hydra issues a fresh token
// per call — fetched twice, the second request would read as a different agent
// and miss the cache, and the row would pass without the cache ever being hit.
func TestGitLab_StaleCachedSecretIsEvictedAndRetried(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)
	useJWTAgentLeg(t, gitlabEnv)
	setupGitLabChain(t, gitlabEnv, gitlabPATChain, gitlabCacheSecretSpec, gitlabCacheSource, "5m",
		[]gitlabChainConsumer{
			{gitlabCacheSpecA, gitlabCacheAgentRoleA},
			{gitlabCacheSpecB, gitlabCacheAgentRoleB},
		})

	// The Vault secret is shared state: the other rows here, and every later
	// run, expect the seeded value. Registered before anything can rewrite it,
	// so a failure between the rotation below and the end of the test still
	// puts it back.
	t.Cleanup(func() {
		if status, resp := h.VaultDirectRequest(t, "POST", gitlabPATVaultPath,
			`{"data":{"pat":"`+gitlabChainedPAT+`"}}`); status >= 400 {
			t.Errorf("restoring the seeded gitlab pat in Vault failed (status %d): %s — later gitlab rows will mint with the wrong token", status, resp)
		}
	})

	// Unlike serveGitLabMint, this handler checks the mint's token: the whole
	// row turns on the upstream accepting only the token Vault currently holds,
	// so which value that is has to change mid-test when the secret rotates.
	// The guard is for the race detector — the handler runs on the server's
	// goroutines.
	var mu sync.Mutex
	acceptedPAT := gitlabChainedPAT
	setAcceptedPAT := func(pat string) { mu.Lock(); acceptedPAT = pat; mu.Unlock() }
	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == gitlabMintPath {
			mu.Lock()
			ok := r.Header.Get("PRIVATE-TOKEN") == acceptedPAT
			mu.Unlock()
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99,"token":"` + gitlabMintedToken + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	upstream.Reset()

	jwt := h.GetDefaultJWT(t)

	// The first request populates the secret cache on its way through: the
	// token is fetched from Vault, cached under the chain's key, and spent on
	// the mint. Fresh fetches are not retried on rejection, so this request
	// proves nothing about eviction — it exists to plant the entry the second
	// request must trip over.
	status, body, _ := h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: jwt,
		Role:       gitlabCacheAgentRoleA,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 2,
	})
	if got := findGitLabMint(t).Header.Get("PRIVATE-TOKEN"); got != gitlabChainedPAT {
		t.Fatalf("cache-populating mint authenticated with %q, want the Vault-held token %q", got, gitlabChainedPAT)
	}

	// The rotation happens where a real one would: at the source, with Warden
	// not told. The upstream flips with it, because a rotated token's defining
	// property is that the old one stops working.
	if status, resp := h.VaultDirectRequest(t, "POST", gitlabPATVaultPath,
		`{"data":{"pat":"`+gitlabRotatedPAT+`"}}`); status >= 400 {
		t.Fatalf("rotating the gitlab pat in Vault failed (status %d): %s", status, resp)
	}
	setAcceptedPAT(gitlabRotatedPAT)
	upstream.Reset()

	// Three calls where the first request made two: the mint that fails, the
	// mint that succeeds after the eviction, and the proxied request. The
	// caller sees none of it — the retry has to make the rotation invisible.
	status, body, _ = h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: jwt,
		Role:       gitlabCacheAgentRoleB,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 3,
	})

	var mints []h.UpstreamRequest
	for _, req := range upstream.Requests() {
		if req.Method == http.MethodPost && req.Path == gitlabMintPath {
			mints = append(mints, req)
		}
	}
	if len(mints) != 2 {
		t.Fatalf("second request made %d mint attempts, want 2 (rejected then retried)", len(mints))
	}
	// The first attempt must carry the token Vault no longer holds. That is the
	// proof the cache was consulted at all — on a miss the fetch would have
	// found the rotated token and the mint would have succeeded first try, and
	// the row would pass against a build with no cache in it.
	if got := mints[0].Header.Get("PRIVATE-TOKEN"); got != gitlabChainedPAT {
		t.Errorf("first mint attempt authenticated with %q, want the stale cached token %q", got, gitlabChainedPAT)
	}
	// And the second must carry the rotated one, which it can only have gotten
	// by evicting the stale entry and reading Vault again.
	if got := mints[1].Header.Get("PRIVATE-TOKEN"); got != gitlabRotatedPAT {
		t.Errorf("retried mint authenticated with %q, want the freshly fetched token %q", got, gitlabRotatedPAT)
	}
}

// serveGitLabOAuth2 makes the stand-in behave like an OAuth application's GitLab:
// it grants a bearer to whoever presents the secret it currently accepts, and
// accepts on the mint only the bearer it last granted. Both halves move together
// through setAccepted, because a rotated secret's defining property is that the
// old one stops working — and so does anything granted from it.
//
// The guard is for the race detector: the handler runs on the server's goroutines
// while the test rotates from its own.
func serveGitLabOAuth2(t *testing.T, secret, bearer string) (setAccepted func(secret, bearer string)) {
	t.Helper()

	var mu sync.Mutex
	acceptedSecret, acceptedBearer := secret, bearer

	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == gitlabTokenPath:
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			ok := r.Form.Get("client_secret") == acceptedSecret
			granted := acceptedBearer
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"` + granted + `","token_type":"bearer","expires_in":7200}`))

		case r.Method == http.MethodPost && r.URL.Path == gitlabMintPath:
			mu.Lock()
			ok := r.Header.Get("Authorization") == "Bearer "+acceptedBearer
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99,"token":"` + gitlabMintedToken + `"}`))

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})

	return func(secret, bearer string) {
		mu.Lock()
		acceptedSecret, acceptedBearer = secret, bearer
		mu.Unlock()
	}
}

// gitlabGrantForm parses a recorded token-grant call's form body. The upstream
// records bodies byte for byte, so the grant's parameters have to be decoded here
// rather than read off a parsed request.
func gitlabGrantForm(t *testing.T, req h.UpstreamRequest) url.Values {
	t.Helper()
	form, err := url.ParseQuery(string(req.Body))
	if err != nil {
		t.Fatalf("token grant body is not a form: %v (body %q)", err, req.Body)
	}
	return form
}

// gitlabRequestsTo returns every recorded call to one path, in order.
func gitlabRequestsTo(path string) []h.UpstreamRequest {
	var found []h.UpstreamRequest
	for _, req := range upstream.Requests() {
		if req.Method == http.MethodPost && req.Path == path {
			found = append(found, req)
		}
	}
	return found
}

// TestGitLab_OAuth2KeylessChainMintsWithVaultHeldSecret is the oauth2 counterpart
// of the pat keyless row, and it proves the chain reaches one call further back.
//
// In pat mode the chained value authenticates the mint, so the mint's header is
// where the chain shows up. Here the chained value is spent on the token grant
// instead, and what authenticates the mint is a bearer the stand-in issued — so
// the row only passes if the secret travelled from Vault to the grant, and the
// grant's answer travelled on to the mint.
func TestGitLab_OAuth2KeylessChainMintsWithVaultHeldSecret(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)
	useJWTAgentLeg(t, gitlabEnv)
	serveGitLabOAuth2(t, gitlabChainedAppSecret, gitlabAppBearer)
	setupGitLabChain(t, gitlabEnv, gitlabOAuth2Chain, gitlabOAuthSecretSpec, gitlabOAuthSource, "",
		[]gitlabChainConsumer{{gitlabOAuthSpec, gitlabOAuthAgentRole}})
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       gitlabOAuthAgentRole,
	})

	// Three calls where the pat keyless row makes two. The extra one is the grant:
	// a pat source spends its chained secret directly, an oauth2 source has to
	// trade it for a bearer first. Still no construction-time check, which is what
	// keeps this at three rather than the inline row's four.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 3,
	})

	grants := gitlabRequestsTo(gitlabTokenPath)
	if len(grants) != 1 {
		t.Fatalf("upstream received %d token grants, want exactly 1", len(grants))
	}
	// The half no driver test can show: the secret the grant spent came out of
	// Vault, not out of config.
	if got := gitlabGrantForm(t, grants[0]).Get("client_secret"); got != gitlabChainedAppSecret {
		t.Errorf("grant presented %q, want the Vault-held application secret %q", got, gitlabChainedAppSecret)
	}
	if got := gitlabGrantForm(t, grants[0]).Get("client_id"); got != gitlabApplicationID {
		t.Errorf("grant presented client_id %q, want the source's %q", got, gitlabApplicationID)
	}

	// And the mint rode the bearer that grant returned, not the secret itself.
	mint := findGitLabMint(t)
	if got := mint.Header.Get("Authorization"); got != "Bearer "+gitlabAppBearer {
		t.Errorf("mint authenticated with %q, want the granted bearer %q", got, "Bearer "+gitlabAppBearer)
	}
	if strings.Contains(string(mint.Body), gitlabChainedAppSecret) {
		t.Errorf("the application secret leaked into the mint body: %s", mint.Body)
	}
}

// TestGitLab_OAuth2StaleCachedSecretIsEvictedAndRetried is the oauth2 counterpart
// of the pat stale-secret row, and it covers a join that mode does not have.
//
// Two caches sit between a rotation and a successful mint here, not one. The
// minting layer caches the fetched application secret for secret_cache_ttl, and
// the driver caches the bearer it granted from that secret for the grant's
// expires_in — which the stand-in sets long enough to outlive this test. So the
// first mint after a rotation goes out under a bearer that is doubly stale, and
// what this row pins is that the caller never sees it: the 401 is marked as a
// rejected chained secret, the minting layer evicts and refetches, and the retry
// succeeds.
//
// It does not pin the driver's own eviction of the refused bearer. Once the
// refetch returns the rotated secret the bearer cache key changes with it, so the
// grant re-runs whether or not the old entry was dropped. The eviction matters for
// a bearer refused while its secret is unchanged — no key rollover to save it —
// and that case is pinned in the driver's unit tests, where the secret is held
// constant.
//
// The two-specs-one-JWT arrangement is the pat row's, for the reasons it gives.
func TestGitLab_OAuth2StaleCachedSecretIsEvictedAndRetried(t *testing.T) {
	ensureEnv(t)
	gitlabEnv := setupGitLabEnv(t)
	useJWTAgentLeg(t, gitlabEnv)
	setAccepted := serveGitLabOAuth2(t, gitlabChainedAppSecret, gitlabAppBearer)
	setupGitLabChain(t, gitlabEnv, gitlabOAuth2Chain, gitlabOAuthCacheSecretSpec, gitlabOAuthCacheSource, "5m",
		[]gitlabChainConsumer{
			{gitlabOAuthCacheSpecA, gitlabOAuthCacheAgentRoleA},
			{gitlabOAuthCacheSpecB, gitlabOAuthCacheAgentRoleB},
		})

	// Shared state, restored before anything can rewrite it — see the pat row.
	t.Cleanup(func() {
		if status, resp := h.VaultDirectRequest(t, "POST", gitlabAppSecretVaultPath,
			`{"data":{"application_secret":"`+gitlabChainedAppSecret+`"}}`); status >= 400 {
			t.Errorf("restoring the seeded gitlab application secret in Vault failed (status %d): %s — later gitlab rows will grant with the wrong secret", status, resp)
		}
	})
	upstream.Reset()

	jwt := h.GetDefaultJWT(t)

	// The priming request: fetches the secret from Vault into the minting layer's
	// cache, grants a bearer into the driver's, and spends it. It proves nothing
	// about eviction — it plants both entries the second request must trip over.
	status, body, _ := h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: jwt,
		Role:       gitlabOAuthCacheAgentRoleA,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 3,
	})

	// The rotation happens where a real one would: at the source, with Warden not
	// told. The stand-in stops honouring the old secret and the bearer granted
	// from it at the same moment.
	if status, resp := h.VaultDirectRequest(t, "POST", gitlabAppSecretVaultPath,
		`{"data":{"application_secret":"`+gitlabRotatedAppSecret+`"}}`); status >= 400 {
		t.Fatalf("rotating the gitlab application secret in Vault failed (status %d): %s", status, resp)
	}
	setAccepted(gitlabRotatedAppSecret, gitlabRotatedAppBearer)
	upstream.Reset()

	// Four calls where the priming request made three: the mint under the stale
	// bearer that fails, the grant that replaces it, the mint that succeeds, and
	// the proxied request. Note there is no grant before the first mint — the
	// driver had a cached bearer and saw no reason to ask for another, which is
	// exactly the state this row exists to get into.
	status, body, _ = h.ChainRequest(t, leaderPort, gitlabEnv, h.ChainOpts{
		AgentToken: jwt,
		Role:       gitlabOAuthCacheAgentRoleB,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + gitlabMintedToken},
		UpstreamCalls: 4,
	})

	mints := gitlabRequestsTo(gitlabMintPath)
	if len(mints) != 2 {
		t.Fatalf("second request made %d mint attempts, want 2 (rejected then retried)", len(mints))
	}
	// The first attempt carrying the stale bearer is the proof both caches were
	// consulted: without the driver's, the mint would have been preceded by a
	// fresh grant and succeeded first try, and this row would pass against a
	// build that caches nothing.
	if got := mints[0].Header.Get("Authorization"); got != "Bearer "+gitlabAppBearer {
		t.Errorf("first mint attempt authenticated with %q, want the stale cached bearer %q", got, "Bearer "+gitlabAppBearer)
	}
	if got := mints[1].Header.Get("Authorization"); got != "Bearer "+gitlabRotatedAppBearer {
		t.Errorf("retried mint authenticated with %q, want the freshly granted bearer %q", got, "Bearer "+gitlabRotatedAppBearer)
	}

	// And exactly one grant, carrying the rotated secret — which the driver can
	// only have gotten by the minting layer evicting its cached copy and reading
	// Vault again.
	grants := gitlabRequestsTo(gitlabTokenPath)
	if len(grants) != 1 {
		t.Fatalf("second request made %d token grants, want exactly 1 (after the stale bearer was evicted)", len(grants))
	}
	if got := gitlabGrantForm(t, grants[0]).Get("client_secret"); got != gitlabRotatedAppSecret {
		t.Errorf("grant presented %q, want the freshly fetched application secret %q", got, gitlabRotatedAppSecret)
	}
}
