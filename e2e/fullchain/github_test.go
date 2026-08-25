//go:build e2e

package fullchain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// github and gitlab are the two providers whose credential extractor is selected
// per request rather than per mount: git smart-HTTP paths get a Basic credential
// built for git, and every other path falls back to the mount's REST extractor.
// github is the one the seed set carries; gitlab's REST leg is equally untested
// end to end and belongs with the rest of that provider's coverage.
//
// e2e/githttp covers github's git half in depth — passthrough, minting,
// attribution, the placeholder-password rule and a real clone — but every one of
// those drives a smart-HTTP path, so the REST half of the same mount has never
// been driven end to end.
//
// It is also the only member of the seed set using TypedTokenExtractor, the one
// shared SDK extractor shape the other providers do not reach.

const githubPAT = "fc-github-not-a-real-token"

var githubEnv = h.ProviderEnv{
	Mount:    "fc-github",
	Type:     "github",
	URLKey:   "github_url",
	CredType: "github_token",
	// A local source carries the token statically and mints nothing, so only
	// the field the credential needs is set. mint_method would be required of a
	// real github source and is not consulted here — the local driver would
	// simply copy it into the minted credential as a stray field.
	CredConfig: map[string]string{"token": githubPAT},
}

// TestGitHub_RESTLegInjectsTokenScheme drives a REST path and pins two things at
// once: the credential shape, and that the request took the REST branch at all.
//
// Nothing positively selects that branch — the git dispatch declines a path it
// does not recognise and the mount-level extractor applies by fallback — so the
// evidence is circumstantial and needs two independent signals:
//
//   - the scheme. REST authenticates with "token <pat>" where the git leg on
//     this same mount sends Basic base64("x-access-token:<pat>"), so a misfiring
//     dispatch would carry the same secret in a visibly different form.
//   - the REST-only headers. The git dispatch suppresses the default Accept and
//     the dynamic headers, so their presence is a signal the credential scheme
//     cannot give on its own. X-GitHub-Api-Version is also the only end-to-end
//     coverage of DynamicHeaders in this suite.
func TestGitHub_RESTLegInjectsTokenScheme(t *testing.T) {
	ensureEnv(t)

	probe := h.ProbePath("github-rest")
	status, body, _ := h.ChainRequest(t, leaderPort, githubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         githubEnv.CertRole(),
		Path:         probe,
		Headers:      h.InertDecoyHeaders(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"Authorization":        "token " + githubPAT,
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	// The user is resolved by the same function the git leg uses, here through
	// its Bearer branch rather than the Basic-password one — the dispatch
	// changes which credential goes out, not who the request is for.
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestGitHub_RESTLegAcceptsUserInBasicPassword covers the other slot the user can
// arrive in. github resolves the second principal through the same helper on
// every path, and that helper accepts either a Bearer token or a JWT-shaped HTTP
// Basic password — the latter existing because git can only send credentials that
// way.
//
// Nothing exercises that slot on a REST path: e2e/githttp drives it only on
// smart-HTTP paths, and the test above supplies a Bearer. The two differ in both
// the path shape and the credential the upstream receives, so this duplicates
// neither.
//
// The Basic username is the agent's role, which is how a git client selects one
// with no configuration beyond the clone URL. The certificate is what actually
// authenticates the agent.
func TestGitHub_RESTLegAcceptsUserInBasicPassword(t *testing.T) {
	ensureEnv(t)

	userJWT := h.FullChainUserJWT(t)
	basic := base64.StdEncoding.EncodeToString([]byte(githubEnv.CertRole() + ":" + userJWT))

	probe := h.ProbePath("github-rest-basic-user")
	status, body, _ := h.ChainRequest(t, leaderPort, githubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		RawAuthz:     "Basic " + basic,
		Role:         githubEnv.CertRole(),
		Path:         probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "token " + githubPAT},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// --- credential chaining (app mode) ---

// The github rows above borrow a local source holding a static token, so nothing
// here had ever driven the github driver's own mint path, let alone its chained
// one. These rows do both, against the recording upstream standing in for the
// GitHub API.
//
// Chaining attaches differently than it does for gitlab, and that is the point
// worth pinning. A gitlab source authenticates itself, so its secret_spec sits on
// the source. A github source holds only a URL — the app id, installation id and
// private key are per-spec, so several specs can share one source for different
// installations — so secret_spec sits on the spec instead.
const (
	githubAppID          = "fc-gh-app-12345"
	githubInstallationID = "67890"

	// What the stand-in returns from the installation-token call. Present in no
	// config: it is minted, not stored.
	githubMintedToken = "ghs_fc_e2e_minted_not_a_real_token"

	githubInstallPath = "/app/installations/" + githubInstallationID + "/access_tokens"

	// Test-local, for the reason gitlab_test.go gives: a killed run skips
	// t.Cleanup, and a spec left hanging off a source blocks that source's
	// deletion, failing the next run's setup.
	githubChainSecretSpec = "fc-gh-key-from-vault"
	githubChainSource     = "fc-gh-app-src"
	githubChainSpec       = "fc-gh-chained-cred"
	githubChainAgentRole  = "fc-gh-chained-agent"

	// A second role bound to the SAME spec, for a second agent to mint through.
	// A role pins the spec its callers mint, so two agents sharing one spec need
	// one role each; the role itself does not enter any cache key, so it is the
	// differing agent, not the differing role, that makes a mint re-run.
	githubChainAgentRoleB = "fc-gh-chained-agent-b"

	// Where this test parks the App private key. Unlike the gitlab secrets this
	// is written by the test rather than seeded by setup.sh: the row asserts the
	// key actually signed the assertion, so the test has to know it, and a
	// freshly generated one keeps real-looking key material out of the repo.
	githubKeyVaultPath = "secret/data/e2e/fc-github-app-key"
)

// githubAppKeyPEM generates an RSA private key in PEM form, plus the parsed key
// for the handler to verify assertions against.
func githubAppKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an App private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(pemBytes), key
}

// serveGitHubInstallToken answers the driver's installation-token call, but only
// for an assertion signed by wantKey — which is what turns this row from "a token
// came back" into "the key from the store is what signed it". Everything else
// falls through to the default probe response so the proxied request behaves like
// every other row's.
func serveGitHubInstallToken(t *testing.T, wantKey *rsa.PrivateKey) (rotate func(key *rsa.PrivateKey, token string)) {
	t.Helper()

	// Guarded because the handler runs on the server's goroutines while a test
	// rotates from its own.
	var mu sync.Mutex
	acceptedKey, mintedToken := wantKey, githubMintedToken

	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost && r.URL.Path == githubInstallPath {
			mu.Lock()
			key, token := acceptedKey, mintedToken
			mu.Unlock()

			if !assertionSignedBy(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), key) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"` + token +
				`","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	return func(key *rsa.PrivateKey, token string) {
		mu.Lock()
		acceptedKey, mintedToken = key, token
		mu.Unlock()
	}
}

// assertionSignedBy verifies the App JWT's RS256 signature. The stand-in never
// sees the private key, only what it signed.
func assertionSignedBy(assertion string, key *rsa.PrivateKey) bool {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) == nil
}

// buildGitHubAppEnv points both the mount and a real github source at the
// upstream, with an inline App key on the mount's own spec — the baseline the
// chained row is measured against.
func buildGitHubAppEnv(upstreamURL, keyPEM string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      "fc-github-app",
		Type:       "github",
		URLKey:     "github_url",
		CredType:   "github_token",
		SourceType: "github",
		SourceConfig: map[string]string{
			"github_url":      upstreamURL,
			"tls_skip_verify": "true",
		},
		CredConfig: map[string]string{
			"mint_method":     "app",
			"app_id":          githubAppID,
			"installation_id": githubInstallationID,
			"private_key":     keyPEM,
		},
	}
}

// setupGitHubAppEnv orders setup the way gitlab's does and for the same reason:
// creating a spec test-mints it, and an app-mode mint is a real API call, so the
// stand-in must be answering first. Recorded traffic is cleared last so setup's
// own calls are not counted against a row.
func setupGitHubAppEnv(t *testing.T, keyPEM string, key *rsa.PrivateKey) (h.ProviderEnv, func(*rsa.PrivateKey, string)) {
	t.Helper()

	rotate := serveGitHubInstallToken(t, key)

	env := buildGitHubAppEnv(upstream.URL, keyPEM)
	h.SetupFullChainProvider(t, leaderPort, upstream.URL, env)
	t.Cleanup(func() { h.TeardownFullChainProviderBestEffort(leaderPort, env) })

	upstream.Reset()
	return env, rotate
}

// setupGitHubChain parks the App key in the store and builds the keyless consumer
// that reads it. Cleanup runs consumer-first: a referenced spec cannot be deleted
// while something names it.
func writeGitHubAppKey(t *testing.T, keyPEM string) {
	t.Helper()
	// Marshalled rather than concatenated: a PEM carries newlines that would
	// otherwise break the JSON body.
	body, err := json.Marshal(map[string]any{"data": map[string]string{"private_key": keyPEM}})
	if err != nil {
		t.Fatalf("encoding the App private key: %v", err)
	}
	if status, resp := h.VaultDirectRequest(t, "POST", githubKeyVaultPath, string(body)); status >= 400 {
		t.Fatalf("parking the App private key in the store failed (status %d): %s", status, resp)
	}
}

func setupGitHubChain(t *testing.T, env h.ProviderEnv, keyPEM string) {
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
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+githubChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+githubChainAgentRoleB, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+githubChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+githubChainSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	writeGitHubAppKey(t, keyPEM)

	// The referenced spec. subject_token_source is not optional: a chained secret
	// is minted as the session-pinned caller, and the store refuses the reference
	// otherwise.
	mustWrite("POST", "sys/cred/specs/"+githubChainSecretSpec, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":"e2e/fc-github-app-key",
			"subject_token_source":"agent_identity"}}`,
		"create the referenced secret spec")

	// The keyless consumer. secret_spec sits on the SPEC, which is where the key
	// it replaces would otherwise live — the inverse of gitlab, whose secret
	// belongs to the source.
	mustWrite("POST", "sys/cred/specs/"+githubChainSpec, `{
		"type":"github_token","source":"`+env.Source()+`","config":{
			"mint_method":"app","app_id":"`+githubAppID+`",
			"installation_id":"`+githubInstallationID+`",
			"secret_spec":"`+githubChainSecretSpec+`","secret_field":"private_key"}}`,
		"create the keyless consuming spec")

	// Two roles bound to the same spec, one per agent: a role pins the spec its
	// callers mint, and both agents must land on this one.
	for _, role := range []string{githubChainAgentRole, githubChainAgentRoleB} {
		mustWrite("POST", "auth/jwt/role/"+role, `{
			"token_policies":["`+env.Policy()+`"],"cred_spec_name":"`+githubChainSpec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the keyless agent role "+role)
	}
}

// TestGitHub_AppModeInjectsMintedToken pins the inline baseline: the driver signs
// an assertion with the key in spec config, mints an installation token against
// it, and that token — not the key — is what goes upstream.
func TestGitHub_AppModeInjectsMintedToken(t *testing.T) {
	ensureEnv(t)
	keyPEM, key := githubAppKeyPEM(t)
	env, _ := setupGitHubAppEnv(t, keyPEM, key)

	status, body, _ := h.ChainRequest(t, leaderPort, env, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         env.CertRole(),
	})

	// Two calls: the installation-token mint, then the proxied request. Unlike
	// gitlab there is no construction-time auth check — a github source holds no
	// credential to check.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "token " + githubMintedToken},
		UpstreamCalls: 2,
	})
}

// TestGitHub_ChainedAppKeyMintsWithStoreHeldKey is the row this section exists
// for: a spec holding no key still mints, because the key travelled from the
// store through federation and MintFromSecret to sign the assertion.
//
// The handler refuses any assertion not signed by that key, so a broken link
// cannot pass — and the injected token appears in no config anywhere, so it can
// only be right if the mint response was parsed and carried through.
//
// A JWT agent leg rather than a certificate, because agent_identity forwards the
// agent's own inbound JWT as the exchange subject and fails closed otherwise.
func TestGitHub_ChainedAppKeyMintsWithStoreHeldKey(t *testing.T) {
	ensureEnv(t)
	keyPEM, key := githubAppKeyPEM(t)
	env, _ := setupGitHubAppEnv(t, keyPEM, key)
	useJWTAgentLeg(t, env)
	setupGitHubChain(t, env, keyPEM)
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, env, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Role:       githubChainAgentRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "token " + githubMintedToken},
		UpstreamCalls: 2,
	})

	// And the key itself never left the store: it signs, it is not sent.
	for _, req := range upstream.Requests() {
		if strings.Contains(string(req.Body), "PRIVATE KEY") {
			t.Errorf("the App private key leaked into an upstream request body: %s", req.Path)
		}
	}
}
