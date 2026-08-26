//go:build e2e

package fullchain

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The oauth2 source can fetch the client credential it authenticates with per mint
// instead of storing it. The source then names no client at all, which is what lets one
// source, one spec and one role front a different OAuth client for every agent.
//
// What a row here can prove that a driver unit test cannot is that the pair reaching the
// token endpoint was resolved from the identity of the agent that asked — carried the
// whole way from the inbound request, through a path templated on it, to the grant.

const (
	// One templated path, one client credential per agent beneath it. Each is a
	// DIFFERENT OAuth client: id and secret both vary, which is the shape the
	// pair-in-payload design exists to allow and a shared client_id could not express.
	oaPerAgentKeyPath = "e2e/fc-oauth2-agent-clients"

	oaPerAgentSecretSpec = "fc-oauth2-per-agent-client"
	oaPerAgentSource     = "fc-oauth2-per-agent-src"
	oaPerAgentSpec       = "fc-oauth2-per-agent-cred"
	oaPerAgentRole       = "fc-oauth2-per-agent"

	oaAgentA = "e2e-agent"
	oaAgentB = "e2e-pipeline"

	oaTokenPath = "/oauth2/token"
)

// oaClient is one tenant's OAuth client, as the stand-in provider sees it.
type oaClient struct {
	id, secret, bearer string
}

// oaGrant is one client_credentials grant the provider was asked to perform.
type oaGrant struct {
	clientID, clientSecret, grantType, scope string
}

// serveOAuth2Provider stands in for the identity provider issuing the bearer. It answers
// only a client whose id AND secret match one it knows, and hands back that client's own
// token.
//
// Matching on the pair is the point: a build that took the id from source config and the
// secret from the chain would present a mismatched pair here and be refused with the
// invalid_client the chained path reads as a stale secret.
//
// It is its own listener rather than a handler on the shared recording upstream: the
// provider is a different host from the API being proxied, and displacing that upstream
// would change what every other row in the package is talking to.
func serveOAuth2Provider(t *testing.T, clients []oaClient) (*httptest.Server, func() []oaGrant) {
	t.Helper()

	var (
		mu     sync.Mutex
		grants []oaGrant
	)

	mux := http.NewServeMux()
	mux.HandleFunc(oaTokenPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		grants = append(grants, oaGrant{
			clientID:     r.Form.Get("client_id"),
			clientSecret: r.Form.Get("client_secret"),
			grantType:    r.Form.Get("grant_type"),
			scope:        r.Form.Get("scope"),
		})
		mu.Unlock()

		for _, c := range clients {
			if r.Form.Get("client_id") == c.id && r.Form.Get("client_secret") == c.secret {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"` + c.bearer + `","token_type":"Bearer","expires_in":3600}`))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() []oaGrant {
		mu.Lock()
		defer mu.Unlock()
		return append([]oaGrant(nil), grants...)
	}
}

// setupOAuth2PerAgentChain parks one client credential per agent under the templated
// path, then builds a single source and a single spec that both agents mint through.
//
// The consuming mount is the one restEnv already stood up: what varies between the two
// agents is the credential, not the provider, and a mount of its own would only add
// setup the rows do not exercise.
func setupOAuth2PerAgentChain(t *testing.T, providerURL string, clientByAgent map[string]oaClient) {
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
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+oaPerAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+oaPerAgentSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+oaPerAgentSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+oaPerAgentSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// Both halves in one payload, because they authenticate as a pair.
	for agent, c := range clientByAgent {
		path := "secret/data/" + oaPerAgentKeyPath + "/" + agent
		body := `{"data":{"client_id":"` + c.id + `","client_secret":"` + c.secret + `"}}`
		if status, resp := h.VaultDirectRequest(t, "POST", path, body); status >= 400 {
			t.Fatalf("parking %s's client credential (status %d): %s", agent, status, resp)
		}
	}

	// The templated referenced spec. It must be session-pinned — a chained secret is
	// minted as the caller, which is also what makes {{agent.sub}} resolve to the agent
	// asking rather than to whoever warmed the cache first.
	mustWrite("POST", "sys/cred/specs/"+oaPerAgentSecretSpec, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret",
			"secret_path":"`+oaPerAgentKeyPath+`/{{agent.sub}}",
			"subject_token_source":"agent_identity"}}`,
		"create the templated client-credential spec")

	// One source for every tenant. It holds neither half, so nothing about it names a
	// client. tls_skip_verify because the stand-in listens on loopback over http, which
	// the token_url guard otherwise refuses.
	mustWrite("POST", "sys/cred/sources/"+oaPerAgentSource, fmt.Sprintf(`{
		"type":"oauth2","config":{
			"token_url":%q,"default_scopes":"read","tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":"client_secret"}}`,
		providerURL+oaTokenPath, oaPerAgentSecretSpec),
		"create the per-agent oauth2 source")

	// The consuming spec declares no identity of its own: the caller's is carried by the
	// referenced spec, and the chained credential authenticates Warden to the provider.
	mustWrite("POST", "sys/cred/specs/"+oaPerAgentSpec, `{
		"type":"oauth_bearer_token","source":"`+oaPerAgentSource+`","config":{
			"scope":"read"}}`,
		"create the per-agent consuming spec")

	mustWrite("POST", "auth/jwt/role/"+oaPerAgentRole, `{
		"token_policies":["`+restEnv.Policy()+`"],"cred_spec_name":"`+oaPerAgentSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the shared per-agent role")
}

// TestOAuth2_PerAgentClientCredential drives two agents through one source, one spec and
// one role, each authenticating to the provider as its own OAuth client.
//
// The client credential is resolved per mint from a path templated on the calling agent,
// so the id and the secret both vary between the two — and the source that fronts them
// stores neither, which is what lets it front both. A build reading the id from config
// and the secret from the chain presents a mismatched pair and is refused; one that
// shared a bearer across tenants proxies the wrong token.
//
// Two agents, one role, one spec, one source.
func TestOAuth2_PerAgentClientCredential(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	clientA := oaClient{id: "oa-app-for-agent-a", secret: "oa-secret-a-not-real", bearer: "oa-bearer-for-agent-a"}
	clientB := oaClient{id: "oa-app-for-agent-b", secret: "oa-secret-b-not-real", bearer: "oa-bearer-for-agent-b"}

	idp, grants := serveOAuth2Provider(t, []oaClient{clientA, clientB})
	setupOAuth2PerAgentChain(t, idp.URL, map[string]oaClient{
		oaAgentA: clientA,
		oaAgentB: clientB,
	})
	upstream.Reset()

	mintAs := func(clientID, secret string) {
		t.Helper()
		status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
			AgentToken: h.GetJWT(t, clientID, secret),
			Role:       oaPerAgentRole,
		})
		if status != 200 {
			t.Fatalf("%s got status %d: %s", clientID, status, body)
		}
	}

	// A first, warming every cache on the way, so B has something to be wrongly served
	// if any of them collapses the two.
	mintAs(oaAgentA, "agent-secret")
	mintAs(oaAgentB, "pipeline-secret")

	// Each grant presented its own client — the pair reaching the provider together is
	// what the source cannot supply and the payload must.
	got := grants()
	if len(got) != 2 {
		t.Fatalf("provider received %d grants, want one per agent", len(got))
	}
	for i, want := range []oaClient{clientA, clientB} {
		if got[i].grantType != "client_credentials" {
			t.Errorf("grant %d used grant_type %q, want client_credentials", i, got[i].grantType)
		}
		if got[i].clientID != want.id {
			t.Errorf("grant %d presented client_id %q, want %q", i, got[i].clientID, want.id)
		}
		if got[i].clientSecret != want.secret {
			t.Errorf("grant %d presented client_secret %q, want %q", i, got[i].clientSecret, want.secret)
		}
		// Chaining replaces the client credential and nothing else: the rest of the
		// source config still reaches the endpoint.
		if got[i].scope != "read" {
			t.Errorf("grant %d requested scope %q, want the source's default_scopes", i, got[i].scope)
		}
	}

	// Each proxied request carried the bearer minted for its own agent's client. B
	// receiving A's would mean a token was shared across tenants.
	var injected []string
	for _, req := range upstream.Requests() {
		// restEnv's mount is configured to inject under a header of its own, which is
		// also the one a row there proves is honoured.
		if got := req.Header.Get("X-Custom-Auth"); got != "" {
			injected = append(injected, got)
		}
	}
	want := []string{"Token " + clientA.bearer, "Token " + clientB.bearer}
	if len(injected) != 2 || injected[0] != want[0] || injected[1] != want[1] {
		t.Errorf("proxied requests carried %v, want %v", injected, want)
	}
}

// TestOAuth2_KeylessSourceRejectsAnInlineClientID pins the create-time half of the rule
// the row above depends on: a source that fetches its client credential may not also name
// a client, since an id from config beside a secret from the chain would present a pair
// belonging to no one.
func TestOAuth2_KeylessSourceRejectsAnInlineClientID(t *testing.T) {
	ensureEnv(t)

	const (
		name       = "fc-oauth2-inline-id-rejected"
		secretSpec = "fc-oauth2-inline-id-secret"
	)

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+secretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// The reference is resolved before the driver's config is validated, so it has to
	// exist for the rejection under test to be the one that fires.
	if status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+secretSpec, leaderPort, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret",
			"secret_path":"`+oaPerAgentKeyPath+`/`+oaAgentA+`",
			"subject_token_source":"agent_identity"}}`); status >= 400 {
		t.Fatalf("create the referenced spec (status %d): %s", status, resp)
	}

	body := fmt.Sprintf(`{"type":"oauth2","config":{
		"token_url":%q,"tls_skip_verify":"true","client_id":"named-anyway",
		"secret_spec":%q,"secret_field":"client_secret"}}`,
		"http://127.0.0.1:1"+oaTokenPath, secretSpec)

	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, body)
	if status < 400 {
		t.Fatalf("a chained source naming a client was accepted (status %d): %s", status, resp)
	}
	if !strings.Contains(string(resp), "client_id") ||
		!strings.Contains(string(resp), "must be omitted when secret_spec is set") {
		t.Errorf("rejection did not name the offending key: %s", resp)
	}
}

// TestOAuth2_KeylessSourceRejectsTheConsentFlow pins the other create-time rule: the
// consent steps that seal an authorization_code grant run on the system backend with no
// caller, so they have no identity to fetch the chained pair as. Accepting the spec would
// defer that to a connect attempt that could only fail.
func TestOAuth2_KeylessSourceRejectsTheConsentFlow(t *testing.T) {
	ensureEnv(t)

	const (
		source     = "fc-oauth2-consent-rejected-src"
		spec       = "fc-oauth2-consent-rejected"
		secretSpec = "fc-oauth2-consent-secret"
	)

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+secretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	if status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+secretSpec, leaderPort, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret",
			"secret_path":"`+oaPerAgentKeyPath+`/`+oaAgentA+`",
			"subject_token_source":"agent_identity"}}`); status >= 400 {
		t.Fatalf("create the referenced spec (status %d): %s", status, resp)
	}

	if status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+source, leaderPort, fmt.Sprintf(`{
		"type":"oauth2","config":{
			"token_url":%q,"auth_url":%q,"tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":"client_secret"}}`,
		"http://127.0.0.1:1"+oaTokenPath, "http://127.0.0.1:1/authorize", secretSpec)); status >= 400 {
		t.Fatalf("create the keyless source (status %d): %s", status, resp)
	}

	status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+spec, leaderPort, `{
		"type":"oauth_bearer_token","source":"`+source+`","config":{
			"auth_method":"authorization_code"}}`)
	if status < 400 {
		t.Fatalf("a consent-gated spec on a chained source was accepted (status %d): %s", status, resp)
	}
	if !strings.Contains(string(resp), "auth_method=client_credentials only") {
		t.Errorf("rejection did not name the restriction: %s", resp)
	}
}
