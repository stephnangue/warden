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

// token_exchange is the source that mints nothing of its own: it trades the caller's
// own identity for a downstream bearer at an RFC 8693 endpoint. What a row here can
// prove that a driver unit test cannot is that the subject travelling to the STS is a
// real inbound agent token, carried the whole way from the request that asked for the
// credential.
//
// These rows drive the keyless arrangement, where the client credential Warden
// authenticates with is itself fetched per mint. The source stores neither half of it,
// so nothing about the source names a client — which is what lets one source, one spec
// and one role front a different OAuth client for every agent.

const (
	// One templated path, one client credential per agent beneath it. Each is a
	// DIFFERENT OAuth client: id and secret both vary, which is the shape the
	// pair-in-payload design exists to allow and a shared client_id could not express.
	txPerAgentKeyPath = "e2e/fc-tx-agent-clients"

	txPerAgentSecretSpec = "fc-tx-per-agent-client"
	txPerAgentSource     = "fc-tx-per-agent-src"
	txPerAgentSpec       = "fc-tx-per-agent-cred"
	txPerAgentRole       = "fc-tx-per-agent"

	txAgentA = "e2e-agent"
	txAgentB = "e2e-pipeline"

	txTokenPath = "/oauth2/token"

	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// txClient is one tenant's OAuth client, as the stand-in STS sees it.
type txClient struct {
	id, secret, bearer string
}

// txGrant is one exchange the STS was asked to perform.
type txGrant struct {
	clientID, clientSecret, subjectToken, grantType string
}

// serveTokenExchangeSTS stands in for the identity provider performing the exchange. It
// issues a bearer only to a client whose id AND secret match one it knows, and hands
// back that client's own token.
//
// Matching on the pair is the point: a build that took the id from source config and the
// secret from the chain would present a mismatched pair here and be refused. The subject
// token is recorded rather than verified — this is a stand-in, and what the row is about
// is which client authenticated, not whether Hydra's signature checks out.
//
// It is its own listener rather than a handler on the shared recording upstream: the STS
// is a different host from the API being proxied, and displacing that upstream would
// change what every other row in the package is talking to.
func serveTokenExchangeSTS(t *testing.T, clients []txClient) (*httptest.Server, func() []txGrant) {
	t.Helper()

	var (
		mu     sync.Mutex
		grants []txGrant
	)

	mux := http.NewServeMux()
	mux.HandleFunc(txTokenPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		grants = append(grants, txGrant{
			clientID:     r.Form.Get("client_id"),
			clientSecret: r.Form.Get("client_secret"),
			subjectToken: r.Form.Get("subject_token"),
			grantType:    r.Form.Get("grant_type"),
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
	return srv, func() []txGrant {
		mu.Lock()
		defer mu.Unlock()
		return append([]txGrant(nil), grants...)
	}
}

// setupTokenExchangePerAgentChain parks one client credential per agent under the
// templated path, then builds a single source and a single spec that both agents mint
// through.
//
// The consuming mount is the one restEnv already stood up: what varies between the two
// agents is the credential, not the provider, and a mount of its own would only add
// setup the rows do not exercise.
func setupTokenExchangePerAgentChain(t *testing.T, stsURL string, clientByAgent map[string]txClient) {
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
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+txPerAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+txPerAgentSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+txPerAgentSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+txPerAgentSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// Both halves in one payload, because they authenticate as a pair.
	for agent, c := range clientByAgent {
		path := "secret/data/" + txPerAgentKeyPath + "/" + agent
		body := `{"data":{"client_id":"` + c.id + `","client_secret":"` + c.secret + `"}}`
		if status, resp := h.VaultDirectRequest(t, "POST", path, body); status >= 400 {
			t.Fatalf("parking %s's client credential (status %d): %s", agent, status, resp)
		}
	}

	// The templated referenced spec. It must be session-pinned — a chained secret is
	// minted as the caller, which is also what makes {{agent.sub}} resolve to the agent
	// asking rather than to whoever warmed the cache first.
	mustWrite("POST", "sys/cred/specs/"+txPerAgentSecretSpec, `{
		"type":"key_value","source":"vault-fed-e2e","config":{
			"mint_method":"kv2_read","kv2_mount":"secret",
			"secret_path":"`+txPerAgentKeyPath+`/{{agent.sub}}",
			"subject_token_source":"agent_identity"}}`,
		"create the templated client-credential spec")

	// One source for every tenant. It holds neither half, so nothing about it names a
	// client. tls_skip_verify because the stand-in listens on loopback over http, which
	// the token_url guard otherwise refuses.
	mustWrite("POST", "sys/cred/sources/"+txPerAgentSource, fmt.Sprintf(`{
		"type":"token_exchange","config":{
			"token_url":%q,"grant":"rfc8693","client_auth":"client_secret_post",
			"tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":"client_secret"}}`,
		stsURL+txTokenPath, txPerAgentSecretSpec),
		"create the per-agent token_exchange source")

	// The consuming spec still declares its own subject: the exchange needs one, and the
	// chained credential authenticates Warden to the STS rather than standing in for the
	// caller.
	mustWrite("POST", "sys/cred/specs/"+txPerAgentSpec, `{
		"type":"oauth_bearer_token","source":"`+txPerAgentSource+`","config":{
			"subject_token_source":"agent_identity",
			"audience":"https://api.internal.example.com"}}`,
		"create the per-agent consuming spec")

	mustWrite("POST", "auth/jwt/role/"+txPerAgentRole, `{
		"token_policies":["`+restEnv.Policy()+`"],"cred_spec_name":"`+txPerAgentSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the shared per-agent role")
}

// TestTokenExchange_PerAgentOAuthClient drives two agents through one source, one spec
// and one role, each authenticating to the STS as its own OAuth client.
//
// The client credential is resolved per mint from a path templated on the calling
// agent, so the id and the secret both vary between the two — and the source that
// fronts them stores neither, which is what lets it front both. A build reading the id
// from config and the secret from the chain presents a mismatched pair and is refused
// by the stand-in; one that shared a bearer across tenants proxies the wrong token.
//
// Two agents, one role, one spec, one source.
func TestTokenExchange_PerAgentOAuthClient(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)

	clientA := txClient{id: "tx-app-for-agent-a", secret: "tx-secret-a-not-real", bearer: "tx-bearer-for-agent-a"}
	clientB := txClient{id: "tx-app-for-agent-b", secret: "tx-secret-b-not-real", bearer: "tx-bearer-for-agent-b"}

	sts, grants := serveTokenExchangeSTS(t, []txClient{clientA, clientB})
	setupTokenExchangePerAgentChain(t, sts.URL, map[string]txClient{
		txAgentA: clientA,
		txAgentB: clientB,
	})
	upstream.Reset()

	mintAs := func(clientID, secret string) {
		t.Helper()
		status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
			AgentToken: h.GetJWT(t, clientID, secret),
			Role:       txPerAgentRole,
		})
		if status != 200 {
			t.Fatalf("%s got status %d: %s", clientID, status, body)
		}
	}

	// A first, warming every cache on the way, so B has something to be wrongly served
	// if any of them collapses the two.
	mintAs(txAgentA, "agent-secret")
	mintAs(txAgentB, "pipeline-secret")

	// Each agent's exchange presented its own client — the pair reaching the STS
	// together is what the source cannot supply and the payload must.
	got := grants()
	if len(got) != 2 {
		t.Fatalf("STS received %d exchanges, want one per agent", len(got))
	}
	for i, want := range []txClient{clientA, clientB} {
		if got[i].grantType != grantTypeTokenExchange {
			t.Errorf("exchange %d used grant_type %q, want %q", i, got[i].grantType, grantTypeTokenExchange)
		}
		if got[i].clientID != want.id {
			t.Errorf("exchange %d presented client_id %q, want %q", i, got[i].clientID, want.id)
		}
		if got[i].clientSecret != want.secret {
			t.Errorf("exchange %d presented client_secret %q, want %q", i, got[i].clientSecret, want.secret)
		}
		// The subject is the agent's own inbound token, not anything the source holds.
		if got[i].subjectToken == "" {
			t.Errorf("exchange %d carried no subject_token", i)
		}
	}
	// And the two subjects differ, which is what makes them two exchanges rather than
	// one served twice.
	if got[0].subjectToken == got[1].subjectToken {
		t.Error("both exchanges carried the same subject_token; the agents were not told apart")
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

// TestTokenExchange_KeylessSourceRejectsAnInlineClientID pins the create-time half of
// the rule the row above depends on: a source that fetches its client credential may not
// also name a client, since an id from config beside a secret from the chain would
// present a pair belonging to no one.
func TestTokenExchange_KeylessSourceRejectsAnInlineClientID(t *testing.T) {
	ensureEnv(t)

	const (
		name       = "fc-tx-inline-id-rejected"
		secretSpec = "fc-tx-inline-id-secret"
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
			"secret_path":"`+txPerAgentKeyPath+`/`+txAgentA+`",
			"subject_token_source":"agent_identity"}}`); status >= 400 {
		t.Fatalf("create the referenced spec (status %d): %s", status, resp)
	}

	body := fmt.Sprintf(`{"type":"token_exchange","config":{
		"token_url":%q,"grant":"rfc8693","client_auth":"client_secret_post",
		"tls_skip_verify":"true","client_id":"named-anyway",
		"secret_spec":%q,"secret_field":"client_secret"}}`,
		"http://127.0.0.1:1"+txTokenPath, secretSpec)

	status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, body)
	if status < 400 {
		t.Fatalf("a chained source naming a client was accepted (status %d): %s", status, resp)
	}
	if !strings.Contains(string(resp), "client_id") ||
		!strings.Contains(string(resp), "must be omitted when secret_spec is set") {
		t.Errorf("rejection did not name the offending key: %s", resp)
	}
}
