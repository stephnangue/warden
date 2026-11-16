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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
		h.RevokeRole(t, leaderPort, "auth/jwt/", txPerAgentRole)
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

	h.GrantRole(t, leaderPort, "auth/jwt/", txPerAgentRole, h.Role{
		Policies: []string{restEnv.Policy()},
		CredSpec: txPerAgentSpec,
	}, nil)
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

// grant=id_jag runs the Identity Assertion JWT Authorization Grant
// (draft-ietf-oauth-identity-assertion-authz-grant-06) in one mint: the subject is
// traded at the IdP for an ID-JAG, which is redeemed at the resource authorization
// server for the bearer the upstream receives. The stand-ins below hold Warden to the
// draft's rules for each side, and refuse anything beyond what the draft's requests
// carry.
const (
	// The IdP knows Warden by the subject token's audience: the IdP checks that the ID
	// token it is handed was issued to the client asking (§4.3.3), and the e2e agent and
	// user tokens are issued for warden-e2e.
	idjagIdPClient      = "warden-e2e"
	idjagIdPSecret      = "idjag-idp-secret-not-real"
	idjagResourceClient = "warden-at-resource"
	idjagResourceSecret = "idjag-resource-secret-not-real"

	idjagSource = "fc-idjag-src"
	idjagSpec   = "fc-idjag-cred"
	idjagRole   = "fc-idjag"

	idjagScope    = "todos.read"
	idjagResource = "https://api.resource.example/"

	tokenTypeIDJAG   = "urn:ietf:params:oauth:token-type:id-jag"
	tokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	grantJWTBearer   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// idjagServers are an IdP and a resource authorization server that share the key the
// IdP signs ID-JAGs with, and record what each was sent.
type idjagServers struct {
	idp, ras *httptest.Server
	key      *rsa.PrivateKey

	mu        sync.Mutex
	idpForms  []url.Values
	rasForms  []url.Values
	spentJTIs map[string]bool
	jtis      []string // every ID-JAG jti the resource server received, in order
	// loseFirst makes the resource server spend the first ID-JAG it is sent and then
	// answer 500, as one whose answer was lost.
	loseFirst bool
	// pkjwtClients are the clients a server accepts a client assertion from. The
	// assertion's signature is not what these rows are about, so it is not verified;
	// its issuer and audience are.
	pkjwtClients map[string]bool
}

// serveIDJAG starts the two servers. The IdP accepts idjagIdPClient by secret, and any
// client in pkjwtClients by assertion; it writes idjagResourceClient into every ID-JAG
// as the client that may redeem it (§3.1). The resource server accepts
// idjagResourceClient by secret, and pkjwtClients by assertion.
func serveIDJAG(t *testing.T, loseFirst bool, pkjwtClients ...string) *idjagServers {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate the ID-JAG signing key: %v", err)
	}
	s := &idjagServers{key: key, spentJTIs: map[string]bool{}, loseFirst: loseFirst, pkjwtClients: map[string]bool{}}
	for _, c := range pkjwtClients {
		s.pkjwtClients[c] = true
	}
	s.ras = httptest.NewServer(http.HandlerFunc(s.redeem))
	s.idp = httptest.NewServer(http.HandlerFunc(s.issue))
	t.Cleanup(func() { s.idp.Close(); s.ras.Close() })
	return s
}

// rasIssuer is the resource authorization server's issuer identifier: what an ID-JAG
// request names as its audience, and what an ID-JAG for it names as its aud.
func (s *idjagServers) rasIssuer() string { return s.ras.URL }

// authenticated returns the client a token request authenticated as, or "".
func (s *idjagServers) authenticated(r *http.Request, secrets map[string]string, endpoint string) string {
	id := r.Form.Get("client_id")
	if assertion := r.Form.Get("client_assertion"); assertion != "" {
		claims := jwtPart(assertion, 1)
		if s.pkjwtClients[id] && claims["iss"] == id && claims["sub"] == id && claims["aud"] == endpoint {
			return id
		}
		return ""
	}
	if want, ok := secrets[id]; ok && r.Form.Get("client_secret") == want {
		return id
	}
	return ""
}

// issue is the IdP's token endpoint, answering ID-JAG requests (§4.3).
func (s *idjagServers) issue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.idpForms = append(s.idpForms, r.PostForm)
	s.mu.Unlock()

	refuse := func(status int, code, why string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": why})
	}
	client := s.authenticated(r, map[string]string{idjagIdPClient: idjagIdPSecret}, s.idp.URL)
	switch {
	case client == "":
		refuse(http.StatusUnauthorized, "invalid_client", "the IdP authenticates every client asking for an ID-JAG")
		return
	case r.Form.Get("grant_type") != grantTypeTokenExchange || r.Form.Get("requested_token_type") != tokenTypeIDJAG:
		refuse(http.StatusBadRequest, "invalid_request", "not an ID-JAG request")
		return
	case r.Form.Get("subject_token_type") != tokenTypeIDToken:
		refuse(http.StatusBadRequest, "invalid_request", "the subject must be an ID token")
		return
	case len(r.Form["audience"]) != 1:
		refuse(http.StatusBadRequest, "invalid_request", "exactly one audience")
		return
	case r.Form.Get("audience") != s.rasIssuer():
		refuse(http.StatusBadRequest, "invalid_target", "no trust relationship with that audience")
		return
	}
	subject, subjectHeader := jwtPart(r.Form.Get("subject_token"), 1), jwtPart(r.Form.Get("subject_token"), 0)
	switch {
	case subjectHeader["typ"] == "at+jwt" || subjectHeader["typ"] == "oauth-id-jag+jwt":
		refuse(http.StatusBadRequest, "invalid_request", "the subject token was issued for another purpose")
		return
	case !audienceIncludes(subject["aud"], client):
		refuse(http.StatusBadRequest, "invalid_request", "the subject token was issued to another client")
		return
	}

	claims := map[string]any{
		"iss": s.idp.URL, "sub": subject["sub"], "aud": s.rasIssuer(),
		"client_id": idjagResourceClient, "jti": randomID(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if scope := r.Form.Get("scope"); scope != "" {
		claims["scope"] = scope
	}
	// A single resource is a string, several a list (§3.1).
	switch resources := r.Form["resource"]; len(resources) {
	case 0:
	case 1:
		claims["resource"] = resources[0]
	default:
		claims["resource"] = resources
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      signRS256(s.key, map[string]any{"alg": "RS256", "typ": "oauth-id-jag+jwt"}, claims),
		"issued_token_type": tokenTypeIDJAG,
		"token_type":        "N_A",
		"expires_in":        300,
	})
}

// redeem is the resource authorization server's token endpoint, redeeming ID-JAGs
// (§4.4).
func (s *idjagServers) redeem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.rasForms = append(s.rasForms, r.PostForm)
	s.mu.Unlock()

	refuse := func(status int, code, why string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": why})
	}
	// The request carries the grant, the assertion, the scope it asks for and the client
	// authentication, and nothing else: resources come from the ID-JAG.
	for key := range r.PostForm {
		switch key {
		case "grant_type", "assertion", "scope", "client_id", "client_secret", "client_assertion", "client_assertion_type":
		default:
			refuse(http.StatusBadRequest, "invalid_request", "unexpected parameter "+key)
			return
		}
	}
	client := s.authenticated(r, map[string]string{idjagResourceClient: idjagResourceSecret}, s.ras.URL)
	if client == "" {
		refuse(http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	// The ID-JAG's issuer and expiry are left unchecked: only the IdP holds the key its
	// signature is checked against, and every ID-JAG here is minutes old.
	jag := r.Form.Get("assertion")
	header, claims := jwtPart(jag, 0), jwtPart(jag, 1)
	switch {
	case r.Form.Get("grant_type") != grantJWTBearer:
		refuse(http.StatusBadRequest, "unsupported_grant_type", "jwt-bearer only")
		return
	case header["typ"] != "oauth-id-jag+jwt" || !verifyRS256(&s.key.PublicKey, jag):
		refuse(http.StatusBadRequest, "invalid_grant", "not an ID-JAG this server trusts")
		return
	case claims["aud"] != s.rasIssuer():
		refuse(http.StatusBadRequest, "invalid_grant", "the ID-JAG is for another server")
		return
	case claims["client_id"] != client:
		refuse(http.StatusBadRequest, "invalid_grant", "the ID-JAG names another client")
		return
	case !scopeWithin(r.Form.Get("scope"), claims["scope"]):
		refuse(http.StatusBadRequest, "invalid_scope", "more scope than the ID-JAG carries")
		return
	}

	jti, _ := claims["jti"].(string)
	s.mu.Lock()
	spent, first := s.spentJTIs[jti], len(s.jtis) == 0
	s.spentJTIs[jti] = true
	s.jtis = append(s.jtis, jti)
	s.mu.Unlock()
	switch {
	case spent:
		refuse(http.StatusBadRequest, "invalid_grant", "the ID-JAG has been used")
		return
	case first && s.loseFirst:
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Like the xaa.dev reference implementation, the token carries only the scope the
	// redemption asks for, not the ID-JAG's: a redemption that names none gets a token
	// with none.
	scope := r.Form.Get("scope")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("idjag:%s|%v", scope, claims["resource"]),
		"token_type":   "Bearer",
		"expires_in":   600,
		"scope":        scope,
	})
}

// scopeWithin reports whether every scope in asked is in granted, an ID-JAG's scope
// claim.
func scopeWithin(asked string, granted any) bool {
	have, _ := granted.(string)
	for _, s := range strings.Fields(asked) {
		if !slices.Contains(strings.Fields(have), s) {
			return false
		}
	}
	return true
}

func (s *idjagServers) forms() (idp, ras []url.Values, jtis []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.idpForms...), append([]url.Values(nil), s.rasForms...), append([]string(nil), s.jtis...)
}

// setupIDJAG builds an id_jag source with sourceConfig over the base below, a spec with
// specConfig, and a role on restEnv's mount minting through them. The servers listen on
// loopback over http, which the token_url guard refuses without tls_skip_verify.
func setupIDJAG(t *testing.T, s *idjagServers, sourceConfig, specConfig map[string]string) {
	t.Helper()
	clear := func() {
		h.RevokeRole(t, leaderPort, "auth/jwt/", idjagRole)
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+idjagSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+idjagSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	source := map[string]string{
		"grant": "id_jag", "token_url": s.idp.URL, "resource_token_url": s.ras.URL, "tls_skip_verify": "true",
		"client_auth": "client_secret_post", "client_id": idjagIdPClient, "client_secret": idjagIdPSecret,
		"resource_client_auth": "client_secret_post", "resource_client_id": idjagResourceClient, "resource_client_secret": idjagResourceSecret,
	}
	for k, v := range sourceConfig {
		if v == "" {
			delete(source, k)
			continue
		}
		source[k] = v
	}
	if status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+idjagSource, leaderPort, mustJSON(t, map[string]any{
		"type": "token_exchange", "config": source,
	})); status >= 400 {
		t.Fatalf("create the id_jag source (status %d): %s", status, resp)
	}

	spec := map[string]string{
		"subject_token_source": "agent_identity", "audience": s.rasIssuer(),
		"scope": idjagScope, "resources": idjagResource,
	}
	for k, v := range specConfig {
		spec[k] = v
	}
	if status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+idjagSpec, leaderPort, mustJSON(t, map[string]any{
		"type": "oauth_bearer_token", "source": idjagSource, "config": spec,
	})); status >= 400 {
		t.Fatalf("create the id_jag spec (status %d): %s", status, resp)
	}
	h.GrantRole(t, leaderPort, "auth/jwt/", idjagRole, h.Role{Policies: []string{restEnv.Policy()}, CredSpec: idjagSpec}, nil)
}

// TestIDJAG_EachLegAsTheDraftAsks drives one agent request through an ID-JAG exchange.
// The IdP is asked for an ID-JAG with the scope and resource it decides on, as the
// client the subject token was issued to; the resource authorization server is sent
// that ID-JAG and nothing else, by the client the ID-JAG names; the upstream receives
// what the redemption returned; and the audit names the agent, both clients, the
// scope issued and the ID-JAG redeemed.
//
// The subject here is the e2e agent's Hydra token, labelled id_token: what the row
// proves is the shape of the two requests, not that Hydra issues ID tokens.
func TestIDJAG_EachLegAsTheDraftAsks(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)
	s := serveIDJAG(t, false)
	setupIDJAG(t, s, nil, nil)

	probe := h.ProbePath("idjag")
	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Role:       idjagRole,
		Path:       probe,
	})
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}

	idp, ras, _ := s.forms()
	if len(idp) != 1 || len(ras) != 1 {
		t.Fatalf("the IdP was asked %d times and the resource server %d, want once each", len(idp), len(ras))
	}
	if got := jwtPart(idp[0].Get("subject_token"), 1)["sub"]; got != txAgentA {
		t.Errorf("the ID-JAG request's subject is %v, want the agent %s", got, txAgentA)
	}
	if got := idp[0].Get("scope"); got != idjagScope {
		t.Errorf("the ID-JAG request carried scope %q, want %q", got, idjagScope)
	}
	if got := idp[0]["resource"]; len(got) != 1 || got[0] != idjagResource {
		t.Errorf("the ID-JAG request carried resources %v, want [%s] sent unchanged", got, idjagResource)
	}
	if got := ras[0].Get("client_id"); got != idjagResourceClient {
		t.Errorf("the redemption authenticated as %q, want the resource client %q", got, idjagResourceClient)
	}
	// The stand-in, like xaa.dev, grants only the scope a redemption asks for, so the
	// bearer below is scoped only because the redemption named what the IdP granted.
	if got := ras[0].Get("scope"); got != idjagScope {
		t.Errorf("the redemption asked for scope %q, want the granted %q", got, idjagScope)
	}
	if ras[0].Get("client_secret") == idjagIdPSecret {
		t.Error("the IdP's client secret reached the resource authorization server")
	}

	want := fmt.Sprintf("Token idjag:%s|%s", idjagScope, idjagResource)
	if injected := injectedBearers(); len(injected) != 1 || injected[0] != want {
		t.Errorf("the upstream received %v, want [%s]", injected, want)
	}

	// The credential's audit names whom it was minted for, the client each leg
	// authenticated as, the scope issued and the ID-JAG redeemed. Audit writes trail
	// the response, so the entry is waited for.
	node := h.NodeNumberForPort(leaderPort)
	var md map[string]string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && md == nil; {
		for _, e := range h.ReadAuditEntries(t, node, probe) {
			if e.Response != nil && e.Response.Credential != nil {
				md = e.Response.Credential.Metadata
			}
		}
		if md == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if md == nil {
		t.Fatal("no audited credential for the request")
	}
	redeemedJTI, _ := jwtPart(ras[0].Get("assertion"), 1)["jti"].(string)
	if redeemedJTI == "" {
		t.Fatal("the redeemed ID-JAG carries no jti")
	}
	for key, want := range map[string]string{
		"subject": txAgentA, "client_id": idjagIdPClient, "resource_client_id": idjagResourceClient,
		"scope": idjagScope, "id_jag_jti": redeemedJTI,
	} {
		if md[key] != want {
			t.Errorf("audited %s = %q, want %q", key, md[key], want)
		}
	}
	h.AssertAuditUser(t, leaderPort, probe, "")
}

// injectedBearers are the credentials the upstream received under restEnv's header.
func injectedBearers() []string {
	var injected []string
	for _, req := range upstream.Requests() {
		if got := req.Header.Get("X-Custom-Auth"); got != "" {
			injected = append(injected, got)
		}
	}
	return injected
}

// TestIDJAG_RetriedRedemptionRedeemsANewIDJAG: the resource authorization server spends
// the first ID-JAG and loses its answer. The retry must not resend that ID-JAG, which
// the server would refuse, but redeem a new one.
func TestIDJAG_RetriedRedemptionRedeemsANewIDJAG(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)
	s := serveIDJAG(t, true)
	setupIDJAG(t, s, nil, nil)

	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Role:       idjagRole,
	})
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	idp, _, jtis := s.forms()
	if len(idp) != 2 {
		t.Errorf("the IdP issued %d ID-JAGs, want 2: one lost, one redeemed", len(idp))
	}
	if len(jtis) != 2 || jtis[0] == jtis[1] {
		t.Errorf("the resource server received ID-JAGs %v, want two different ones", jtis)
	}
}

// TestIDJAG_WritesRefuseAnUnauthenticatedOrSharedSecretClient: a public client, which
// the draft forbids (the IdP must authenticate the client), and a secret-based client
// that would present the IdP's secret at the resource authorization server, which
// Warden forbids, are refused when the source is written.
func TestIDJAG_WritesRefuseAnUnauthenticatedOrSharedSecretClient(t *testing.T) {
	ensureEnv(t)
	const name = "fc-idjag-refused"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "") })

	for _, tc := range []struct {
		name   string
		config map[string]string
		want   string
	}{
		{"a public client", map[string]string{"client_auth": "none"}, "client_auth=none cannot be used with grant=id_jag"},
		{"a secret with no resource client", map[string]string{
			"client_auth": "client_secret_post", "client_id": idjagIdPClient, "client_secret": idjagIdPSecret,
		}, "leg 2 would otherwise send the IdP's client secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]string{
				"grant": "id_jag", "token_url": "http://127.0.0.1:1/token", "resource_token_url": "http://127.0.0.1:2/token",
				"tls_skip_verify": "true",
			}
			for k, v := range tc.config {
				config[k] = v
			}
			status, resp := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort, mustJSON(t, map[string]any{
				"type": "token_exchange", "config": config,
			}))
			if status < 400 {
				t.Fatalf("the source was accepted (status %d): %s", status, resp)
			}
			if !strings.Contains(string(resp), tc.want) {
				t.Errorf("the refusal does not say %q: %s", tc.want, resp)
			}
		})
	}
}

// TestIDJAG_TheIDJAGNamesTheClientThatRedeemsIt: a source that authenticates leg 2 as
// its IdP client, where the resource authorization server knows another client, is
// refused there with invalid_grant: the ID-JAG names the resource server's client, not
// the one presenting it (§4.4.1). Nothing reaches the upstream.
func TestIDJAG_TheIDJAGNamesTheClientThatRedeemsIt(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)
	s := serveIDJAG(t, false, idjagIdPClient)
	setupIDJAG(t, s, map[string]string{
		"client_auth": "private_key_jwt", "client_secret": "", "private_key": rsaKeyPEM(t),
		"resource_client_auth": "", "resource_client_id": "", "resource_client_secret": "",
	}, nil)

	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Role:       idjagRole,
	})
	// An upstream refusal of the credential is a 403 to the caller.
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", status, body)
	}
	idp, ras, _ := s.forms()
	if len(ras) != 1 || ras[0].Get("client_id") != idjagIdPClient {
		t.Fatalf("the resource server saw %v, want one redemption by %q", ras, idjagIdPClient)
	}
	if len(idp) != 1 {
		t.Errorf("the IdP issued %d ID-JAGs, want 1: a refused one is not retried", len(idp))
	}
	if !strings.Contains(string(body), "refused the ID-JAG") {
		t.Errorf("the failure does not name the refused ID-JAG: %s", body)
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("the upstream received %d requests, want none", n)
	}
}

// TestIDJAG_TheUserIsTheSubject: with subject_token_source=user_identity, the ID-JAG is
// for the user whose token rides beside the agent's, not for the agent.
func TestIDJAG_TheUserIsTheSubject(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, restEnv)
	s := serveIDJAG(t, false)
	setupIDJAG(t, s, nil, map[string]string{"subject_token_source": "user_identity"})

	user := h.FullChainUserJWT(t)
	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentToken: h.GetJWT(t, txAgentA, "agent-secret"),
		Bearer:     user,
		Role:       idjagRole,
	})
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	idp, _, _ := s.forms()
	if len(idp) != 1 {
		t.Fatalf("the IdP was asked %d times, want once", len(idp))
	}
	if got, want := jwtPart(idp[0].Get("subject_token"), 1)["sub"], jwtPart(user, 1)["sub"]; got != want {
		t.Errorf("the ID-JAG request's subject is %v, want the user %v", got, want)
	}
	if injected := injectedBearers(); len(injected) != 1 {
		t.Errorf("the upstream received %v, want the one redeemed bearer", injected)
	}
}

// jwtPart decodes one part of a compact JWT (0 header, 1 claims) without verifying it,
// or returns an empty map.
func jwtPart(token string, i int) map[string]any {
	parts := strings.Split(token, ".")
	out := map[string]any{}
	if len(parts) < 2 {
		return out
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// audienceIncludes reports whether a JWT aud claim, a string or a list, names want.
func audienceIncludes(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if v == want {
				return true
			}
		}
	}
	return false
}

func signRS256(key *rsa.PrivateKey, header, claims map[string]any) string {
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func verifyRS256(key *rsa.PublicKey, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func rsaKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate a client key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode the client key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode a request body: %v", err)
	}
	return string(raw)
}
