//go:build e2e

// Package msgraph drives delegated Microsoft Graph access end to end: an agent
// presenting a user's token, Warden exchanging it on-behalf-of the user at a fake
// Entra, and the resulting token reaching the upstream — plus the refusals and
// challenges the msgraph provider answers itself.
//
// Two mounts share one on_behalf_of spec. The token's journey to an upstream is
// observed through an mcp mount pointed at an in-process stub: the msgraph
// provider only ever talks to a real Graph host, by design. The msgraph mount is
// driven only where it answers before any upstream is contacted — a refused
// $batch, a claims challenge, a missing consent.
package msgraph

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const (
	oboTenant = "00000000-0000-0000-0000-0000000000e3"
	oboClient = "11111111-1111-1111-1111-1111111111e3"

	userAuthMount = "obo-user-jwt"
	userAuthRole  = "obo-user"
	sourceName    = "e2e-obo-azure"
	specName      = "e2e-obo-graph"
	agentRole     = "e2e-obo-agent"
	policyName    = "e2e-obo-access"
	stubMount     = "obo-stub"    // mcp provider pointed at the stub upstream
	graphMount    = "obo-msgraph" // the msgraph provider, refusals only

	// shortStubMount is stubMount with users validated under shortUserRole, whose
	// token lives shortUserTTL: the bound a delegated token must not outlive.
	shortStubMount = "obo-stub-short"
	shortUserRole  = "obo-user-short"
	shortUserTTL   = 4 * time.Second

	// azureMount is the azure provider, to prove it refuses Graph $batch too.
	azureMount = "obo-azure"

	// localGraphMount is the msgraph provider pointed at the stub upstream, which
	// the e2e build allows (provider/msgraph/hosts_e2e.go): link rewriting runs
	// through it end to end.
	localGraphMount = "obo-msgraph-local"

	// The audience an Entra federated identity credential expects; the actor
	// assertion is minted with it when the source names none.
	federationAudience = "api://AzureADTokenExchange"
)

// Entra answers, switched per scenario.
const (
	entraOK int32 = iota
	entraClaims
	entraConsent
)

// claimsChallenge is the claims request the fake Entra demands in entraClaims mode.
const claimsChallenge = `{"access_token":{"acrs":{"essential":true,"value":"c1"}}}`

// oboGrant is one token request the fake Entra received.
type oboGrant struct {
	Path            string
	GrantType       string
	ClientID        string
	Assertion       string
	ClientAssertion string
	AssertionType   string
	RequestedUse    string
	Scope           string
	HasSecret       bool
}

var (
	envOnce    sync.Once
	leaderPort int

	// agentJWT is the agent's token for every request. It is fetched once: the
	// credential cache is keyed by the agent's token as well as the user's, so a
	// fresh agent token per request would make every request a cache miss.
	agentJWT string

	entra     *httptest.Server
	upstream  *httptest.Server
	entraMode atomic.Int32
	issued    atomic.Int64

	mu              sync.Mutex
	grants          []oboGrant
	upstreamBearers []string // Authorization headers the stub upstream received
)

func TestMain(m *testing.M) {
	code := m.Run()
	if leaderPort != 0 {
		teardownBestEffort(leaderPort)
	}
	if entra != nil {
		entra.Close()
	}
	if upstream != nil {
		upstream.Close()
	}
	os.Exit(code)
}

// startEntra stands in for Entra's token endpoint: it records each OBO request and
// answers according to entraMode. Every success carries a distinct access token,
// and the refresh_token Entra returns unasked, which must never surface.
func startEntra() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		grants = append(grants, oboGrant{
			Path:            r.URL.Path,
			GrantType:       r.PostForm.Get("grant_type"),
			ClientID:        r.PostForm.Get("client_id"),
			Assertion:       r.PostForm.Get("assertion"),
			ClientAssertion: r.PostForm.Get("client_assertion"),
			AssertionType:   r.PostForm.Get("client_assertion_type"),
			RequestedUse:    r.PostForm.Get("requested_token_use"),
			Scope:           r.PostForm.Get("scope"),
			HasSecret:       r.PostForm.Has("client_secret"),
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch entraMode.Load() {
		case entraClaims:
			w.WriteHeader(http.StatusBadRequest)
			claims, _ := json.Marshal(claimsChallenge)
			fmt.Fprintf(w, `{"error":"interaction_required","error_description":"AADSTS50079: jane@contoso.com must enroll in MFA\r\nTrace ID: x","error_codes":[50079],"claims":%s}`, claims)
		case entraConsent:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant","suberror":"consent_required","error_codes":[65001]}`)
		default:
			n := issued.Add(1)
			fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"graph-token-%d","refresh_token":"RT-must-not-leak"}`, n)
		}
	}))
}

// startUpstream stands in for Graph: it records the bearer each request carried.
// A listing answers one page with an absolute next link on itself, as Graph does,
// and a request for that next page answers the last one.
func startUpstream() *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamBearers = append(upstreamBearers, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/me/messages") && r.URL.Query().Get("$skiptoken") == "":
			fmt.Fprintf(w, `{"value":[{"id":"1"}],"@odata.nextLink":%q}`, srv.URL+"/v1.0/me/messages?$top=1&$skiptoken=page2")
		case strings.HasSuffix(r.URL.Path, "/me/messages"):
			fmt.Fprintf(w, `{"value":[{"id":"2"}],"page":%q}`, r.URL.Query().Get("$skiptoken"))
		default:
			fmt.Fprint(w, `{"displayName":"stub"}`)
		}
	}))
	return srv
}

// resetRecordings clears what both stubs recorded and sets Entra's answer, so each
// test counts only its own traffic.
func resetRecordings(mode int32) {
	mu.Lock()
	defer mu.Unlock()
	grants, upstreamBearers = nil, nil
	entraMode.Store(mode)
}

func recordedGrants() []oboGrant {
	mu.Lock()
	defer mu.Unlock()
	return append([]oboGrant(nil), grants...)
}

func recordedBearers() []string {
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), upstreamBearers...)
}

// ensureEnv builds the shared environment once for the package: the stubs, the
// user auth mount, the keyless azure source and on_behalf_of spec, the agent
// role, and both provider mounts.
func ensureEnv(t *testing.T) {
	t.Helper()
	envOnce.Do(func() {
		leaderPort = h.GetLeaderPort(t)
		agentJWT = h.GetDefaultJWT(t)
		entra = startEntra()
		upstream = startUpstream()
		setup(t, leaderPort)
	})
	if entra == nil || upstream == nil {
		t.Fatal("the msgraph e2e environment is not available")
	}
}

func mustAPI(t *testing.T, port int, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, port, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

func setup(t *testing.T, port int) {
	t.Helper()
	teardownBestEffort(port)

	// The user leg: Hydra-issued user tokens, on their own auth mount.
	mustAPI(t, port, "POST", "sys/auth/"+userAuthMount, `{"type":"jwt"}`, "mount the user auth method")
	time.Sleep(time.Second)
	mustAPI(t, port, "PUT", "auth/"+userAuthMount+"/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q}`, h.HydraIssuer, h.HydraIssuer),
		"configure the user auth method")
	mustAPI(t, port, "POST", "auth/"+userAuthMount+"/role/"+userAuthRole,
		`{"user_claim":"sub","token_ttl":3600}`, "create the user role")
	mustAPI(t, port, "POST", "auth/"+userAuthMount+"/role/"+shortUserRole,
		fmt.Sprintf(`{"user_claim":"sub","token_ttl":%d}`, int(shortUserTTL.Seconds())), "create the short-lived user role")

	// The keyless source points its token requests at the fake Entra.
	mustAPI(t, port, "POST", "sys/cred/sources/"+sourceName,
		fmt.Sprintf(`{"type":"azure","config":{"auth_method":"oidc_federation","login_endpoint":%q}}`, entra.URL),
		"create the keyless azure source")
	mustAPI(t, port, "POST", "sys/cred/specs/"+specName, `{
		"type":"azure_bearer_token","source":"`+sourceName+`","config":{
			"mint_method":"on_behalf_of",
			"tenant_id":"`+oboTenant+`","client_id":"`+oboClient+`",
			"resource_uri":"https://graph.microsoft.com/",
			"subject_token_source":"user_identity",
			"actor_token_source":"warden_identity"}}`,
		"create the on_behalf_of spec")

	var rules []string
	for _, mount := range []string{stubMount, graphMount, shortStubMount, azureMount, localGraphMount} {
		rules = append(rules, fmt.Sprintf(`path \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\"]\n}`, mount))
	}
	mustAPI(t, port, "POST", "sys/policies/cbp/"+policyName,
		fmt.Sprintf(`{"policy":"%s"}`, strings.Join(rules, `\n`)), "create the policy")
	mustAPI(t, port, "POST", "auth/jwt/role/"+agentRole,
		fmt.Sprintf(`{"token_policies":[%q],"cred_spec_name":%q,"user_claim":"sub","token_ttl":3600}`, policyName, specName),
		"create the agent role")

	userLeg := fmt.Sprintf(`"auto_auth_path":"auth/jwt/","user_auth_path":"auth/%s/","user_auth_role":%q`, userAuthMount, userAuthRole)
	mustAPI(t, port, "POST", "sys/providers/"+stubMount, `{"type":"mcp","description":"stub Graph"}`, "mount the stub provider")
	mustAPI(t, port, "POST", "sys/providers/"+graphMount, `{"type":"msgraph","description":"Microsoft Graph"}`, "mount msgraph")
	time.Sleep(time.Second)
	mustAPI(t, port, "PUT", stubMount+"/config",
		fmt.Sprintf(`{"mcp_url":%q,"tls_skip_verify":true,"timeout":"30s",%s}`, upstream.URL, userLeg),
		"configure the stub provider")
	mustAPI(t, port, "PUT", graphMount+"/config",
		fmt.Sprintf(`{"timeout":"30s",%s}`, userLeg), "configure msgraph")

	shortUserLeg := fmt.Sprintf(`"auto_auth_path":"auth/jwt/","user_auth_path":"auth/%s/","user_auth_role":%q`, userAuthMount, shortUserRole)
	mustAPI(t, port, "POST", "sys/providers/"+shortStubMount, `{"type":"mcp","description":"stub Graph, short-lived users"}`, "mount the short stub provider")
	mustAPI(t, port, "POST", "sys/providers/"+azureMount, `{"type":"azure","description":"Azure"}`, "mount azure")
	mustAPI(t, port, "POST", "sys/providers/"+localGraphMount, `{"type":"msgraph","description":"Microsoft Graph (local stub)"}`, "mount local msgraph")
	time.Sleep(time.Second)
	mustAPI(t, port, "PUT", shortStubMount+"/config",
		fmt.Sprintf(`{"mcp_url":%q,"tls_skip_verify":true,"timeout":"30s",%s}`, upstream.URL, shortUserLeg),
		"configure the short stub provider")
	mustAPI(t, port, "PUT", azureMount+"/config", fmt.Sprintf(`{"timeout":"30s",%s}`, userLeg), "configure azure")
	mustAPI(t, port, "PUT", localGraphMount+"/config",
		fmt.Sprintf(`{"graph_url":%q,"tls_skip_verify":true,"timeout":"30s",%s}`, upstream.URL, userLeg),
		"configure local msgraph")

	// Link rewriting needs Warden's external base, the protected-resource resource_url.
	h.EnableProtectedResourceMetadata(t, port)
}

func teardownBestEffort(port int) {
	token := rootTokenBestEffort()
	if token == "" {
		return
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed e2e cert
	}
	del := func(path string) {
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/%s", h.NodeURL(port), path), nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Warden-Token", token)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	for _, mount := range []string{stubMount, graphMount, shortStubMount, azureMount, localGraphMount} {
		del("sys/providers/" + mount)
	}
	del("auth/jwt/role/" + agentRole)
	del("sys/policies/cbp/" + policyName)
	del("sys/cred/specs/" + specName)
	del("sys/cred/sources/" + sourceName)
	del("sys/auth/" + userAuthMount)
}

func rootTokenBestEffort() string {
	b, err := os.ReadFile(filepath.Join(h.E2EDir(), ".root_token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// gatewayGET calls a mount's gateway as agentRole, with the agent's JWT out of
// band and the user's token in Authorization.
func gatewayGET(t *testing.T, mount, apiPath, userToken string) (int, []byte, http.Header) {
	t.Helper()
	return gatewayCall(t, http.MethodGet, mount, apiPath, userToken, "")
}

func gatewayCall(t *testing.T, method, mount, apiPath, userToken, body string) (int, []byte, http.Header) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s/role/%s/gateway/%s", h.NodeURL(leaderPort), mount, agentRole, strings.TrimPrefix(apiPath, "/"))
	if _, err := url.Parse(u); err != nil {
		t.Fatalf("bad gateway URL %q: %v", u, err)
	}
	hdrs := map[string]string{"X-Warden-Agent-Token": agentJWT}
	if userToken != "" {
		hdrs["Authorization"] = "Bearer " + userToken
	}
	status, respBody, headers := h.DoRequestWithResponseHeaders(t, method, u, hdrs, body)
	return status, respBody, http.Header(headers)
}

// userToken is a fresh user token: a new token is a new cache key, so each test
// starts from a mint rather than a cached credential.
func userToken(t *testing.T) string {
	t.Helper()
	return h.UserJWT(t)
}
