//go:build e2e

package fullchain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// openai stands for the default token extractor — no native channel, no scheme
// dispatch — paired with the credential extractor that has the most positive
// branches. Because its inbound side is the plain case, it is also what the
// cross-cutting rows in chain_test.go use as their carrier.

// Deliberately carrying no "sk-" prefix. Nothing in the chain parses the shape
// of a credential — it is copied from the spec to the upstream header verbatim —
// so a realistic prefix would buy no coverage while making every one of these
// files trip a secret scanner. Keep test credentials unmistakably synthetic.
const (
	openaiKey     = "fc-openai-not-a-real-key"
	openaiOrg     = "fc-e2e-organization"
	openaiProject = "fc-e2e-project"
)

// Each optional field needs its own spec, because a role binds exactly one —
// hence the variants rather than one spec mutated between rows.
//
// The apikey source with credential_fields is the documented shape for a
// credential carrying more than a key, and the only one that carries adjuncts:
// api_key owns exactly one field, and everything beside it travels because the
// source names it. Four specs share one declaration, which is the point of
// putting it on the source.
var openaiEnv = h.ProviderEnv{
	Mount:        "fc-openai",
	Type:         "openai",
	URLKey:       "openai_url",
	CredType:     "api_key",
	SourceType:   "apikey",
	SourceConfig: map[string]string{"credential_fields": "organization_id,project_id"},
	CredConfig:   map[string]string{"api_key": openaiKey},
	Variants: map[string]map[string]string{
		"org":  {"api_key": openaiKey, "organization_id": openaiOrg},
		"proj": {"api_key": openaiKey, "project_id": openaiProject},
		"both": {"api_key": openaiKey, "organization_id": openaiOrg, "project_id": openaiProject},
	},
}

// TestOpenAI_OptionalHeaderCombinations covers every positive branch of the
// credential extractor with the most of them: a bearer key plus two headers that
// appear only when their field is set. An extractor that emitted an empty header
// instead of omitting it would still return the right key, so the absent
// assertions are the point.
func TestOpenAI_OptionalHeaderCombinations(t *testing.T) {
	ensureEnv(t)

	auth := "Bearer " + openaiKey
	cases := []struct {
		name   string
		role   string
		want   map[string]string
		absent []string
	}{
		{
			name:   "key only",
			role:   openaiEnv.CertRole(),
			want:   map[string]string{"Authorization": auth},
			absent: []string{"OpenAI-Organization", "OpenAI-Project"},
		},
		{
			name:   "with organization",
			role:   openaiEnv.VariantRole("org"),
			want:   map[string]string{"Authorization": auth, "OpenAI-Organization": openaiOrg},
			absent: []string{"OpenAI-Project"},
		},
		{
			name:   "with project",
			role:   openaiEnv.VariantRole("proj"),
			want:   map[string]string{"Authorization": auth, "OpenAI-Project": openaiProject},
			absent: []string{"OpenAI-Organization"},
		},
		{
			name: "with both",
			role: openaiEnv.VariantRole("both"),
			want: map[string]string{
				"Authorization":       auth,
				"OpenAI-Organization": openaiOrg,
				"OpenAI-Project":      openaiProject,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.role,
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      tc.want,
				Absent:        h.AlwaysAbsent(tc.absent...),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestOpenAI_ClientSuppliedOrgAndProjectAreStripped checks the headers the
// provider declares it removes. A caller that could set its own organization
// would be choosing which account the minted key bills against.
func TestOpenAI_ClientSuppliedOrgAndProjectAreStripped(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiEnv.VariantRole("both"),
		Headers: map[string]string{
			"OpenAI-Organization": "org-attacker",
			"OpenAI-Project":      "proj-attacker",
		},
	})

	// The mount's own values must win outright — not merge, not append.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"Authorization":       "Bearer " + openaiKey,
			"OpenAI-Organization": openaiOrg,
			"OpenAI-Project":      openaiProject,
		},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// ============================================================================
// Keyless: workload identity federation
// ============================================================================
//
// Every row above spends a static key from an apikey source. These spend none. An
// openai source mints by presenting a Warden-signed assertion to OpenAI's token
// endpoint as an RFC 8693 token exchange and receiving a short-lived bearer, which
// the provider injects in place of the key. What only a full chain shows is the two
// meeting: the assertion Warden signs, the exchange it drives, and the bearer that
// reaches the upstream.
//
// The rows share the static rows' mount: one mount serving a key and a bearer side
// by side is what the extractor's type-switch promises.
//
// Every resource is test-local, as in the anthropic suite: a killed run skips
// t.Cleanup, and a stranded spec would block its source from being deleted.

const (
	openaiWIFSource   = "fc-openai-wif-src"
	openaiWIFProvider = "fc-e2e-identity-provider"
	openaiWIFAudience = "https://warden.e2e.example.com/openai"

	// The stub keys its answer on the service account, so each behaviour a row
	// needs is an account, with its own spec and role.
	openaiWIFAccount         = "fc-e2e-service-account"
	openaiWIFShortAccount    = "fc-e2e-short-lived"
	openaiWIFRejectedAccount = "fc-e2e-rejected"

	// The lifetime the stub gives a short-lived token. The driver ends its lease at
	// half of it — the minute's margin would leave nothing of a token this short —
	// so a row can wait out the lease while the token it was served is still good.
	openaiWIFShortLifetime = 10 * time.Second

	openaiTokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	openaiJWTTokenType       = "urn:ietf:params:oauth:token-type:jwt"
	openaiAccessTokenType    = "urn:ietf:params:oauth:token-type:access_token"
)

// openaiWIFTarget is one spec on the keyless source and the cert role binding it.
type openaiWIFTarget struct{ spec, role, account string }

var (
	openaiWIFMain     = openaiWIFTarget{"fc-openai-wif-cred", "fc-openai-wif-role", openaiWIFAccount}
	openaiWIFShort    = openaiWIFTarget{"fc-openai-wif-short", "fc-openai-wif-short-role", openaiWIFShortAccount}
	openaiWIFRejected = openaiWIFTarget{"fc-openai-wif-rejected", "fc-openai-wif-rejected-role", openaiWIFRejectedAccount}
)

// openaiOAuth stands in for OpenAI's token endpoint. The source's openai_auth_url
// points here and the mount's openai_url at the recording upstream, so the exchange
// and the inference call land on different listeners — as in production, where the
// exchange goes to auth.openai.com and only api.openai.com is proxied.
//
// It refuses what a real endpoint would — another path, a body that is not JSON, a
// grant that is not a token exchange, a subject that is not a JWT, an identity
// provider it does not know — so a driver drifting from the contract fails here
// rather than passing against a stub that takes anything. It does not check the
// assertion's signature: the rows do that against the published JWKS, which is the
// check an upstream actually makes.
var openaiOAuth *httptest.Server

var (
	openaiOAuthOnce   sync.Once
	openaiOAuthMu     sync.Mutex
	openaiOAuthGrants []map[string]string // grants received, in order
	openaiOAuthAt     []time.Time         // when each grant arrived, in the same order
)

// openaiOAuthToken is the bearer the stub issues for the nth grant naming account,
// counted from 1 within a test. Numbering them is what lets a row tell a re-mint
// from a cached token: one value seen twice is one exchange served twice.
func openaiOAuthToken(account string, n int) string {
	return fmt.Sprintf("fc-openai-federated-%s-%d", account, n)
}

func startOpenAIOAuth() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" {
			http.Error(w, "unexpected call "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			http.Error(w, "want a JSON body, got "+ct, http.StatusUnsupportedMediaType)
			return
		}
		var grant map[string]string
		if err := json.NewDecoder(r.Body).Decode(&grant); err != nil {
			http.Error(w, "body is not a JSON object of strings", http.StatusBadRequest)
			return
		}

		openaiOAuthMu.Lock()
		openaiOAuthGrants = append(openaiOAuthGrants, grant)
		openaiOAuthAt = append(openaiOAuthAt, time.Now())
		n := 0
		for _, g := range openaiOAuthGrants {
			if g["service_account_id"] == grant["service_account_id"] {
				n++
			}
		}
		openaiOAuthMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if grant["grant_type"] != openaiTokenExchangeGrant {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		if grant["subject_token_type"] != openaiJWTTokenType || grant["identity_provider_id"] != openaiWIFProvider {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		lifetime := 3600
		switch grant["service_account_id"] {
		case openaiWIFRejectedAccount:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"no service account mapping matched the subject token"}`))
			return
		case openaiWIFShortAccount:
			lifetime = int(openaiWIFShortLifetime / time.Second)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      openaiOAuthToken(grant["service_account_id"], n),
			"issued_token_type": openaiAccessTokenType,
			"token_type":        "Bearer",
			"expires_in":        lifetime,
			"expires_at":        time.Now().Add(time.Duration(lifetime) * time.Second).Unix(),
		})
	}))
}

// ensureOpenAIOAuth starts the stub on first use and clears what it recorded, so a
// row counts only its own exchanges.
func ensureOpenAIOAuth(t *testing.T) {
	t.Helper()
	openaiOAuthOnce.Do(func() { openaiOAuth = startOpenAIOAuth() })
	openaiOAuthMu.Lock()
	defer openaiOAuthMu.Unlock()
	openaiOAuthGrants, openaiOAuthAt = nil, nil
}

func openaiOAuthSeen() []map[string]string {
	openaiOAuthMu.Lock()
	defer openaiOAuthMu.Unlock()
	return append([]map[string]string(nil), openaiOAuthGrants...)
}

// openaiOAuthSeenAt is when each grant arrived — the instant a mint happened, which
// the caller's own clock cannot see.
func openaiOAuthSeenAt() []time.Time {
	openaiOAuthMu.Lock()
	defer openaiOAuthMu.Unlock()
	return append([]time.Time(nil), openaiOAuthAt...)
}

// setupOpenAIWIF builds the keyless source and, per target, a spec and the cert
// role binding it. Order is load-bearing: a source cannot be deleted while a spec
// names it, so cleanup runs roles, then specs, then the source — which also clears
// whatever a killed run left behind before building.
func setupOpenAIWIF(t *testing.T) {
	t.Helper()

	targets := []openaiWIFTarget{openaiWIFMain, openaiWIFShort, openaiWIFRejected}
	clear := func() {
		for _, tg := range targets {
			h.APIRequest(t, "DELETE", "auth/cert/role/"+tg.role, leaderPort, "")
		}
		for _, tg := range targets {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+tg.spec, leaderPort, "")
		}
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+openaiWIFSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// No key anywhere. The source names the identity provider that trusts Warden's
	// issuer, the audience it expects, and where to exchange.
	mustWriteJSON(t, "sys/cred/sources/"+openaiWIFSource, map[string]any{
		"type": "openai",
		"config": map[string]string{
			"auth_method":          "oidc_federation",
			"identity_provider_id": openaiWIFProvider,
			"audience":             openaiWIFAudience,
			"openai_auth_url":      openaiOAuth.URL,
		},
	}, "create the keyless openai source")

	for _, tg := range targets {
		mustWriteJSON(t, "sys/cred/specs/"+tg.spec, map[string]any{
			"type":   "oauth_bearer_token",
			"source": openaiWIFSource,
			"config": map[string]string{
				"subject_token_source": "warden_identity",
				"service_account_id":   tg.account,
			},
		}, "create the keyless spec "+tg.spec)

		mustWriteJSON(t, "auth/cert/role/"+tg.role, map[string]any{
			"allowed_common_names": []string{h.FullChainAgentCN},
			"token_policies":       []string{openaiEnv.Policy()},
			"cred_spec_name":       tg.spec,
			"token_ttl":            3600,
		}, "create the cert role "+tg.role)
	}
}

// TestOpenAI_WIFInjectsTheExchangedBearer is the row the keyless path exists for.
//
// The request carries the user's own JWT in Authorization and an organization and
// project the client chose. The upstream must see none of them: only the bearer
// OpenAI issued for Warden's assertion, and no org/project header, since that
// bearer is bound to its service account's own.
func TestOpenAI_WIFInjectsTheExchangedBearer(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)
	upstream.Reset()

	user := h.FullChainUserJWT(t)
	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       user,
		Role:         openaiWIFMain.role,
		Headers: map[string]string{
			"OpenAI-Organization": "org-attacker",
			"OpenAI-Project":      "proj-attacker",
		},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + openaiOAuthToken(openaiWIFAccount, 1)},
		Absent:        h.AlwaysAbsent("OpenAI-Organization", "OpenAI-Project"),
		UpstreamCalls: 1,
	})

	grants := openaiOAuthSeen()
	if len(grants) != 1 {
		t.Fatalf("token exchanges = %d, want 1", len(grants))
	}
	grant := grants[0]
	for field, want := range map[string]string{
		"grant_type":           openaiTokenExchangeGrant,
		"subject_token_type":   openaiJWTTokenType,
		"identity_provider_id": openaiWIFProvider,
		"service_account_id":   openaiWIFAccount,
	} {
		if got := grant[field]; got != want {
			t.Errorf("exchange %s = %q, want %q", field, got, want)
		}
	}

	// The assertion is checked the way OpenAI checks it: against the issuer's
	// published JWKS, then the claims a service account mapping matches on.
	assertion := grant["subject_token"]
	if assertion == user {
		t.Fatal("the exchange presented the user's JWT; warden_identity must present an assertion Warden minted")
	}
	claims := h.VerifyAssertion(t, leaderPort, assertion)
	if got := claims["iss"]; got != wardenIssuerURL {
		t.Errorf("assertion iss = %v, want %s — an identity provider pins it exactly", got, wardenIssuerURL)
	}
	if got := claims["aud"]; got != openaiWIFAudience {
		t.Errorf("assertion aud = %v, want the source's audience %s", got, openaiWIFAudience)
	}
	if sub, _ := claims["sub"].(string); !strings.HasPrefix(sub, "wid:") {
		t.Errorf("assertion sub = %q, want the wid: identity shape", sub)
	}
	if got := claims["warden_role"]; got != openaiWIFMain.role {
		t.Errorf("assertion warden_role = %v, want %s", got, openaiWIFMain.role)
	}
	if got, want := claims["warden_resource"], "openai:"+openaiWIFAccount; got != want {
		t.Errorf("assertion warden_resource = %v, want %s", got, want)
	}
	// The spec discloses no user, so this is the agent-only shape: the agent at the
	// top, no delegation.
	for _, claim := range []string{"act", "warden_namespace"} {
		if _, ok := claims[claim]; ok {
			t.Errorf("assertion carries %s; an agent-only spec mints no delegation", claim)
		}
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Until(time.Unix(int64(exp), 0)) <= 0 {
		t.Errorf("assertion exp = %v, want a time in the future", claims["exp"])
	}

	// The assertion is itself a credential, exchangeable until it expires. It goes
	// to the token endpoint and nowhere else.
	if strings.Contains(upstream.Last(t).Header.Get("Authorization"), assertion) {
		t.Error("the assertion reached the upstream; only the exchanged bearer should")
	}
}

// TestOpenAI_OneMountServesKeyAndBearer pins the type-switch from the outside: the
// same mount, the same caller, two roles — one bound to a static key with its
// organization and project, one to the keyless source — and each credential goes
// out in its own shape.
func TestOpenAI_OneMountServesKeyAndBearer(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)

	for _, tc := range []struct {
		name   string
		role   string
		want   map[string]string
		absent []string
	}{
		{
			name: "static key",
			role: openaiEnv.VariantRole("both"),
			want: map[string]string{
				"Authorization":       "Bearer " + openaiKey,
				"OpenAI-Organization": openaiOrg,
				"OpenAI-Project":      openaiProject,
			},
		},
		{
			name:   "federated bearer",
			role:   openaiWIFMain.role,
			want:   map[string]string{"Authorization": "Bearer " + openaiOAuthToken(openaiWIFAccount, 1)},
			absent: []string{"OpenAI-Organization", "OpenAI-Project"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()
			status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.role,
			})
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      tc.want,
				Absent:        h.AlwaysAbsent(tc.absent...),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestOpenAI_WIFSessionReusesItsTokenThenRemintsEarly pins both halves of the
// lease. A session reuses the token it was issued, so an inference call does not
// pay a token exchange; and the lease ends before the token does, so the re-mint
// happens while the old token is still good.
//
// One certificate and one user JWT throughout: a credential is keyed on the agent
// and user tokens together, so re-fetching either would mint afresh.
func TestOpenAI_WIFSessionReusesItsTokenThenRemintsEarly(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)

	cert := agentCert(t)
	user := h.FullChainUserJWT(t)
	send := func(wantToken string) {
		t.Helper()
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
			AgentCertPEM: cert,
			Bearer:       user,
			Role:         openaiWIFShort.role,
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"Authorization": "Bearer " + wantToken},
			Absent:        h.AlwaysAbsent("OpenAI-Organization", "OpenAI-Project"),
			UpstreamCalls: 1,
		})
	}

	// The first token is issued after sentAt, so it is good until at least
	// sentAt + its lifetime — a lower bound that needs no clock on the Warden side.
	sentAt := time.Now()
	first := openaiOAuthToken(openaiWIFShortAccount, 1)
	send(first)
	servedAt := time.Now()

	send(first)
	if n := len(openaiOAuthSeen()); n != 1 {
		t.Fatalf("two requests in one session made %d token exchanges, want 1 — every inference call would pay for one", n)
	}

	// Past the lease, which ends at half the token's life, but not past the token.
	time.Sleep(time.Until(servedAt.Add(openaiWIFShortLifetime/2 + 500*time.Millisecond)))
	send(openaiOAuthToken(openaiWIFShortAccount, 2))
	at := openaiOAuthSeenAt()
	if len(at) != 2 {
		t.Fatalf("token exchanges after the lease ended = %d, want 2", len(at))
	}
	// Judged by when the second exchange arrived, not by when the request that
	// caused it returned: a re-mint after the first token expired would prove only
	// that expiry works.
	if remint := at[1].Sub(sentAt); remint >= openaiWIFShortLifetime {
		t.Fatalf("the re-mint came %s after the first request, by which time the first token had expired; it must come while that token is still good", remint)
	}
}

// TestOpenAI_WIFRejectedExchangeFailsClosed covers a service account mapping
// refusing the assertion. The request stops at the mint: nothing reaches the
// upstream, the refusal is not retried, and the assertion does not come back in
// the error the caller reads.
//
// 403: what failed is the trust between Warden's issuer and the OpenAI
// organization, which neither the caller nor a retry can change. A 500 would be
// retried by every SDK, and each retry would ask again for a token OpenAI will keep
// refusing.
func TestOpenAI_WIFRejectedExchangeFailsClosed(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiWIFRejected.role,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})

	grants := openaiOAuthSeen()
	if len(grants) != 1 {
		t.Fatalf("token exchanges = %d, want 1 — an RFC 6749 refusal is final, and retrying it only repeats the refusal", len(grants))
	}
	if assertion := grants[0]["subject_token"]; assertion != "" && strings.Contains(string(body), assertion) {
		t.Error("the error returned to the caller carries the assertion")
	}
	// In OpenAI's error shape, so the caller's SDK surfaces the reason.
	assertOpenAIError(t, body, "warden_credential_refused")
}

// assertOpenAIError checks a gateway failure came back in OpenAI's error shape,
// with Warden's code and a message marked as Warden's — what an OpenAI SDK
// decodes and shows its caller.
func assertOpenAIError(t *testing.T, body []byte, wantCode string) {
	t.Helper()
	var env struct {
		Error struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    string  `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not OpenAI's error shape: %v: %s", err, body)
	}
	if env.Error.Code != wantCode {
		t.Errorf("error.code = %q, want %q: %s", env.Error.Code, wantCode, body)
	}
	if env.Error.Type == "" {
		t.Errorf("error.type is empty: %s", body)
	}
	if !strings.HasPrefix(env.Error.Message, "Warden: ") {
		t.Errorf("error.message = %q, want it marked as Warden's", env.Error.Message)
	}
}

// TestOpenAI_WIFBearerRidesAStreamedCompletion drives the call the mount exists
// for — a streamed POST to /v1/chat/completions — with a federated credential. The
// body is parsed on the way through for policy, and the response arrives as a
// stream; neither may disturb which credential goes upstream, and the body must
// arrive as sent.
func TestOpenAI_WIFBearerRidesAStreamedCompletion(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)

	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "data: {\"object\":\"chat.completion.chunk\"}\n\ndata: [DONE]\n\n")
	})
	upstream.Reset()

	const completion = `{"model":"gpt-e2e","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	resp := h.ChainStream(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiWIFMain.role,
		Path:         "v1/chat/completions",
		Body:         completion,
	})
	defer resp.Body.Close()
	streamed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, streamed)
	}
	if !strings.Contains(string(streamed), "[DONE]") {
		t.Errorf("the stream did not reach the caller: %q", streamed)
	}

	got := upstream.Last(t)
	if got.Method != http.MethodPost || got.Path != "/v1/chat/completions" {
		t.Errorf("upstream saw %s %s, want POST /v1/chat/completions", got.Method, got.Path)
	}
	if want := "Bearer " + openaiOAuthToken(openaiWIFAccount, 1); got.Header.Get("Authorization") != want {
		t.Errorf("upstream Authorization = %q, want %q", got.Header.Get("Authorization"), want)
	}
	if string(got.Body) != completion {
		t.Errorf("upstream body = %s, want the completion as sent", got.Body)
	}
}

// TestOpenAI_WIFMisconfigurationRefusedAtWrite drives the write-time rules through
// the API. An openai spec is an exchange spec, so the store neither test-mints it
// nor verifies it when written; each of these would otherwise be accepted and then
// fail on every request, or — the rotation row — never fail and never work.
func TestOpenAI_WIFMisconfigurationRefusedAtWrite(t *testing.T) {
	ensureEnv(t)
	ensureOpenAIOAuth(t)
	setupOpenAIWIF(t)

	const name = "fc-openai-wif-refused"
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "")
	})

	spec := func(config map[string]string) map[string]any {
		return map[string]any{"type": "oauth_bearer_token", "source": openaiWIFSource, "config": config}
	}
	withSubject := func(extra map[string]string) map[string]string {
		cfg := map[string]string{"subject_token_source": "warden_identity", "service_account_id": openaiWIFAccount}
		for k, v := range extra {
			cfg[k] = v
		}
		return cfg
	}
	for _, tc := range []struct {
		name string
		path string
		body map[string]any
		want string
	}{
		{
			// Without it the exchange path never engages and every mint fails.
			name: "spec without a subject source",
			path: "sys/cred/specs/" + name,
			body: spec(map[string]string{"service_account_id": openaiWIFAccount}),
			want: "subject_token_source",
		},
		{
			// The identity provider trusts Warden's issuer; the agent's own token
			// would be presented to a provider that cannot accept it.
			name: "spec forwarding the agent's own token",
			path: "sys/cred/specs/" + name,
			body: spec(map[string]string{"subject_token_source": "agent_identity", "service_account_id": openaiWIFAccount}),
			want: "warden_identity",
		},
		{
			name: "spec without a service account",
			path: "sys/cred/specs/" + name,
			body: spec(map[string]string{"subject_token_source": "warden_identity"}),
			want: "service_account_id",
		},
		{
			// Read from the source only; a spec value would do nothing.
			name: "spec naming an identity provider",
			path: "sys/cred/specs/" + name,
			body: spec(withSubject(map[string]string{"identity_provider_id": "fc-e2e-other-provider"})),
			want: "identity_provider_id",
		},
		{
			// Looks like it sets the assertion's audience while the source's goes out.
			name: "spec setting the source's audience key",
			path: "sys/cred/specs/" + name,
			body: spec(withSubject(map[string]string{"audience": "https://other.example.com"})),
			want: "assertion_audience",
		},
		{
			// The bearer sends no org/project header; a value here would do nothing.
			name: "spec naming a project",
			path: "sys/cred/specs/" + name,
			body: spec(withSubject(map[string]string{"project_id": "proj_e2e"})),
			want: "project_id",
		},
		{
			name: "source with the service account",
			path: "sys/cred/sources/" + name,
			body: map[string]any{"type": "openai", "config": map[string]string{
				"auth_method":          "oidc_federation",
				"identity_provider_id": openaiWIFProvider,
				"service_account_id":   openaiWIFAccount,
			}},
			want: "belongs on the spec",
		},
		{
			// auth_method is what marks a source federated to the store.
			name: "source without auth_method",
			path: "sys/cred/sources/" + name,
			body: map[string]any{"type": "openai", "config": map[string]string{"identity_provider_id": openaiWIFProvider}},
			want: "auth_method",
		},
		{
			// A keyless source has nothing to rotate; enrolled, it would fail every
			// cycle for as long as it existed.
			name: "source with a rotation period",
			path: "sys/cred/sources/" + name,
			body: map[string]any{
				"type":            "openai",
				"rotation_period": 86400,
				"config":          map[string]string{"auth_method": "oidc_federation", "identity_provider_id": openaiWIFProvider},
			},
			want: "rotation_period",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			status, resp := h.APIRequest(t, "POST", tc.path, leaderPort, string(encoded))
			if status != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", status, resp)
			}
			if !strings.Contains(string(resp), tc.want) {
				t.Errorf("want the refusal to name %s, got: %s", tc.want, resp)
			}
		})
	}
}
