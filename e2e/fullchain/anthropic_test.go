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

// anthropic stands for the channels token extractor in its ordinary order:
// X-Warden-Token first, then the native x-api-key header. Outbound it is the
// case where the credential lands in a custom header beside headers the mount
// governs itself — the version, the betas and the requesting user's profile —
// or, from a keyless source, in Authorization instead.

// No vendor prefix — see the note in openai_test.go.
const (
	anthropicKey       = "fc-anthropic-not-a-real-key"
	anthropicWorkspace = "wrkspc_fce2eworkspace"
)

// The workspace travels as an adjunct, so the source has to be the apikey type
// and name it: no other source carries a field beside the key, and a spec setting
// one on any other source is refused when it is written. A local source here
// would not merely fail to exercise carriage — it would stop the spec existing.
var anthropicEnv = h.ProviderEnv{
	Mount:        "fc-anthropic",
	Type:         "anthropic",
	URLKey:       "anthropic_url",
	CredType:     "api_key",
	SourceType:   "apikey",
	SourceConfig: map[string]string{"credential_fields": "workspace_id"},
	CredConfig:   map[string]string{"api_key": anthropicKey},
	Variants: map[string]map[string]string{
		"workspace": {"api_key": anthropicKey, "workspace_id": anthropicWorkspace},
	},
}

// TestAnthropic_MountVersionReplacesClients checks the version the upstream sees
// is the mount's, whatever the client sent.
//
// The version is supplied as a fallback — set only where the request carries no
// such header. That amounts to an override only because the client's copy is
// stripped first. A client sending its own is what would expose the two coming
// apart: without the strip, its version would win and the mount's would never be
// sent.
func TestAnthropic_MountVersionReplacesClients(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
		Headers:      map[string]string{"anthropic-version": "1999-01-01"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"x-api-key":         anthropicKey,
			"anthropic-version": "2023-06-01",
		},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// writeAnthropicConfig applies a partial config write to the shared mount and
// restores the provider's own settings afterwards, so no other test in the
// package sees them. The profile key is cleared in the same write as the betas:
// clearing the betas alone would leave a key without its beta, which the mount
// rightly refuses.
func writeAnthropicConfig(t *testing.T, body string) {
	t.Helper()
	status, resp := h.APIRequest(t, "POST", anthropicEnv.Mount+"/config", leaderPort, body)
	if status < 200 || status >= 300 {
		t.Fatalf("write %s/config: status %d: %s", anthropicEnv.Mount, status, resp)
	}
	t.Cleanup(func() {
		status, resp := h.APIRequest(t, "POST", anthropicEnv.Mount+"/config", leaderPort,
			`{"anthropic_version": "", "beta_allowlist": "*", "beta_required": "", "user_profile_metadata_key": ""}`)
		if status < 200 || status >= 300 {
			t.Errorf("restore %s/config: status %d: %s", anthropicEnv.Mount, status, resp)
		}
	})
}

// TestAnthropic_ClientBetasPassThroughByDefault covers a mount nobody has
// configured. anthropic-beta is now stripped and put back by the extractor, so
// this is what would notice if putting it back stopped happening.
func TestAnthropic_ClientBetasPassThroughByDefault(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
		Headers:      map[string]string{"anthropic-beta": "a-2026-01-01, b-2026-01-01"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"anthropic-beta": "a-2026-01-01, b-2026-01-01"},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestAnthropic_BetaPolicyAndVersionFromConfig drives the mount's settings
// through a real config write: the allowlist drops what it does not name, the
// required beta is added, and the configured version replaces the default.
func TestAnthropic_BetaPolicyAndVersionFromConfig(t *testing.T) {
	ensureEnv(t)

	writeAnthropicConfig(t, `{
		"anthropic_version": "2024-01-01",
		"beta_allowlist": "a-2026-01-01",
		"beta_required": "r-2026-01-01"
	}`)

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
		Headers:      map[string]string{"anthropic-beta": "a-2026-01-01,x-2026-01-01"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"x-api-key":         anthropicKey,
			"anthropic-version": "2024-01-01",
			"anthropic-beta":    "a-2026-01-01,r-2026-01-01",
		},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestAnthropic_InvalidBetaConfigRefused checks a bad value is refused by the
// config write itself. Validation that ran only when a mount is enabled would
// accept it here, and every request would then fail upstream instead.
//
// The two rows are refused by different layers, and each asserts which. A bad
// beta name is the provider's own check. An array given for a comma-separated
// list — the natural mistake — never reaches the provider: the framework checks
// the field's type first. That row pins the guarantee the provider relies on,
// since its handler reads the fields assuming they are strings.
func TestAnthropic_InvalidBetaConfigRefused(t *testing.T) {
	ensureEnv(t)

	for name, tc := range map[string]struct{ body, layer string }{
		"invalid name": {`{"beta_required": "not a beta"}`, "is not a valid beta name"},
		"array value":  {`{"beta_allowlist": ["a-2026-01-01"]}`, "field validation failed"},
	} {
		status, resp := h.APIRequest(t, "POST", anthropicEnv.Mount+"/config", leaderPort, tc.body)
		if status != 400 {
			t.Errorf("%s: want 400, got %d: %s", name, status, resp)
			continue
		}
		if !strings.Contains(string(resp), tc.layer) {
			t.Errorf("%s: want the refusal to say %q, got: %s", name, tc.layer, resp)
		}
	}
}

// TestAnthropic_WorkspaceFollowsTheCredential covers both branches of the
// optional header. The absent assertion is the point of the first row: an
// extractor that emitted an empty workspace would still send the right key, and
// the upstream refuses an empty value — so it would pass a key check while
// breaking every request made with a single-workspace key.
func TestAnthropic_WorkspaceFollowsTheCredential(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name   string
		role   string
		want   map[string]string
		absent []string
	}{
		{
			name:   "key only",
			role:   anthropicEnv.CertRole(),
			want:   map[string]string{"x-api-key": anthropicKey},
			absent: []string{"anthropic-workspace-id"},
		},
		{
			name: "with workspace",
			role: anthropicEnv.VariantRole("workspace"),
			want: map[string]string{
				"x-api-key":              anthropicKey,
				"anthropic-workspace-id": anthropicWorkspace,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
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

// TestAnthropic_ClientSuppliedWorkspaceIsStripped checks a client cannot choose
// the workspace our key spends against — and reads the cache of.
//
// The key-only row is the one that proves the strip. With a workspace on the
// credential the injection overwrites the client's value, so that row would pass
// with or without the header on the removal list. Only where the credential names
// no workspace does anything stand between the client's header and the upstream.
func TestAnthropic_ClientSuppliedWorkspaceIsStripped(t *testing.T) {
	ensureEnv(t)

	const attacker = "wrkspc_attacker"

	t.Run("credential names none", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.FullChainUserJWT(t),
			Role:         anthropicEnv.CertRole(),
			Headers:      map[string]string{"anthropic-workspace-id": attacker},
		})

		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"x-api-key": anthropicKey},
			Absent:        h.AlwaysAbsent("anthropic-workspace-id"),
			UpstreamCalls: 1,
		})
	})

	t.Run("credential names one", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.FullChainUserJWT(t),
			Role:         anthropicEnv.VariantRole("workspace"),
			Headers:      map[string]string{"anthropic-workspace-id": attacker},
		})

		// The mount's own value must win outright — not merge, not append.
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status: 200,
			Injected: map[string]string{
				"x-api-key":              anthropicKey,
				"anthropic-workspace-id": anthropicWorkspace,
			},
			Absent:        h.AlwaysAbsent(),
			UpstreamCalls: 1,
		})
	})
}

// The Hydra client whose subject is shaped like an upstream profile id — see
// its entry in e2e/setup.sh.
const (
	anthropicProfiledUser       = "uprof_e2e-anthropic-user"
	anthropicProfiledUserSecret = "anthropic-user-secret"
	anthropicProfileMetadataKey = "anthropic_user_profile_id"
	anthropicProfileBeta        = "user-profiles-2026-09-04"
)

// mapUserSubjectToProfile has the shared user auth role copy each user's sub
// into verified token metadata under the key the mount reads, and restores the
// role afterwards so no other test's users gain metadata.
func mapUserSubjectToProfile(t *testing.T) {
	t.Helper()
	path := "auth/fullchain-user-jwt/role/" + h.FullChainUserAuthRole
	status, resp := h.APIRequest(t, "PUT", path, leaderPort,
		`{"metadata_claims": {"sub": "`+anthropicProfileMetadataKey+`"}}`)
	if status < 200 || status >= 300 {
		t.Fatalf("map sub on %s: status %d: %s", path, status, resp)
	}
	t.Cleanup(func() {
		status, resp := h.APIRequest(t, "PUT", path, leaderPort, `{"metadata_claims": {}}`)
		if status < 200 || status >= 300 {
			t.Errorf("restore %s: status %d: %s", path, status, resp)
		}
	})
}

// TestAnthropic_ProfileFromUserMetadata drives attribution through the whole
// chain: a claim on the user's token, mapped into verified metadata at login,
// read by the mount and sent upstream.
//
// Every row sends its own anthropic-user-profile-id as well. Only the verified
// user identity may name a profile, so the client's value must never reach the
// upstream — whether the mount then sends the user's, or sends none at all.
func TestAnthropic_ProfileFromUserMetadata(t *testing.T) {
	ensureEnv(t)
	mapUserSubjectToProfile(t)
	writeAnthropicConfig(t, `{
		"beta_required": "`+anthropicProfileBeta+`",
		"user_profile_metadata_key": "`+anthropicProfileMetadataKey+`"
	}`)

	claimed := map[string]string{"anthropic-user-profile-id": "uprof_claimed-by-client"}

	t.Run("profiled user", func(t *testing.T) {
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.GetJWT(t, anthropicProfiledUser, anthropicProfiledUserSecret),
			Role:         anthropicEnv.CertRole(),
			Headers:      claimed,
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status: 200,
			Injected: map[string]string{
				"x-api-key":                 anthropicKey,
				"anthropic-user-profile-id": anthropicProfiledUser,
				"anthropic-beta":            anthropicProfileBeta,
			},
			Absent:        h.AlwaysAbsent(),
			UpstreamCalls: 1,
		})
	})

	// This user's subject is mapped too, but is not a profile id. It is dropped
	// rather than sent to be refused, and the request goes ahead unattributed.
	t.Run("user whose subject is not a profile", func(t *testing.T) {
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.FullChainUserJWT(t),
			Role:         anthropicEnv.CertRole(),
			Headers:      claimed,
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"x-api-key": anthropicKey},
			Absent:        h.AlwaysAbsent("anthropic-user-profile-id"),
			UpstreamCalls: 1,
		})
	})

	// No user, so no one to attribute: the agent is never a source.
	t.Run("no user", func(t *testing.T) {
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Role:         anthropicEnv.CertRole(),
			Headers:      claimed,
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"x-api-key": anthropicKey},
			Absent:        h.AlwaysAbsent("anthropic-user-profile-id"),
			UpstreamCalls: 1,
		})
	})
}

// TestAnthropic_UnpairedProfileConfigRefused checks the mount will not take a
// profile key without the beta the upstream requires beside the header.
func TestAnthropic_UnpairedProfileConfigRefused(t *testing.T) {
	ensureEnv(t)

	status, resp := h.APIRequest(t, "POST", anthropicEnv.Mount+"/config", leaderPort,
		`{"user_profile_metadata_key": "`+anthropicProfileMetadataKey+`"}`)
	if status != 400 {
		t.Fatalf("want 400 for a profile key with no user-profiles beta, got %d: %s", status, resp)
	}
}

// TestAnthropic_OperatorTokenOutranksNativeChannel is the mirror of
// TestNewRelic_NativeChannelOutranksOperatorToken, and the reason both exist:
// anthropic consults X-Warden-Token *first* and x-api-key second, so the same
// pair of headers resolves the other way round. See that test for why neither
// request can succeed and why the failure shape is the observable.
//
// Here the operator token wins the agent slot. It resolves, so the request gets
// as far as the mint and dies there for want of a bound credential spec — a 400,
// where newrelic's unresolvable JWT produces a 403.
func TestAnthropic_OperatorTokenOutranksNativeChannel(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, anthropicEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		WardenToken: h.RootToken(t),
		Role:        anthropicEnv.JWTAgentRole(),
		Headers:     map[string]string{"x-api-key": h.GetDefaultJWT(t)},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        400,
		UpstreamCalls: 0,
	})
	// The operator token got far enough to be resolved — which is what says it,
	// and not the x-api-key JWT, occupied the agent slot.
	if !strings.Contains(string(body), "credential spec") {
		t.Errorf("want the mint to fail for a missing credential spec, got: %s", body)
	}
}

// TestAnthropic_NativeChannelCarriesAgent puts the agent in the native channel
// rather than a certificate. x-api-key is consulted second, after
// X-Warden-Token, and unlike X-Warden-Token it leaves the user slot open — so
// both principals resolve from a request carrying no certificate at all.
func TestAnthropic_NativeChannelCarriesAgent(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, anthropicEnv)

	probe := h.ProbePath("anthropic-native-channel")
	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		Bearer:  h.FullChainUserJWT(t),
		Role:    anthropicEnv.JWTAgentRole(),
		Headers: map[string]string{"x-api-key": h.GetDefaultJWT(t)},
		Path:    probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"x-api-key": anthropicKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// ============================================================================
// Keyless: workload identity federation
// ============================================================================
//
// Every row above spends a static key from an apikey source. These spend none. An
// anthropic source mints by presenting a Warden-signed assertion to Anthropic's token
// endpoint and receiving a short-lived bearer, which the provider injects in place of
// the key. What only a full chain shows is the two meeting: the assertion Warden signs,
// the exchange it drives, and the bearer that reaches the upstream.
//
// The rows share the static rows' mount, and that is itself a claim under test: one
// mount serving a key and a bearer side by side is what the extractor's type-switch
// promises.
//
// Every resource is test-local, as in the gcp suite: a killed run skips t.Cleanup,
// and a stranded spec would block its source from being deleted, which the next run's
// setup cannot recover from.

const (
	anthropicWIFSource   = "fc-anthropic-wif-src"
	anthropicWIFOrg      = "00000000-0000-4000-8000-00000000e2e0"
	anthropicWIFAudience = "https://warden.e2e.example.com/anthropic"
	anthropicWIFAccount  = "svac_fce2eaccount"

	// The stub keys its answer on the federation rule, so each behaviour a row needs
	// is a rule, with its own spec and role.
	anthropicWIFRule         = "fdrl_fce2erule"
	anthropicWIFShortRule    = "fdrl_fce2eshortlived"
	anthropicWIFRejectedRule = "fdrl_fce2erejected"

	// The lifetime the stub gives a short-lived token. The driver ends its lease at
	// half of it — the minute's margin would leave nothing of a token this short — so
	// a row can wait out the lease while the token it was served is still good.
	//
	// Long enough that both windows the row depends on have room on a slow runner:
	// two requests inside the 5s lease, and the re-mint inside the 10s token.
	anthropicWIFShortLifetime = 10 * time.Second

	anthropicJWTBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// anthropicWIFTarget is one spec on the keyless source and the cert role binding it.
type anthropicWIFTarget struct{ spec, role, rule string }

var (
	anthropicWIFMain     = anthropicWIFTarget{"fc-anthropic-wif-cred", "fc-anthropic-wif-role", anthropicWIFRule}
	anthropicWIFShort    = anthropicWIFTarget{"fc-anthropic-wif-short", "fc-anthropic-wif-short-role", anthropicWIFShortRule}
	anthropicWIFRejected = anthropicWIFTarget{"fc-anthropic-wif-rejected", "fc-anthropic-wif-rejected-role", anthropicWIFRejectedRule}
)

// anthropicOAuth stands in for Anthropic's token endpoint. The source's anthropic_url
// points here and the mount's at the recording upstream, so the exchange and the
// inference call land on different listeners — as in production, where only the
// second is proxied.
//
// It refuses what a real endpoint would — another path, a body that is not JSON, a
// grant that is not jwt-bearer — so a driver drifting back to a form body fails here
// rather than passing against a stub that takes anything. It does not check the
// assertion's signature: the rows do that against the published JWKS, which is the
// check an upstream actually makes.
var anthropicOAuth *httptest.Server

var (
	anthropicOAuthOnce   sync.Once
	anthropicOAuthMu     sync.Mutex
	anthropicOAuthGrants []map[string]string // grants received, in order
	anthropicOAuthAt     []time.Time         // when each grant arrived, in the same order
)

// anthropicOAuthToken is the bearer the stub issues for the nth grant naming rule,
// counted from 1 within a test. Numbering them is what lets a row tell a re-mint from
// a cached token: one value seen twice is one exchange served twice.
//
// No vendor prefix, for the reason in openai_test.go.
func anthropicOAuthToken(rule string, n int) string {
	return fmt.Sprintf("fc-anthropic-oat-%s-%d", rule, n)
}

func startAnthropicOAuth() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/token" {
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

		anthropicOAuthMu.Lock()
		anthropicOAuthGrants = append(anthropicOAuthGrants, grant)
		anthropicOAuthAt = append(anthropicOAuthAt, time.Now())
		n := 0
		for _, g := range anthropicOAuthGrants {
			if g["federation_rule_id"] == grant["federation_rule_id"] {
				n++
			}
		}
		anthropicOAuthMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if grant["grant_type"] != anthropicJWTBearerGrant {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		lifetime := 3600
		switch grant["federation_rule_id"] {
		case anthropicWIFRejectedRule:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"assertion does not satisfy the federation rule"}`))
			return
		case anthropicWIFShortRule:
			lifetime = int(anthropicWIFShortLifetime / time.Second)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": anthropicOAuthToken(grant["federation_rule_id"], n),
			"token_type":   "Bearer",
			"expires_in":   lifetime,
		})
	}))
}

// ensureAnthropicOAuth starts the stub on first use and clears what it recorded, so a
// row counts only its own exchanges. The source naming it is built per test, so it
// stays out of ensureEnv, as the gcp stub does.
func ensureAnthropicOAuth(t *testing.T) {
	t.Helper()
	anthropicOAuthOnce.Do(func() { anthropicOAuth = startAnthropicOAuth() })
	anthropicOAuthMu.Lock()
	defer anthropicOAuthMu.Unlock()
	anthropicOAuthGrants, anthropicOAuthAt = nil, nil
}

func anthropicOAuthSeen() []map[string]string {
	anthropicOAuthMu.Lock()
	defer anthropicOAuthMu.Unlock()
	return append([]map[string]string(nil), anthropicOAuthGrants...)
}

// anthropicOAuthSeenAt is when each grant arrived — the instant a mint happened, which
// the caller's own clock cannot see: its request returns only after the whole chain.
func anthropicOAuthSeenAt() []time.Time {
	anthropicOAuthMu.Lock()
	defer anthropicOAuthMu.Unlock()
	return append([]time.Time(nil), anthropicOAuthAt...)
}

// anthropicMustWrite POSTs v as JSON and fails the test on anything but success.
func anthropicMustWrite(t *testing.T, path string, v any, what string) {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %s: %v", what, err)
	}
	if status, resp := h.APIRequest(t, "POST", path, leaderPort, string(body)); status < 200 || status > 299 {
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// setupAnthropicWIF builds the keyless source and, per target, a spec and the cert
// role binding it. Order is load-bearing: a source cannot be deleted while a spec
// names it, so cleanup runs roles, then specs, then the source — which also clears
// whatever a killed run left behind before building.
func setupAnthropicWIF(t *testing.T) {
	t.Helper()

	targets := []anthropicWIFTarget{anthropicWIFMain, anthropicWIFShort, anthropicWIFRejected}
	clear := func() {
		for _, tg := range targets {
			h.APIRequest(t, "DELETE", "auth/cert/role/"+tg.role, leaderPort, "")
		}
		for _, tg := range targets {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+tg.spec, leaderPort, "")
		}
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+anthropicWIFSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// No key anywhere. The source names the organization, the audience the
	// federation rules match, and where to exchange.
	anthropicMustWrite(t, "sys/cred/sources/"+anthropicWIFSource, map[string]any{
		"type": "anthropic",
		"config": map[string]string{
			"auth_method":     "oidc_federation",
			"organization_id": anthropicWIFOrg,
			"audience":        anthropicWIFAudience,
			"anthropic_url":   anthropicOAuth.URL,
		},
	}, "create the keyless anthropic source")

	for _, tg := range targets {
		// The workspace is named so a row can show it goes into the exchange and not
		// into a header: the token the exchange returns already binds it.
		anthropicMustWrite(t, "sys/cred/specs/"+tg.spec, map[string]any{
			"type":   "oauth_bearer_token",
			"source": anthropicWIFSource,
			"config": map[string]string{
				"subject_token_source": "warden_identity",
				"federation_rule_id":   tg.rule,
				"service_account_id":   anthropicWIFAccount,
				"workspace_id":         anthropicWorkspace,
			},
		}, "create the keyless spec "+tg.spec)

		anthropicMustWrite(t, "auth/cert/role/"+tg.role, map[string]any{
			"allowed_common_names": []string{h.FullChainAgentCN},
			"token_policies":       []string{anthropicEnv.Policy()},
			"cred_spec_name":       tg.spec,
			"token_ttl":            3600,
		}, "create the cert role "+tg.role)
	}
}

// TestAnthropic_WIFInjectsTheExchangedBearer is the row the keyless path exists for.
//
// The request carries the user's own JWT in Authorization and a workspace the client
// chose. The upstream must see neither: only the bearer Anthropic issued for Warden's
// assertion — exactly one Authorization value, so the caller's does not ride beside
// it — and no workspace header, since that bearer binds its own.
func TestAnthropic_WIFInjectsTheExchangedBearer(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)
	upstream.Reset()

	user := h.FullChainUserJWT(t)
	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       user,
		Role:         anthropicWIFMain.role,
		Headers:      map[string]string{"anthropic-workspace-id": "wrkspc_attacker"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"Authorization":     "Bearer " + anthropicOAuthToken(anthropicWIFRule, 1),
			"anthropic-version": "2023-06-01",
		},
		Absent:        h.AlwaysAbsent("x-api-key", "anthropic-workspace-id"),
		UpstreamCalls: 1,
	})

	grants := anthropicOAuthSeen()
	if len(grants) != 1 {
		t.Fatalf("token exchanges = %d, want 1", len(grants))
	}
	grant := grants[0]
	for field, want := range map[string]string{
		"grant_type":         anthropicJWTBearerGrant,
		"organization_id":    anthropicWIFOrg,
		"federation_rule_id": anthropicWIFRule,
		"service_account_id": anthropicWIFAccount,
		"workspace_id":       anthropicWorkspace,
	} {
		if got := grant[field]; got != want {
			t.Errorf("exchange %s = %q, want %q", field, got, want)
		}
	}

	// The assertion is checked the way Anthropic checks it: against the issuer's
	// published JWKS, then the claims a federation rule matches on.
	assertion := grant["assertion"]
	if assertion == user {
		t.Fatal("the exchange presented the user's JWT; warden_identity must present an assertion Warden minted")
	}
	claims := h.VerifyAssertion(t, leaderPort, assertion)
	if got := claims["iss"]; got != wardenIssuerURL {
		t.Errorf("assertion iss = %v, want %s — a federation issuer pins it exactly", got, wardenIssuerURL)
	}
	if got := claims["aud"]; got != anthropicWIFAudience {
		t.Errorf("assertion aud = %v, want the source's audience %s", got, anthropicWIFAudience)
	}
	if sub, _ := claims["sub"].(string); !strings.HasPrefix(sub, "wid:") {
		t.Errorf("assertion sub = %q, want the wid: identity shape", sub)
	}
	if got := claims["warden_role"]; got != anthropicWIFMain.role {
		t.Errorf("assertion warden_role = %v, want %s", got, anthropicWIFMain.role)
	}
	if got, want := claims["warden_resource"], "anthropic:"+anthropicWIFAccount; got != want {
		t.Errorf("assertion warden_resource = %v, want %s", got, want)
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

// TestAnthropic_OneMountServesKeyAndBearer pins the type-switch from the outside: the
// same mount, the same caller, two roles — one bound to a static key, one to the
// keyless source — and each credential lands in its own header with the other's
// absent. A mount that could serve only one shape would force an operator migrating
// to federation to stand up a second mount and move every client.
func TestAnthropic_OneMountServesKeyAndBearer(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)

	for _, tc := range []struct {
		name   string
		role   string
		want   map[string]string
		absent string
	}{
		{"static key", anthropicEnv.CertRole(), map[string]string{"x-api-key": anthropicKey}, "Authorization"},
		{"federated bearer", anthropicWIFMain.role, map[string]string{"Authorization": "Bearer " + anthropicOAuthToken(anthropicWIFRule, 1)}, "x-api-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()
			status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.role,
			})
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      tc.want,
				Absent:        h.AlwaysAbsent(tc.absent),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestAnthropic_WIFSessionReusesItsTokenThenRemintsEarly pins both halves of the
// lease. A session reuses the token it was issued, so an inference call does not pay a
// token exchange; and the lease ends before the token does, so the re-mint happens
// while the old token is still good rather than after a request has gone upstream
// carrying an expired one.
//
// One certificate and one user JWT throughout: a credential is keyed on the agent and
// user tokens together, so re-fetching either would mint afresh and make every request
// look like a re-mint. See TestFullChain_LiveSessionKeepsItsCredential.
func TestAnthropic_WIFSessionReusesItsTokenThenRemintsEarly(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)

	cert := agentCert(t)
	user := h.FullChainUserJWT(t)
	send := func(wantToken string) {
		t.Helper()
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
			AgentCertPEM: cert,
			Bearer:       user,
			Role:         anthropicWIFShort.role,
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"Authorization": "Bearer " + wantToken},
			Absent:        h.AlwaysAbsent("x-api-key"),
			UpstreamCalls: 1,
		})
	}

	// The first token is issued after sentAt, so it is good until at least
	// sentAt + its lifetime — a lower bound that needs no clock on the Warden side.
	sentAt := time.Now()
	first := anthropicOAuthToken(anthropicWIFShortRule, 1)
	send(first)
	servedAt := time.Now()

	send(first)
	if n := len(anthropicOAuthSeen()); n != 1 {
		t.Fatalf("two requests in one session made %d token exchanges, want 1 — every inference call would pay for one", n)
	}

	// Past the lease, which ends at half the token's life, but not past the token.
	time.Sleep(time.Until(servedAt.Add(anthropicWIFShortLifetime/2 + 500*time.Millisecond)))
	send(anthropicOAuthToken(anthropicWIFShortRule, 2))
	at := anthropicOAuthSeenAt()
	if len(at) != 2 {
		t.Fatalf("token exchanges after the lease ended = %d, want 2", len(at))
	}
	// Without this the row could pass for the wrong reason: a re-mint that came after
	// the first token expired proves only that expiry works. It is judged by when the
	// second exchange arrived, not by when the request that caused it returned —
	// that includes the whole round trip after the mint, which a slow runner would
	// count against a re-mint that was on time.
	if remint := at[1].Sub(sentAt); remint >= anthropicWIFShortLifetime {
		t.Fatalf("the re-mint came %s after the first request, by which time the first token had expired; it must come while that token is still good", remint)
	}
}

// TestAnthropic_WIFRejectedExchangeFailsClosed covers a federation rule refusing the
// assertion. The request stops at the mint: nothing reaches the upstream, the refusal
// is not retried, and the assertion — exchangeable until it expires — does not come
// back in the error the caller reads.
//
// 403: what failed is the trust between Warden's issuer and the organization, which
// neither the caller nor a retry can change. A 500 would be retried by every SDK, and
// each retry would ask the organization again for a token it will keep refusing.
func TestAnthropic_WIFRejectedExchangeFailsClosed(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicWIFRejected.role,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})

	grants := anthropicOAuthSeen()
	if len(grants) != 1 {
		t.Fatalf("token exchanges = %d, want 1 — an RFC 6749 refusal is final, and retrying it only repeats the refusal", len(grants))
	}
	if assertion := grants[0]["assertion"]; assertion != "" && strings.Contains(string(body), assertion) {
		t.Error("the error returned to the caller carries the assertion")
	}
}

// TestAnthropic_WIFBearerRidesAStreamedMessage drives the call the mount exists for —
// a streamed POST to /v1/messages — with a federated credential. The body is parsed on
// the way through for policy, and the response arrives as a stream; neither may
// disturb which credential goes upstream, and the body must arrive as sent.
func TestAnthropic_WIFBearerRidesAStreamedMessage(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)

	upstream.SetHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	})
	upstream.Reset()

	const message = `{"model":"claude-e2e","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hello"}]}`
	resp := h.ChainStream(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicWIFMain.role,
		Path:         "v1/messages",
		Body:         message,
	})
	defer resp.Body.Close()
	streamed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, streamed)
	}
	if !strings.Contains(string(streamed), "message_stop") {
		t.Errorf("the stream did not reach the caller: %q", streamed)
	}

	got := upstream.Last(t)
	if got.Method != http.MethodPost || got.Path != "/v1/messages" {
		t.Errorf("upstream saw %s %s, want POST /v1/messages", got.Method, got.Path)
	}
	if want := "Bearer " + anthropicOAuthToken(anthropicWIFRule, 1); got.Header.Get("Authorization") != want {
		t.Errorf("upstream Authorization = %q, want %q", got.Header.Get("Authorization"), want)
	}
	if string(got.Body) != message {
		t.Errorf("upstream body = %s, want the message as sent", got.Body)
	}
}

// TestAnthropic_WIFMisconfigurationRefusedAtWrite drives the write-time rules through
// the API. An anthropic spec is an exchange spec, so the store neither test-mints it
// nor verifies it when written; each of these would otherwise be accepted and then
// fail on every request, or — the rotation row — never fail and never work.
func TestAnthropic_WIFMisconfigurationRefusedAtWrite(t *testing.T) {
	ensureEnv(t)
	ensureAnthropicOAuth(t)
	setupAnthropicWIF(t)

	const name = "fc-anthropic-wif-refused"
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "")
	})

	spec := func(config map[string]string) map[string]any {
		return map[string]any{"type": "oauth_bearer_token", "source": anthropicWIFSource, "config": config}
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
			body: spec(map[string]string{"federation_rule_id": anthropicWIFRule, "service_account_id": anthropicWIFAccount}),
			want: "subject_token_source",
		},
		{
			// The federation rules trust Warden's issuer; the agent's own token would
			// be presented to a rule that cannot accept it.
			name: "spec forwarding the agent's own token",
			path: "sys/cred/specs/" + name,
			body: spec(map[string]string{
				"subject_token_source": "agent_identity",
				"federation_rule_id":   anthropicWIFRule,
				"service_account_id":   anthropicWIFAccount,
			}),
			want: "warden_identity",
		},
		{
			name: "spec with an id in the wrong field",
			path: "sys/cred/specs/" + name,
			body: spec(map[string]string{
				"subject_token_source": "warden_identity",
				"federation_rule_id":   anthropicWIFRule,
				"service_account_id":   anthropicWIFRule,
			}),
			want: `starting with \"svac_\"`,
		},
		{
			// auth_method is what marks a source federated to the store.
			name: "source without auth_method",
			path: "sys/cred/sources/" + name,
			body: map[string]any{"type": "anthropic", "config": map[string]string{"organization_id": anthropicWIFOrg}},
			want: "auth_method",
		},
		{
			// A keyless source has nothing to rotate; enrolled, it would fail every
			// cycle for as long as it existed.
			name: "source with a rotation period",
			path: "sys/cred/sources/" + name,
			body: map[string]any{
				"type":            "anthropic",
				"rotation_period": 86400,
				"config":          map[string]string{"auth_method": "oidc_federation", "organization_id": anthropicWIFOrg},
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
