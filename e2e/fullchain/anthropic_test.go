//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// anthropic stands for the channels token extractor in its ordinary order:
// X-Warden-Token first, then the native x-api-key header. Outbound it is the
// case where the credential lands in a custom header beside headers the mount
// governs itself — the version, the betas and the requesting user's profile.

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
