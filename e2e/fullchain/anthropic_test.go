//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// anthropic stands for the channels token extractor in its ordinary order:
// X-Warden-Token first, then the native x-api-key header. Outbound it is the
// case where the credential lands in a custom header while a static default
// header is applied as well.

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

// TestAnthropic_DefaultHeaderCoexistsWithCredential guards an ordering hazard:
// the provider's static headers are applied after the credential headers, so a
// static header whose name collided with a credential header would silently
// overwrite the credential. Nothing collides today; this is what would notice if
// something started to.
func TestAnthropic_DefaultHeaderCoexistsWithCredential(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
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
