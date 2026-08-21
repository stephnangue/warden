//go:build e2e

package fullchain

import (
	"testing"

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
// The apikey source with optional_metadata is the documented shape for a
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
	SourceConfig: map[string]string{"optional_metadata": "organization_id,project_id"},
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
