//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// rest is the generic escape hatch: where every other provider compiles its
// credential shape in, this one takes it from mount config. That inverts what a
// row here proves — not that the provider knows GitHub's scheme or Datadog's
// header names, but that an operator's configuration is what actually reaches
// the upstream.
//
// Its extractor is also the only one assembled per request rather than per
// mount for a reason other than the path, which is why the config values are
// deliberately unusual: a default-shaped row would pass whether or not the
// configuration was consulted at all.

const restToken = "fc-rest-not-a-real-token"

var restEnv = h.ProviderEnv{
	Mount:    "fc-rest",
	Type:     "rest",
	URLKey:   "base_url",
	CredType: "api_key",
	ExtraConfig: map[string]any{
		// None of these are defaults. The default would put "Bearer <token>" in
		// Authorization, which is also what several other providers do — so a
		// row using it could not tell "configuration honoured" from "provider
		// happened to behave that way".
		"token_header": "X-Custom-Auth",
		"token_prefix": "Token ",
		"headers":      map[string]any{"X-Tenant": "fc-e2e-tenant"},
	},
	CredConfig: map[string]string{"api_key": restToken},
}

// TestREST_ConfiguredHeaderAndPrefixAreHonoured checks the three parts of the
// contract together: the token lands in the configured header, under the
// configured prefix, alongside the configured static headers — and Authorization,
// where the default would have put it, stays empty.
func TestREST_ConfiguredHeaderAndPrefixAreHonoured(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, restEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         restEnv.CertRole(),
		// Both configured headers are also sent by the caller. The mount's
		// values must replace them, not merge or lose to them — a static header
		// a caller can overwrite is worth less than no static header, since it
		// reads as enforced while being caller-controlled.
		Headers: map[string]string{
			"X-Tenant":      "attacker-tenant",
			"X-Custom-Auth": "Token attacker-supplied",
		},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"X-Custom-Auth": "Token " + restToken,
			"X-Tenant":      "fc-e2e-tenant",
		},
		// Authorization is where the default would have put the credential, and
		// where the caller's own arrived. Empty here means the configuration was
		// honoured and the inbound credential was dropped rather than passed on.
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}
