//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// newrelic is the inverted channel order: the native Api-Key header is consulted
// *before* X-Warden-Token. It is also the one provider whose inbound agent
// channel and outbound credential header share a name, which makes it the
// sharpest leak test in the suite — and the reason the cross-cutting
// Authorization row uses it as its carrier.

// No vendor prefix — see the note in openai_test.go.
const newrelicKey = "fc-newrelic-not-a-real-key"

var newrelicEnv = h.ProviderEnv{
	Mount:      "fc-newrelic",
	Type:       "newrelic",
	URLKey:     "newrelic_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": newrelicKey},
}

// TestNewRelic_ClientApiKeyNeverReachesUpstream sends a caller-supplied value in
// the very header the credential extractor writes to. Forwarding rather than
// replacing it would send the caller's value upstream under the mount's
// identity.
func TestNewRelic_ClientApiKeyNeverReachesUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, newrelicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         newrelicEnv.CertRole(),
		Headers:      map[string]string{"Api-Key": "attacker-supplied-not-a-real-key"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Api-Key": newrelicKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestNewRelic_NativeChannelOutranksOperatorToken pins the ordering that makes
// newrelic different from every other channels provider: Api-Key is consulted
// *before* X-Warden-Token, where anthropic and the rest consult X-Warden-Token
// first. Read it together with its mirror,
// TestAnthropic_OperatorTokenOutranksNativeChannel — neither means much alone.
//
// Both headers are sent, and which one the extractor picks decides which of two
// distinct failures follows. Neither request can succeed: presenting
// X-Warden-Token at all makes core skip transparent authentication entirely,
// whatever the extractor chose, so no agent gets authenticated either way. What
// differs is the shape of the failure, and that is the observable:
//
//	Api-Key wins here            → agent is a JWT, looked up as an opaque
//	                               operator token, resolves to nothing → 403
//	X-Warden-Token wins (anthropic) → agent is the operator token, which resolves
//	                               but binds no credential spec → 400
//
// Reorder the varargs in either provider's extractor and these two swap. No
// Bearer is sent — with one, the ambiguity gate would reject the request before
// any extractor ran and the ordering would stay unobserved.
func TestNewRelic_NativeChannelOutranksOperatorToken(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, newrelicEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, newrelicEnv, h.ChainOpts{
		WardenToken: h.RootToken(t),
		Role:        newrelicEnv.JWTAgentRole(),
		Headers:     map[string]string{"Api-Key": h.GetDefaultJWT(t)},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})
	// Distinguishes this from anthropic's outcome: had the operator token been
	// selected it would have resolved, and the request would have died at the
	// mint with "no credential spec" instead.
	if strings.Contains(string(body), "credential spec") {
		t.Errorf("operator token appears to have won the agent slot; want the Api-Key value: %s", body)
	}
}

// TestNewRelic_NativeChannelCarriesAgentAndLeavesUserSlotOpen is the row
// newrelic is in this suite for. The agent arrives in Api-Key and, unlike
// X-Warden-Token, that header does not close the user slot — so both principals
// resolve from headers alone.
//
// The same request is the strongest form of the leak test above: here the header
// really does arrive carrying a Warden agent token, not a decoy.
func TestNewRelic_NativeChannelCarriesAgentAndLeavesUserSlotOpen(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, newrelicEnv)

	probe := h.ProbePath("newrelic-native-channel")
	status, body, _ := h.ChainRequest(t, leaderPort, newrelicEnv, h.ChainOpts{
		Bearer:  h.FullChainUserJWT(t),
		Role:    newrelicEnv.JWTAgentRole(),
		Headers: map[string]string{"Api-Key": h.GetDefaultJWT(t)},
		Path:    probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Api-Key": newrelicKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}
