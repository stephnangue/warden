//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// splunk is the second scheme-dispatch provider. Its agent credential rides
// Authorization under Splunk's own scheme, so agent and user share the header
// and are told apart by which scheme is present — the same shape as elastic, on
// a different scheme name, which is what makes the pair worth having: a
// regression in the shared helper would have to break both.
//
// Outbound it is the plainest case in the suite, the Bearer extractor ten
// providers share, so this row also stands in for all of them.

const splunkKey = "fc-splunk-not-a-real-key"

var splunkEnv = h.ProviderEnv{
	Mount:      "fc-splunk",
	Type:       "splunk",
	URLKey:     "splunk_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": splunkKey},
}

// TestSplunk_NativeSchemeClaimsAgentSlotAndLeavesNoUser mirrors the elastic row.
// An agent arriving under the Splunk scheme speaks for the header, so no user
// can be carried, and the certificate that is also present is never consulted.
//
// Were the out-of-band agent checked first, the certificate would win, the
// extractor would return an empty agent, and the certificate login would fail
// against the bearer-only agent leg this test repoints to — so the 200 is what
// pins the ordering rather than merely observing a success.
func TestSplunk_NativeSchemeClaimsAgentSlotAndLeavesNoUser(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, splunkEnv)

	probe := h.ProbePath("splunk-native-scheme")
	status, body, _ := h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		RawAuthz:     "Splunk " + h.GetDefaultJWT(t),
		Role:         splunkEnv.JWTAgentRole(),
		Path:         probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, "")
}
