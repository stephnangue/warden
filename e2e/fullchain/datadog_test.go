//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// datadog is the only user of the multi-field extractor: one required field and
// one optional, each landing in its own header rather than a single
// Authorization value. Its inbound side is the plain default extractor, so the
// rows here are about the outbound shape.

const datadogAPIKey = "fc-datadog-not-a-real-key"

var datadogEnv = h.ProviderEnv{
	Mount:      "fc-datadog",
	Type:       "datadog",
	URLKey:     "datadog_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": datadogAPIKey},
}

// TestDatadog_RequiredKeyInjected covers the reachable half of the multi-field
// extractor: the required field lands in its own header rather than in an
// Authorization value.
//
// The optional half cannot be reached. Its field is application_key, and nothing
// in the tree produces one — api_key, the type datadog's own help text points
// at, carries only api_key, key_id, key_name, organization_id and project_id, so
// a spec that sets application_key has it dropped before the credential is
// built. Covering that branch needs a variant spec and a positive assertion, and
// neither can be written until the field is carriable.
//
// DD-APPLICATION-KEY is deliberately NOT asserted absent. The header is in no
// strip list and the extractor never injects it, so a caller-supplied value
// reaches the upstream today — asserting absence without sending one would pass
// vacuously, and sending one would fail. The assertion belongs here once that
// passthrough is closed.
func TestDatadog_RequiredKeyInjected(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         datadogEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:   200,
		Injected: map[string]string{"DD-API-KEY": datadogAPIKey},
		// The credential rides its own header, leaving Authorization untouched
		// by injection — so a leaked caller credential would be visible there
		// rather than overwritten.
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}
