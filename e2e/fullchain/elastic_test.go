//go:build e2e

package fullchain

import (
	"encoding/base64"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// elastic is scheme dispatch: its own agent credential rides Authorization under
// the native ApiKey scheme, so agent and user can share the header only by
// dispatching on which scheme is present. It is the one provider where a user
// credential is sometimes structurally impossible rather than merely absent.

// The credential is the base64 id:key pair the cluster issued, and the extractor
// must pass it through rather than encode it again — so the value has to be
// genuinely encoded, not merely opaque.
//
// Assembled rather than written out. A literal base64 blob of this length reads
// as a real credential to a secret scanner however synthetic its contents, and
// unlike the other providers here the encoding means a reviewer cannot see at a
// glance that it is fake.
var elasticKey = base64.StdEncoding.EncodeToString([]byte("fc-elastic-id:fc-elastic-not-a-real-secret"))

var elasticEnv = h.ProviderEnv{
	Mount:      "fc-elastic",
	Type:       "elastic",
	URLKey:     "elastic_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": elasticKey},
}

// TestElastic_NativeSchemeClaimsAgentSlotAndLeavesNoUser is the row elastic is
// here for. When the agent arrives under the ApiKey scheme the header is spoken
// for, and the request succeeds with an agent and no user rather than misreading
// the agent as one.
//
// A certificate is presented deliberately and must change nothing, which is what
// makes this row discriminating: the scheme is checked before the out-of-band
// agent, so the certificate is never consulted. Were the order reversed the
// extractor would yield an empty agent, the certificate login would be attempted
// against the bearer-only agent leg this test repoints to, and the request would
// 401 instead of succeeding.
//
// The contrasting shape — certificate as agent, plain Bearer as user, and a user
// duly captured — is TestFullChain_CertAgentWithUser/fc-elastic. Note it differs
// in the agent leg as well as the scheme, so the pair brackets the behaviour
// rather than isolating a single variable.
func TestElastic_NativeSchemeClaimsAgentSlotAndLeavesNoUser(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, elasticEnv)

	probe := h.ProbePath("elastic-native-scheme")
	status, body, _ := h.ChainRequest(t, leaderPort, elasticEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		RawAuthz:     "ApiKey " + h.GetDefaultJWT(t),
		Role:         elasticEnv.JWTAgentRole(),
		Path:         probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "ApiKey " + elasticKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, "")
}
