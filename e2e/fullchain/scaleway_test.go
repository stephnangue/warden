//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// scaleway is the first of the four dual-mode gateways in this package —
// providers that serve a REST API and an S3-compatible object store from one
// mount, detecting which per request. Two things make them worth rows of their
// own.
//
// They were unreachable by this suite until the config apply path was fixed: the
// upstream URL could only be set at mount time, the agent leg only by a later
// config write, and that write reset every key it did not name. There was no
// order that configured both.
//
// And scaleway is the one that authenticates with a header other than
// Authorization, which is why the inbound-Authorization row lives here.

// No vendor prefix — see the note in openai_test.go.
const (
	scalewayAccessKey = "SCWFCNOTAREALKEY0000"
	scalewaySecretKey = "fc-scaleway-not-a-real-secret-key"
)

var scalewayEnv = h.ProviderEnv{
	Mount:    "fc-scaleway",
	Type:     "scaleway",
	URLKey:   "scaleway_url",
	CredType: "scaleway_keys",
	CredConfig: map[string]string{
		"access_key": scalewayAccessKey,
		"secret_key": scalewaySecretKey,
	},
}

// TestScaleway_MintLandsInNativeHeader is the baseline: the credential reaches
// the upstream in X-Auth-Token, which is where Scaleway looks, and none of the
// inbound Warden channels follow it.
func TestScaleway_MintLandsInNativeHeader(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         scalewayEnv.CertRole(),
		Path:         "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestScaleway_InboundAuthorizationNeverReachesUpstream is the row this provider
// exists to carry. Scaleway authenticates with X-Auth-Token, so nothing the
// provider injects would overwrite Authorization — and the SDK used to leave it
// in place for exactly that reason, forwarding the caller's Warden credential to
// the vendor.
//
// The user leg is deliberately off. With it on, core captures the user and
// deletes Authorization itself before the backend ever sees the request
// (request_handler.go, at user capture), so the row would pass whether or not
// the gateway strips anything. Off, the agent's own JWT stays on Authorization
// all the way to handleAPIRequest, and only the strip keeps it off the wire.
func TestScaleway_InboundAuthorizationNeverReachesUpstream(t *testing.T) {
	ensureEnv(t)
	defer h.ResetFullChainLegs(t, leaderPort, upstream.URL, scalewayEnv)
	h.SetFullChainLegs(t, leaderPort, upstream.URL, scalewayEnv, h.JWTAgentPath, "")

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		Bearer: h.GetDefaultJWT(t),
		Role:   scalewayEnv.JWTAgentRole(),
		Path:   "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}

// TestScaleway_AgentTokenChannelFreesAuthorization pins the row the dual-mode
// SDK used to get wrong. It never read X-Warden-Agent-Token at all, so a request
// that separated the two principals properly had the *user's* bearer taken as
// the agent — the mount authenticated as the wrong party, and said so nowhere.
func TestScaleway_AgentTokenChannelFreesAuthorization(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, scalewayEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, scalewayEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		AgentToken:   h.GetDefaultJWT(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         scalewayEnv.JWTAgentRole(),
		Path:         "instance/v1/zones/fr-par-1/servers",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Auth-Token": scalewaySecretKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
}
