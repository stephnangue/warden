//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// cloudflare is the dual-mode gateway that injects into Authorization, so it is
// the counterpart to scaleway: same SDK, same two modes, opposite answer to
// "what happens to the caller's Authorization". Here the mint overwrites it,
// which is the case that always worked; scaleway is where it did not.

// No vendor prefix — see the note in openai_test.go.
const cloudflareAPIToken = "fc-cloudflare-not-a-real-api-token"

var cloudflareEnv = h.ProviderEnv{
	Mount:       "fc-cloudflare",
	Type:        "cloudflare",
	URLKey:      "cloudflare_url",
	CredType:    "cloudflare_keys",
	ExtraConfig: map[string]any{"account_id": "fc-account-id"},
	CredConfig:  map[string]string{"api_token": cloudflareAPIToken},
}

// TestCloudflare_MintReplacesInboundAuthorization sends a user JWT on
// Authorization and expects the minted token there instead. The overwrite is
// what keeps the user's credential off the wire — the same property scaleway
// has to get by stripping, since nothing it injects would displace it.
func TestCloudflare_MintReplacesInboundAuthorization(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, cloudflareEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         cloudflareEnv.CertRole(),
		Path:         "client/v4/zones",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + cloudflareAPIToken},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestCloudflare_AgentTokenChannelCarriesBothPrincipals is the dual-mode SDK's
// user leg on the injects-into-Authorization side. The agent arrives in its own
// channel, the user on Authorization, and the mint still lands on Authorization
// — so the row also shows the user's JWT being displaced rather than merged.
func TestCloudflare_AgentTokenChannelCarriesBothPrincipals(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, cloudflareEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, cloudflareEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		AgentToken:   h.GetDefaultJWT(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         cloudflareEnv.JWTAgentRole(),
		Path:         "client/v4/zones",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + cloudflareAPIToken},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}
