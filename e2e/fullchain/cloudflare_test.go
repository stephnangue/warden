//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// cloudflare is the dual-mode gateway that injects into Authorization, so it is
// the counterpart to scaleway: same SDK, same two modes, opposite answer to
// "what happens to the caller's Authorization". Here the mint overwrites it,
// which is the case that always worked; scaleway is where it did not.

// No vendor prefix — see the note in openai_test.go.
const cloudflareAPIToken = "fc-cloudflare-not-a-real-api-token"

// The keyless chain's names. Test-local, the source included, for the reason
// gitlab_test.go gives: a spec left hanging off a shared source by a killed run
// would block that source's deletion in the next run's setup.
const (
	// Seeded by setup.sh at secret/e2e/cloudflare-token, and nowhere else.
	cloudflareChainedAPIToken = "fc-cloudflare-chained-not-a-real-api-token"

	cloudflareTokenSecretSpec = "fc-cf-token-from-vault"
	cloudflareChainSource     = "fc-cf-keyless-src"
	cloudflareChainSpec       = "fc-cf-chained-cred"
	cloudflareChainAgentRole  = "fc-cf-chained-agent"
)

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

// setupCloudflareChain builds the SPEC-level chain: a cloudflare source that holds
// nothing, and a spec naming the key_value spec that reads the token from Vault.
func setupCloudflareChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+cloudflareChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+cloudflareChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+cloudflareChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+cloudflareTokenSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	scalewayReferencedSpec(t, cloudflareTokenSecretSpec, "e2e/cloudflare-token", subj)

	scalewayMustWrite(t, "POST", "sys/cred/sources/"+cloudflareChainSource,
		`{"type":"cloudflare","config":{}}`, "create the keyless cloudflare source")

	// No type: the source infers cloudflare_keys. No secret_field: the token is
	// stored as api_token, the name the driver reads by default.
	status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+cloudflareChainSpec, leaderPort, `{
		"source":"`+cloudflareChainSource+`","config":{"secret_spec":"`+cloudflareTokenSecretSpec+`"}}`)
	if status != 200 && status != 201 {
		t.Fatalf("create the spec-chained cloudflare spec (status %d): %s", status, resp)
	}
	// The suite runs at keyless_enforcement_level=warn, which reports every write
	// that would leave a secret stored. This one stores none, so it says nothing.
	if strings.Contains(string(resp), "keyless_enforcement_level") {
		t.Errorf("a chained cloudflare spec stores no secret, but its create warned: %s", resp)
	}

	scalewayMustWrite(t, "POST", "auth/jwt/role/"+cloudflareChainAgentRole, `{
		"token_policies":["`+cloudflareEnv.Policy()+`"],"cred_spec_name":"`+cloudflareChainSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained cloudflare agent role")
}

// TestCloudflare_KeylessChainServesVaultHeldToken is the keyless path for
// cloudflare_keys: the token exists only in Vault, fetched per request as the
// caller, and arrives on Authorization. The source calls nothing — a cloudflare
// source serves a credential that already exists — so the one upstream call is
// the proxied request, and the chained token's arrival is what proves the chain:
// it differs from the token the local spec holds inline.
func TestCloudflare_KeylessChainServesVaultHeldToken(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, cloudflareEnv)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupCloudflareChain(t, subj)
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, cloudflareEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Bearer:     h.FullChainUserJWT(t),
				Role:       cloudflareChainAgentRole,
				Path:       "client/v4/zones",
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"Authorization": "Bearer " + cloudflareChainedAPIToken},
				Absent:        h.AlwaysAbsent(),
				UpstreamCalls: 1,
			})
		})
	}
}
