//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// ovh is the dual-mode gateway whose credential is minted rather than held.
// scaleway and cloudflare both sit on a local source, so their rows prove the
// injection but not the mint; this one exchanges a service account for a bearer
// token on every request.
//
// The exchange is a plain OAuth2 client_credentials grant, so Hydra can issue
// it — reached through the source's token_url, which exists because a
// deployment's service-account tokens need not come from ovh.com. Without that
// override the regional endpoint map is the only answer and every mint would
// call the vendor for real.

const ovhClientSecret = "agent-secret"

var ovhEnv = h.ProviderEnv{
	Mount:      "fc-ovh",
	Type:       "ovh",
	URLKey:     "ovh_url",
	CredType:   "ovh_keys",
	SourceType: "ovh",
	SourceConfig: map[string]string{
		"client_id":       "e2e-agent",
		"client_secret":   ovhClientSecret,
		"token_url":       h.HydraIssuer + "/oauth2/token",
		"tls_skip_verify": "true",
	},
	CredConfig: map[string]string{"mint_method": "oauth2_token"},
}

// TestOVH_MintedTokenReachesUpstream drives the whole chain including the
// credential exchange: the source trades its service account for a bearer
// token, and that token — not the caller's — is what the upstream sees.
func TestOVH_MintedTokenReachesUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, ovhEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         ovhEnv.CertRole(),
		Path:         "me",
	})

	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	got := upstream.Last(t)
	authz := got.Header.Get("Authorization")

	// The value is whatever Hydra minted this run, so it cannot be compared to a
	// constant. What it must not be is anything the request already had, or the
	// service account itself: forwarding the caller's bearer, or handing the
	// client_secret through unexchanged, would both leave a plausible-looking
	// Bearer on the wire.
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok || token == "" {
		t.Fatalf("Authorization = %q, want a Bearer token", authz)
	}
	if token == h.FullChainUserJWT(t) {
		t.Error("the caller's own JWT was forwarded as the credential")
	}
	if token == ovhClientSecret {
		t.Error("the service account secret was forwarded unexchanged")
	}
	// Hydra issues JWTs, so a minted token is one. Anything else means the mint
	// was skipped and some other value rode through.
	if !strings.HasPrefix(token, "ey") {
		t.Errorf("credential %q is not a minted JWT", token)
	}
	if got.Path != "/me" {
		t.Errorf("upstream path = %q, want /me", got.Path)
	}
}
