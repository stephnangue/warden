//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// dynatrace is the only provider that accepts two different credential types and
// emits a different Authorization scheme for each — an API token under
// Dynatrace's own "Api-Token" scheme, an OAuth token under Bearer. The type
// decides, so covering it means two mounts rather than two roles on one: a role
// binds a spec, and the two specs need different types and different sources.
//
// Neither arm had any test at all before this.

const (
	dynatraceAPIToken   = "fc-dynatrace-not-a-real-token"
	dynatraceOAuthToken = "fc-dynatrace-not-a-real-oauth-token"
)

var dynatraceEnv = h.ProviderEnv{
	Mount:      "fc-dynatrace",
	Type:       "dynatrace",
	URLKey:     "dynatrace_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": dynatraceAPIToken},
}

// The OAuth arm needs an oauth_bearer_token credential, which no local source
// will hold — so it uses an oauth2 source, configured for the one mint path that
// touches no network.
//
// The default grant is client_credentials, which really does call the token
// endpoint; pointed at the harness's issuer it mints a live token whose value no
// assertion can predict, and the row would then be testing the OAuth2 driver
// rather than this provider's extractor. Under authorization_code the driver
// instead returns the spec's static access token verbatim — the path a provider
// that issues no refresh token takes — which keeps the assertion exact and the
// subject the extractor. token_url is required of the source either way and is
// never called here.
var dynatraceOAuthEnv = h.ProviderEnv{
	Mount:      "fc-dynatrace-oauth",
	Type:       "dynatrace",
	URLKey:     "dynatrace_url",
	CredType:   "oauth_bearer_token",
	SourceType: "oauth2",
	SourceConfig: map[string]string{
		"token_url":       h.HydraIssuer + "/oauth2/token",
		"tls_skip_verify": "true",
	},
	// auth_method belongs on the spec, where it is a declared field; the source
	// schema does not define it and would carry it only because unknown keys are
	// ignored. access_token is documented as sealed at connect time rather than
	// operator-set, but IsConnected accepts a hand-written value, so nothing
	// enforces it — this fixture leans on that gap to mint an OAuth credential
	// without a network call.
	CredConfig: map[string]string{
		"auth_method":  "authorization_code",
		"access_token": dynatraceOAuthToken,
	},
}

// TestDynatrace_CredentialTypeSelectsScheme drives both arms and asserts they
// differ. Either alone would show only that some credential reached the
// upstream; together they show the type is what chooses the scheme.
//
// The distinction is not cosmetic — Dynatrace rejects an API token presented as
// a Bearer, so a provider that collapsed the two arms would fail every request
// with a credential that is itself perfectly valid.
func TestDynatrace_CredentialTypeSelectsScheme(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name string
		env  h.ProviderEnv
		want string
	}{
		{"api token", dynatraceEnv, "Api-Token " + dynatraceAPIToken},
		{"oauth token", dynatraceOAuthEnv, "Bearer " + dynatraceOAuthToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, tc.env, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.env.CertRole(),
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"Authorization": tc.want},
				Absent:        h.AlwaysAbsent(),
				UpstreamCalls: 1,
			})
		})
	}
}
