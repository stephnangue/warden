//go:build e2e

package fullchain

import (
	"fmt"
	"strings"
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
	dynatraceAPIToken = "fc-dynatrace-not-a-real-token"

	// The harness issuer's client secret for the OAuth arm. Asserted against, so
	// that handing it through unexchanged cannot pass for a minted token.
	dynatraceOAuthClientSecret = "agent-secret"
)

var dynatraceEnv = h.ProviderEnv{
	Mount:      "fc-dynatrace",
	Type:       "dynatrace",
	URLKey:     "dynatrace_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": dynatraceAPIToken},
}

// The OAuth arm needs an oauth_bearer_token credential, which no local source
// will hold — so it uses an oauth2 source against the harness issuer and mints
// for real, under the default client_credentials grant.
//
// It used to take the authorization_code path instead, whose driver returns the
// spec's static access_token verbatim, because that made the proxied header an
// exact constant. That relied on writing access_token into the spec by hand —
// a key the server seals at connect time and now refuses from an operator, so
// the shortcut is gone along with the hole it depended on. A live mint costs the
// exact assertion and buys a real token-endpoint round trip; what this row is
// actually for, that the credential *type* selects the scheme, is carried by the
// Bearer prefix, which no api_key credential would ever produce.
var dynatraceOAuthEnv = h.ProviderEnv{
	Mount:      "fc-dynatrace-oauth",
	Type:       "dynatrace",
	URLKey:     "dynatrace_url",
	CredType:   "oauth_bearer_token",
	SourceType: "oauth2",
	SourceConfig: map[string]string{
		"token_url":       h.HydraIssuer + "/oauth2/token",
		"client_id":       "e2e-agent",
		"client_secret":   dynatraceOAuthClientSecret,
		"tls_skip_verify": "true",
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

	// The API arm's credential is a constant, so the whole header is.
	t.Run("api token", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, dynatraceEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.FullChainUserJWT(t),
			Role:         dynatraceEnv.CertRole(),
		})

		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"Authorization": "Api-Token " + dynatraceAPIToken},
			Absent:        h.AlwaysAbsent(),
			UpstreamCalls: 1,
		})
	})

	// The OAuth arm's is whatever the issuer minted this run, so the assertions
	// are on shape: the scheme, which is the thing under test, and enough about
	// the value to rule out anything the request already carried arriving in its
	// place.
	t.Run("oauth token", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, dynatraceOAuthEnv, h.ChainOpts{
			AgentCertPEM: agentCert(t),
			Bearer:       h.FullChainUserJWT(t),
			Role:         dynatraceOAuthEnv.CertRole(),
		})

		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Absent:        h.AlwaysAbsent(),
			UpstreamCalls: 1,
		})

		authz := upstream.Last(t).Header.Get("Authorization")
		token, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok || token == "" {
			t.Fatalf("Authorization = %q, want a Bearer token — the scheme is what the credential type selects", authz)
		}
		if token == h.FullChainUserJWT(t) {
			t.Error("the caller's own JWT was forwarded as the credential")
		}
		if token == dynatraceOAuthClientSecret {
			t.Error("the client secret was forwarded unexchanged")
		}
		// The harness issuer signs JWTs, so a minted token is one. Anything else
		// means the mint was skipped and some other value rode through.
		if !strings.HasPrefix(token, "ey") {
			t.Errorf("credential %q is not a minted JWT", token)
		}
	})
}

// TestDynatrace_SealedOAuthKeysAreRefused pins the guard the fixture above used
// to depend on. access_token is documented as sealed at connect time; until the
// write path enforced that, this create returned 200 and the spec reported
// itself connected on the strength of a value an operator had typed.
//
// It is here rather than beside the other credential rows because this is the
// mount whose fixture the guard cost — leaving the two apart is how the reason
// for the conversion above gets lost.
func TestDynatrace_SealedOAuthKeysAreRefused(t *testing.T) {
	ensureEnv(t)

	for _, key := range []string{"access_token", "refresh_token"} {
		t.Run(key, func(t *testing.T) {
			specName := "fc-dynatrace-forged-" + key
			// A create that is refused leaves nothing, which is the point of the
			// row. Clean up anyway: on a binary without the guard it succeeds, and
			// the spec left behind pins the source and breaks the next run's setup
			// with a 409 rather than a readable failure.
			t.Cleanup(func() {
				h.APIRequest(t, "DELETE", "sys/cred/specs/"+specName, leaderPort, "")
			})

			payload := fmt.Sprintf(
				`{"type":"oauth_bearer_token","source":%q,"config":{"auth_method":"authorization_code","client_id":"e2e-agent",%q:"forged-by-the-operator"}}`,
				dynatraceOAuthEnv.Source(), key)

			status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+specName, leaderPort, payload)

			if status != 400 {
				t.Fatalf("spec create with a sealed %s: status %d, want 400 — body %s", key, status, body)
			}
			// The status alone is not enough. A forged refresh_token also draws a
			// 400 from the create-time test-mint, which fails when the issuer
			// rejects it — so a row asserting only the code would pass against a
			// binary with no guard at all. The refusal has to be this one.
			if !strings.Contains(string(body), "sealed") || !strings.Contains(string(body), key) {
				t.Errorf("want the sealed-key refusal naming %s; body = %s", key, body)
			}
		})
	}
}
