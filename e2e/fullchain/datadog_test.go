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
//
// Both halves of the optional field are covered together, and they belong
// together: it is injected only when the credential carries one, so on a spec
// without an application key the same header arriving from a caller would ride
// through untouched. Reachable inbound and unstripped outbound were one problem.

const (
	datadogAPIKey = "fc-datadog-not-a-real-key"
	datadogAppKey = "fc-datadog-not-a-real-app-key"
)

// The apikey source declares the second field; api_key is the only one the
// credential type carries on its own. One declaration serves both specs.
var datadogEnv = h.ProviderEnv{
	Mount:        "fc-datadog",
	Type:         "datadog",
	URLKey:       "datadog_url",
	CredType:     "api_key",
	SourceType:   "apikey",
	SourceConfig: map[string]string{"optional_metadata": "application_key"},
	CredConfig:   map[string]string{"api_key": datadogAPIKey},
	Variants: map[string]map[string]string{
		"app": {"api_key": datadogAPIKey, "application_key": datadogAppKey},
	},
}

// TestDatadog_KeyHeadersFollowTheCredential covers both branches of the
// multi-field extractor: the required field always lands in its own header, and
// the optional one appears only when the credential has it.
//
// The absent assertion on the required-only row is what makes the pair
// meaningful — an extractor that emitted an empty DD-APPLICATION-KEY would
// satisfy an injection-only check while sending Datadog a header it must not
// receive.
func TestDatadog_KeyHeadersFollowTheCredential(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name   string
		role   string
		want   map[string]string
		absent []string
	}{
		{
			name: "api key only",
			role: datadogEnv.CertRole(),
			want: map[string]string{"DD-API-KEY": datadogAPIKey},
			// The credential rides its own header, leaving Authorization
			// untouched by injection — so a leaked caller credential would be
			// visible there rather than overwritten.
			absent: []string{"Authorization", "DD-APPLICATION-KEY"},
		},
		{
			name: "with an application key",
			role: datadogEnv.VariantRole("app"),
			want: map[string]string{
				"DD-API-KEY":         datadogAPIKey,
				"DD-APPLICATION-KEY": datadogAppKey,
			},
			absent: []string{"Authorization"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.role,
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      tc.want,
				Absent:        h.AlwaysAbsent(tc.absent...),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestDatadog_ClientSuppliedApplicationKeyIsStripped is the other half of the
// pair, and the reason the strip cannot wait.
//
// The header is conditionally injected, so without a strip list a caller could
// pair an application key of their own with the mount's API key — an inbound
// credential proxying onward under the mount's identity. The row drives the
// required-only spec deliberately: on the variant that carries one, injection
// would overwrite the caller's value and the assertion would hold either way.
func TestDatadog_ClientSuppliedApplicationKeyIsStripped(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, datadogEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         datadogEnv.CertRole(),
		Headers:      map[string]string{"DD-APPLICATION-KEY": "caller-supplied-app-key"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"DD-API-KEY": datadogAPIKey},
		Absent:        h.AlwaysAbsent("Authorization", "DD-APPLICATION-KEY"),
		UpstreamCalls: 1,
	})
}
