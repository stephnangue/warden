//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// honeycomb is the one provider whose credential data selects between two
// entirely different auth headers rather than two shapes of the same one. Which
// makes the mode selector — key_id — the thing worth pinning: it changes both the
// header name and the value's construction.
//
// The management branch used to be unreachable. It required a key_secret field no
// source could produce, so a mount configured for a management key answered every
// request with 401 rather than degrading to the ingest branch. It now reads the
// secret from api_key, which the credential type guarantees.

const (
	honeycombIngestKey = "fc-honeycomb-not-a-real-ingest-key"
	honeycombKeyID     = "fc-honeycomb-key-id"
	honeycombKeySecret = "fc-honeycomb-not-a-real-key-secret"
)

// The apikey source is deliberate, not incidental. On a local source every field
// of the spec config reaches the credential, so a management row would pass
// without naming key_id anywhere — and would hide the fact that the apikey driver
// carries only api_key plus the fields optional_metadata lists. Getting that wrong
// is silent: the credential mints, key_id is absent, and the mount quietly serves
// the ingest branch instead.
var honeycombEnv = h.ProviderEnv{
	Mount:        "fc-honeycomb",
	Type:         "honeycomb",
	URLKey:       "honeycomb_url",
	CredType:     "api_key",
	SourceType:   "apikey",
	SourceConfig: map[string]string{"optional_metadata": "key_id"},
	CredConfig:   map[string]string{"api_key": honeycombIngestKey},
	Variants: map[string]map[string]string{
		"mgmt": {"api_key": honeycombKeySecret, "key_id": honeycombKeyID},
	},
}

// TestHoneycomb_AuthModeFollowsKeyID drives both branches through one mount,
// changing only which spec the role binds.
//
// Each row asserts the other mode's header absent, which is where the value is:
// an extractor that emitted both would satisfy an injection-only assertion while
// sending the ingest key to an endpoint that must not receive it.
func TestHoneycomb_AuthModeFollowsKeyID(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name   string
		role   string
		want   map[string]string
		absent []string
	}{
		{
			name:   "ingest key, no key_id",
			role:   honeycombEnv.CertRole(),
			want:   map[string]string{"X-Honeycomb-Team": honeycombIngestKey},
			absent: []string{"Authorization"},
		},
		{
			name: "management key, key_id selects the mode",
			role: honeycombEnv.VariantRole("mgmt"),
			want: map[string]string{
				"Authorization": "Bearer " + honeycombKeyID + ":" + honeycombKeySecret,
			},
			absent: []string{"X-Honeycomb-Team"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, honeycombEnv, h.ChainOpts{
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

// TestHoneycomb_ClientSuppliedTeamHeaderIsStripped covers the strip, and it only
// bites in management mode: there the provider injects Authorization and never
// touches X-Honeycomb-Team, so without a strip list a caller's own value would
// ride to the upstream beside Warden's credential — an inbound credential
// proxying onward under the mount's identity.
//
// In ingest mode the same header is overwritten by injection, so a row there
// would pass whether or not the strip existed.
func TestHoneycomb_ClientSuppliedTeamHeaderIsStripped(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, honeycombEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         honeycombEnv.VariantRole("mgmt"),
		Headers:      map[string]string{"X-Honeycomb-Team": "caller-supplied-team-key"},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"Authorization": "Bearer " + honeycombKeyID + ":" + honeycombKeySecret,
		},
		Absent:        h.AlwaysAbsent("X-Honeycomb-Team"),
		UpstreamCalls: 1,
	})
}
