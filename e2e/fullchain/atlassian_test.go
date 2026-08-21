//go:build e2e

package fullchain

import (
	"encoding/base64"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// atlassian picks between two auth schemes on the presence of a second
// credential field, and unusually it is the *fallback* that was reachable: with
// no way to carry an email, every mount sent Bearer, while Atlassian Cloud API
// tokens authenticate with Basic email:token. The branch that works against the
// real service was the dead one.
//
// Both rows drive the same mount and the same token, differing only in which
// spec the role binds — so what they isolate is the field, not the setup.

const (
	atlassianToken = "fc-atlassian-not-a-real-token"
	atlassianEmail = "fc-svc@example.com"
)

// The source declares email; api_key is the only field the credential type
// carries on its own. The default spec deliberately omits it, so the Bearer
// fallback stays covered rather than becoming unreachable in turn.
var atlassianEnv = h.ProviderEnv{
	Mount:        "fc-atlassian",
	Type:         "atlassian",
	URLKey:       "atlassian_url",
	CredType:     "api_key",
	SourceType:   "apikey",
	SourceConfig: map[string]string{"credential_fields": "email"},
	CredConfig:   map[string]string{"api_key": atlassianToken},
	Variants: map[string]map[string]string{
		"basic": {"api_key": atlassianToken, "email": atlassianEmail},
	},
}

// TestAtlassian_SchemeFollowsTheEmailField covers both branches of the
// extractor.
//
// The Basic value is asserted as the exact encoded pair rather than merely
// "starts with Basic": the whole point of the field is which identity the token
// authenticates as, and an extractor that encoded the wrong half — or encoded
// the token alone — would pass a prefix check while authenticating as nobody.
func TestAtlassian_SchemeFollowsTheEmailField(t *testing.T) {
	ensureEnv(t)

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(atlassianEmail+":"+atlassianToken))

	cases := []struct {
		name string
		role string
		want string
	}{
		{
			name: "token only falls back to Bearer",
			role: atlassianEnv.CertRole(),
			want: "Bearer " + atlassianToken,
		},
		{
			name: "an email switches to Basic",
			role: atlassianEnv.VariantRole("basic"),
			want: basic,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, atlassianEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.role,
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
