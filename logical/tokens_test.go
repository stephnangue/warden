package logical

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/listener"
	"github.com/stretchr/testify/assert"
)

// withCert returns r carrying a trusted client certificate the way the API
// listener's middleware presents one — via the request context, never a header.
func withCert(r *http.Request) *http.Request {
	return r.WithContext(listener.WithForwardedClientCert(r.Context(), &x509.Certificate{}))
}

func newReq(headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/github/gateway/user", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestExtractTokensDefault_UserLegOff is the byte-identity invariant the whole
// migration rests on: with no effective user_auth_path the rule must resolve the
// agent exactly as the pre-0.20 extractor did (X-Warden-Token, then
// Authorization: Bearer) and must never produce a user — no matter what else the
// request carries.
func TestExtractTokensDefault_UserLegOff(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		cert      bool
		wantAgent string
	}{
		{"lone bearer is the agent", map[string]string{"Authorization": "Bearer a"}, false, "a"},
		{"warden token wins over bearer", map[string]string{"X-Warden-Token": "w", "Authorization": "Bearer a"}, false, "w"},
		{"lowercase bearer", map[string]string{"Authorization": "bearer a"}, false, "a"},
		{"non-bearer scheme ignored", map[string]string{"Authorization": "Basic abc"}, false, ""},
		{"nothing", nil, false, ""},

		// The two channels that would otherwise free Authorization are inert.
		{"agent-token header ignored", map[string]string{"X-Warden-Agent-Token": "ag", "Authorization": "Bearer a"}, false, "a"},
		{"cert does not shift Authorization", map[string]string{"Authorization": "Bearer a"}, true, "a"},
		{"cert with no bearer", nil, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(tc.headers)
			if tc.cert {
				r = withCert(r)
			}
			agent, user := ExtractTokensDefault(r, false)
			assert.Equal(t, tc.wantAgent, agent)
			assert.Empty(t, user, "userLeg=false must never produce a user")
		})
	}
}

func TestExtractTokensDefault_UserLegOn(t *testing.T) {
	t.Run("warden token does NOT free Authorization for the user", func(t *testing.T) {
		// X-Warden-Token is the operator credential; gateway traffic is the
		// workload surface. Leaving it out of the user leg keeps exactly two
		// out-of-band agent channels — the dedicated header and mTLS — and
		// makes step 1 behave identically on both legs.
		agent, user := ExtractTokensDefault(newReq(map[string]string{
			"X-Warden-Token": "w", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "w", agent)
		assert.Empty(t, user)
	})

	t.Run("agent-token header frees Authorization for the user", func(t *testing.T) {
		agent, user := ExtractTokensDefault(newReq(map[string]string{
			"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("agent-token header is not shadowed by an ambient cert", func(t *testing.T) {
		// A service-mesh sidecar makes a forwarded cert present on nearly every
		// request. Testing the cert first would mis-attribute the workload to
		// the sidecar's identity, so the dedicated channel must win.
		r := withCert(newReq(map[string]string{
			"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u",
		}))
		agent, user := ExtractTokensDefault(r, true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("cert is the agent, signalled by an empty agent", func(t *testing.T) {
		r := withCert(newReq(map[string]string{"Authorization": "Bearer u"}))
		agent, user := ExtractTokensDefault(r, true)
		assert.Empty(t, agent, "an empty agent means the cert is the agent")
		assert.Equal(t, "u", user)
	})

	t.Run("lone bearer with no agent channel stays the agent", func(t *testing.T) {
		// Warden always has an agent; a bare bearer is it, not a user.
		agent, user := ExtractTokensDefault(newReq(map[string]string{"Authorization": "Bearer a"}), true)
		assert.Equal(t, "a", agent)
		assert.Empty(t, user)
	})
}

// TestExtractTokensDefault_ForgedCertHeaders proves a client cannot shift
// Authorization by forging the forwarding headers. Only the request context —
// populated by the listener middleware after its trusted-proxy check — counts.
func TestExtractTokensDefault_ForgedCertHeaders(t *testing.T) {
	for _, h := range []string{"X-SSL-Client-Cert", "X-Forwarded-Client-Cert"} {
		t.Run(h, func(t *testing.T) {
			r := newReq(map[string]string{h: "<pem>", "Authorization": "Bearer a"})
			agent, user := ExtractTokensDefault(r, true)
			assert.Equal(t, "a", agent, "a forged cert header must not make the bearer a user")
			assert.Empty(t, user)
		})
	}
}

func TestExtractTokensWithChannels(t *testing.T) {
	t.Run("first matching channel wins and frees Authorization", func(t *testing.T) {
		agent, user := ExtractTokensWithChannels(newReq(map[string]string{
			"X-Vault-Token": "v", "Authorization": "Bearer u",
		}), true, "X-Warden-Token", "X-Vault-Token")
		assert.Equal(t, "v", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("channel order is preserved", func(t *testing.T) {
		agent, _ := ExtractTokensWithChannels(newReq(map[string]string{
			"Api-Key": "k", "X-Warden-Token": "w",
		}), false, "Api-Key", "X-Warden-Token")
		assert.Equal(t, "k", agent, "the provider's own precedence must be honoured")
	})

	t.Run("falls through to Authorization as agent", func(t *testing.T) {
		agent, user := ExtractTokensWithChannels(newReq(map[string]string{
			"Authorization": "Bearer a",
		}), false, "X-Vault-Token")
		assert.Equal(t, "a", agent)
		assert.Empty(t, user)
	})
}

func TestStripScheme(t *testing.T) {
	assert.Equal(t, "tok", StripScheme("Bearer tok", "Bearer "))
	assert.Equal(t, "tok", StripScheme("bearer tok", "Bearer "), "scheme match is case-insensitive")
	assert.Equal(t, "tok", StripScheme("ApiKey tok", "ApiKey "))
	assert.Empty(t, StripScheme("Basic abc", "Bearer "))
	assert.Empty(t, StripScheme("Bearer ", "Bearer "), "an empty remainder is not a token")
	assert.Equal(t, " tok", StripScheme("Bearer  tok", "Bearer "), "the remainder is verbatim, not trimmed")
}
