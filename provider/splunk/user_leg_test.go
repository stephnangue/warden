package splunk

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/listener"
	"github.com/stretchr/testify/assert"
)

func plainReq(headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/splunk/gateway/services/search/jobs", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func withCert(r *http.Request) *http.Request {
	return r.WithContext(listener.WithForwardedClientCert(r.Context(), &x509.Certificate{}))
}

// TestExtractTokens_SchemeDispatch covers the case where the provider's own
// agent credential already occupies Authorization. Splunk's native "Splunk"
// scheme is always the agent; "Bearer" becomes the user only once an agent has
// arrived out of band. Without this dispatch one of the two legs would have to
// be broken.
func TestExtractTokens_SchemeDispatch(t *testing.T) {
	t.Run("agent precedence with the user leg off", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			headers   map[string]string
			wantAgent string
		}{
			{"warden token wins", map[string]string{"X-Warden-Token": "w", "Authorization": "Splunk s"}, "w"},
			{"native Splunk scheme", map[string]string{"Authorization": "Splunk s"}, "s"},
			{"bearer fallback", map[string]string{"Authorization": "Bearer b"}, "b"},
			{"lowercase splunk scheme now matches", map[string]string{"Authorization": "splunk s"}, "s"},
			{"unknown scheme ignored", map[string]string{"Authorization": "Basic abc"}, ""},
			{"nothing", nil, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				agent, user := extractTokens(plainReq(tc.headers), false)
				assert.Equal(t, tc.wantAgent, agent)
				assert.Empty(t, user, "userLeg=false must never produce a user")
			})
		}
	})

	t.Run("native Splunk scheme is the agent and leaves no user slot", func(t *testing.T) {
		agent, user := extractTokens(plainReq(map[string]string{"Authorization": "Splunk s"}), true)
		assert.Equal(t, "s", agent)
		assert.Empty(t, user, "the agent occupies Authorization, so there is no user slot")
	})

	t.Run("Splunk scheme wins even under a client cert", func(t *testing.T) {
		agent, user := extractTokens(withCert(plainReq(map[string]string{"Authorization": "Splunk s"})), true)
		assert.Equal(t, "s", agent)
		assert.Empty(t, user)
	})

	t.Run("cert agent makes Bearer the user", func(t *testing.T) {
		agent, user := extractTokens(withCert(plainReq(map[string]string{"Authorization": "Bearer u"})), true)
		assert.Empty(t, agent, "an empty agent means the cert is the agent")
		assert.Equal(t, "u", user)
	})

	t.Run("agent-token header makes Bearer the user", func(t *testing.T) {
		agent, user := extractTokens(plainReq(map[string]string{
			"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("X-Warden-Token does not free Authorization for the user", func(t *testing.T) {
		// The operator credential never opens the user leg. See
		// logical.ExtractTokensDefault.
		agent, user := extractTokens(plainReq(map[string]string{
			"X-Warden-Token": "w", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "w", agent)
		assert.Empty(t, user)
	})
}
