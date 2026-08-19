package newrelic

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/listener"
	"github.com/stretchr/testify/assert"
)

func certReq(headers map[string]string) *http.Request {
	return withCert(plainReq(headers))
}

func plainReq(headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/newrelic/gateway/v2/applications.json", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func withCert(r *http.Request) *http.Request {
	return r.WithContext(listener.WithForwardedClientCert(r.Context(), &x509.Certificate{}))
}

// TestExtractTokens covers both legs. With userLeg false the result must stay
// byte-identical to the pre-0.20 extractor, including this provider's own
// channel precedence; with userLeg true an out-of-band agent frees Authorization
// for the user.
func TestExtractTokens(t *testing.T) {
	t.Run("agent precedence with the user leg off", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			headers   map[string]string
			wantAgent string
		}{
			{"api key wins over warden token", map[string]string{"Api-Key": "k", "X-Warden-Token": "w"}, "k"},
			{"warden token over bearer", map[string]string{"X-Warden-Token": "w", "Authorization": "Bearer b"}, "w"},
			{"bearer fallback", map[string]string{"Authorization": "Bearer b"}, "b"},
			{"lowercase bearer now matches", map[string]string{"Authorization": "bearer b"}, "b"},
			{"nothing", nil, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				agent, user := extractTokens(plainReq(tc.headers), false)
				assert.Equal(t, tc.wantAgent, agent)
				assert.Empty(t, user, "userLeg=false must never produce a user")
			})
		}
	})

	t.Run("native channel frees Authorization for the user", func(t *testing.T) {
		agent, user := extractTokens(plainReq(map[string]string{
			"Api-Key": "ag", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("cert agent makes Authorization the user", func(t *testing.T) {
		agent, user := extractTokens(certReq(map[string]string{"Authorization": "Bearer u"}), true)
		assert.Empty(t, agent, "an empty agent means the cert is the agent")
		assert.Equal(t, "u", user)
	})

	t.Run("agent-token header is not shadowed by an ambient cert", func(t *testing.T) {
		agent, user := extractTokens(certReq(map[string]string{
			"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("lone bearer stays the agent", func(t *testing.T) {
		agent, user := extractTokens(plainReq(map[string]string{"Authorization": "Bearer a"}), true)
		assert.Equal(t, "a", agent)
		assert.Empty(t, user, "warden always has an agent; a bare bearer is it")
	})
}
