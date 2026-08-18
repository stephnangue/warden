package elastic

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/listener"
	"github.com/stretchr/testify/assert"
)

func withClientCert(r *http.Request) *http.Request {
	return r.WithContext(listener.WithForwardedClientCert(r.Context(), &x509.Certificate{}))
}

// TestExtractTokens_SchemeDispatch covers the case where the provider's own
// agent credential already occupies Authorization. Elasticsearch's native
// "ApiKey" scheme is always the agent; "Bearer" becomes the user only once an
// agent has arrived out of band. Without this dispatch one of the two legs
// would have to be broken.
func TestExtractTokens_SchemeDispatch(t *testing.T) {
	newReq := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest("GET", "/v1/elastic/gateway/_search", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	t.Run("native ApiKey scheme is the agent and leaves no user slot", func(t *testing.T) {
		agent, user := extractTokens(newReq(map[string]string{"Authorization": "ApiKey k"}), true)
		assert.Equal(t, "k", agent)
		assert.Empty(t, user, "the agent occupies Authorization, so there is no user slot")
	})

	t.Run("ApiKey wins even under a client cert", func(t *testing.T) {
		r := withClientCert(newReq(map[string]string{"Authorization": "ApiKey k"}))
		agent, user := extractTokens(r, true)
		assert.Equal(t, "k", agent)
		assert.Empty(t, user)
	})

	t.Run("cert agent makes Bearer the user", func(t *testing.T) {
		r := withClientCert(newReq(map[string]string{"Authorization": "Bearer u"}))
		agent, user := extractTokens(r, true)
		assert.Empty(t, agent, "an empty agent means the cert is the agent")
		assert.Equal(t, "u", user)
	})

	t.Run("agent-token header makes Bearer the user", func(t *testing.T) {
		agent, user := extractTokens(newReq(map[string]string{
			"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u",
		}), true)
		assert.Equal(t, "ag", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("userLeg off keeps the 0.19 precedence", func(t *testing.T) {
		for _, tc := range []struct{ header, want string }{
			{"ApiKey k", "k"},
			{"Bearer b", "b"},
		} {
			agent, user := extractTokens(newReq(map[string]string{"Authorization": tc.header}), false)
			assert.Equal(t, tc.want, agent)
			assert.Empty(t, user)
		}
	})
}
