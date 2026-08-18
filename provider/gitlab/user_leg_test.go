package gitlab

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractTokens_UserLeg covers GitLab's user leg, including the git
// smart-HTTP shape where a cert agent frees the Basic password slot while the
// username still names the AGENT's auth role.
//
// GitLab is the provider whose precedence the default rule would have broken:
// it reads Authorization: Bearer AHEAD of X-Warden-Token. That order predates
// the user leg and must survive with userLeg false.
func TestExtractTokens_UserLeg(t *testing.T) {
	const repo = "/v1/gitlab/gateway/group/repo.git/info/refs"
	const api = "/v1/gitlab/gateway/api/v4/user"

	t.Run("Bearer still outranks X-Warden-Token with the user leg off", func(t *testing.T) {
		r := httptest.NewRequest("GET", api, nil)
		r.Header.Set("Authorization", "Bearer b")
		r.Header.Set("X-Warden-Token", "w")
		agent, user := extractTokens(r, false)
		assert.Equal(t, "b", agent, "the pre-0.20 precedence must be preserved")
		assert.Empty(t, user)
	})

	t.Run("PRIVATE-TOKEN frees Authorization for the user", func(t *testing.T) {
		r := httptest.NewRequest("GET", api, nil)
		r.Header.Set("PRIVATE-TOKEN", "pt")
		r.Header.Set("Authorization", "Bearer u")
		agent, user := extractTokens(r, true)
		assert.Equal(t, "pt", agent)
		assert.Equal(t, "u", user)
	})

	t.Run("cert agent takes the user from the Basic password", func(t *testing.T) {
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "eyJ.user.jwt")
		agent, user := extractTokens(withClientCert(r), true)
		assert.Empty(t, agent, "an empty agent means the cert is the agent")
		assert.Equal(t, "eyJ.user.jwt", user)
	})

	t.Run("cert agent takes the user from an explicit Bearer", func(t *testing.T) {
		// Bearer and Basic are the same header, so a request can only ever
		// carry one of them — this is the http.extraHeader shape, not a
		// precedence test.
		r := httptest.NewRequest("GET", repo, nil)
		r.Header.Set("Authorization", "Bearer bearer-user-token")
		agent, user := extractTokens(withClientCert(r), true)
		assert.Empty(t, agent)
		assert.Equal(t, "bearer-user-token", user)
	})

	t.Run("agent-token header frees both slots for the user", func(t *testing.T) {
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "eyJ.user.jwt")
		r.Header.Set("X-Warden-Agent-Token", "eyJ.agent.jwt")
		agent, user := extractTokens(r, true)
		assert.Equal(t, "eyJ.agent.jwt", agent)
		assert.Equal(t, "eyJ.user.jwt", user)
	})

	t.Run("Basic agent with no cert has no user leg", func(t *testing.T) {
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "eyJ.agent.jwt")
		agent, user := extractTokens(r, true)
		assert.Equal(t, "eyJ.agent.jwt", agent)
		assert.Empty(t, user, "with no out-of-band agent the password stays the agent")
	})
}

// TestExtractTokens_WardenTokenOrderUnchanged pins that GitLab needs no
// user-leg special case. Its legacy Bearer-before-X-Warden-Token order is safe
// on both legs precisely because X-Warden-Token never opens the user leg: there
// is no shape in which a user token could be resolved as the agent here.
func TestExtractTokens_WardenTokenOrderUnchanged(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
	r.Header.Set("X-Warden-Token", "w")
	r.Header.Set("Authorization", "Bearer u")

	for _, userLeg := range []bool{false, true} {
		agent, user := extractTokens(r, userLeg)
		assert.Equal(t, "u", agent, "the legacy Bearer-first order holds on both legs")
		assert.Empty(t, user)
	}
}

// TestExtractTokens_PlaceholderPassword pins the escape for cert-authenticated
// git clients. Git mandates a password whenever it does Basic auth, so a client
// with no user token still has to send something — conventionally "x". That
// placeholder must NOT be captured as a user credential: doing so fails
// validation and 401s a request that proceeds fine on a mount without
// user_auth_path. Requiring the JWT shape is free, because every mount format
// that can authenticate the user leg requires a JWT anyway.
func TestExtractTokens_PlaceholderPassword(t *testing.T) {
	const repo = "/v1/gitlab/gateway/group/repo.git/info/refs"

	for _, placeholder := range []string{"x", "placeholder", "unused", "-"} {
		t.Run(placeholder, func(t *testing.T) {
			r := httptest.NewRequest("GET", repo, nil)
			r.SetBasicAuth("agent-role", placeholder)
			agent, user := extractTokens(withClientCert(r), true)
			assert.Empty(t, agent, "the cert is the agent")
			assert.Empty(t, user, "a non-JWT password is a git placeholder, not a user credential")
		})
	}

	t.Run("a JWT-shaped password is still taken", func(t *testing.T) {
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "eyJ.real.user")
		_, user := extractTokens(withClientCert(r), true)
		assert.Equal(t, "eyJ.real.user", user)
	})

	t.Run("an empty password is also no user", func(t *testing.T) {
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "")
		_, user := extractTokens(withClientCert(r), true)
		assert.Empty(t, user)
	})
}
