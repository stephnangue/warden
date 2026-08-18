package github

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractTokens_UserLeg covers the git smart-HTTP user leg. When the agent
// authenticates with a client certificate, neither Basic slot is needed for the
// agent: the username still names the AGENT's auth role (read separately by
// GetAuthRoleFromRequest) and the password comes free for the user. That makes
// https://<agent-role>:<user-token>@host/... work with no client configuration.
func TestExtractTokens_UserLeg(t *testing.T) {
	const repo = "/v1/github/gateway/owner/repo.git/info/refs"

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
		// The unchanged 0.19 shape: the password IS the agent.
		r := httptest.NewRequest("GET", repo, nil)
		r.SetBasicAuth("agent-role", "eyJ.agent.jwt")
		agent, user := extractTokens(r, true)
		assert.Equal(t, "eyJ.agent.jwt", agent)
		assert.Empty(t, user, "with no out-of-band agent the password stays the agent")
	})

	t.Run("cert agent with no credential at all yields neither", func(t *testing.T) {
		// Git's first info/refs probe. Both legs empty; the cert still
		// authenticates the agent downstream.
		r := httptest.NewRequest("GET", repo, nil)
		agent, user := extractTokens(withClientCert(r), true)
		assert.Empty(t, agent)
		assert.Empty(t, user)
	})

	t.Run("REST path behaves the same", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		r.Header.Set("Authorization", "Bearer user-token")
		agent, user := extractTokens(withClientCert(r), true)
		assert.Empty(t, agent)
		assert.Equal(t, "user-token", user, "an explicit Bearer is taken verbatim, JWT-shaped or not")
	})
}

// TestExtractTokens_PlaceholderPassword pins the escape for cert-authenticated
// git clients. Git mandates a password whenever it does Basic auth, so a client
// with no user token still has to send something — conventionally "x". That
// placeholder must NOT be captured as a user credential: doing so fails
// validation and 401s a request that proceeds fine on a mount without
// user_auth_path. Requiring the JWT shape is free, because every mount format
// that can authenticate the user leg requires a JWT anyway.
func TestExtractTokens_PlaceholderPassword(t *testing.T) {
	const repo = "/v1/github/gateway/owner/repo.git/info/refs"

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
