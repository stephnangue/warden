//go:build e2e

package githttp

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// basicAuth renders a Basic credential the way git does.
func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// gitURL is the full smart-HTTP probe URL for the fixture repository.
func gitURL() string {
	return h.NodeURL(leaderPort) + "/v1/" + h.GitSmartHTTPPath()
}

// certHeaders presents the agent as a client certificate.
func certHeaders(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"X-SSL-Client-Cert": h.URLEncodePEM(agentCert(t))}
}

// TestGitProbePassesThroughUnderCertAgent is the regression test for the bug
// this suite exists for.
//
// Git's opening info/refs carries no Authorization, and for git the role rides
// in the Basic username and the user credential in the Basic password — so a
// probe forced through authentication has neither and fails for want of a role.
// It has to reach the upstream, whose challenge is what teaches git to retry
// with credentials at all.
func TestGitProbePassesThroughUnderCertAgent(t *testing.T) {
	ensureEnv(t)

	status, body, respHeaders := h.DoRequestWithResponseHeaders(t, "GET",
		gitURL(), certHeaders(t), "")

	require.Equal(t, http.StatusUnauthorized, status,
		"the upstream's challenge must be relayed, not swallowed: %s", string(body))
	assert.Contains(t, http.Header(respHeaders).Get("WWW-Authenticate"), "Basic",
		"without a Basic challenge git cannot know which scheme to retry with")

	reqs := upstream.Requests()
	require.Len(t, reqs, 1, "the probe must reach the upstream exactly once")
	assert.Empty(t, reqs[0].Authorization,
		"a passthrough probe mints nothing and must inject nothing")
}

// TestGitSecondPassMintsAndWithholdsUserCredential covers the retry git makes
// after that challenge: the agent stays on the certificate, the role arrives as
// the Basic username and the user identity as the Basic password.
//
// The assertion that matters is the negative one — the user's own credential
// must never proxy onward. What reaches the upstream is the credential Warden
// minted for it.
func TestGitSecondPassMintsAndWithholdsUserCredential(t *testing.T) {
	ensureEnv(t)

	userJWT := h.UserJWT(t)
	headers := certHeaders(t)
	headers["Authorization"] = basicAuth(h.GitAgentCertRole, userJWT)

	status, body := h.DoRequest(t, "GET", gitURL(), headers, "")
	require.Equal(t, http.StatusOK, status,
		"cert agent plus a user credential must authenticate: %s", string(body))

	last := upstream.Last(t)
	assert.Equal(t, basicAuth("x-access-token", h.GitPAT), last.Authorization,
		"the upstream must receive the minted credential")
	assert.NotContains(t, last.Authorization, userJWT,
		"the user's own credential must never proxy upstream")

	for _, header := range []string{"X-Warden-Token", "X-Warden-Agent-Token", "X-Ssl-Client-Cert"} {
		assert.Empty(t, last.Header.Get(header),
			"%s must be stripped before the request leaves Warden", header)
	}
}

// TestGitPerUserAttribution proves the user principal reached the mint path and
// was recorded. Attribution is the only record that a clone was performed for a
// specific person rather than by the agent alone.
func TestGitPerUserAttribution(t *testing.T) {
	ensureEnv(t)

	headers := certHeaders(t)
	headers["Authorization"] = basicAuth(h.GitAgentCertRole, h.UserJWT(t))

	status, body := h.DoRequest(t, "GET", gitURL(), headers, "")
	require.Equal(t, http.StatusOK, status, string(body))

	nodeNum := h.NodeNumberForPort(leaderPort)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range h.ReadAuditEntries(t, nodeNum, h.GitMount) {
			if e.Auth != nil && e.Auth.User != nil && strings.Contains(e.Auth.User.Subject, "e2e-pipeline") {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Error("no audit entry attributed the clone to the user — the user principal never reached the mint path")
}

// TestGitHeaderAgentProbeIsChallenged covers the shape with no passthrough: an
// agent on X-Warden-Agent-Token is authenticated rather than passed through, so
// no upstream response will be relayed. Warden must issue the challenge itself,
// or git is told a request failed with no indication that retrying would help.
func TestGitHeaderAgentProbeIsChallenged(t *testing.T) {
	ensureEnv(t)
	defer restoreEnv(t)

	// Repoint the agent leg at JWT so the header channel is the one in play.
	h.SetGitAgentPath(t, leaderPort, upstream.URL, "auth/jwt/", h.GitUserAuthMount, "")

	status, body, respHeaders := h.DoRequestWithResponseHeaders(t, "GET", gitURL(),
		map[string]string{"X-Warden-Agent-Token": h.GetDefaultJWT(t)}, "")

	require.Equal(t, http.StatusUnauthorized, status,
		"a probe with no resolvable role must fail: %s", string(body))
	assert.Equal(t, `Basic realm="warden"`, http.Header(respHeaders).Get("WWW-Authenticate"),
		"RFC 7235 requires a challenge on a 401, and here it is also the only way "+
			"the client learns to retry with the role in the Basic username")

	assert.Empty(t, upstream.Requests(),
		"an authenticated agent must not be passed through to the upstream")
}

// TestGitProbeCompatibilityOffUserLeg pins the unchanged behaviour of a mount
// that never opted in. There the Basic password is the agent's own credential
// and no user is captured, exactly as before the user leg existed.
func TestGitProbeCompatibilityOffUserLeg(t *testing.T) {
	ensureEnv(t)
	defer restoreEnv(t)

	h.SetGitAgentPath(t, leaderPort, upstream.URL, "auth/cert/", "", "")

	// The probe still passes through: off the user leg an empty agent has always
	// meant "no credential", and that is what a probe carries.
	status, _, respHeaders := h.DoRequestWithResponseHeaders(t, "GET", gitURL(), certHeaders(t), "")
	require.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, http.Header(respHeaders).Get("WWW-Authenticate"), "Basic")

	upstream.Reset()

	// And the retry authenticates on the Basic password as the agent's own
	// credential rather than a user's.
	headers := certHeaders(t)
	headers["Authorization"] = basicAuth(h.GitAgentCertRole, "x")

	status, body := h.DoRequest(t, "GET", gitURL(), headers, "")
	require.Equal(t, http.StatusOK, status,
		"a non-JWT password is git's mandatory placeholder and must be ignored: %s", string(body))
	assert.Equal(t, basicAuth("x-access-token", h.GitPAT), upstream.Last(t).Authorization)
}
