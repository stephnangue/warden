//go:build e2e

package userleg

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// =============================================================================
// The user leg: two principals on one request
// =============================================================================
//
// The agent arrives out of band — a client certificate, or X-Warden-Agent-Token
// — which frees Authorization to carry a USER credential. These are the only
// tests in the suite that run with an effective user_auth_path, so without them
// the entire feature could regress unnoticed.

// challengeOf returns the WWW-Authenticate header, failing if absent.
func challengeOf(t *testing.T, hdrs map[string][]string) string {
	t.Helper()
	v := hdrs["Www-Authenticate"]
	if len(v) == 0 {
		t.Fatal("expected a WWW-Authenticate header; RFC 7235 requires one on a 401")
	}
	return v[0]
}

// TestUserLeg_MissingUserChallengesWithDiscoverableMetadata is the bootstrap the
// whole feature exists for: a request that needs a user but has none must not
// merely fail — it must say where to go, and that URL must actually resolve.
//
// The second half is the part only e2e can check. The challenge URL and the
// metadata endpoint are built independently; if they drift, a client follows the
// link, gets a 404, and never learns where to authenticate.
func TestUserLeg_MissingUserChallengesWithDiscoverableMetadata(t *testing.T) {
	ensureEnv(t)
	port := leaderPort
	cert := agentCert(t)

	// A spec requiring a user is not configured on this mount, so a plain
	// request succeeds; what we assert here is the challenge shape when the
	// user leg is engaged but no user credential is present. Use an explicitly
	// invalid user token to force the user-authentication failure path.
	status, _, hdrs := h.DoRequestWithResponseHeaders(t, "GET",
		h.NodeURL(port)+"/v1/"+h.UserLegMount+"/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Role":     "e2e-userleg-agent",
			"X-SSL-Client-Cert": h.URLEncodePEM(cert),
			"Authorization":     "Bearer not-a-valid-user-token",
		}, "")

	if status != 401 {
		t.Fatalf("an unusable user credential must be 401 (clients begin discovery there), got %d", status)
	}

	challenge := challengeOf(t, hdrs)
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("challenge must name where to authenticate: %q", challenge)
	}
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("a presented-and-rejected credential should say so: %q", challenge)
	}

	// Follow the link exactly as a client would.
	url := extractResourceMetadata(t, challenge)
	fetchStatus, body := h.DoRequest(t, "GET", url, nil, "")
	if fetchStatus != 200 {
		t.Fatalf("the challenge named %s, which returned %d — the bootstrap dies here", url, fetchStatus)
	}

	var doc prmDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("challenge pointed at something that is not a metadata document: %v", err)
	}
	if len(doc.AuthorizationServers) == 0 {
		t.Error("the document a challenge names must tell the client which authorization server to use")
	}
}

// extractResourceMetadata pulls the URL out of a WWW-Authenticate challenge the
// way a client would.
func extractResourceMetadata(t *testing.T, challenge string) string {
	t.Helper()
	const key = `resource_metadata="`
	i := strings.Index(challenge, key)
	if i < 0 {
		t.Fatalf("no resource_metadata in %q", challenge)
	}
	rest := challenge[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated resource_metadata in %q", challenge)
	}
	return rest[:j]
}

// TestUserLeg_CertAgentWithUserSucceeds is the happy path, and the only place
// the two principals are proven distinct end to end: the audit entry must
// attribute the request to the USER, not the agent.
func TestUserLeg_CertAgentWithUserSucceeds(t *testing.T) {
	ensureEnv(t)
	port := leaderPort
	cert := agentCert(t)
	userJWT := h.UserJWT(t)

	status, body := h.UserLegRequest(t, port, cert, map[string]string{
		"Authorization": "Bearer " + userJWT,
	})
	if status != 200 {
		t.Fatalf("cert agent + valid user should succeed, got %d: %s", status, string(body))
	}

	// The user principal is identity-only and never authorizes the request, so
	// the audit trail is where its effect is observable.
	assertUserAttributed(t, port, "e2e-pipeline")
}

// TestUserLeg_AgentTokenHeaderWithUserSucceeds covers the non-mTLS shape: an
// agent that presents a JWT on the dedicated header, leaving Authorization for
// the user. This is the flow a bearer-JWT or service-mesh agent uses.
func TestUserLeg_AgentTokenHeaderWithUserSucceeds(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	// Repoint the mount's agent leg at the JWT auth mount, leaving the user leg
	// intact. Restored afterwards so test ordering cannot matter.
	//
	// A dedicated role is needed: e2e-reader's policy grants vault/gateway*, not
	// this mount, so reusing it would fail authorization rather than exercise the
	// agent channel.
	h.CreateUserLegJWTRole(t, port)
	h.SetUserLegAgentPath(t, port, "auth/jwt/", h.UserLegJWTRole)
	defer restoreEnv(t)

	status, body := h.DoRequest(t, "GET",
		h.NodeURL(port)+"/v1/"+h.UserLegMount+"/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Agent-Token": h.GetDefaultJWT(t),
			"Authorization":        "Bearer " + h.UserJWT(t),
			"X-Warden-Role":        h.UserLegJWTRole,
		}, "")

	if status != 200 {
		t.Fatalf("agent-token header + user on Authorization should succeed, got %d: %s", status, string(body))
	}
	assertUserAttributed(t, port, "e2e-pipeline")
}

// TestUserLeg_OperatorTokenPlusUserIsRejected pins the one genuinely ambiguous
// combination. X-Warden-Token is the operator credential and carries no user;
// Authorization is where the user rides. Presenting both means one of the two is
// silently discarded, so it is refused with an explanation instead.
func TestUserLeg_OperatorTokenPlusUserIsRejected(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	rootToken := h.RootToken(t)
	status, body := h.DoRequest(t, "GET",
		h.NodeURL(port)+"/v1/"+h.UserLegMount+"/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Token": rootToken,
			"Authorization":  "Bearer " + h.UserJWT(t),
		}, "")

	if status != 400 {
		t.Fatalf("operator token + user credential must be refused with 400, got %d: %s", status, string(body))
	}
	if !strings.Contains(string(body), "X-Warden-Agent-Token") {
		t.Errorf("the error should name the fix, got: %s", string(body))
	}
}

// TestUserLeg_NonOptedInMountUnchanged is the compatibility half stated as a
// test: on a mount without user_auth_path the same headers must behave exactly
// as they did before the feature existed — Authorization is the agent, and no
// ambiguity rejection fires.
func TestUserLeg_NonOptedInMountUnchanged(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	// vault/ has auto_auth_path but no user_auth_path.
	status, body := h.DoRequest(t, "GET",
		h.NodeURL(port)+"/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config",
		map[string]string{"Authorization": "Bearer " + h.GetDefaultJWT(t)}, "")

	if status != 200 {
		t.Fatalf("a bearer JWT must still authenticate the agent on a non-opted-in mount, got %d: %s",
			status, string(body))
	}

	// And the ambiguity rejection must NOT fire here. Asserted on the message
	// rather than the status: this mount can 400 for unrelated reasons (a root
	// token carries no credential spec), and a bare status check would pass or
	// fail for the wrong reason.
	_, body = h.DoRequest(t, "GET",
		h.NodeURL(port)+"/v1/vault/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Token": h.RootToken(t),
			"Authorization":  "Bearer " + h.GetDefaultJWT(t),
		}, "")
	if strings.Contains(string(body), "cannot be combined with an Authorization credential") {
		t.Error("the ambiguity rejection must be scoped to protected-resource mounts")
	}
}

// TestUserLeg_ChallengeOmitsMetadataWhenUnconfigured verifies the challenge
// degrades honestly: RFC 7235 still requires a challenge on a 401, but naming a
// document that would 404 is worse than naming none.
func TestUserLeg_ChallengeOmitsMetadataWhenUnconfigured(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	h.DisableProtectedResourceMetadata(t, port)
	defer restoreEnv(t)

	cert := agentCert(t)
	status, _, hdrs := h.DoRequestWithResponseHeaders(t, "GET",
		h.NodeURL(port)+"/v1/"+h.UserLegMount+"/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Role":     "e2e-userleg-agent",
			"X-SSL-Client-Cert": h.URLEncodePEM(cert),
			"Authorization":     "Bearer not-a-valid-user-token",
		}, "")

	if status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
	challenge := challengeOf(t, hdrs)
	if strings.Contains(challenge, "resource_metadata=") {
		t.Errorf("no document is served, so none should be named: %q", challenge)
	}
	if !strings.Contains(challenge, "Bearer") {
		t.Errorf("a 401 must still carry a challenge: %q", challenge)
	}
}

// assertUserAttributed polls the audit log for an entry attributing a request to
// the given user subject. Polls because audit writes are not synchronous with
// the response, matching how the existing audit tests read the log.
func assertUserAttributed(t *testing.T, port int, wantSubject string) {
	t.Helper()
	nodeNum := h.NodeNumberForPort(port)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range h.ReadAuditEntries(t, nodeNum, h.UserLegMount) {
			if e.Auth != nil && e.Auth.User != nil && strings.Contains(e.Auth.User.Subject, wantSubject) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("no audit entry attributed the request to user %q — the user principal never reached the mint path", wantSubject)
}
