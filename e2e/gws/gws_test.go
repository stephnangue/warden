//go:build e2e

package gws

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const profile = "gmail.googleapis.com/gmail/v1/users/me/profile"

// The whole delegated path: Warden's assertion names the user, Google signs a
// delegation assertion as the delegating account, the trade yields a token acting
// as that user, and that token, nothing else, reaches the Workspace API.
func TestGWS_DelegatedTokenReachesWorkspace(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, userToken(t, alice), "", nil)
	require.Equal(t, http.StatusOK, status, "%s", body)
	assert.JSONEq(t, `{"emailAddress":"`+alice+`"}`, string(body), "Gmail answers as the user")

	sts, signed, traded, calls := recorded()
	require.Len(t, sts, 1, "one federation")
	assert.Equal(t, "gcp-dwd:"+delegatingAccount, sts[0]["warden_resource"],
		"the assertion carries the resource the pool binds the right to sign to")
	assert.Equal(t, alice, sts[0]["sub"], "a gcp verifier is shown the user as the subject")
	act, _ := sts[0]["act"].(map[string]any)
	require.NotNil(t, act, "and the agent as the actor")
	assert.True(t, strings.HasSuffix(act["sub"].(string), ":e2e-agent"), "actor %v", act["sub"])

	require.Len(t, signed, 1, "Google signed one delegation assertion")
	assert.Equal(t, delegatingAccount, signed[0]["iss"])
	assert.Equal(t, alice, signed[0]["sub"])
	assert.Equal(t, "https://oauth2.googleapis.com/token", signed[0]["aud"])
	assert.Equal(t, "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.file", signed[0]["scope"],
		"scopes space-separated, as Google wants them")

	require.Len(t, traded, 1, "and traded it once")
	assert.Equal(t, alice, traded[0]["sub"])

	require.Len(t, calls, 1)
	assert.Equal(t, "/"+profile, calls[0].Path, "the stand-in sees the host segment and Google's path")
	assert.Regexp(t, `^Bearer ya29\.e2e\.alice@gws\.e2e\.test\.\d+$`, calls[0].Bearer, "the user's token, nothing else")
}

// A delegated token is cached per user: the same user reuses it, another user
// mints their own, and neither is ever served the other's.
func TestGWS_CachedPerUser(t *testing.T) {
	ensureEnv(t)
	resetRecordings()
	a := userToken(t, alice)

	for i := 0; i < 3; i++ {
		status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, a, "", nil)
		require.Equal(t, http.StatusOK, status, "%s", body)
	}
	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, userToken(t, bob), "", nil)
	require.Equal(t, http.StatusOK, status, "%s", body)
	assert.JSONEq(t, `{"emailAddress":"`+bob+`"}`, string(body))

	_, _, traded, calls := recorded()
	require.Len(t, traded, 2, "one trade per user")
	assert.Equal(t, alice, traded[0]["sub"])
	assert.Equal(t, bob, traded[1]["sub"])
	require.Len(t, calls, 4)
	assert.Equal(t, calls[0].Bearer, calls[2].Bearer, "alice kept her token")
	assert.NotEqual(t, calls[0].Bearer, calls[3].Bearer, "bob got his own")
}

// Concurrent first requests for one user coalesce into a single federation,
// signature and trade.
func TestGWS_ConcurrentFirstCallsMintOnce(t *testing.T) {
	ensureEnv(t)
	resetRecordings()
	user := userToken(t, alice)

	const n = 10
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _, _ = gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, user, "", nil)
		}()
	}
	wg.Wait()
	for i, s := range statuses {
		assert.Equal(t, http.StatusOK, s, "request %d", i)
	}
	sts, signed, traded, _ := recorded()
	assert.Len(t, sts, 1)
	assert.Len(t, signed, 1)
	assert.Len(t, traded, 1)
}

// A user outside the delegated domains is refused before Google is asked anything.
func TestGWS_UserOutsideTheDomainIsRefused(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, userToken(t, eve), "", nil)
	require.Equal(t, http.StatusForbidden, status, "%s", body)
	gstatus, reason, message := googleError(t, body)
	assert.Equal(t, "PERMISSION_DENIED", gstatus)
	assert.Equal(t, "userNotAllowed", reason)
	assert.NotContains(t, message, eve, "a refusal never repeats the address")

	sts, signed, traded, calls := recorded()
	assert.Empty(t, sts, "no federation")
	assert.Empty(t, signed, "no signature")
	assert.Empty(t, traded, "no trade")
	assert.Empty(t, calls, "nothing reaches the API")
}

// A user in the domain whom Google does not know is the caller's to hear about:
// a 403 that retrying cannot fix, not an outage.
func TestGWS_UnknownUserIsRefused(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, userToken(t, ghost), "", nil)
	require.Equal(t, http.StatusForbidden, status, "%s", body)
	_, reason, _ := googleError(t, body)
	assert.Equal(t, "userNotAllowed", reason)
	_, _, _, calls := recorded()
	assert.Empty(t, calls)
}

// A scope the Admin console did not authorize is refused by Google, and the
// caller is told so without the delegating account being named.
func TestGWS_ScopeNotAuthorizedIsRefused(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, unauthRole, http.MethodGet, gwsMount, "www.googleapis.com/drive/v3/files", userToken(t, alice), "", nil)
	require.Equal(t, http.StatusForbidden, status, "%s", body)
	_, reason, message := googleError(t, body)
	assert.Equal(t, "forbidden", reason)
	assert.Contains(t, message, "unauthorized_client")
	assert.NotContains(t, message, delegatingAccount)
	_, _, _, calls := recorded()
	assert.Empty(t, calls)
}

// A request carrying no user cannot be delegated to anyone: a 401 the client can
// act on, with nothing minted.
func TestGWS_NoUserIs401(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, headers := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, "", "", nil)
	require.Equal(t, http.StatusUnauthorized, status, "%s", body)
	_, reason, _ := googleError(t, body)
	assert.Equal(t, "authError", reason)
	assert.Contains(t, headers.Get("WWW-Authenticate"), "resource_metadata=")
	sts, _, _, _ := recorded()
	assert.Empty(t, sts)
}

// What a path policy cannot see into is refused before anything reaches Google:
// batches, credentials in the query, hosts the mount does not allow, bodies
// policy did not read as JSON. A method override header never arrives.
func TestGWS_Refusals(t *testing.T) {
	ensureEnv(t)
	resetRecordings()
	user := userToken(t, alice)

	// A batch as a client library sends one: multipart/mixed, each part a request.
	batch := map[string]string{"Content-Type": "multipart/mixed; boundary=b"}
	batchBody := "--b\r\nContent-Type: application/http\r\n\r\nDELETE /gmail/v1/users/me/messages/1\r\n\r\n--b--"
	for _, tc := range []struct {
		method, path, reason string
		status               int
		headers              map[string]string
		body                 string
	}{
		{http.MethodPost, "www.googleapis.com/batch/drive/v3", "batchNotSupported", http.StatusBadRequest, batch, batchBody},
		{http.MethodPost, "gmail.googleapis.com/batch", "batchNotSupported", http.StatusBadRequest, batch, batchBody},
		{http.MethodGet, profile + "?access_token=x", "credentialInQuery", http.StatusBadRequest, nil, ""},
		{http.MethodGet, profile + "?%24httpMethod=DELETE", "credentialInQuery", http.StatusBadRequest, nil, ""},
		{http.MethodGet, "storage.googleapis.com/storage/v1/b", "hostNotAllowed", http.StatusForbidden, nil, ""},
		{http.MethodPost, "gmail.googleapis.com/gmail/v1/users/me/labels", "unsupportedMediaType", http.StatusUnsupportedMediaType,
			map[string]string{"Content-Type": "application/x-protobuf"}, "\x0a\x01x"},
		// Core parses a form, but Workspace methods take JSON.
		{http.MethodPost, "gmail.googleapis.com/gmail/v1/users/me/labels", "unsupportedMediaType", http.StatusUnsupportedMediaType,
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "name=x"},
		{http.MethodGet, profile, "bodyNotAllowed", http.StatusBadRequest, nil, `{"q":"x"}`},
	} {
		status, body, _ := gatewayCall(t, agentRole, tc.method, gwsMount, tc.path, user, tc.body, tc.headers)
		assert.Equal(t, tc.status, status, "%s: %s", tc.path, body)
		_, reason, _ := googleError(t, body)
		assert.Equal(t, tc.reason, reason, tc.path)
	}
	_, _, _, calls := recorded()
	assert.Empty(t, calls, "no refused request reaches the API")

	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, user, "",
		map[string]string{"X-HTTP-Method-Override": "DELETE"})
	require.Equal(t, http.StatusOK, status, "%s", body)
	_, _, _, calls = recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, http.MethodGet, calls[0].Method, "the method policy authorized, override dropped")
}

// A resumable upload session comes back pointing at Warden, under the same role,
// and the content sent there reaches Google's session with the user's token.
func TestGWS_UploadSessionRoutesBackThroughWarden(t *testing.T) {
	ensureEnv(t)
	resetRecordings()
	user := userToken(t, alice)

	status, body, headers := gatewayCall(t, agentRole, http.MethodPost, gwsMount,
		"www.googleapis.com/upload/drive/v3/files?uploadType=resumable", user, `{"name":"e2e.bin"}`,
		map[string]string{"Content-Type": "application/json", "X-Upload-Content-Type": "application/octet-stream"})
	require.Equal(t, http.StatusOK, status, "%s", body)
	want := h.UserLegResourceURL + "/v1/" + gwsMount + "/role/" + agentRole +
		"/gateway/www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=e2e-session"
	require.Equal(t, want, headers.Get("Location"), "the session points back at the gateway")

	// Send the content as a client library would: to the URI it was given.
	status, body, _ = h.DoRequestWithResponseHeaders(t, http.MethodPut, headers.Get("Location"), map[string]string{
		"Authorization":        "Bearer " + user,
		"X-Warden-Agent-Token": agentJWT,
		"Content-Type":         "application/octet-stream",
	}, "e2e upload content")
	require.Equal(t, http.StatusOK, status, "%s", body)
	assert.Contains(t, string(body), `"e2e-file"`)

	_, _, traded, calls := recorded()
	require.Len(t, calls, 2)
	assert.Equal(t, http.MethodPut, calls[1].Method)
	assert.Equal(t, "/www.googleapis.com/upload/drive/v3/files", calls[1].Path)
	assert.Contains(t, calls[1].Query, "upload_id=e2e-session")
	assert.Equal(t, calls[0].Bearer, calls[1].Bearer, "the chunk carried the user's token")
	assert.Len(t, traded, 1, "and the cached one")
}

// A token acting as a user rides only the gws provider: the gcp provider, which
// sends tokens anywhere under googleapis.com, refuses it.
func TestGWS_GCPProviderRefusesTheDelegatedToken(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, gcpRole, http.MethodGet, gcpMount, profile, userToken(t, alice), "", nil)
	assert.NotEqual(t, http.StatusOK, status, "%s", body)
	assert.GreaterOrEqual(t, status, 400)
	_, _, _, calls := recorded()
	assert.Empty(t, calls)
}

// The audit trail of a delegated request names the user the token acted as and the
// account that delegated, and nothing of the token itself.
func TestGWS_AuditNamesTheDelegatedUser(t *testing.T) {
	ensureEnv(t)
	resetRecordings()

	status, body, _ := gatewayCall(t, agentRole, http.MethodGet, gwsMount, profile, userToken(t, bob), "", nil)
	require.Equal(t, http.StatusOK, status, "%s", body)

	node := h.NodeNumberForPort(leaderPort)
	deadline := time.Now().Add(10 * time.Second)
	var md map[string]string
	for time.Now().Before(deadline) && md == nil {
		for _, e := range h.ReadAuditEntries(t, node, gwsMount+"/") {
			if e.Response != nil && e.Response.Credential != nil && e.Response.Credential.Metadata["delegated_user"] == bob {
				md = e.Response.Credential.Metadata
			}
		}
		if md == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	require.NotNil(t, md, "the delegated credential was audited")
	assert.Equal(t, delegatingAccount, md["service_account"])
	for k, v := range md {
		assert.NotContains(t, v, "ya29.", "metadata %s carries no token", k)
	}
}
