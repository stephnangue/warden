//go:build e2e

package msgraph

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// jwtClaims decodes a JWT's claims without verifying it.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "not a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// graphError decodes Graph's error envelope.
func graphError(t *testing.T, body []byte) (code, message string) {
	t.Helper()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "not Graph's error shape: %s", body)
	return env.Error.Code, env.Error.Message
}

// The whole delegated path: the user's own token is the OBO assertion, Warden's
// assertion of the agent authenticates the app, and the token Entra issues — and
// only that — reaches the upstream.
func TestOBO_DelegatedTokenReachesUpstream(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)
	user := userToken(t)

	status, body, _ := gatewayGET(t, stubMount, "v1.0/me", user)
	require.Equal(t, http.StatusOK, status, "%s", body)

	got := recordedGrants()
	require.Equal(t, 1, len(got), "one exchange at Entra")
	g := got[0]
	assert.Equal(t, "/"+oboTenant+"/oauth2/v2.0/token", g.Path)
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", g.GrantType)
	assert.Equal(t, "on_behalf_of", g.RequestedUse)
	assert.Equal(t, oboClient, g.ClientID)
	assert.Equal(t, "https://graph.microsoft.com/.default", g.Scope)
	assert.Equal(t, user, g.Assertion, "the user's token is the OBO assertion")
	assert.False(t, g.HasSecret, "a keyless exchange carries no secret")
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", g.AssertionType)
	require.NotEqual(t, user, g.ClientAssertion, "the user's token is never the client credential")

	actor := jwtClaims(t, g.ClientAssertion)
	sub, _ := actor["sub"].(string)
	assert.True(t, strings.HasPrefix(sub, "wid:") && strings.HasSuffix(sub, ":e2e-agent"),
		"the client assertion names the agent (got sub %q)", sub)
	assert.Equal(t, federationAudience, actor["aud"])

	bearers := recordedBearers()
	require.Len(t, bearers, 1)
	assert.Regexp(t, `^Bearer graph-token-\d+$`, bearers[0], "the delegated token, nothing else, reaches the upstream")
	assert.NotContains(t, string(body), "RT-must-not-leak")
}

// A delegated token is cached per user token: the same token reuses it, another
// user mints their own.
func TestOBO_CachedPerUser(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)
	first := userToken(t)

	for i := 0; i < 3; i++ {
		status, body, _ := gatewayGET(t, stubMount, "v1.0/me", first)
		require.Equal(t, http.StatusOK, status, "%s", body)
	}
	require.Equal(t, 1, len(recordedGrants()), "the same user token is served from the cache")

	second := userToken(t)
	status, body, _ := gatewayGET(t, stubMount, "v1.0/me", second)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Equal(t, 2, len(recordedGrants()), "another user token mints its own")

	bearers := recordedBearers()
	require.Len(t, bearers, 4)
	assert.Equal(t, bearers[0], bearers[2], "the first user kept their token")
	assert.NotEqual(t, bearers[0], bearers[3], "the second user got their own")
}

// Concurrent first requests for one user coalesce into a single exchange.
func TestOBO_ConcurrentFirstCallsExchangeOnce(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)
	user := userToken(t)

	const n = 10
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _, _ = gatewayGET(t, stubMount, "v1.0/me", user)
		}()
	}
	wg.Wait()
	for i, s := range statuses {
		assert.Equal(t, http.StatusOK, s, "request %d", i)
	}
	assert.Equal(t, 1, len(recordedGrants()), "one exchange for all of them")
}

// A Conditional Access claims challenge reaches the client as Microsoft's
// WWW-Authenticate format, in Graph's error shape, with nothing Entra wrote as
// free text.
func TestMSGraph_ClaimsChallenge(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraClaims)

	status, body, headers := gatewayGET(t, graphMount, "v1.0/me", userToken(t))
	require.Equal(t, http.StatusUnauthorized, status, "%s", body)

	challenges := headers.Values("WWW-Authenticate")
	require.Len(t, challenges, 1, "exactly one challenge")
	want := `Bearer realm="` + oboTenant + `", authorization_uri="` + entra.URL + "/" + oboTenant +
		`/oauth2/v2.0/authorize", error="insufficient_claims", claims="` +
		base64.StdEncoding.EncodeToString([]byte(claimsChallenge)) + `"`
	assert.Equal(t, want, challenges[0])

	code, _ := graphError(t, body)
	assert.Equal(t, "InvalidAuthenticationToken", code)
	assert.NotContains(t, string(body), "jane@contoso.com")
	assert.NotContains(t, strings.Join(challenges, ""), "jane@contoso.com")
}

// Missing admin consent is the operator's to fix: a 403 that says so.
func TestMSGraph_ConsentMissing(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraConsent)

	status, body, headers := gatewayGET(t, graphMount, "v1.0/me", userToken(t))
	require.Equal(t, http.StatusForbidden, status, "%s", body)
	assert.Empty(t, headers.Values("WWW-Authenticate"), "re-authenticating will not help")

	code, message := graphError(t, body)
	assert.Equal(t, "Authorization_RequestDenied", code)
	assert.Contains(t, message, "admin consent is missing")
}

// $batch is refused whatever the policy grants, before Graph is contacted.
func TestMSGraph_BatchRefused(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)

	for _, path := range []string{"v1.0/$batch", "beta/$batch", "V1.0/$Batch", "v1.0/me/../$batch"} {
		status, body, _ := gatewayCall(t, http.MethodPost, graphMount, path, userToken(t),
			`{"requests":[{"id":"1","method":"GET","url":"/me"}]}`)
		assert.Equal(t, http.StatusBadRequest, status, "%s: %s", path, body)
		code, _ := graphError(t, body)
		assert.Equal(t, "batchNotSupported", code, path)
	}
}

// A request carrying no user cannot be exchanged on anyone's behalf: a 401 the
// client can act on, in Graph's shape.
func TestMSGraph_NoUserIs401(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)

	status, body, _ := gatewayGET(t, graphMount, "v1.0/me", "")
	require.Equal(t, http.StatusUnauthorized, status, "%s", body)
	assert.Empty(t, recordedGrants(), "nothing to exchange without a user")
}

// A delegated token never outlives the user's own: once the user's token entry
// expires, the same user token is exchanged afresh rather than served from cache.
func TestOBO_CachedTokenDoesNotOutliveTheUser(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)
	user := userToken(t)

	status, body, _ := gatewayGET(t, shortStubMount, "v1.0/me", user)
	require.Equal(t, http.StatusOK, status, "%s", body)
	status, body, _ = gatewayGET(t, shortStubMount, "v1.0/me", user)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Equal(t, 1, len(recordedGrants()), "cached while the user's token lives")

	time.Sleep(shortUserTTL + time.Second)
	status, body, _ = gatewayGET(t, shortStubMount, "v1.0/me", user)
	require.Equal(t, http.StatusOK, status, "%s", body)
	assert.Equal(t, 2, len(recordedGrants()), "re-exchanged once the user's token expired")
}

// The azure provider refuses Graph $batch on its own, whatever the policy grants.
func TestAzure_GraphBatchRefused(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)

	status, body, _ := gatewayCall(t, http.MethodPost, azureMount, "graph.microsoft.com/v1.0/$batch", userToken(t),
		`{"requests":[{"id":"1","method":"GET","url":"/me"}]}`)
	assert.Equal(t, http.StatusBadRequest, status, "%s", body)
	assert.Contains(t, string(body), "$batch")
}

// Graph's absolute paging link comes back pointing at the gateway, under the
// same role, and following it reaches the next page through Warden with the
// delegated token.
func TestMSGraph_PagingLinkRoutesBackThroughWarden(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)
	user := userToken(t)

	status, body, _ := gatewayGET(t, localGraphMount, "v1.0/me/messages", user)
	require.Equal(t, http.StatusOK, status, "%s", body)
	var page struct {
		NextLink string `json:"@odata.nextLink"`
	}
	require.NoError(t, json.Unmarshal(body, &page), "%s", body)
	want := h.UserLegResourceURL + "/v1/" + localGraphMount + "/role/" + agentRole +
		"/gateway/v1.0/me/messages?$top=1&$skiptoken=page2"
	require.Equal(t, want, page.NextLink)

	// Follow it as an SDK would: verbatim.
	status, body, _ = h.DoRequestWithResponseHeaders(t, http.MethodGet, page.NextLink, map[string]string{
		"Authorization":        "Bearer " + user,
		"X-Warden-Agent-Token": agentJWT,
	}, "")
	require.Equal(t, http.StatusOK, status, "%s", body)
	assert.Contains(t, string(body), `"page":"page2"`)

	bearers := recordedBearers()
	require.Len(t, bearers, 2)
	assert.Regexp(t, `^Bearer graph-token-\d+$`, bearers[1], "the next page carried the delegated token")
	assert.Equal(t, 1, len(recordedGrants()), "and the cached one")
}

// The audit trail of a delegated request records the minted credential's identity,
// and nothing of the refresh_token Entra returned alongside it.
func TestOBO_AuditCarriesNoRefreshToken(t *testing.T) {
	ensureEnv(t)
	resetRecordings(entraOK)

	status, body, _ := gatewayGET(t, stubMount, "v1.0/me", userToken(t))
	require.Equal(t, http.StatusOK, status, "%s", body)

	node := h.NodeNumberForPort(leaderPort)
	deadline := time.Now().Add(10 * time.Second)
	var sawDelegated bool
	for time.Now().Before(deadline) && !sawDelegated {
		for _, e := range h.ReadAuditEntries(t, node, stubMount+"/") {
			if e.Response != nil && e.Response.Credential != nil && e.Response.Credential.Metadata["delegated"] == "true" {
				sawDelegated = true
			}
		}
		if !sawDelegated {
			time.Sleep(200 * time.Millisecond)
		}
	}
	require.True(t, sawDelegated, "the delegated credential was audited")

	raw, err := os.ReadFile(filepath.Join(h.E2EDir(), ".logs", fmt.Sprintf("node%d-audit.log", node)))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "RT-must-not-leak")
}
