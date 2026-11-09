package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// azureStub stands in for Entra ID's token endpoint and the Graph application
// endpoints the driver's rotation uses. It keeps each app's password credentials so a
// test can see exactly what was added and removed.
type azureStub struct {
	*httptest.Server

	mu sync.Mutex
	// creds holds each app's password credentials, keyed by appId.
	creds map[string][]passwordCredentialInfo
	// rejectedSecrets are client secrets the token endpoint refuses.
	rejectedSecrets map[string]bool
	// tokenStatus, when non-zero, is returned by the token endpoint instead of a token.
	tokenStatus int
	// tokenBody overrides the token endpoint's success body.
	tokenBody string
	// tokenHook runs on every token request, before it is answered.
	tokenHook func(form url.Values)
	// addPasswordBody overrides the addPassword success body.
	addPasswordBody string
	// addPasswordGate, when set, holds addPassword until it is closed.
	addPasswordGate chan struct{}
	// addPasswordSeen is signalled when an addPassword request arrives.
	addPasswordSeen chan struct{}
	// removeAlways400 makes removePassword fail with 400 even for a present key.
	removeAlways400 bool

	tokenCalls  atomic.Int32
	addCalls    atomic.Int32
	removeCalls atomic.Int32
	removedKeys []string
	paths       []string
	nextKey     int
}

func newAzureStub(t *testing.T) *azureStub {
	t.Helper()
	s := &azureStub{
		creds:           map[string][]passwordCredentialInfo{},
		rejectedSecrets: map[string]bool{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *azureStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.Method+" "+r.URL.Path)
	s.mu.Unlock()

	switch {
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		s.serveToken(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1.0/applications(appId='"):
		s.serveGraph(w, r)
	default:
		http.Error(w, "unexpected call "+r.URL.Path, http.StatusBadRequest)
	}
}

func (s *azureStub) serveToken(w http.ResponseWriter, r *http.Request) {
	s.tokenCalls.Add(1)
	_ = r.ParseForm()

	s.mu.Lock()
	hook, status, body := s.tokenHook, s.tokenStatus, s.tokenBody
	rejected := s.rejectedSecrets[r.PostForm.Get("client_secret")]
	s.mu.Unlock()

	if hook != nil {
		hook(r.PostForm)
	}
	if status != 0 {
		http.Error(w, `{"error":"server_error"}`, status)
		return
	}
	if rejected {
		http.Error(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if body != "" {
		_, _ = w.Write([]byte(body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("tok-%s-%d", r.PostForm.Get("scope"), s.tokenCalls.Load()),
		"expires_in":   3600,
		"token_type":   "Bearer",
	})
}

func (s *azureStub) serveGraph(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1.0/applications(appId='")
	appID, op, ok := strings.Cut(rest, "')")
	if !ok {
		http.Error(w, "malformed application path", http.StatusBadRequest)
		return
	}

	switch {
	case r.Method == http.MethodPost && op == "/addPassword":
		s.addCalls.Add(1)
		if s.addPasswordSeen != nil {
			s.addPasswordSeen <- struct{}{}
		}
		if s.addPasswordGate != nil {
			<-s.addPasswordGate
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.addPasswordBody != "" {
			_, _ = w.Write([]byte(s.addPasswordBody))
			return
		}
		s.nextKey++
		keyID := fmt.Sprintf("aaaaaaaa-0000-0000-0000-%012d", s.nextKey)
		s.creds[appID] = append(s.creds[appID], passwordCredentialInfo{KeyID: keyID, DisplayName: "warden-rotated-new"})
		_ = json.NewEncoder(w).Encode(map[string]string{"keyId": keyID, "secretText": "secret-" + keyID})

	case r.Method == http.MethodPost && op == "/removePassword":
		s.removeCalls.Add(1)
		var body struct {
			KeyID string `json:"keyId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.removedKeys = append(s.removedKeys, body.KeyID)
		if s.removeAlways400 {
			http.Error(w, `{"error":{"code":"Request_BadRequest"}}`, http.StatusBadRequest)
			return
		}
		kept := s.creds[appID][:0]
		found := false
		for _, c := range s.creds[appID] {
			if c.KeyID == body.KeyID {
				found = true
				continue
			}
			kept = append(kept, c)
		}
		s.creds[appID] = kept
		if !found {
			// Graph does not document this response; any client error will do.
			http.Error(w, `{"error":{"code":"Request_BadRequest"}}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && op == "":
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"passwordCredentials": s.creds[appID]})

	default:
		http.Error(w, "unexpected graph call "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
	}
}

func (s *azureStub) seedCreds(appID string, creds ...passwordCredentialInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[appID] = append(s.creds[appID], creds...)
}

func (s *azureStub) credsOf(appID string) []passwordCredentialInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]passwordCredentialInfo(nil), s.creds[appID]...)
}

func (s *azureStub) removed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.removedKeys...)
}

func (s *azureStub) set(f func(s *azureStub)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// newStubbedAzureDriver returns a static driver whose Entra and Graph calls reach stub.
func newStubbedAzureDriver(stub *azureStub) *AzureDriver {
	d := newTestAzureDriver()
	d.loginHost = stub.URL
	d.graphHost = stub.URL
	return d
}

// =============================================================================
// Token acquisition
// =============================================================================

func TestAzureScope(t *testing.T) {
	for in, want := range map[string]string{
		"https://management.azure.com/":              "https://management.azure.com/.default",
		"https://management.azure.com":               "https://management.azure.com/.default",
		"https://graph.microsoft.com/.default":       "https://graph.microsoft.com/.default",
		"api://11111111-1111-1111-1111-111111111111": "api://11111111-1111-1111-1111-111111111111/.default",
		"https://ossrdbms-aad.database.windows.net/": "https://ossrdbms-aad.database.windows.net/.default",
	} {
		assert.Equal(t, want, azureScope(in), "azureScope(%q)", in)
	}
}

// TestAzureDriver_Mint_ResourceWithoutTrailingSlash pins the scope Entra receives for
// a resource written without its trailing slash: glued straight onto ".default" it
// would name a resource that does not exist.
func TestAzureDriver_Mint_ResourceWithoutTrailingSlash(t *testing.T) {
	stub := newAzureStub(t)
	var scope atomic.Value
	stub.set(func(s *azureStub) { s.tokenHook = func(f url.Values) { scope.Store(f.Get("scope")) } })

	d := newStubbedAzureDriver(stub)
	_, meta, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{
		"client_id":     testAzureClient,
		"client_secret": "spec-secret",
		"resource_uri":  "https://management.azure.com",
	})})
	require.NoError(t, err)
	assert.Equal(t, "https://management.azure.com/.default", scope.Load())
	assert.Equal(t, "https://management.azure.com", meta["resource_uri"], "metadata keeps the resource as configured")
}

func TestAzureDriver_PostTokenRequest_RejectsEmptyTokenAndNonPositiveExpiry(t *testing.T) {
	for name, body := range map[string]string{
		"empty access_token": `{"access_token":"","expires_in":3600}`,
		"zero expires_in":    `{"access_token":"tok","expires_in":0}`,
		"negative expires":   `{"access_token":"tok","expires_in":-5}`,
		"missing both":       `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			stub := newAzureStub(t)
			stub.set(func(s *azureStub) { s.tokenBody = body })
			d := newStubbedAzureDriver(stub)
			_, _, err := d.acquireToken(context.Background(), testAzureTenant, testAzureClient, "s", armResource)
			require.Error(t, err)
		})
	}
}

func TestAzureDriver_GetSourceToken_CachesAndRefetchesAfterRotation(t *testing.T) {
	stub := newAzureStub(t)
	d := newStubbedAzureDriver(stub)
	ctx := context.Background()

	first, err := d.getSourceToken(ctx, armResource)
	require.NoError(t, err)
	second, err := d.getSourceToken(ctx, armResource)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.EqualValues(t, 1, stub.tokenCalls.Load(), "a live cached token is served without a request")

	d.tokenCache.InvalidateGeneration()
	third, err := d.getSourceToken(ctx, armResource)
	require.NoError(t, err)
	assert.NotEqual(t, first, third, "a token from a superseded generation must not be served")
	assert.EqualValues(t, 2, stub.tokenCalls.Load())
}

// TestAzureDriver_GetSourceToken_ShortLivedTokenNotServedStale covers a token whose
// lifetime is inside the refresh buffer: it is never served from cache.
func TestAzureDriver_GetSourceToken_ShortLivedTokenNotServedStale(t *testing.T) {
	stub := newAzureStub(t)
	stub.set(func(s *azureStub) { s.tokenBody = `{"access_token":"short","expires_in":60}` })
	d := newStubbedAzureDriver(stub)

	for i := 0; i < 3; i++ {
		_, err := d.getSourceToken(context.Background(), armResource)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 3, stub.tokenCalls.Load())
}

// TestAzureDriver_GetSourceToken_SingleFlight pins the coalescing: a cold cache hit by
// many callers at once reaches Entra once.
func TestAzureDriver_GetSourceToken_SingleFlight(t *testing.T) {
	stub := newAzureStub(t)
	release := make(chan struct{})
	stub.set(func(s *azureStub) { s.tokenHook = func(url.Values) { <-release } })
	d := newStubbedAzureDriver(stub)

	var wg, started sync.WaitGroup
	tokens := make([]string, 50)
	errs := make([]error, 50)
	for i := range tokens {
		wg.Add(1)
		started.Add(1)
		go func(i int) {
			defer wg.Done()
			started.Done()
			tokens[i], errs[i] = d.getSourceToken(context.Background(), armResource)
		}(i)
	}
	// Hold the one request open until every caller is running, then give the
	// stragglers time to reach the in-flight fetch rather than start their own.
	started.Wait()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i := range tokens {
		require.NoError(t, errs[i])
		assert.Equal(t, tokens[0], tokens[i])
	}
	assert.EqualValues(t, 1, stub.tokenCalls.Load(), "concurrent misses must be coalesced into one request")
}

// TestAzureDriver_GetSourceToken_FollowerSurvivesLeaderCancel pins that one caller
// giving up does not fail the others waiting on the same fetch.
func TestAzureDriver_GetSourceToken_FollowerSurvivesLeaderCancel(t *testing.T) {
	stub := newAzureStub(t)
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	stub.set(func(s *azureStub) {
		s.tokenHook = func(url.Values) {
			arrived <- struct{}{}
			<-release
		}
	})
	d := newStubbedAzureDriver(stub)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := d.getSourceToken(leaderCtx, armResource)
		leaderErr <- err
	}()
	<-arrived // the leader's request is in flight

	followerTok := make(chan string, 1)
	followerErr := make(chan error, 1)
	go func() {
		tok, err := d.getSourceToken(context.Background(), armResource)
		followerTok <- tok
		followerErr <- err
	}()

	cancelLeader()
	require.ErrorIs(t, <-leaderErr, context.Canceled, "the cancelled caller returns at once")

	close(release)
	require.NoError(t, <-followerErr, "the follower must not inherit the leader's cancellation")
	assert.NotEmpty(t, <-followerTok)
	assert.EqualValues(t, 1, stub.tokenCalls.Load(), "the follower joined the in-flight fetch")
}

// TestAzureDriver_GetSourceToken_BoundedGenerationRetries drives the pathological case
// of a rotation landing during every fetch: the caller gives up instead of looping.
func TestAzureDriver_GetSourceToken_BoundedGenerationRetries(t *testing.T) {
	stub := newAzureStub(t)
	d := newStubbedAzureDriver(stub)
	stub.set(func(s *azureStub) { s.tokenHook = func(url.Values) { d.tokenCache.InvalidateGeneration() } })

	_, err := d.getSourceToken(context.Background(), armResource)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotated")
	assert.EqualValues(t, azureSourceTokenAttempts, stub.tokenCalls.Load())
}

// =============================================================================
// Graph permission probe
// =============================================================================

func TestAzureDriver_HasGraphPermissions_NegativeResultExpires(t *testing.T) {
	stub := newAzureStub(t)
	stub.set(func(s *azureStub) { s.tokenStatus = http.StatusServiceUnavailable })
	d := newStubbedAzureDriver(stub)
	now := time.Now()
	d.now = func() time.Time { return now }

	assert.False(t, d.SupportsRotation(), "a failed probe reports no rotation support")

	stub.set(func(s *azureStub) { s.tokenStatus = 0 })
	assert.False(t, d.SupportsRotation(), "the failure is cached briefly to avoid hammering Entra")

	now = now.Add(graphPermsNegativeTTL + time.Second)
	assert.True(t, d.SupportsRotation(), "a transient failure must not switch rotation off for good")
	assert.True(t, d.SupportsSpecRotation())
}

func TestAzureDriver_HasGraphPermissions_RotationInvalidatesResult(t *testing.T) {
	stub := newAzureStub(t)
	d := newStubbedAzureDriver(stub)

	require.True(t, d.SupportsRotation())
	calls := stub.tokenCalls.Load()
	require.True(t, d.SupportsRotation())
	assert.Equal(t, calls, stub.tokenCalls.Load(), "a fresh positive result is served from cache")

	stub.set(func(s *azureStub) { s.tokenStatus = http.StatusUnauthorized })
	d.tokenCache.InvalidateGeneration()
	assert.False(t, d.SupportsRotation(), "a new generation re-probes with the new credentials")
}

// =============================================================================
// Source rotation
// =============================================================================

func TestAzureDriver_PrepareRotation_AddsOnlyAndUsesGraphAppIdForm(t *testing.T) {
	stub := newAzureStub(t)
	// A spec on the same app registration holds a Warden-rotated secret, and a
	// staged rotation's secret is still inside its activation window. Neither is
	// this rotation's to delete.
	stub.seedCreds(testAzureClient,
		passwordCredentialInfo{KeyID: "22222222-2222-2222-2222-222222222222", DisplayName: "warden-rotated-1"},
		passwordCredentialInfo{KeyID: "33333333-3333-3333-3333-333333333333", DisplayName: "warden-rotated-2"},
		passwordCredentialInfo{KeyID: "44444444-4444-4444-4444-444444444444", DisplayName: "warden-rotated-3"},
	)
	d := newStubbedAzureDriver(stub)

	newConfig, cleanup, activateAfter, err := d.PrepareRotation(context.Background())
	require.NoError(t, err)

	assert.EqualValues(t, 1, stub.addCalls.Load())
	assert.EqualValues(t, 0, stub.removeCalls.Load(), "prepare must never remove a credential it cannot prove is its own")
	assert.Len(t, stub.credsOf(testAzureClient), 4)

	assert.NotEqual(t, "test-secret", newConfig["client_secret"])
	assert.NotEmpty(t, newConfig["secret_id"])
	assert.Equal(t, testAzureClient, newConfig["client_id"], "the rest of the config is carried over")
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", cleanup["old_secret_id"])
	assert.Equal(t, DefaultAzureActivationDelay, activateAfter)

	stub.mu.Lock()
	paths := append([]string(nil), stub.paths...)
	stub.mu.Unlock()
	assert.Contains(t, paths, "POST /v1.0/applications(appId='"+testAzureClient+"')/addPassword")
}

// TestAzureDriver_PrepareRotation_DoesNotBlockSourceTokenReaders pins that no lock is
// held across Graph: a slow addPassword must not stall readers of a cached token.
func TestAzureDriver_PrepareRotation_DoesNotBlockSourceTokenReaders(t *testing.T) {
	stub := newAzureStub(t)
	gate := make(chan struct{})
	seen := make(chan struct{}, 1)
	stub.set(func(s *azureStub) { s.addPasswordGate, s.addPasswordSeen = gate, seen })
	d := newStubbedAzureDriver(stub)

	_, err := d.getSourceToken(context.Background(), armResource)
	require.NoError(t, err)

	prepared := make(chan error, 1)
	go func() {
		_, _, _, err := d.PrepareRotation(context.Background())
		prepared <- err
	}()
	<-seen // addPassword is in flight and held

	// Returning at all while addPassword is held open proves no lock spans it.
	_, err = d.getSourceToken(context.Background(), armResource)
	require.NoError(t, err)

	close(gate)
	require.NoError(t, <-prepared)
}

func TestAzureDriver_CommitRotation_VerifiesBeforeSwap(t *testing.T) {
	stub := newAzureStub(t)
	stub.set(func(s *azureStub) { s.rejectedSecrets["bad-secret"] = true })
	d := newStubbedAzureDriver(stub)
	ctx := context.Background()

	cached, err := d.getSourceToken(ctx, armResource)
	require.NoError(t, err)
	gen := d.tokenCache.GetGeneration()

	bad := map[string]string{"tenant_id": testAzureTenant, "client_id": testAzureClient, "client_secret": "bad-secret", "secret_id": "k2"}
	err = d.CommitRotation(ctx, bad)
	require.Error(t, err)
	assert.Equal(t, "test-secret", d.getClientSecret(), "a refused secret must leave the working credentials in place")
	assert.Equal(t, gen, d.tokenCache.GetGeneration(), "and the cached tokens valid")

	good := map[string]string{"tenant_id": testAzureTenant, "client_id": testAzureClient, "client_secret": "good-secret", "secret_id": "k3"}
	require.NoError(t, d.CommitRotation(ctx, good))
	assert.Equal(t, "good-secret", d.getClientSecret())
	assert.Greater(t, d.tokenCache.GetGeneration(), gen)

	fresh, err := d.getSourceToken(ctx, armResource)
	require.NoError(t, err)
	assert.NotEqual(t, cached, fresh, "a token minted by the retired secret must not be served")
}

func TestAzureDriver_CleanupRotation_RemovesExactlyTheOldKey(t *testing.T) {
	stub := newAzureStub(t)
	old := "22222222-2222-2222-2222-222222222222"
	peer := "33333333-3333-3333-3333-333333333333"
	stub.seedCreds(testAzureClient,
		passwordCredentialInfo{KeyID: old, DisplayName: "warden-rotated-1"},
		passwordCredentialInfo{KeyID: peer, DisplayName: "warden-rotated-2"},
	)
	d := newStubbedAzureDriver(stub)

	require.NoError(t, d.CleanupRotation(context.Background(), map[string]string{"old_secret_id": old}))
	assert.Equal(t, []string{old}, stub.removed())
	assert.Equal(t, []passwordCredentialInfo{{KeyID: peer, DisplayName: "warden-rotated-2"}}, stub.credsOf(testAzureClient))
}

// TestAzureDriver_CleanupRotation_TargetsTheRotatedApp covers a cleanup retried after
// the source was pointed at another app: it must still remove the key from the app
// it was created on, not report success because the new app never had it.
func TestAzureDriver_CleanupRotation_TargetsTheRotatedApp(t *testing.T) {
	stub := newAzureStub(t)
	d := newStubbedAzureDriver(stub)

	_, cleanup, _, err := d.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, testAzureClient, cleanup["client_id"])

	old := cleanup["old_secret_id"]
	stub.seedCreds(testAzureClient, passwordCredentialInfo{KeyID: old})

	// The operator re-points the source at another app before cleanup runs.
	other := "abababab-abab-abab-abab-abababababab"
	d.configMu.Lock()
	d.credSource.Config = d.credSource.Config.With("client_id", other)
	d.configMu.Unlock()

	require.NoError(t, d.CleanupRotation(context.Background(), cleanup))
	for _, c := range stub.credsOf(testAzureClient) {
		assert.NotEqual(t, old, c.KeyID, "the retired key must be removed from the app it was rotated on")
	}
}

// =============================================================================
// Spec rotation
// =============================================================================

func TestAzureDriver_PrepareSpecRotation_NeverRemovesOtherCredentials(t *testing.T) {
	stub := newAzureStub(t)
	workload := "55555555-5555-5555-5555-555555555555"
	// Another spec on the same workload app, with its own live Warden secret.
	stub.seedCreds(workload,
		passwordCredentialInfo{KeyID: "66666666-6666-6666-6666-666666666666", DisplayName: "warden-rotated-1"},
		passwordCredentialInfo{KeyID: "77777777-7777-7777-7777-777777777777", DisplayName: "warden-rotated-2"},
	)
	d := newStubbedAzureDriver(stub)

	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{
		"client_id":     workload,
		"client_secret": "old",
		"secret_id":     "66666666-6666-6666-6666-666666666666",
	})}
	newConfig, cleanup, _, err := d.PrepareSpecRotation(context.Background(), spec)
	require.NoError(t, err)

	assert.EqualValues(t, 0, stub.removeCalls.Load())
	assert.Len(t, stub.credsOf(workload), 3)
	assert.Equal(t, workload, cleanup["client_id"])
	assert.Equal(t, "66666666-6666-6666-6666-666666666666", cleanup["old_secret_id"])
	assert.NotEqual(t, "old", newConfig["client_secret"])
}

func TestAzureDriver_CommitSpecRotation_VerifiesNewSecret(t *testing.T) {
	stub := newAzureStub(t)
	stub.set(func(s *azureStub) { s.rejectedSecrets["bad-secret"] = true })
	d := newStubbedAzureDriver(stub)
	spec := &credential.CredSpec{Name: "s"}

	err := d.CommitSpecRotation(context.Background(), spec, map[string]string{
		"client_id": testAzureClient, "client_secret": "bad-secret",
	})
	require.Error(t, err, "a refused secret must stop the rotation before cleanup deletes the old one")

	require.NoError(t, d.CommitSpecRotation(context.Background(), spec, map[string]string{
		"client_id": testAzureClient, "client_secret": "good-secret",
	}))

	err = d.CommitSpecRotation(context.Background(), spec, map[string]string{"client_id": testAzureClient})
	require.Error(t, err)
}

// =============================================================================
// Graph password operations
// =============================================================================

func TestAzureDriver_AddPassword_RejectsIncompleteResponseAndDiscards(t *testing.T) {
	t.Run("keyId without secret is removed again", func(t *testing.T) {
		stub := newAzureStub(t)
		stub.set(func(s *azureStub) {
			s.addPasswordBody = `{"keyId":"88888888-8888-8888-8888-888888888888","secretText":""}`
		})
		d := newStubbedAzureDriver(stub)

		_, _, err := d.addPasswordCredential(context.Background(), "graph-token", testAzureClient)
		require.Error(t, err)
		assert.Equal(t, []string{"88888888-8888-8888-8888-888888888888"}, stub.removed())
	})

	t.Run("secret without keyId is refused", func(t *testing.T) {
		stub := newAzureStub(t)
		stub.set(func(s *azureStub) { s.addPasswordBody = `{"keyId":"","secretText":"s"}` })
		d := newStubbedAzureDriver(stub)

		_, _, err := d.addPasswordCredential(context.Background(), "graph-token", testAzureClient)
		require.Error(t, err)
		assert.Empty(t, stub.removed(), "there is no key id to remove")
	})
}

func TestAzureDriver_RemovePassword_IdempotentOnlyWhenKeyAbsent(t *testing.T) {
	gone := "99999999-9999-9999-9999-999999999999"
	present := "12121212-1212-1212-1212-121212121212"

	t.Run("already removed counts as removed", func(t *testing.T) {
		stub := newAzureStub(t)
		d := newStubbedAzureDriver(stub)
		require.NoError(t, d.removePasswordCredential(context.Background(), "graph-token", testAzureClient, gone))
	})

	t.Run("a refusal for a key that is still there is an error", func(t *testing.T) {
		stub := newAzureStub(t)
		stub.seedCreds(testAzureClient, passwordCredentialInfo{KeyID: present})
		stub.set(func(s *azureStub) { s.removeAlways400 = true })
		d := newStubbedAzureDriver(stub)
		require.Error(t, d.removePasswordCredential(context.Background(), "graph-token", testAzureClient, present))
	})
}

func TestAzureDriver_GraphAppURL_RejectsNonUUID(t *testing.T) {
	d := newTestAzureDriver()
	for _, appID := range []string{"", "app", "x') or true or ('", "../applications", testAzureClient + "/x"} {
		_, err := d.graphAppURL(appID)
		assert.Error(t, err, "appID %q", appID)
	}
}

// =============================================================================
// Config validation and type inference
// =============================================================================

func TestAzureDriverFactory_ValidateConfig_ActivationDelay(t *testing.T) {
	f := &AzureDriverFactory{}
	base := map[string]string{
		"tenant_id":     testAzureTenant,
		"client_id":     testAzureClient,
		"client_secret": "s",
		"secret_id":     "k",
	}
	with := func(v string) credential.Config {
		c := map[string]string{}
		for k, val := range base {
			c[k] = val
		}
		c["activation_delay"] = v
		return credential.NewConfig(c)
	}

	require.NoError(t, f.ValidateConfig(with("10m")))
	require.NoError(t, f.ValidateConfig(with("0s")))
	require.Error(t, f.ValidateConfig(with("5 minutes")), "an unparseable delay must not silently become the default")
	require.Error(t, f.ValidateConfig(with("-1m")))
}

func TestAzureDriverFactory_ValidateConfig_ClientIDMustBeUUID(t *testing.T) {
	f := &AzureDriverFactory{}
	err := f.ValidateConfig(credential.NewConfig(map[string]string{
		"tenant_id":     testAzureTenant,
		"client_id":     "not-a-uuid",
		"client_secret": "s",
		"secret_id":     "k",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")

	err = f.ValidateConfig(credential.NewConfig(map[string]string{
		"auth_method": "oidc_federation",
		"client_id":   "app') or ('",
	}))
	require.Error(t, err)
}

func TestAzureDriverFactory_InferCredentialType(t *testing.T) {
	f := &AzureDriverFactory{}
	infer := func(m string) (string, error) {
		return f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": m}))
	}

	typ, err := infer("")
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAzureBearerToken, typ)

	typ, err = infer("bearer_token")
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAzureBearerToken, typ)

	_, err = infer("azure_db_iam_token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")

	_, err = infer("key_vault_secret")
	require.ErrorIs(t, err, errKeyVaultSecretRemoved)

	_, err = infer("bogus")
	require.Error(t, err)
}

// =============================================================================
// Cleanup
// =============================================================================

func TestAzureDriver_Cleanup_ClosesIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 8)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	defer srv.Close()

	d := newTestAzureDriver()
	d.loginHost = srv.URL
	d.httpClient = &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}

	_, _, err := d.acquireToken(context.Background(), testAzureTenant, testAzureClient, "s", armResource)
	require.NoError(t, err)

	require.NoError(t, d.Cleanup(context.Background()))
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Cleanup must close the driver's idle connections")
	}
}
