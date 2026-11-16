package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// How the first request is lost after the authorization server has already recorded its
// assertion.
const (
	loseAnswerTo500  = "a 500 after recording the jti"
	loseAnswerToDrop = "the connection dropped after recording the jti"
)

// singleUseAS stands in for an authorization server that enforces single use of client
// assertions, as OIDC Core requires and Okta, Keycloak and Hydra do: every jti it sees
// is recorded, and one seen before is refused as invalid_client. The first request is
// recorded and then lost — the case a retry has to survive, since the server has spent
// the assertion while the client never learned the outcome.
type singleUseAS struct {
	srv *httptest.Server

	mu sync.Mutex
	// answerFor, when set, answers the nth request (from 0) in place of the fixed
	// answer, so an IdP can issue a different ID-JAG each time.
	answerFor func(n int) map[string]interface{}
	// singleUseGrants makes the server accept each grant assertion (an ID-JAG) only once,
	// as a resource authorization server tracking its jti may; one seen before is refused
	// as invalid_grant.
	singleUseGrants bool
	seen            map[string]bool
	jtis            []string // every jti received, in order, replays included
	seenGrants      map[string]bool
	grants          []string // every grant assertion received, in order
}

func newSingleUseAS(t *testing.T, loseFirst string, answer map[string]interface{}) *singleUseAS {
	t.Helper()
	as := &singleUseAS{seen: map[string]bool{}, seenGrants: map[string]bool{}}
	as.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		jti := assertionJTI(r.Form.Get("client_assertion"))
		grant := r.Form.Get("assertion")

		as.mu.Lock()
		n := len(as.jtis)
		first := n == 0
		replay := as.seen[jti]
		as.seen[jti] = true
		as.jtis = append(as.jtis, jti)
		grantReplay := as.singleUseGrants && grant != "" && as.seenGrants[grant]
		if grant != "" {
			as.seenGrants[grant] = true
			as.grants = append(as.grants, grant)
		}
		reply := answer
		if as.answerFor != nil {
			reply = as.answerFor(n)
		}
		as.mu.Unlock()

		switch {
		case replay:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client_assertion token has already been used"}`))
		case grantReplay:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"the ID-JAG has already been used"}`))
		case first && loseFirst == loseAnswerTo500:
			w.WriteHeader(http.StatusInternalServerError)
		case first && loseFirst == loseAnswerToDrop:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(reply)
		}
	}))
	t.Cleanup(as.srv.Close)
	return as
}

// issueIDJAGs makes the server answer each request with a new ID-JAG.
func (as *singleUseAS) issueIDJAGs() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.answerFor = func(n int) map[string]interface{} {
		_, body := issuesIDJAGs(n)
		return body
	}
}

// spendGrants makes the server accept each ID-JAG only once.
func (as *singleUseAS) spendGrants() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.singleUseGrants = true
}

func (as *singleUseAS) received() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.jtis...)
}

// receivedGrants is every grant assertion (an ID-JAG) the server received, in order.
func (as *singleUseAS) receivedGrants() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.grants...)
}

// assertionJTI reads the jti out of a compact JWS without verifying it.
func assertionJTI(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]interface{}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	jti, _ := claims["jti"].(string)
	return jti
}

var bearerAnswer = map[string]interface{}{"access_token": "t", "token_type": "Bearer", "expires_in": 60}

// TestTokenExchange_RetryPresentsAFreshAssertion: a retry after the server spent the
// first assertion carries a new one, so the mint succeeds instead of being refused as a
// replay — for a key held here and one held in a KMS, whether the first answer was a 500
// or never arrived.
func TestTokenExchange_RetryPresentsAFreshAssertion(t *testing.T) {
	for _, lose := range []string{loseAnswerTo500, loseAnswerToDrop} {
		t.Run("local key, "+lose, func(t *testing.T) {
			as := newSingleUseAS(t, lose, bearerAnswer)
			d := newExchangeDriver(map[string]string{
				"token_url":   as.srv.URL,
				"client_auth": clientAuthPrivateKeyJWT,
				"client_id":   "warden-gateway",
				"private_key": testRSAPrivateKeyPEM(t),
			}, as.srv.Client())

			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{},
				subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
			require.NoError(t, err, "the retry must not be refused as a replay")
			assertTwoDistinctJTIs(t, as.received())
		})

		t.Run("KMS key, "+lose, func(t *testing.T) {
			kms, kmsURL := newFakeSigningBackend(t)
			as := newSingleUseAS(t, lose, bearerAnswer)
			d := newExchangeDriver(kmsSourceConfig(as.srv.URL), as.srv.Client())

			_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(),
				&credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{})},
				subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
				capabilityMaterial(kmsURL, nil))
			require.NoError(t, err, "the retry must not be refused as a replay")
			assertTwoDistinctJTIs(t, as.received())
			assert.Equal(t, 2, kms.signCalls, "each attempt is signed afresh")
		})
	}
}

// TestTokenExchange_IDJAGRetriesPresentFreshAssertions: both legs retry with a new
// client assertion of their own, each bound to its own endpoint, and a retried leg 2
// redeems a new ID-JAG: the resource authorization server here spends each ID-JAG it
// sees, the first one included, whose answer it then loses — to a 500 or a dropped
// connection.
func TestTokenExchange_IDJAGRetriesPresentFreshAssertions(t *testing.T) {
	for _, lose := range []string{loseAnswerTo500, loseAnswerToDrop} {
		t.Run(lose, func(t *testing.T) {
			t.Parallel()
			kms, kmsURL := newFakeSigningBackend(t)
			idp := newSingleUseAS(t, loseAnswerTo500, nil)
			idp.issueIDJAGs()
			res := newSingleUseAS(t, lose, map[string]interface{}{"access_token": "final", "expires_in": 600})
			res.spendGrants()

			d := newExchangeDriver(map[string]string{
				"token_url":          idp.srv.URL,
				"resource_token_url": res.srv.URL,
				"grant":              tokenExchangeGrantIDJAG,
				"client_auth":        clientAuthKMSPrivateKeyJWT,
				"secret_spec":        "idp-client-signer",
			}, &http.Client{})
			spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://resource-as.example.com"})}

			rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec,
				subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
				capabilityMaterial(kmsURL, nil))
			require.NoError(t, err)
			assert.Equal(t, "final", rawData["api_key"])

			// Leg 1: a lost answer and its retry, then the ID-JAG asked for by leg 2's retry.
			idpJTIs := idp.received()
			require.Len(t, idpJTIs, 3)
			assert.Len(t, map[string]bool{idpJTIs[0]: true, idpJTIs[1]: true, idpJTIs[2]: true}, 3, "every client assertion is new")
			assertTwoDistinctJTIs(t, res.received())
			grants := res.receivedGrants()
			require.Len(t, grants, 2)
			assert.NotEqual(t, grants[0], grants[1], "the retried redemption replayed the spent ID-JAG")
			assert.Equal(t, 5, kms.signCalls, "three IdP attempts and two redemptions, each signed afresh")
		})
	}
}

// tokenStub is a token endpoint that answers the nth request (from 0) with status and
// body, and counts requests.
type tokenStub struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
}

func newTokenStub(t *testing.T, answer func(n int) (int, map[string]interface{})) *tokenStub {
	t.Helper()
	s := &tokenStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		n := s.calls
		s.calls++
		s.mu.Unlock()
		status, body := answer(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *tokenStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// issuesIDJAGs answers every request with a new ID-JAG.
func issuesIDJAGs(n int) (int, map[string]interface{}) {
	return http.StatusOK, map[string]interface{}{
		"access_token":      makeUnsignedJWT(map[string]interface{}{"jti": fmt.Sprintf("id-jag-%d", n)}),
		"issued_token_type": tokenTypeIDJAG, "token_type": "N_A", "expires_in": 300,
	}
}

// losesFirst answers the first request with a 500 and every later one with the token.
func losesFirst(n int) (int, map[string]interface{}) {
	if n == 0 {
		return http.StatusInternalServerError, map[string]interface{}{}
	}
	return http.StatusOK, map[string]interface{}{"access_token": "final", "expires_in": 600}
}

// TestTokenExchange_IDJAGRetryEdges: what a retried leg 2 does when the leg 1 it runs
// fails, and what is never retried.
func TestTokenExchange_IDJAGRetryEdges(t *testing.T) {
	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://resource-as.example.com"})}
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))
	chainedDriver := func(t *testing.T, idpURL, resURL string) (*TokenExchangeDriver, credential.SecretMaterial) {
		_, kmsURL := newFakeSigningBackend(t)
		return newExchangeDriver(map[string]string{
			"token_url":          idpURL,
			"resource_token_url": resURL,
			"grant":              tokenExchangeGrantIDJAG,
			"client_auth":        clientAuthKMSPrivateKeyJWT,
			"secret_spec":        "idp-client-signer",
		}, &http.Client{}), capabilityMaterial(kmsURL, nil)
	}

	t.Run("a leg-1 refusal inside a leg-2 retry reads as leg 1's", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			if n == 0 {
				return issuesIDJAGs(n)
			}
			return http.StatusBadRequest, map[string]interface{}{"error": "access_denied"}
		})
		res := newTokenStub(t, losesFirst)
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "id_jag: the IdP does not allow"), err.Error())
		assert.NotContains(t, err.Error(), "resource authorization server failed")
		assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
		assert.Equal(t, 1, res.count(), "nothing more is sent once the new ID-JAG is refused")
	})

	t.Run("a leg-1 client rejection inside a leg-2 retry is wrapped once", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			if n == 0 {
				return issuesIDJAGs(n)
			}
			return http.StatusUnauthorized, map[string]interface{}{"error": "invalid_client"}
		})
		res := newTokenStub(t, losesFirst)
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "the IdP rejected the chained client: evict and retry")
		assert.True(t, strings.HasPrefix(err.Error(), "id_jag: the IdP rejected the chained client credential"), err.Error())
		assert.Equal(t, 1, strings.Count(err.Error(), "rejected the chained client credential"), err.Error())
	})

	t.Run("a chained client rejected at leg 2 is evicted, and named as the resource server's", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, issuesIDJAGs)
		res := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusUnauthorized, map[string]interface{}{"error": "invalid_client"}
		})
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
		assert.True(t, strings.HasPrefix(err.Error(), "id_jag: the resource authorization server rejected the chained client credential"), err.Error())
	})

	t.Run("a user challenge inside a leg-2 retry reaches the caller", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			if n == 0 {
				return issuesIDJAGs(n)
			}
			return http.StatusBadRequest, map[string]interface{}{"error": "invalid_request", "error_description": "token expired"}
		})
		res := newTokenStub(t, losesFirst)
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)
		userSpec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com", credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
		})}

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), userSpec, subject, material)
		assert.ErrorIs(t, err, credential.ErrUserChallenge)
	})

	t.Run("the ID-JAG a leg-2 retry asks for is tried once", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			if n == 0 {
				return issuesIDJAGs(n)
			}
			return http.StatusInternalServerError, map[string]interface{}{}
		})
		res := newTokenStub(t, losesFirst)
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requesting the ID-JAG from the IdP failed")
		assert.Equal(t, 2, idp.count(), "one ID-JAG for the first redemption, one try for the retry's")
	})

	t.Run("a retried redemption asks for the scope granted with its new ID-JAG", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			_, answer := issuesIDJAGs(n)
			answer["scope"] = []string{"files:read files:write", "files:read"}[min(n, 1)]
			return http.StatusOK, answer
		})
		var mu sync.Mutex
		var scopes []string
		res := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			mu.Lock()
			first := len(scopes) == 0
			scopes = append(scopes, r.PostForm.Get("scope"))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if first {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final", "expires_in": 600})
		}))
		t.Cleanup(res.Close)
		d, material := chainedDriver(t, idp.srv.URL, res.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com", "scope": "files:read files:write",
		})}, subject, material)
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"files:read files:write", "files:read"}, scopes, "each redemption names the scope granted with the ID-JAG it sends")
	})

	t.Run("a 429 at leg 2 costs a new ID-JAG", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, issuesIDJAGs)
		res := newTokenStub(t, func(n int) (int, map[string]interface{}) {
			if n == 0 {
				return http.StatusTooManyRequests, map[string]interface{}{}
			}
			return losesFirst(n)
		})
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.NoError(t, err)
		assert.Equal(t, "final", rawData["api_key"])
		assert.Equal(t, 2, idp.count(), "an attempt cannot tell a 429 from a lost answer")
	})

	t.Run("a refused ID-JAG is not redeemed again", func(t *testing.T) {
		t.Parallel()
		idp := newTokenStub(t, issuesIDJAGs)
		res := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusBadRequest, map[string]interface{}{"error": "invalid_grant", "error_description": "client_id mismatch"}
		})
		d, material := chainedDriver(t, idp.srv.URL, res.srv.URL)

		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec, subject, material)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the resource authorization server refused the ID-JAG")
		assert.Equal(t, 1, res.count())
		assert.Equal(t, 1, idp.count())
	})

	t.Run("the caller's deadline reaches the leg 1 a leg-2 retry runs", func(t *testing.T) {
		t.Parallel()
		// The IdP answers the first request and holds every later one until the caller
		// gives up; the resource authorization server always fails, so its retry asks
		// for a new ID-JAG and waits on the IdP.
		var mu sync.Mutex
		idpCalls := 0
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n := idpCalls
			idpCalls++
			mu.Unlock()
			if n > 0 {
				// The server notices the caller leaving only once the body is read.
				_ = r.ParseForm()
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				return
			}
			_, body := issuesIDJAGs(n)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}))
		t.Cleanup(idp.Close)
		res := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusInternalServerError, map[string]interface{}{}
		})
		d, material := chainedDriver(t, idp.URL, res.srv.URL)

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, spec, subject, material)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(start), 2500*time.Millisecond, "the leg 1 a retry ran outlived the caller's deadline")
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, 2, idpCalls, "the retry's leg 1 was reached")
	})
}

// TestTokenExchange_AssertionFailureIsNotATokenEndpointError: a capability found spent
// fails before anything is sent. Building the assertion inside the request must not
// turn that into a token-endpoint failure: the message and the sentinel are what they
// were when the assertion was built ahead of the request.
func TestTokenExchange_AssertionFailureIsNotATokenEndpointError(t *testing.T) {
	_, kmsURL := newFakeSigningBackend(t)
	as := newSingleUseAS(t, "", bearerAnswer)
	d := newExchangeDriver(kmsSourceConfig(as.srv.URL), as.srv.Client())

	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(),
		&credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{})},
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		capabilityMaterial(kmsURL, map[string]string{
			"token_expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		}))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
	assert.True(t, strings.HasPrefix(err.Error(), "token_exchange: the fetched signing capability expired"),
		"the failure reads as itself, not as a rejected exchange: %v", err)
	assert.Empty(t, as.received(), "nothing is sent for a capability known to be spent")
}

func assertTwoDistinctJTIs(t *testing.T, jtis []string) {
	t.Helper()
	require.Len(t, jtis, 2, "one lost attempt, then one retry")
	assert.NotEmpty(t, jtis[0])
	assert.NotEqual(t, jtis[0], jtis[1], "the retry replayed the first assertion")
}
