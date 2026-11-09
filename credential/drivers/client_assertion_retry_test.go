package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	mu   sync.Mutex
	seen map[string]bool
	jtis []string // every jti received, in order, replays included
}

func newSingleUseAS(t *testing.T, loseFirst string, answer map[string]interface{}) *singleUseAS {
	t.Helper()
	as := &singleUseAS{seen: map[string]bool{}}
	as.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		jti := assertionJTI(r.Form.Get("client_assertion"))

		as.mu.Lock()
		first := len(as.jtis) == 0
		replay := as.seen[jti]
		as.seen[jti] = true
		as.jtis = append(as.jtis, jti)
		as.mu.Unlock()

		switch {
		case replay:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client_assertion token has already been used"}`))
		case first && loseFirst == loseAnswerTo500:
			w.WriteHeader(http.StatusInternalServerError)
		case first && loseFirst == loseAnswerToDrop:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(answer)
		}
	}))
	t.Cleanup(as.srv.Close)
	return as
}

func (as *singleUseAS) received() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.jtis...)
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
// assertion of their own, each bound to its own endpoint.
func TestTokenExchange_IDJAGRetriesPresentFreshAssertions(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	idp := newSingleUseAS(t, loseAnswerTo500, map[string]interface{}{
		"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300})
	res := newSingleUseAS(t, loseAnswerTo500, map[string]interface{}{"access_token": "final", "expires_in": 600})

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
	assertTwoDistinctJTIs(t, idp.received())
	assertTwoDistinctJTIs(t, res.received())
	assert.Equal(t, 4, kms.signCalls, "two attempts per leg, each signed afresh")
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
