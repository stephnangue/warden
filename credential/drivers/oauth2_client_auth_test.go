package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oauth2TestKey is an RSA key and its PEM, as an operator would paste it.
type oauth2TestKey struct {
	priv *rsa.PrivateKey
	pem  string
}

func newOAuth2TestKey(t *testing.T) oauth2TestKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return oauth2TestKey{priv: priv, pem: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
}

// tokenRequest is what a token endpoint received.
type tokenRequest struct {
	form             url.Values
	basicID, basicPw string
	basic            bool
}

// newRecordingTokenEndpoint answers every request with answer and records it.
func newRecordingTokenEndpoint(t *testing.T, answer map[string]interface{}) (*httptest.Server, func() []tokenRequest) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []tokenRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		req := tokenRequest{form: r.PostForm}
		req.basicID, req.basicPw, req.basic = r.BasicAuth()
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []tokenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]tokenRequest(nil), seen...)
	}
}

// newOAuth2DriverFromConfig builds a driver the way the registry does, so a source key
// is parsed exactly as it is in production.
func newOAuth2DriverFromConfig(t *testing.T, cfg map[string]string) *OAuth2Driver {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	drv, err := (&OAuth2DriverFactory{}).Create(credential.NewConfig(cfg), log)
	require.NoError(t, err)
	return drv.(*OAuth2Driver)
}

// verifiedAssertion checks a client assertion against pub and returns its claims and kid.
func verifiedAssertion(t *testing.T, form url.Values, pub *rsa.PublicKey) (josejwt.Claims, string) {
	t.Helper()
	assert.Equal(t, clientAssertionType, form.Get("client_assertion_type"))
	assert.Empty(t, form.Get("client_secret"), "a key-authenticated client sends no secret")
	parsed, err := josejwt.ParseSigned(form.Get("client_assertion"))
	require.NoError(t, err)
	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(pub, &claims), "the assertion must verify against the client's key")
	require.Len(t, parsed.Headers, 1)
	return claims, parsed.Headers[0].KeyID
}

var oauth2BearerAnswer = map[string]interface{}{"access_token": "at", "token_type": "Bearer", "expires_in": 3600}

func TestOAuth2DriverFactory_ValidateConfig_ClientAuth(t *testing.T) {
	key := newOAuth2TestKey(t)
	base := func(over map[string]string) credential.Config {
		cfg := map[string]string{"token_url": "https://idp.example.com/token"}
		for k, v := range over {
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}
	cases := []struct {
		name   string
		config credential.Config
		errMsg string
	}{
		{"post is the default", base(map[string]string{"client_id": "c", "client_secret": "s"}), ""},
		{"basic", base(map[string]string{"client_auth": "client_secret_basic", "client_id": "c", "client_secret": "s"}), ""},
		{"private_key_jwt", base(map[string]string{"client_auth": "private_key_jwt", "client_id": "c", "private_key": key.pem, "client_assertion_kid": "k"}), ""},
		{"private_key_jwt with the key left to the specs", base(map[string]string{"client_auth": "private_key_jwt", "auth_url": "https://idp.example.com/authorize"}), ""},
		{"issuer audience", base(map[string]string{"client_auth": "private_key_jwt", "client_assertion_aud": "issuer", "issuer": "https://idp.example.com"}), ""},
		{"chained private_key_jwt", base(map[string]string{"client_auth": "private_key_jwt", "secret_spec": "idp-key"}), ""},
		{"unknown method", base(map[string]string{"client_auth": "tls_client_auth"}), "client_auth"},
		{"a key on a secret source", base(map[string]string{"client_id": "c", "client_secret": "s", "private_key": key.pem}), "private_key must be omitted for client_auth=client_secret_post"},
		{"a kid on a basic source", base(map[string]string{"client_auth": "client_secret_basic", "client_assertion_kid": "k"}), "client_assertion_kid must be omitted for client_auth=client_secret_basic"},
		{"an audience on a secret source", base(map[string]string{"client_assertion_aud": "issuer"}), "client_assertion_aud must be omitted"},
		{"a secret beside the key", base(map[string]string{"client_auth": "private_key_jwt", "client_id": "c", "client_secret": "s", "private_key": key.pem}), "client_secret must be omitted for client_auth=private_key_jwt"},
		{"issuer audience without an issuer", base(map[string]string{"client_auth": "private_key_jwt", "client_assertion_aud": "issuer"}), "client_assertion_aud=issuer requires issuer"},
		{"a kid with no key beside it", base(map[string]string{"client_auth": "private_key_jwt", "client_assertion_kid": "k"}), "client_assertion_kid names the key stored beside it, and this source has none"},
		{"not a key", base(map[string]string{"client_auth": "private_key_jwt", "private_key": "not-a-pem"}), "private_key"},
		{"unsupported algorithm", base(map[string]string{"client_auth": "private_key_jwt", "client_assertion_alg": "ES256"}), "client_assertion_alg"},
		{"chained source keeps a key", base(map[string]string{"client_auth": "private_key_jwt", "secret_spec": "idp-key", "private_key": key.pem}), "private_key must be omitted when secret_spec is set"},
		{"chained source keeps a kid", base(map[string]string{"client_auth": "private_key_jwt", "secret_spec": "idp-key", "client_assertion_kid": "k"}), "client_assertion_kid must be omitted when secret_spec is set"},
		{"token_param cannot forge the assertion", base(map[string]string{"token_param.client_assertion": "x"}), "token_param.client_assertion cannot override"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&OAuth2DriverFactory{}).ValidateConfig(tc.config)
			if tc.errMsg == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestOAuth2DriverFactory_StoredSecrets_PrivateKey(t *testing.T) {
	held := (&OAuth2DriverFactory{}).StoredSecrets(credential.NewConfig(map[string]string{"private_key": "PEM"}))
	assert.Equal(t, []string{"private_key"}, held)
}

// The source's key signs a client_credentials assertion naming the client and the
// token endpoint, under the source's kid, and no secret travels with it.
func TestOAuth2Driver_PrivateKeyJWT_ClientCredentials(t *testing.T) {
	key := newOAuth2TestKey(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":            srv.URL,
		"client_auth":          "private_key_jwt",
		"client_id":            "warden-gateway",
		"private_key":          key.pem,
		"client_assertion_kid": "key-1",
	})

	rawData, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"scope": "read"})})
	require.NoError(t, err)
	assert.Equal(t, "at", rawData["api_key"])

	reqs := received()
	require.Len(t, reqs, 1)
	assert.Equal(t, "client_credentials", reqs[0].form.Get("grant_type"))
	assert.Equal(t, "read", reqs[0].form.Get("scope"))
	assert.Equal(t, "warden-gateway", reqs[0].form.Get("client_id"))
	claims, kid := verifiedAssertion(t, reqs[0].form, &key.priv.PublicKey)
	assert.Equal(t, "warden-gateway", claims.Issuer)
	assert.Equal(t, "warden-gateway", claims.Subject)
	assert.Equal(t, josejwt.Audience{srv.URL}, claims.Audience)
	assert.NotEmpty(t, claims.ID)
	assert.Equal(t, "key-1", kid)
}

// An authorization server enforcing RFC 7523bis accepts only its issuer identifier as
// the audience.
func TestOAuth2Driver_PrivateKeyJWT_IssuerAudience(t *testing.T) {
	key := newOAuth2TestKey(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":            srv.URL,
		"issuer":               "https://sso.example.com/realms/acme",
		"client_auth":          "private_key_jwt",
		"client_assertion_aud": "issuer",
		"client_id":            "warden-gateway",
		"private_key":          key.pem,
	})

	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)})
	require.NoError(t, err)
	claims, _ := verifiedAssertion(t, received()[0].form, &key.priv.PublicKey)
	assert.Equal(t, josejwt.Audience{"https://sso.example.com/realms/acme"}, claims.Audience, "the issuer, as the sole audience")
}

// An authorization_code spec brings its own client and key, and both the code exchange
// and every refresh authenticate with them.
func TestOAuth2Driver_PrivateKeyJWT_AuthorizationCodeAndRefresh(t *testing.T) {
	key := newOAuth2TestKey(t)
	srv, received := newRecordingTokenEndpoint(t, map[string]interface{}{
		"access_token": "at", "refresh_token": "rt-1", "expires_in": 3600,
	})
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"auth_url":    "https://idp.example.com/authorize",
		"client_auth": "private_key_jwt",
	})
	spec := &credential.CredSpec{Name: "alice", Type: credential.TypeOAuthBearerToken, Config: credential.NewConfig(map[string]string{
		"auth_method":          "authorization_code",
		"client_id":            "alice-app",
		"private_key":          key.pem,
		"client_assertion_kid": "alice-key",
	})}

	sealed, err := d.ExchangeAuthorizationCode(context.Background(), spec, "the-code", "http://127.0.0.1:8765/callback", "the-verifier")
	require.NoError(t, err)
	require.Equal(t, "rt-1", sealed["refresh_token"])

	spec.Config = spec.Config.With("refresh_token", sealed["refresh_token"])
	_, _, _, _, err = d.MintCredential(context.Background(), spec)
	require.NoError(t, err)

	reqs := received()
	require.Len(t, reqs, 2)
	assert.Equal(t, "authorization_code", reqs[0].form.Get("grant_type"))
	assert.Equal(t, "the-code", reqs[0].form.Get("code"))
	assert.Equal(t, "refresh_token", reqs[1].form.Get("grant_type"))
	for i, req := range reqs {
		assert.Equal(t, "alice-app", req.form.Get("client_id"), "request %d", i)
		claims, kid := verifiedAssertion(t, req.form, &key.priv.PublicKey)
		assert.Equal(t, "alice-app", claims.Subject, "request %d", i)
		assert.Equal(t, "alice-key", kid, "request %d", i)
	}
	assert.NotEqual(t, reqs[0].form.Get("client_assertion"), reqs[1].form.Get("client_assertion"))
}

// A spec's key brings its own kid and never inherits the source's: the source's kid
// names another key, and an authorization server selecting by kid would verify the
// assertion against the wrong one.
func TestOAuth2Driver_PrivateKeyJWT_SpecKeyDoesNotInheritSourceKid(t *testing.T) {
	sourceKey, specKey := newOAuth2TestKey(t), newOAuth2TestKey(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":            srv.URL,
		"client_auth":          "private_key_jwt",
		"client_id":            "shared",
		"private_key":          sourceKey.pem,
		"client_assertion_kid": "source-key",
	})

	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{
		"private_key": specKey.pem,
	})})
	require.NoError(t, err)
	_, kid := verifiedAssertion(t, received()[0].form, &specKey.priv.PublicKey)
	assert.Empty(t, kid, "the source's kid names the source's key")
}

func TestOAuth2Driver_PrivateKeyJWT_MissingKey(t *testing.T) {
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   "https://idp.example.com/token",
		"client_auth": "private_key_jwt",
		"client_id":   "c",
	})
	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing client_id or private_key")
}

// chainedKeyMaterial is the payload a referenced spec yields for a chained
// private_key_jwt source: the id, the key, and the kid stored beside it.
func chainedKeyMaterial(clientID, pemKey, kid string) credential.SecretMaterial {
	data := map[string]string{"client_id": clientID, "private_key": pemKey}
	if kid != "" {
		data["kid"] = kid
	}
	return credential.SecretMaterial{Data: data}
}

func TestOAuth2Driver_ChainedPrivateKeyJWT(t *testing.T) {
	key := newOAuth2TestKey(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"client_auth": "private_key_jwt",
		"secret_spec": "idp-client-key",
	})

	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		chainedKeyMaterial("agent-client", key.pem, "agent-key"))
	require.NoError(t, err)
	req := received()[0]
	assert.Equal(t, "agent-client", req.form.Get("client_id"))
	claims, kid := verifiedAssertion(t, req.form, &key.priv.PublicKey)
	assert.Equal(t, "agent-client", claims.Subject)
	assert.Equal(t, "agent-key", kid)

	// A payload without the key it now has to hold is refetched, not failed for the
	// rest of its cache life.
	_, _, _, _, err = d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		credential.SecretMaterial{Data: map[string]string{"client_id": "agent-client", "client_secret": "s"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
	assert.Contains(t, err.Error(), "no private key in fetched secret material")
}

// A key the authorization server no longer accepts asks for a fresh one.
func TestOAuth2Driver_ChainedPrivateKeyJWT_RejectedKeyIsReplaced(t *testing.T) {
	key := newOAuth2TestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(srv.Close)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"client_auth": "private_key_jwt",
		"secret_spec": "idp-client-key",
	})

	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		chainedKeyMaterial("agent-client", key.pem, ""))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
}

// The driver is shared; concurrent mints chaining different clients each sign with
// their own key and name their own client.
func TestOAuth2Driver_ChainedPrivateKeyJWT_ConcurrentMintsKeepKeysApart(t *testing.T) {
	const n = 8
	keys := make([]oauth2TestKey, n)
	for i := range keys {
		keys[i] = newOAuth2TestKey(t)
	}
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"client_auth": "private_key_jwt",
		"secret_spec": "idp-client-key",
	})

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, _, errs[i] = d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
				chainedKeyMaterial(fmt.Sprintf("client-%d", i), keys[i].pem, fmt.Sprintf("kid-%d", i)))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "mint %d", i)
	}

	reqs := received()
	require.Len(t, reqs, n)
	for _, req := range reqs {
		var i int
		_, err := fmt.Sscanf(req.form.Get("client_id"), "client-%d", &i)
		require.NoError(t, err)
		claims, kid := verifiedAssertion(t, req.form, &keys[i].priv.PublicKey)
		assert.Equal(t, fmt.Sprintf("client-%d", i), claims.Subject)
		assert.Equal(t, fmt.Sprintf("kid-%d", i), kid)
	}
}

// client_secret_basic sends the pair in the Authorization header and nothing in the
// body, in every flow.
func TestOAuth2Driver_ClientSecretBasic_AllFlows(t *testing.T) {
	srv, received := newRecordingTokenEndpoint(t, map[string]interface{}{
		"access_token": "at", "refresh_token": "rt-1", "expires_in": 3600,
	})
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"auth_url":    "https://idp.example.com/authorize",
		"client_auth": "client_secret_basic",
	})
	ccSpec := &credential.CredSpec{Name: "cc", Config: credential.NewConfig(map[string]string{
		"client_id": "id:with colon", "client_secret": "s3cr%t",
	})}
	codeSpec := &credential.CredSpec{Name: "code", Config: credential.NewConfig(map[string]string{
		"auth_method": "authorization_code", "client_id": "id:with colon", "client_secret": "s3cr%t",
	})}

	_, _, _, _, err := d.MintCredential(context.Background(), ccSpec)
	require.NoError(t, err)
	_, err = d.ExchangeAuthorizationCode(context.Background(), codeSpec, "the-code", "http://127.0.0.1:8765/callback", "")
	require.NoError(t, err)
	codeSpec.Config = codeSpec.Config.With("refresh_token", "rt-1")
	_, _, _, _, err = d.MintCredential(context.Background(), codeSpec)
	require.NoError(t, err)

	reqs := received()
	require.Len(t, reqs, 3)
	for i, req := range reqs {
		require.True(t, req.basic, "request %d carries Basic auth", i)
		// net/http hands back the raw user and password; RFC 6749 §2.3.1 urlencodes them.
		id, _ := url.QueryUnescape(req.basicID)
		pw, _ := url.QueryUnescape(req.basicPw)
		assert.Equal(t, "id:with colon", id, "request %d", i)
		assert.Equal(t, "s3cr%t", pw, "request %d", i)
		assert.Empty(t, req.form.Get("client_id"), "request %d: one authentication method per request", i)
		assert.Empty(t, req.form.Get("client_secret"), "request %d", i)
	}
}

// A chained client_secret_basic source presents the fetched pair in the header, and
// nothing in the body.
func TestOAuth2Driver_ChainedClientSecretBasic(t *testing.T) {
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"client_auth": "client_secret_basic",
		"secret_spec": "idp-client-credential",
	})
	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		chainedClientCredential("agent-client", "agent-secret"))
	require.NoError(t, err)

	req := received()[0]
	require.True(t, req.basic)
	assert.Equal(t, "agent-client", req.basicID)
	assert.Equal(t, "agent-secret", req.basicPw)
	assert.Empty(t, req.form.Get("client_id"))
	assert.Empty(t, req.form.Get("client_secret"))
}

// A chained client_secret_basic credential refused with a bare 401 asks for a fresh one.
func TestOAuth2Driver_ChainedClientSecretBasic_RejectionSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	d := newOAuth2DriverFromConfig(t, map[string]string{
		"token_url":   srv.URL,
		"client_auth": "client_secret_basic",
		"secret_spec": "idp-client-credential",
	})
	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		chainedClientCredential("c", "stale"))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
}

// Every oauth2 flow retries with a fresh assertion, so a server that spent the first
// one does not refuse the retry as a replay.
func TestOAuth2Driver_PrivateKeyJWT_RetryPresentsAFreshAssertion(t *testing.T) {
	key := newOAuth2TestKey(t)
	answer := map[string]interface{}{"access_token": "at", "refresh_token": "rt-1", "expires_in": 3600}
	spec := func(cfg map[string]string) *credential.CredSpec {
		return &credential.CredSpec{Name: "s", Config: credential.NewConfig(cfg)}
	}
	flows := map[string]func(d *OAuth2Driver) error{
		"client_credentials": func(d *OAuth2Driver) error {
			_, _, _, _, err := d.MintCredential(context.Background(), spec(map[string]string{"client_id": "c", "private_key": key.pem}))
			return err
		},
		"authorization code exchange": func(d *OAuth2Driver) error {
			_, err := d.ExchangeAuthorizationCode(context.Background(), spec(map[string]string{
				"auth_method": "authorization_code", "client_id": "c", "private_key": key.pem,
			}), "the-code", "http://127.0.0.1:8765/callback", "")
			return err
		},
		"refresh": func(d *OAuth2Driver) error {
			_, _, _, _, err := d.MintCredential(context.Background(), spec(map[string]string{
				"auth_method": "authorization_code", "client_id": "c", "private_key": key.pem, "refresh_token": "rt-0",
			}))
			return err
		},
	}
	for name, flow := range flows {
		t.Run(name, func(t *testing.T) {
			as := newSingleUseAS(t, loseAnswerTo500, answer)
			d := newOAuth2DriverFromConfig(t, map[string]string{
				"token_url":   as.srv.URL,
				"auth_url":    "https://idp.example.com/authorize",
				"client_auth": "private_key_jwt",
			})
			require.NoError(t, flow(d), "the retry must not be refused as a replay")
			assertTwoDistinctJTIs(t, as.received())
		})
	}
}

func TestOAuth2DriverFactory_PlanKeyless_PrivateKeyJWT(t *testing.T) {
	f := &OAuth2DriverFactory{}
	current := credential.NewConfig(map[string]string{
		"token_url": "https://idp.example.com/token", "client_auth": "private_key_jwt",
		"client_id": "c", "private_key": "PEM", "client_assertion_kid": "k",
	})
	plan, err := f.PlanKeyless(current, map[string]string{credential.ConfigSecretSpec: "idp-client-key"})
	require.NoError(t, err)
	for _, k := range []string{"client_id", "private_key", "client_assertion_kid"} {
		v, ok := plan.Delta[k]
		assert.True(t, ok && v == "", "%s is cleared", k)
	}
	_, touched := plan.Delta["client_auth"]
	assert.False(t, touched, "the method stays: the chain supplies a key")
	require.Len(t, plan.Leftovers, 1)
	assert.Equal(t, "client assertion signing key", plan.Leftovers[0].Kind)

	prereqs := f.KeylessPrerequisites(credential.NewConfig(map[string]string{
		"client_auth": "private_key_jwt", credential.ConfigSecretSpec: "idp-client-key",
	}), nil, credential.TrustEnv{})
	require.NotEmpty(t, prereqs)
	assert.Contains(t, fmt.Sprint(prereqs), "client_id and private_key")

	none := credential.NewConfig(nil)
	specPlan, err := f.PlanKeylessSpec("s", credential.NewConfig(map[string]string{"private_key": "PEM", "client_assertion_kid": "k"}), none, none, nil)
	require.NoError(t, err)
	assert.Contains(t, specPlan.Delta, "private_key")
	assert.Contains(t, specPlan.Delta, "client_assertion_kid")
	require.Len(t, specPlan.Leftovers, 1)
	assert.Equal(t, "client assertion signing key", specPlan.Leftovers[0].Kind)
}
