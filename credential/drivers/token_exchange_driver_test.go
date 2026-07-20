package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeUnsignedJWT builds a JWT whose (unverified) payload carries the given
// claims. Signature verification is out of scope here — the driver only decodes
// the subject/minted token to extract audit metadata.
func makeUnsignedJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func newExchangeDriver(config map[string]string, client *http.Client) *TokenExchangeDriver {
	return &TokenExchangeDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeTokenExchange, Config: config},
		httpClient: client,
	}
}

func verifiedSubject(jwt string) *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:       jwt,
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
	}
}

func TestTokenExchangeDriver_RFC8693_Verified(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user-123"})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
		assert.Equal(t, subject, r.Form.Get("subject_token"))
		assert.Equal(t, credential.TokenTypeJWT, r.Form.Get("subject_token_type"))
		assert.Equal(t, "https://api.internal.example.com", r.Form.Get("audience"))
		assert.Equal(t, "read:orders", r.Form.Get("scope"))
		assert.Equal(t, "warden-gateway", r.Form.Get("client_id"))
		assert.Equal(t, "s3cret", r.Form.Get("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "downstream-token", "token_type": "Bearer", "expires_in": 1800,
		})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":     server.URL,
		"grant":         tokenExchangeGrantRFC8693,
		"client_auth":   clientAuthSecretPost,
		"client_id":     "warden-gateway",
		"client_secret": "s3cret",
	}, server.Client())
	spec := &credential.CredSpec{Name: "internal-api", Config: map[string]string{
		"audience": "https://api.internal.example.com",
		"scope":    "read:orders",
	}}

	rawData, meta, ttl, leaseID, err := d.MintCredentialWithExchange(context.Background(), spec, verifiedSubject(subject))
	require.NoError(t, err)
	assert.Equal(t, "downstream-token", rawData["api_key"])
	assert.Equal(t, 1800*time.Second, ttl)
	assert.Empty(t, leaseID)
	assert.Equal(t, "user-123", meta["subject"])
	assert.Equal(t, "true", meta["subject_verified"])
}

func TestTokenExchangeDriver_JWTBearer_Entra(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user-9"})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.Form.Get("grant_type"))
		assert.Equal(t, subject, r.Form.Get("assertion"))
		assert.Equal(t, "on_behalf_of", r.Form.Get("requested_token_use"))
		assert.Equal(t, "https://graph.microsoft.com/.default", r.Form.Get("scope"))
		assert.Empty(t, r.Form.Get("subject_token"), "jwt_bearer must not send subject_token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "graph-token", "expires_in": 3600})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":                       server.URL,
		"grant":                           tokenExchangeGrantJWTBearer,
		"client_auth":                     clientAuthSecretPost,
		"client_id":                       "cid",
		"client_secret":                   "cs",
		"token_param.requested_token_use": "on_behalf_of",
	}, server.Client())
	spec := &credential.CredSpec{Config: map[string]string{"scope": "https://graph.microsoft.com/.default"}}

	rawData, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, verifiedSubject(subject))
	require.NoError(t, err)
	assert.Equal(t, "graph-token", rawData["api_key"])
}

func TestTokenExchangeDriver_JWTBearer_RejectsAudience(t *testing.T) {
	// audience is an rfc8693 param with no jwt-bearer slot: reject, don't silently
	// drop — and the STS must not be called. (resources are RFC 8707 and allowed.)
	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "grant": tokenExchangeGrantJWTBearer, "client_id": "c", "client_secret": "s",
	}, sts.Client())
	spec := &credential.CredSpec{Config: map[string]string{"audience": "https://target.example.com"}}
	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
	assert.False(t, called, "the STS must not be called when the config is rejected")
}

// resourceValues returns all repeated `resource` form values the STS received.
func assertResources(t *testing.T, form url.Values, want ...string) {
	t.Helper()
	assert.ElementsMatch(t, want, form["resource"], "repeated RFC 8707 resource indicators")
}

func TestTokenExchangeDriver_Resources_MultiValue(t *testing.T) {
	// RFC 8707: `resources` (space-separated) is sent as repeated `resource` params,
	// on both rfc8693 and jwt_bearer.
	for _, grant := range []string{tokenExchangeGrantRFC8693, tokenExchangeGrantJWTBearer} {
		t.Run(grant, func(t *testing.T) {
			var got url.Values
			sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				got = r.Form
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
			}))
			defer sts.Close()
			d := newExchangeDriver(map[string]string{
				"token_url": sts.URL, "grant": grant, "client_id": "c", "client_secret": "s",
			}, sts.Client())
			spec := &credential.CredSpec{Config: map[string]string{
				"resources": "https://api.example.com https://api2.example.com",
			}}
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
			require.NoError(t, err)
			assertResources(t, got, "https://api.example.com", "https://api2.example.com")
		})
	}
}

func TestTokenExchangeDriver_ClientSecretBasic(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "u"})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		wantCreds := base64.StdEncoding.EncodeToString([]byte("cid:cs"))
		assert.Equal(t, "Basic "+wantCreds, r.Header.Get("Authorization"))
		assert.Empty(t, r.Form.Get("client_secret"), "basic auth must not put the secret in the body")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":     server.URL,
		"client_auth":   clientAuthSecretBasic,
		"client_id":     "cid",
		"client_secret": "cs",
	}, server.Client())

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, verifiedSubject(subject))
	require.NoError(t, err)
}

func TestTokenExchangeDriver_MintCredential_DefensiveError(t *testing.T) {
	d := newExchangeDriver(map[string]string{"token_url": "https://idp.example.com"}, http.DefaultClient)
	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires caller exchange inputs")
}

func TestTokenExchangeDriver_UnverifiedRejected_NoCall(t *testing.T) {
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": server.URL, "client_id": "c", "client_secret": "s",
	}, server.Client())
	inputs := &credential.ExchangeInputs{
		SubjectToken:       makeUnsignedJWT(map[string]interface{}{"sub": "u"}),
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginUnverified,
	}
	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unverified subject")
	assert.False(t, called, "the STS must not be called for an unverified subject")
}

func TestTokenExchangeDriver_ActorVerified_Forwarded(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user"})
	actor := makeUnsignedJWT(map[string]interface{}{"sub": "agent"})

	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, subject, r.Form.Get("subject_token"))
		assert.Equal(t, actor, r.Form.Get("actor_token"))
		assert.Equal(t, credential.TokenTypeJWT, r.Form.Get("actor_token_type"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	// A verified (auth_token) actor is forwarded as-is — no subject-validation config needed.
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
	}, sts.Client())
	inputs := verifiedSubject(subject)
	inputs.ActorToken = actor
	inputs.ActorTokenType = credential.TokenTypeJWT
	inputs.ActorTokenOrigin = credential.ExchangeOriginVerified

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.NoError(t, err)
}

func TestTokenExchangeDriver_ActorHeader_Validated(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()
	now := time.Now()
	actor := signTestJWT(t, priv, josejwt.Claims{
		Issuer: "https://issuer.example.com/", Subject: "agent",
		Audience: josejwt.Audience{"api://warden"},
		IssuedAt: josejwt.NewNumericDate(now), NotBefore: josejwt.NewNumericDate(now),
		Expiry: josejwt.NewNumericDate(now.Add(time.Hour)),
	})
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user"})

	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, actor, r.Form.Get("actor_token"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_jwks_url": jwks.URL, "subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := verifiedSubject(subject) // subject verified (forwarded as-is)
	inputs.ActorToken = actor
	inputs.ActorTokenType = credential.TokenTypeJWT
	inputs.ActorTokenOrigin = credential.ExchangeOriginUnverified // header-sourced → validated

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.NoError(t, err)
}

func TestTokenExchangeDriver_ActorHeader_BadSignature_FailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()
	actor := signTestJWT(t, other, josejwt.Claims{
		Issuer: "https://issuer.example.com/", Subject: "attacker",
		Audience: josejwt.Audience{"api://warden"}, Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_jwks_url": jwks.URL, "subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "user"}))
	inputs.ActorToken = actor
	inputs.ActorTokenType = credential.TokenTypeJWT
	inputs.ActorTokenOrigin = credential.ExchangeOriginUnverified

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor token failed validation")
	assert.False(t, called)
}

func TestTokenExchangeDriver_Actor_JWTBearerRejected(t *testing.T) {
	d := newExchangeDriver(map[string]string{
		"token_url": "https://idp.example.com", "grant": tokenExchangeGrantJWTBearer, "client_id": "c", "client_secret": "s",
	}, http.DefaultClient)
	inputs := verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))
	inputs.ActorToken = makeUnsignedJWT(map[string]interface{}{"sub": "agent"})
	inputs.ActorTokenType = credential.TokenTypeJWT
	inputs.ActorTokenOrigin = credential.ExchangeOriginVerified

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no actor slot")
}

func TestTokenExchangeDriverFactory_ValidateConfig(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	base := func() map[string]string {
		return map[string]string{
			"token_url": "https://idp.example.com/token", "client_id": "c", "client_secret": "s",
		}
	}

	require.NoError(t, f.ValidateConfig(base()))

	t.Run("missing token_url", func(t *testing.T) {
		c := base()
		delete(c, "token_url")
		assert.Error(t, f.ValidateConfig(c))
	})
	t.Run("missing client credentials", func(t *testing.T) {
		c := base()
		delete(c, "client_secret")
		assert.Error(t, f.ValidateConfig(c))
	})
	t.Run("bad grant", func(t *testing.T) {
		c := base()
		c["grant"] = "nope"
		assert.Error(t, f.ValidateConfig(c))
	})
	t.Run("token_param overriding a core field", func(t *testing.T) {
		c := base()
		c["token_param.subject_token"] = "x"
		assert.Error(t, f.ValidateConfig(c))
	})
	t.Run("id_jag without resource_token_url", func(t *testing.T) {
		c := base()
		c["grant"] = tokenExchangeGrantIDJAG
		assert.Error(t, f.ValidateConfig(c))
	})
	t.Run("id_jag with resource_token_url", func(t *testing.T) {
		c := base()
		c["grant"] = tokenExchangeGrantIDJAG
		c["resource_token_url"] = "https://auth.resourceapp.example.com/token"
		assert.NoError(t, f.ValidateConfig(c))
	})
	t.Run("non-https token_url", func(t *testing.T) {
		c := base()
		c["token_url"] = "http://idp.example.com/token"
		assert.Error(t, f.ValidateConfig(c))
	})
}

// signTestJWT signs claims with priv and serves the matching JWKS from a test
// server, returning the token and the JWKS URL.
func signTestJWT(t *testing.T, priv *rsa.PrivateKey, claims josejwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	tok, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return tok
}

func jwksServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	}))
}

func TestTokenExchangeDriver_HeaderSubject_ValidatedAndExchanged(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()

	now := time.Now()
	subject := signTestJWT(t, priv, josejwt.Claims{
		Issuer:   "https://issuer.example.com/",
		Subject:  "user-abc",
		Audience: josejwt.Audience{"api://warden"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, subject, r.Form.Get("subject_token"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "down", "expires_in": 300})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":        sts.URL,
		"client_id":        "c",
		"client_secret":    "s",
		"subject_jwks_url": jwks.URL,
		"subject_issuer":   "https://issuer.example.com/",
		"subject_audience": "api://warden",
	}, sts.Client())

	inputs := &credential.ExchangeInputs{
		SubjectToken:       subject,
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginUnverified,
	}
	rawData, meta, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.NoError(t, err)
	assert.Equal(t, "down", rawData["api_key"])
	assert.Equal(t, "user-abc", meta["subject"])
	assert.Equal(t, "false", meta["subject_verified"], "a header-sourced subject is validated but not inbound-verified")
}

func TestTokenExchangeDriver_HeaderSubject_BadSignature_FailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048) // signs the token; not in the JWKS
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()

	now := time.Now()
	subject := signTestJWT(t, other, josejwt.Claims{
		Issuer: "https://issuer.example.com/", Subject: "attacker",
		Audience: josejwt.Audience{"api://warden"}, Expiry: josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_jwks_url": jwks.URL, "subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := &credential.ExchangeInputs{SubjectToken: subject, SubjectTokenType: credential.TokenTypeJWT, SubjectTokenOrigin: credential.ExchangeOriginUnverified}

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed validation")
	assert.False(t, called, "an invalid subject must never reach the STS")
}

func TestTokenExchangeDriver_HeaderSubject_Expired_FailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()
	now := time.Now()
	// Validly signed, correct issuer/audience, but expired (well past the 150s leeway).
	subject := signTestJWT(t, priv, josejwt.Claims{
		Issuer: "https://issuer.example.com/", Subject: "u",
		Audience: josejwt.Audience{"api://warden"},
		IssuedAt: josejwt.NewNumericDate(now.Add(-2 * time.Hour)),
		Expiry:   josejwt.NewNumericDate(now.Add(-1 * time.Hour)),
	})

	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_jwks_url": jwks.URL, "subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := &credential.ExchangeInputs{SubjectToken: subject, SubjectTokenType: credential.TokenTypeJWT, SubjectTokenOrigin: credential.ExchangeOriginUnverified}

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed validation")
	assert.False(t, called, "an expired subject must never reach the STS")
}

func TestTokenExchangeDriver_HeaderSubject_WrongAudience_FailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, &priv.PublicKey)
	defer jwks.Close()
	now := time.Now()
	// Valid signature and issuer, but the token is audienced for a different service.
	subject := signTestJWT(t, priv, josejwt.Claims{
		Issuer: "https://issuer.example.com/", Subject: "u",
		Audience: josejwt.Audience{"api://someone-else"},
		IssuedAt: josejwt.NewNumericDate(now), Expiry: josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_jwks_url": jwks.URL, "subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := &credential.ExchangeInputs{SubjectToken: subject, SubjectTokenType: credential.TokenTypeJWT, SubjectTokenOrigin: credential.ExchangeOriginUnverified}

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed validation")
	assert.False(t, called, "a wrong-audience subject must never reach the STS")
}

func TestTokenExchangeDriver_HeaderSubject_NoKeyset_FailClosed(t *testing.T) {
	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()
	// issuer+audience set, but no jwks/discovery URL → cannot validate → fail closed.
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
		"subject_issuer": "https://issuer.example.com/", "subject_audience": "api://warden",
	}, sts.Client())
	inputs := &credential.ExchangeInputs{
		SubjectToken:       makeUnsignedJWT(map[string]interface{}{"sub": "u"}),
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginUnverified,
	}
	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.False(t, called)
}

func TestTokenExchangeDriver_PrivateKeyJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var gotAssertion string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, clientAssertionType, r.Form.Get("client_assertion_type"))
		assert.Empty(t, r.Form.Get("client_secret"))
		gotAssertion = r.Form.Get("client_assertion")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   sts.URL,
		"client_auth": clientAuthPrivateKeyJWT,
		"client_id":   "warden-gateway",
		"private_key": privPEM,
	}, sts.Client())

	_, _, _, _, err = d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
	require.NoError(t, err)

	// The client assertion must verify against the public key with the expected claims.
	require.NotEmpty(t, gotAssertion)
	parsed, err := josejwt.ParseSigned(gotAssertion)
	require.NoError(t, err)
	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(&priv.PublicKey, &claims))
	assert.Equal(t, "warden-gateway", claims.Issuer)
	assert.Equal(t, "warden-gateway", claims.Subject)
	assert.Contains(t, claims.Audience, sts.URL)
	assert.NotEmpty(t, claims.ID, "assertion should carry a jti")
}

func TestTokenExchangeDriver_IDJAG(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user"})

	// Leg 2: resource authorization server redeems the ID-JAG for an access token.
	resSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.Form.Get("grant_type"))
		assert.Equal(t, "the-id-jag", r.Form.Get("assertion"))
		assert.Equal(t, "files:read", r.Form.Get("scope"))
		assertResources(t, r.Form, "https://api.example.com") // RFC 8707 on the final token (leg 2)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final-access", "expires_in": 600})
	}))
	defer resSrv.Close()

	// Leg 1: home IdP exchanges the subject for an ID-JAG bound to the resource AS.
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
		assert.Equal(t, tokenTypeIDJAG, r.Form.Get("requested_token_type"))
		assert.Equal(t, subject, r.Form.Get("subject_token"))
		assert.Equal(t, "https://resource-as.example.com", r.Form.Get("audience"))
		assert.Empty(t, r.Form["resource"], "resources belong on leg 2, not leg 1")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300})
	}))
	defer idpSrv.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":          idpSrv.URL,
		"resource_token_url": resSrv.URL,
		"grant":              tokenExchangeGrantIDJAG,
		"client_id":          "c",
		"client_secret":      "s",
	}, &http.Client{})
	spec := &credential.CredSpec{Config: map[string]string{
		"audience":  "https://resource-as.example.com",
		"scope":     "files:read",
		"resources": "https://api.example.com",
	}}

	rawData, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), spec, verifiedSubject(subject))
	require.NoError(t, err)
	assert.Equal(t, "final-access", rawData["api_key"], "the final resource-AS access token is returned, not the ID-JAG")
	assert.Equal(t, 600*time.Second, ttl)
}

func TestTokenExchangeDriverFactory_Basics(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	assert.Equal(t, credential.SourceTypeTokenExchange, f.Type())
	ct, err := f.InferCredentialType(nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, ct)
	assert.ElementsMatch(t, []string{"client_secret", "private_key", "ca_data"}, f.SensitiveConfigFields())
}
