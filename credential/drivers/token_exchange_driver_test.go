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

// subjectInputs builds exchange inputs carrying only a subject token. Every
// forwarded subject is trusted at the source, so the driver forwards it as-is.
func subjectInputs(jwt string) *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:     jwt,
		SubjectTokenType: credential.TokenTypeJWT,
	}
}

func TestTokenExchangeDriver_RFC8693(t *testing.T) {
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

	rawData, meta, ttl, leaseID, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(subject))
	require.NoError(t, err)
	assert.Equal(t, "downstream-token", rawData["api_key"])
	assert.Equal(t, 1800*time.Second, ttl)
	assert.Empty(t, leaseID)
	assert.Equal(t, "user-123", meta["subject"])
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

	rawData, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(subject))
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
	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
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
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
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

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subjectInputs(subject))
	require.NoError(t, err)
}

func TestTokenExchangeDriver_MintCredential_DefensiveError(t *testing.T) {
	d := newExchangeDriver(map[string]string{"token_url": "https://idp.example.com"}, http.DefaultClient)
	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires caller exchange inputs")
}

func TestTokenExchangeDriver_Actor_Forwarded(t *testing.T) {
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

	// The actor is trusted at the source, so it is forwarded to the STS as-is.
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
	}, sts.Client())
	inputs := subjectInputs(subject)
	inputs.ActorToken = actor
	inputs.ActorTokenType = credential.TokenTypeJWT

	_, meta, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.NoError(t, err)
	// The delegation is attributable in the credential metadata: subject=user (act
	// on behalf of), actor=agent (acting). Never the raw bytes.
	assert.Equal(t, "user", meta["subject"])
	assert.Equal(t, "agent", meta["actor"])
	assert.NotContains(t, meta, "actor_token")
}

// When no actor is present the metadata carries no actor keys at all, so a plain
// (non-delegated) exchange is not mislabelled as delegation.
func TestTokenExchangeDriver_NoActor_NoActorMetadata(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "user-123"})
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_id": "c", "client_secret": "s",
	}, sts.Client())

	_, meta, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subjectInputs(subject))
	require.NoError(t, err)
	assert.Equal(t, "user-123", meta["subject"])
	assert.NotContains(t, meta, "actor")
}

func TestTokenExchangeDriver_Actor_JWTBearerRejected(t *testing.T) {
	d := newExchangeDriver(map[string]string{
		"token_url": "https://idp.example.com", "grant": tokenExchangeGrantJWTBearer, "client_id": "c", "client_secret": "s",
	}, http.DefaultClient)
	inputs := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))
	inputs.ActorToken = makeUnsignedJWT(map[string]interface{}{"sub": "agent"})
	inputs.ActorTokenType = credential.TokenTypeJWT

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

	_, _, _, _, err = d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
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

// chainedMaterial wraps a single secret value as SecretMaterial (as credential chaining
// would hand it to the driver).
func chainedMaterial(secret string) credential.SecretMaterial {
	return credential.SecretMaterial{Data: map[string]string{"value": secret}, Field: "value"}
}

// The chained client secret (from secret_spec) is used as client_secret in the form,
// with no inline client_secret on the source.
func TestTokenExchangeDriver_ChainedClientSecret_Post(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "u"})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "warden-gateway", r.Form.Get("client_id"))
		assert.Equal(t, "chained-secret", r.Form.Get("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   server.URL,
		"client_auth": clientAuthSecretPost,
		"client_id":   "warden-gateway",
		"secret_spec": "idp-client-secret", // no inline client_secret
	}, server.Client())

	rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(subject), chainedMaterial("chained-secret"))
	require.NoError(t, err)
	assert.Equal(t, "t", rawData["api_key"])
}

// The chained secret is used for client_secret_basic (Authorization header).
func TestTokenExchangeDriver_ChainedClientSecret_Basic(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "u"})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		require.True(t, ok, "expected Basic auth header")
		assert.Equal(t, "warden-gateway", user)
		assert.Equal(t, "chained-secret", pass)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   server.URL,
		"client_auth": clientAuthSecretBasic,
		"client_id":   "warden-gateway",
		"secret_spec": "idp-client-secret",
	}, server.Client())

	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(subject), chainedMaterial("chained-secret"))
	require.NoError(t, err)
}

// For private_key_jwt, the chained material is the PEM key that signs the assertion.
func TestTokenExchangeDriver_ChainedPrivateKeyJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var gotAssertion string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
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
		"secret_spec": "idp-key", // no inline private_key
	}, sts.Client())

	_, _, _, _, err = d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})), chainedMaterial(privPEM))
	require.NoError(t, err)

	require.NotEmpty(t, gotAssertion)
	parsed, err := josejwt.ParseSigned(gotAssertion)
	require.NoError(t, err)
	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(&priv.PublicKey, &claims), "assertion signed with the chained key")
	assert.Equal(t, "warden-gateway", claims.Issuer)
}

// An empty chained secret is a configuration error, surfaced before any token request.
func TestTokenExchangeDriver_ChainedEmptySecretErrors(t *testing.T) {
	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_auth": clientAuthSecretPost, "client_id": "c", "secret_spec": "s",
	}, sts.Client())
	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})), chainedMaterial(""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
	assert.False(t, called, "no token request when the chained secret is empty")
}

// An upstream invalid_client on the CHAINED path maps to ErrChainedSecretRejected (so the
// manager evicts + retries); the non-chained path does NOT wrap the sentinel.
func TestTokenExchangeDriver_ChainedInvalidClientSentinel(t *testing.T) {
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_client"})
	}))
	defer sts.Close()

	cfg := map[string]string{"token_url": sts.URL, "client_auth": clientAuthSecretPost, "client_id": "c"}
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))

	// Chained: wraps the sentinel.
	dChained := newExchangeDriver(cfg, sts.Client())
	_, _, _, _, err := dChained.MintCredentialWithExchangeFromSecret(context.Background(), &credential.CredSpec{}, subject, chainedMaterial("stale"))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "chained invalid_client -> evict-and-retry sentinel")

	// Non-chained (inline secret): same upstream error, but NOT the chained sentinel.
	cfg2 := map[string]string{"token_url": sts.URL, "client_auth": clientAuthSecretPost, "client_id": "c", "client_secret": "s"}
	dInline := newExchangeDriver(cfg2, sts.Client())
	_, _, _, _, err = dInline.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subject)
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected, "non-chained path must not request an evict-and-retry")
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

	rawData, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(subject))
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
