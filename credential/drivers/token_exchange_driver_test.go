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

// A source in chaining mode holds neither half of the client credential: not the secret,
// which is what chaining exists to remove, and not the id, which is only meaningful
// beside the secret it belongs to.
func TestTokenExchangeDriverFactory_ValidateConfig_Chaining(t *testing.T) {
	f := &TokenExchangeDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name: "secret-based, neither half inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "secret_field": "client_secret",
			},
		},
		{
			name: "secret-based, client_secret still inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "client_secret": "s",
			},
			wantErr: "client_secret must be omitted when secret_spec is set",
		},
		{
			name: "secret-based, client_id still inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretBasic,
				"secret_spec": "idp-client-secret", "client_id": "c",
			},
			wantErr: "client_id must be omitted when secret_spec is set",
		},
		{
			name: "private_key_jwt, neither half inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "secret_field": "private_key",
			},
		},
		{
			name: "private_key_jwt, private_key still inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "private_key": testRSAPrivateKeyPEM(t),
			},
			wantErr: "private_key must be omitted when secret_spec is set",
		},
		{
			name: "private_key_jwt, client_id still inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "client_id": "c",
			},
			wantErr: "client_id must be omitted when secret_spec is set",
		},
		{
			// A kid names one key among several; kept on the source it would be stamped
			// on assertions signed by every agent's key.
			name: "private_key_jwt, client_assertion_kid still inline",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "client_assertion_kid": "key-1",
			},
			wantErr: "client_assertion_kid must be omitted when secret_spec is set",
		},
		{
			// kid is meaningless to the secret methods, so it is not policed there.
			name: "secret-based, an inert kid is left alone",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "client_assertion_kid": "key-1",
			},
		},
		{
			// The chained branch must not short-circuit the rest of validation. This
			// one matters more when chained than inline: a chained source holds no
			// client_id, so an unprotected token_param.client_id would be the only
			// one on the wire.
			name: "chained, token_param overriding a core field",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "token_param.client_id": "sneaky",
			},
			wantErr: "cannot override a core token-exchange field",
		},
		{
			name: "chained id_jag without resource_token_url",
			config: map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"grant": tokenExchangeGrantIDJAG, "secret_spec": "idp-client-secret",
			},
			wantErr: "resource_token_url is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := f.ValidateConfig(tc.config)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// testRSAPrivateKeyPEM returns a throwaway PEM key, for cases that need a key-shaped
// value rather than a working signature.
func testRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
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

// chainedMaterial wraps a whole client credential as SecretMaterial (as credential
// chaining would hand it to the driver). The secret sits under a field the source named
// with secret_field; the id travels beside it under the conventional key, which is the
// only place it can come from once the source stores neither half.
func chainedMaterial(clientID, secret string) credential.SecretMaterial {
	return credential.SecretMaterial{
		Data:  map[string]string{"value": secret, "client_id": clientID},
		Field: "value",
	}
}

// chainedConventionalMaterial is the same credential with no secret_field resolved, so
// both halves are read by convention.
func chainedConventionalMaterial(clientID, secret, secretKey string) credential.SecretMaterial {
	return credential.SecretMaterial{Data: map[string]string{secretKey: secret, "client_id": clientID}}
}

// The chained client credential (from secret_spec) is used in the form, with the source
// holding neither half — so the id reaching the endpoint can only have come from the
// fetched payload.
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
		"secret_spec": "idp-client-secret", // neither client_id nor client_secret inline
	}, server.Client())

	rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(subject),
		chainedMaterial("warden-gateway", "chained-secret"))
	require.NoError(t, err)
	assert.Equal(t, "t", rawData["api_key"])
}

// The chained pair is used for client_secret_basic (Authorization header) — both the
// user and the password halves come from the payload.
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
		"secret_spec": "idp-client-secret",
	}, server.Client())

	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(subject),
		chainedMaterial("warden-gateway", "chained-secret"))
	require.NoError(t, err)
}

// For private_key_jwt, the chained material is the PEM key that signs the assertion —
// and the id it is issued under. The two have to arrive together: an assertion signed
// with the payload's key while claiming a config-held id would name a client it cannot
// prove it is.
func TestTokenExchangeDriver_ChainedPrivateKeyJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var gotAssertion, gotClientID string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Empty(t, r.Form.Get("client_secret"))
		gotAssertion = r.Form.Get("client_assertion")
		gotClientID = r.Form.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   sts.URL,
		"client_auth": clientAuthPrivateKeyJWT,
		"secret_spec": "idp-key", // neither client_id nor private_key inline
	}, sts.Client())

	_, _, _, _, err = d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		chainedMaterial("warden-gateway", privPEM))
	require.NoError(t, err)

	assert.Equal(t, "warden-gateway", gotClientID)
	require.NotEmpty(t, gotAssertion)
	parsed, err := josejwt.ParseSigned(gotAssertion)
	require.NoError(t, err)
	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(&priv.PublicKey, &claims), "assertion signed with the chained key")
	assert.Equal(t, "warden-gateway", claims.Issuer)
	assert.Equal(t, "warden-gateway", claims.Subject)
}

// A secret_field that resolved to nothing is a configuration error, surfaced before any
// token request — and named as a secret_field problem, since the field was the source's
// own instruction about where to look.
func TestTokenExchangeDriver_ChainedEmptySecretErrors(t *testing.T) {
	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_auth": clientAuthSecretPost, "secret_spec": "s",
	}, sts.Client())
	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		chainedMaterial("c", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
	assert.Contains(t, err.Error(), "secret_field")
	assert.False(t, called, "no token request when the chained secret is empty")
}

// A resolved secret_field that is empty must NOT quietly fall back to a conventional
// key: the field is the source's own statement of where its secret lives, so an empty
// one is a misconfiguration rather than an invitation to look elsewhere.
func TestTokenExchangeDriver_ChainedResolvedFieldEmptyDoesNotFallBack(t *testing.T) {
	called := false
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer sts.Close()
	d := newExchangeDriver(map[string]string{
		"token_url": sts.URL, "client_auth": clientAuthSecretPost, "secret_spec": "s",
	}, sts.Client())

	material := credential.SecretMaterial{
		Data:  map[string]string{"value": "", "client_secret": "would-have-worked", "client_id": "c"},
		Field: "value",
	}
	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})), material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_field")
	assert.False(t, called, "no token request when the named field resolved to nothing")
}

// With no secret_field resolved, both halves are read by convention.
func TestTokenExchangeDriver_ChainedConventionalKeys(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "u"})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "conventional-id", r.Form.Get("client_id"))
		assert.Equal(t, "conventional-secret", r.Form.Get("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer server.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   server.URL,
		"client_auth": clientAuthSecretPost,
		"secret_spec": "idp-client-secret",
	}, server.Client())

	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(subject),
		chainedConventionalMaterial("conventional-id", "conventional-secret", "client_secret"))
	require.NoError(t, err)
}

// The private_key_jwt equivalent: the PEM is read by convention too.
func TestTokenExchangeDriver_ChainedPrivateKeyJWT_ConventionalKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var gotAssertion string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotAssertion = r.Form.Get("client_assertion")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":   sts.URL,
		"client_auth": clientAuthPrivateKeyJWT,
		"secret_spec": "idp-key",
	}, sts.Client())

	_, _, _, _, err = d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		chainedConventionalMaterial("conventional-id", privPEM, "private_key"))
	require.NoError(t, err)

	require.NotEmpty(t, gotAssertion)
	parsed, err := josejwt.ParseSigned(gotAssertion)
	require.NoError(t, err)
	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(&priv.PublicKey, &claims))
	assert.Equal(t, "conventional-id", claims.Issuer)
}

// A payload carrying a secret but no id fails before anything is sent. The id has
// nowhere to fall back to — a chained source holds none — so an absent one and an empty
// one are the same failure, and neither may reach the endpoint as a half-formed pair.
func TestTokenExchangeDriver_ChainedPayloadWithoutAnIDFailsBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name     string
		material credential.SecretMaterial
		config   map[string]string
		wantErr  string // defaults to the missing-id message
	}{
		{
			name:     "id absent",
			material: credential.SecretMaterial{Data: map[string]string{"value": "s"}, Field: "value"},
		},
		{
			name:     "id empty",
			material: chainedMaterial("", "s"),
		},
		{
			name:     "conventional keys, id absent",
			material: credential.SecretMaterial{Data: map[string]string{"client_secret": "s"}},
		},
		{
			// A payload holding nothing but an id: the single-key shortcut in
			// resolveSecretField hands it back as the secret field, and without a guard
			// the one value would be spent as both halves of the pair.
			name:     "id only, resolved as the secret field",
			material: credential.SecretMaterial{Data: map[string]string{"client_id": "x"}, Field: "client_id"},
			wantErr:  "holds a client id but no secret",
		},
		{
			// Both id_jag legs authenticate, so the check has to fire ahead of leg 1
			// rather than between the two.
			name:     "id_jag, id absent",
			material: credential.SecretMaterial{Data: map[string]string{"value": "s"}, Field: "value"},
			config: map[string]string{
				"grant":              tokenExchangeGrantIDJAG,
				"resource_token_url": "https://resource.example/token",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			defer sts.Close()

			cfg := map[string]string{
				"token_url": sts.URL, "client_auth": clientAuthSecretPost, "secret_spec": "s",
			}
			for k, v := range tc.config {
				cfg[k] = v
			}
			spec := &credential.CredSpec{Config: map[string]string{"audience": "https://resource.example"}}

			d := newExchangeDriver(cfg, sts.Client())
			_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
				context.Background(), spec, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})), tc.material)
			require.Error(t, err)
			want := tc.wantErr
			if want == "" {
				want = "no client id in fetched secret material"
			}
			assert.Contains(t, err.Error(), want)
			assert.False(t, called, "no request may be sent without a complete pair")
			// A payload missing a half is refetched once rather than failing for the
			// rest of its cache TTL.
			assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		})
	}
}

// The key id travels with the key it names. Two agents signing with different keys must
// present different kids — a source-wide one would name the wrong key for all but one.
func TestTokenExchangeDriver_ChainedPrivateKeyJWT_KidComesFromThePayload(t *testing.T) {
	tests := []struct {
		name     string
		material func(pem string) credential.SecretMaterial
		wantKid  string
	}{
		{
			name: "kid under client_assertion_kid",
			material: func(p string) credential.SecretMaterial {
				return credential.SecretMaterial{Data: map[string]string{
					"value": p, "client_id": "agent-a-client", "client_assertion_kid": "key-for-agent-a",
				}, Field: "value"}
			},
			wantKid: "key-for-agent-a",
		},
		{
			name: "kid under the conventional short name",
			material: func(p string) credential.SecretMaterial {
				return credential.SecretMaterial{Data: map[string]string{
					"private_key": p, "client_id": "agent-b-client", "kid": "key-for-agent-b",
				}}
			},
			wantKid: "key-for-agent-b",
		},
		{
			// Optional: an AS resolving the key from the client id alone needs none.
			name: "no kid in the payload",
			material: func(p string) credential.SecretMaterial {
				return credential.SecretMaterial{Data: map[string]string{
					"value": p, "client_id": "agent-c-client",
				}, Field: "value"}
			},
			wantKid: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			require.NoError(t, err)
			privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

			var gotAssertion string
			sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				gotAssertion = r.Form.Get("client_assertion")
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
			}))
			defer sts.Close()

			// The source names no key and no key id.
			d := newExchangeDriver(map[string]string{
				"token_url":   sts.URL,
				"client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key",
			}, sts.Client())

			_, _, _, _, err = d.MintCredentialWithExchangeFromSecret(
				context.Background(), &credential.CredSpec{},
				subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})), tc.material(privPEM))
			require.NoError(t, err)

			require.NotEmpty(t, gotAssertion)
			parsed, err := josejwt.ParseSigned(gotAssertion)
			require.NoError(t, err)
			require.NoError(t, parsed.Claims(&priv.PublicKey, &josejwt.Claims{}), "signed with the chained key")
			require.Len(t, parsed.Headers, 1)
			assert.Equal(t, tc.wantKid, parsed.Headers[0].KeyID)
		})
	}
}

// An incomplete payload asks the manager to refetch; a source misconfigured with an
// unknown client_auth must not, since a second read cannot change the answer.
func TestTokenExchangeDriver_ChainedUnknownClientAuthIsNotRefetchable(t *testing.T) {
	d := newExchangeDriver(map[string]string{
		"token_url": "https://idp.example.com/token", "client_auth": "mtls", "secret_spec": "s",
	}, &http.Client{})

	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), &credential.CredSpec{}, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		chainedMaterial("c", "s"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential chaining supports client_auth")
	assert.NotErrorIs(t, err, credential.ErrChainedSecretIncomplete)
}

// Both ID-JAG legs authenticate, each against its own endpoint, and both do so as the
// chained client. A build that substituted the pair on only one leg would still mint.
func TestTokenExchangeDriver_ChainedIDJAG_PairOnBothLegs(t *testing.T) {
	var leg1ID, leg1Secret, leg2ID, leg2Secret string

	// Leg 2: resource authorization server redeems the ID-JAG.
	resSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		leg2ID, leg2Secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final", "expires_in": 60})
	}))
	defer resSrv.Close()

	// Leg 1: home IdP mints the ID-JAG.
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		leg1ID, leg1Secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":      "the-id-jag",
			"issued_token_type": tokenTypeIDJAG,
			"expires_in":        60,
		})
	}))
	defer idpSrv.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":          idpSrv.URL,
		"resource_token_url": resSrv.URL,
		"grant":              tokenExchangeGrantIDJAG,
		"client_auth":        clientAuthSecretPost,
		"secret_spec":        "idp-client-secret",
	}, &http.Client{})

	spec := &credential.CredSpec{Config: map[string]string{"audience": "https://resource-as.example.com"}}
	rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(
		context.Background(), spec, subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		chainedMaterial("jag-client", "jag-secret"))
	require.NoError(t, err)
	assert.Equal(t, "final", rawData["api_key"])

	assert.Equal(t, "jag-client", leg1ID, "leg 1 authenticates as the chained client")
	assert.Equal(t, "jag-secret", leg1Secret)
	assert.Equal(t, "jag-client", leg2ID, "leg 2 authenticates as the chained client")
	assert.Equal(t, "jag-secret", leg2Secret)
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

	cfg := map[string]string{"token_url": sts.URL, "client_auth": clientAuthSecretPost}
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))

	// Chained: wraps the sentinel. invalid_client does not say which half was refused,
	// and the eviction refetches both, so a stale id evicts exactly as a stale secret does.
	dChained := newExchangeDriver(cfg, sts.Client())
	_, _, _, _, err := dChained.MintCredentialWithExchangeFromSecret(context.Background(), &credential.CredSpec{}, subject, chainedMaterial("c", "stale"))
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
