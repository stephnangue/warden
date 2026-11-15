package drivers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
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
	return newTokenExchangeDriver(credential.NewConfig(config), client, nil)
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
	spec := &credential.CredSpec{Name: "internal-api", Config: credential.NewConfig(map[string]string{
		"audience": "https://api.internal.example.com",
		"scope":    "read:orders",
	})}

	rawData, meta, ttl, leaseID, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(subject))
	require.NoError(t, err)
	assert.Equal(t, "downstream-token", rawData["api_key"])
	assert.Equal(t, 1800*time.Second-exchangedTokenBuffer, ttl)
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
	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"scope": "https://graph.microsoft.com/.default"})}

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
	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://target.example.com"})}
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
			spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{
				"resources": "https://api.example.com https://api2.example.com",
			})}
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

// A public client presents no client credential: no secret in the body, no Basic
// header, no client assertion. client_id travels only when the source names one.
func TestTokenExchangeDriver_PublicClient(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "wid:root:auth_jwt_1:agent-1"})

	for _, tc := range []struct {
		name     string
		clientID string
	}{
		{name: "with client_id", clientID: "warden"},
		{name: "without client_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got url.Values
			var authHeader string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				got = r.Form
				authHeader = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "bank-token", "expires_in": 300})
			}))
			defer server.Close()

			cfg := map[string]string{"token_url": server.URL, "client_auth": clientAuthNone}
			if tc.clientID != "" {
				cfg["client_id"] = tc.clientID
			}
			d := newExchangeDriver(cfg, server.Client())

			rawData, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subjectInputs(subject))
			require.NoError(t, err)
			assert.Equal(t, "bank-token", rawData["api_key"])

			assert.Equal(t, grantTypeTokenExchange, got.Get("grant_type"))
			assert.Equal(t, subject, got.Get("subject_token"))
			assert.Equal(t, tc.clientID, got.Get("client_id"))
			_, hasID := got["client_id"]
			assert.Equal(t, tc.clientID != "", hasID, "client_id is sent only when configured")
			for _, field := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
				_, present := got[field]
				assert.Falsef(t, present, "a public client must not send %s", field)
			}
			assert.Empty(t, authHeader, "a public client must not send an Authorization header")
		})
	}
}

// noClientCredential asserts a token request carried no client credential.
func noClientCredential(t *testing.T, r *http.Request) {
	t.Helper()
	for _, field := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
		_, present := r.Form[field]
		assert.Falsef(t, present, "a public client must not send %s", field)
	}
	assert.Empty(t, r.Header.Get("Authorization"), "a public client must not send an Authorization header")
}

// The other grants go through the same client authentication, so a public client
// stays credential-free on every leg.
func TestTokenExchangeDriver_PublicClient_OtherGrants(t *testing.T) {
	subject := makeUnsignedJWT(map[string]interface{}{"sub": "u"})

	t.Run("jwt_bearer", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			assert.Equal(t, grantTypeJWTBearer, r.Form.Get("grant_type"))
			noClientCredential(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
		}))
		defer server.Close()
		d := newExchangeDriver(map[string]string{
			"token_url": server.URL, "grant": tokenExchangeGrantJWTBearer, "client_auth": clientAuthNone,
		}, server.Client())
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, subjectInputs(subject))
		require.NoError(t, err)
	})

	// The IdP must authenticate the client it issues an ID-JAG to
	// (draft-ietf-oauth-identity-assertion-authz-grant §4.3.3), so id_jag never runs as a
	// public client: refused on a write, and before anything is sent for a source stored
	// before that check existed.
	t.Run("id_jag is refused", func(t *testing.T) {
		p := newIDJAGPair(t)
		cfg := map[string]string{
			"token_url":          "https://idp.example.com/token",
			"resource_token_url": "https://as.example.com/token",
			"grant":              tokenExchangeGrantIDJAG,
			"client_auth":        clientAuthNone,
			"client_id":          "warden",
		}
		err := (&TokenExchangeDriverFactory{}).ValidateConfig(credential.NewConfig(cfg))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_auth=none cannot be used with grant=id_jag")

		d := p.driver(map[string]string{"client_auth": clientAuthNone, "client_id": "warden", "client_secret": ""})
		_, _, _, _, err = d.MintCredentialWithExchange(context.Background(), p.spec(nil), subjectInputs(subject))
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "this id_jag source cannot mint until it is updated: client_auth=none cannot be used with grant=id_jag"), err.Error())
		assert.Zero(t, p.idpCalls)
		assert.Zero(t, p.resCalls)

		// A stored source that is public and also overrides the request names the client
		// first: no override matters until a client can authenticate.
		d = p.driver(map[string]string{"client_auth": clientAuthNone, "client_secret": "", "token_param.audience": "x"})
		_, _, _, _, err = d.MintCredentialWithExchange(context.Background(), p.spec(nil), subjectInputs(subject))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_auth=none")
		assert.NotContains(t, err.Error(), "token_param.audience")
	})

	t.Run("a public source switched to id_jag is refused on the write", func(t *testing.T) {
		// What an update validates: the stored config with the sent keys merged in.
		merged := map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": clientAuthNone, "client_id": "warden",
			"grant": tokenExchangeGrantIDJAG, "resource_token_url": "https://as.example.com/token",
		}
		err := (&TokenExchangeDriverFactory{}).ValidateConfig(credential.NewConfig(merged))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_auth=none cannot be used with grant=id_jag")
	})

	t.Run("other grants keep client_auth=none", func(t *testing.T) {
		for _, grant := range []string{tokenExchangeGrantRFC8693, tokenExchangeGrantJWTBearer} {
			cfg := credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthNone, "grant": grant,
			})
			assert.NoError(t, (&TokenExchangeDriverFactory{}).ValidateConfig(cfg), grant)
			assert.NoError(t, storedIDJAGRefusal(cfg), grant)
		}
	})
}

func TestTokenExchangeDriverFactory_PublicClientValidation(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	base := func() map[string]string {
		return map[string]string{"token_url": "https://as.example.com/token", "client_auth": clientAuthNone}
	}

	require.NoError(t, f.ValidateConfig(credential.NewConfig(base())), "no client_id is fine")
	withID := base()
	withID["client_id"] = "warden"
	require.NoError(t, f.ValidateConfig(credential.NewConfig(withID)))

	for _, key := range []string{"client_secret", "private_key", "client_assertion_alg", "client_assertion_kid",
		credential.ConfigSecretSpec, credential.ConfigSecretField, "secret_cache_ttl"} {
		t.Run("rejects "+key, func(t *testing.T) {
			c := base()
			c[key] = "x"
			if key == "private_key" {
				c[key] = testRSAPrivateKeyPEM(t)
			}
			if key == "client_assertion_alg" {
				c[key] = "RS256"
			}
			err := f.ValidateConfig(credential.NewConfig(c))
			require.Error(t, err)
			assert.Contains(t, err.Error(), key+" must be omitted for client_auth=none")
		})
	}
}

// A public-client source stores nothing, which is what keyless_enforcement_level
// reads: it gates on StoredSecrets alone.
func TestTokenExchangeDriverFactory_PublicClientStoresNoSecret(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	cfg := credential.NewConfig(map[string]string{
		"token_url": "https://as.example.com/token", "client_auth": clientAuthNone, "client_id": "warden",
	})
	require.NoError(t, f.ValidateConfig(cfg))
	assert.Empty(t, f.StoredSecrets(cfg))
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

	require.NoError(t, f.ValidateConfig(credential.NewConfig(base())))

	t.Run("missing token_url", func(t *testing.T) {
		c := base()
		delete(c, "token_url")
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("missing client credentials", func(t *testing.T) {
		c := base()
		delete(c, "client_secret")
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("bad grant", func(t *testing.T) {
		c := base()
		c["grant"] = "nope"
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("token_param overriding a core field", func(t *testing.T) {
		c := base()
		c["token_param.subject_token"] = "x"
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("id_jag without resource_token_url", func(t *testing.T) {
		c := base()
		c["grant"] = tokenExchangeGrantIDJAG
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	// idJAG is base as an id_jag source with a resource client of its own, which a
	// secret-based IdP client needs.
	idJAG := func() map[string]string {
		c := base()
		c["grant"] = tokenExchangeGrantIDJAG
		c["resource_token_url"] = "https://auth.resourceapp.example.com/token"
		c["resource_client_auth"] = clientAuthSecretPost
		c["resource_client_id"] = "c-at-resource"
		c["resource_client_secret"] = "rs"
		return c
	}
	t.Run("id_jag with resource_token_url", func(t *testing.T) {
		assert.NoError(t, f.ValidateConfig(credential.NewConfig(idJAG())))
	})
	// The ID-JAG request's own fields are Warden's to set: the pinned ones say what is
	// asked for and of whom, the first-class ones have keys of their own.
	for _, key := range []string{"requested_token_type", "audience", "scope", "resource"} {
		t.Run("id_jag refuses token_param."+key, func(t *testing.T) {
			c := idJAG()
			c["token_param."+key] = "x"
			err := f.ValidateConfig(credential.NewConfig(c))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token_param."+key)
		})
	}
	t.Run("id_jag keeps other token_param extras", func(t *testing.T) {
		c := idJAG()
		c["token_param.tenant"] = "acme"
		assert.NoError(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("jwt_bearer keeps token_param.audience", func(t *testing.T) {
		// Its documented workaround for an IdP that wants an audience on jwt-bearer.
		c := base()
		c["grant"] = tokenExchangeGrantJWTBearer
		c["token_param.audience"] = "https://api.example.com"
		assert.NoError(t, f.ValidateConfig(credential.NewConfig(c)))
	})
	t.Run("non-https token_url", func(t *testing.T) {
		c := base()
		c["token_url"] = "http://idp.example.com/token"
		assert.Error(t, f.ValidateConfig(credential.NewConfig(c)))
	})
}

// A source in chaining mode holds neither half of the client credential: not the secret,
// which is what chaining exists to remove, and not the id, which is only meaningful
// beside the secret it belongs to.
func TestTokenExchangeDriverFactory_ValidateConfig_Chaining(t *testing.T) {
	f := &TokenExchangeDriverFactory{}

	tests := []struct {
		name    string
		config  credential.Config
		wantErr string
	}{
		{
			name: "secret-based, neither half inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "secret_field": "client_secret",
			}),
		},
		{
			name: "secret-based, client_secret still inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "client_secret": "s",
			}),
			wantErr: "client_secret must be omitted when secret_spec is set",
		},
		{
			name: "secret-based, client_id still inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretBasic,
				"secret_spec": "idp-client-secret", "client_id": "c",
			}),
			wantErr: "client_id must be omitted when secret_spec is set",
		},
		{
			name: "private_key_jwt, neither half inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "secret_field": "private_key",
			}),
		},
		{
			name: "private_key_jwt, private_key still inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "private_key": testRSAPrivateKeyPEM(t),
			}),
			wantErr: "private_key must be omitted when secret_spec is set",
		},
		{
			name: "private_key_jwt, client_id still inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "client_id": "c",
			}),
			wantErr: "client_id must be omitted when secret_spec is set",
		},
		{
			// A kid names one key among several; kept on the source it would be stamped
			// on assertions signed by every agent's key.
			name: "private_key_jwt, client_assertion_kid still inline",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
				"secret_spec": "idp-key", "client_assertion_kid": "key-1",
			}),
			wantErr: "client_assertion_kid must be omitted when secret_spec is set",
		},
		{
			// kid is meaningless to the secret methods, so it is not policed there.
			name: "secret-based, an inert kid is left alone",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "client_assertion_kid": "key-1",
			}),
		},
		{
			// The chained branch must not short-circuit the rest of validation. This
			// one matters more when chained than inline: a chained source holds no
			// client_id, so an unprotected token_param.client_id would be the only
			// one on the wire.
			name: "chained, token_param overriding a core field",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"secret_spec": "idp-client-secret", "token_param.client_id": "sneaky",
			}),
			wantErr: "cannot override a core token-exchange field",
		},
		{
			name: "chained id_jag without resource_token_url",
			config: credential.NewConfig(map[string]string{
				"token_url": "https://idp.example.com/token", "client_auth": clientAuthSecretPost,
				"grant": tokenExchangeGrantIDJAG, "secret_spec": "idp-client-secret",
			}),
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
		config   credential.Config
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
			config: credential.NewConfig(map[string]string{
				"grant":              tokenExchangeGrantIDJAG,
				"resource_token_url": "https://resource.example/token",
			}),
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
			for k, v := range tc.config.All() {
				cfg[k] = v
			}
			spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://resource.example"})}

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

	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://resource-as.example.com"})}
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

// A source that names a resource client authenticates leg 2 as that client, the one the
// ID-JAG's client_id names, and leg 1 as the IdP client — from its own config or from
// one chained payload, with each client's method and audience its own.
func TestTokenExchangeDriver_IDJAG_ResourceClient(t *testing.T) {
	ctx := context.Background()
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "user"}))
	assertionOf := func(t *testing.T, form url.Values) (header, claims map[string]interface{}) {
		t.Helper()
		parts := strings.Split(form.Get("client_assertion"), ".")
		require.Len(t, parts, 3)
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &header))
		return header, unverifiedJWTClaims(form.Get("client_assertion"))
	}
	resourceSecret := map[string]string{
		"resource_client_auth": clientAuthSecretPost, "resource_client_id": "c-at-resource", "resource_client_secret": "rs",
	}

	t.Run("inline: each leg authenticates as its own client", func(t *testing.T) {
		p := newIDJAGPair(t)
		_, meta, _, _, err := p.driver(resourceSecret).MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Equal(t, "c", p.leg1.Get("client_id"))
		assert.Equal(t, "s", p.leg1.Get("client_secret"))
		assert.Equal(t, "c-at-resource", p.leg2.Get("client_id"))
		assert.Equal(t, "rs", p.leg2.Get("client_secret"))
		assert.Equal(t, "c", meta["client_id"], "audit names the IdP client")
		assert.Equal(t, "c-at-resource", meta["resource_client_id"], "and the client that redeemed the ID-JAG")
	})

	t.Run("inline: a secret at the IdP, an assertion naming the resource issuer", func(t *testing.T) {
		p := newIDJAGPair(t)
		_, _, _, _, err := p.driver(map[string]string{
			"resource_client_auth": clientAuthPrivateKeyJWT, "resource_client_id": "c-at-resource",
			"resource_private_key": testRSAPrivateKeyPEM(t), "resource_client_assertion_kid": "res-key-1",
			"resource_client_assertion_aud": clientAssertionAudIssuer, "resource_issuer": "https://res.example.com",
		}).MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Equal(t, "s", p.leg1.Get("client_secret"))
		assert.Empty(t, p.leg1.Get("client_assertion"))

		assert.Empty(t, p.leg2.Get("client_secret"), "the IdP's secret never reaches the resource server")
		header, claims := assertionOf(t, p.leg2)
		assert.Equal(t, "res-key-1", header["kid"])
		assert.Equal(t, "c-at-resource", claims["iss"])
		assert.Equal(t, "c-at-resource", claims["sub"])
		assert.Equal(t, "https://res.example.com", claims["aud"])
	})

	t.Run("chained: one payload carries a pair per leg", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"client_id": "", "client_secret": "", "secret_spec": "xaa-clients", "resource_client_auth": clientAuthSecretBasic,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "client_secret": "idp-secret",
			"resource_client_id": "xaa-app", "resource_client_secret": "xaa-secret",
		}})
		require.NoError(t, err)
		assert.Equal(t, "idp-app", p.leg1.Get("client_id"))
		assert.Equal(t, "idp-secret", p.leg1.Get("client_secret"))
		assert.Empty(t, p.leg1Auth, "leg 1 sends no Authorization header")
		assert.Equal(t, basicClientAuthHeader("xaa-app", "xaa-secret"), p.leg2Auth, "leg 2 authenticates with basic, as its own client")
		assert.Empty(t, p.leg2.Get("client_secret"))
	})

	t.Run("inline: basic at the resource server, post at the IdP", func(t *testing.T) {
		p := newIDJAGPair(t)
		_, _, _, _, err := p.driver(map[string]string{
			"resource_client_auth": clientAuthSecretBasic, "resource_client_id": "c-at-resource", "resource_client_secret": "rs",
		}).MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Empty(t, p.leg1Auth)
		assert.Equal(t, "s", p.leg1.Get("client_secret"))
		assert.Equal(t, basicClientAuthHeader("c-at-resource", "rs"), p.leg2Auth)
		assert.Empty(t, p.leg2.Get("client_id"), "basic carries the client in the header only")
	})

	t.Run("chained: each client's key id is its own", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"client_auth": clientAuthPrivateKeyJWT, "client_id": "", "client_secret": "", "secret_spec": "xaa-clients",
			"resource_client_auth": clientAuthPrivateKeyJWT,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "private_key": testRSAPrivateKeyPEM(t), "kid": "idp-key",
			"resource_client_id": "xaa-app", "resource_private_key": testRSAPrivateKeyPEM(t),
			"resource_client_assertion_kid": "xaa-key", "resource_kid": "ignored",
		}})
		require.NoError(t, err)
		leg1Header, _ := assertionOf(t, p.leg1)
		leg2Header, leg2Claims := assertionOf(t, p.leg2)
		assert.Equal(t, "idp-key", leg1Header["kid"])
		assert.Equal(t, "xaa-key", leg2Header["kid"], "resource_client_assertion_kid comes before resource_kid; the IdP's kid never reaches leg 2")
		assert.Equal(t, "xaa-app", leg2Claims["iss"])
	})

	t.Run("chained: secret_field cannot select the resource client's secret", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"client_id": "", "client_secret": "", "secret_spec": "xaa-clients", "resource_client_auth": clientAuthSecretPost,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{
			Field: "resource_client_secret",
			Data: map[string]string{
				"client_id": "idp-app", "client_secret": "idp-secret",
				"resource_client_id": "xaa-app", "resource_client_secret": "xaa-secret",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "names the resource client's credential")
		assert.NotErrorIs(t, err, credential.ErrChainedSecretIncomplete, "refetching cannot change a field selector")
		assert.Zero(t, p.idpCalls, "the resource secret never reaches the IdP")
	})

	t.Run("a cleared client_auth reads as unset", func(t *testing.T) {
		// An update clears a field by storing it empty, which the pair's driver helper
		// would drop; these configs keep it.
		p := newIDJAGPair(t)
		_, meta, _, _, err := newExchangeDriver(map[string]string{
			"token_url": p.idp.URL, "resource_token_url": p.res.URL, "grant": tokenExchangeGrantIDJAG,
			"client_auth": "", "client_id": "c", "client_secret": "s",
			"resource_client_auth": clientAuthSecretPost, "resource_client_id": "r", "resource_client_secret": "rs",
		}, &http.Client{}).MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Equal(t, "s", p.leg1.Get("client_secret"), "client_secret_post, the default")
		assert.Equal(t, "c", meta["client_id"])

		p = newIDJAGPair(t)
		_, _, _, _, err = newExchangeDriver(map[string]string{
			"token_url": p.idp.URL, "resource_token_url": p.res.URL, "grant": tokenExchangeGrantIDJAG,
			"client_auth": "", "secret_spec": "xaa-clients", "resource_client_auth": clientAuthSecretPost,
		}, &http.Client{}).MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "client_secret": "idp-secret", "resource_client_id": "xaa-app", "resource_client_secret": "xaa-secret",
		}})
		require.NoError(t, err)
		assert.Equal(t, "idp-secret", p.leg1.Get("client_secret"))

		// The other grants read it the same way.
		var got url.Values
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			got = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
		}))
		t.Cleanup(sts.Close)
		_, _, _, _, err = newExchangeDriver(map[string]string{"token_url": sts.URL, "client_auth": "", "client_id": "c", "client_secret": "s"}, &http.Client{}).
			MintCredentialWithExchange(ctx, &credential.CredSpec{}, subject)
		require.NoError(t, err)
		assert.Equal(t, "s", got.Get("client_secret"))
	})

	t.Run("chained: a key at the IdP and a secret at the resource server", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"client_auth": clientAuthPrivateKeyJWT, "client_id": "", "client_secret": "", "secret_spec": "xaa-clients",
			"resource_client_auth": clientAuthSecretPost,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "private_key": testRSAPrivateKeyPEM(t), "kid": "idp-key",
			"resource_client_id": "xaa-app", "resource_client_secret": "xaa-secret",
		}})
		require.NoError(t, err)
		header, claims := assertionOf(t, p.leg1)
		assert.Equal(t, "idp-key", header["kid"])
		assert.Equal(t, "idp-app", claims["iss"])
		assert.Equal(t, "xaa-app", p.leg2.Get("client_id"))
		assert.Equal(t, "xaa-secret", p.leg2.Get("client_secret"))
	})

	t.Run("chained: a payload without the resource client is incomplete", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"client_id": "", "client_secret": "", "secret_spec": "xaa-clients", "resource_client_auth": clientAuthSecretPost,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, p.spec(nil), subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "client_secret": "idp-secret", "resource_client_id": "xaa-app",
		}})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete, "a cached payload that predates the resource client is refetched")
		assert.Contains(t, err.Error(), "resource client")
		assert.Contains(t, err.Error(), "resource_client_secret")
		assert.Zero(t, p.idpCalls, "nothing is sent")
	})

	t.Run("chained: a resource client the resource server rejects is evicted", func(t *testing.T) {
		var leg2 url.Values
		idp := newTokenStub(t, issuesIDJAGs)
		res := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			leg2 = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_client"})
		}))
		t.Cleanup(res.Close)
		d := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.URL, "grant": tokenExchangeGrantIDJAG,
			"secret_spec": "xaa-clients", "resource_client_auth": clientAuthSecretPost,
		}, &http.Client{})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(ctx, &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com",
		})}, subject, credential.SecretMaterial{Data: map[string]string{
			"client_id": "idp-app", "client_secret": "idp-secret",
			"resource_client_id": "xaa-app", "resource_client_secret": "rotated-away",
		}})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "the refetch replaces both pairs")
		assert.True(t, strings.HasPrefix(err.Error(), "id_jag: the resource authorization server rejected the chained client credential"), err.Error())
		assert.Equal(t, "xaa-app", leg2.Get("client_id"), "what was rejected is the resource client")
		assert.Equal(t, "rotated-away", leg2.Get("client_secret"))
	})

	t.Run("a stored resource key that does not parse fails the mint, not the build", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{
			"resource_client_auth": clientAuthPrivateKeyJWT, "resource_client_id": "c-at-resource", "resource_private_key": "not-a-key",
		})
		_, _, _, _, err := d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid resource_private_key")
		assert.Zero(t, p.idpCalls, "no ID-JAG is asked for that could not be redeemed")
		assert.Zero(t, p.resCalls)
	})

	t.Run("other grants record no client ids", func(t *testing.T) {
		var got url.Values
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			got = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
		}))
		t.Cleanup(sts.Close)
		_, meta, _, _, err := newExchangeDriver(map[string]string{"token_url": sts.URL, "client_id": "c", "client_secret": "s"}, &http.Client{}).
			MintCredentialWithExchange(ctx, &credential.CredSpec{}, subject)
		require.NoError(t, err)
		assert.Equal(t, "c", got.Get("client_id"))
		assert.NotContains(t, meta, "client_id")
		assert.NotContains(t, meta, "resource_client_id")
	})
}

// A resource client is configured whole or not at all, only for id_jag, and its rules
// are its own; a secret-based IdP client needs one, since leg 2 would otherwise present
// the IdP's secret to another authorization server.
func TestTokenExchangeDriverFactory_ValidateConfig_ResourceClient(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	key := testRSAPrivateKeyPEM(t)
	cfg := func(over map[string]string) credential.Config {
		c := map[string]string{
			"token_url": "https://idp.example.com/token", "grant": tokenExchangeGrantIDJAG,
			"resource_token_url": "https://res.example.com/token",
			"client_id":          "c", "client_secret": "s",
			"resource_client_auth": clientAuthSecretPost, "resource_client_id": "r", "resource_client_secret": "rs",
		}
		for k, v := range over {
			if v == "" {
				delete(c, k)
				continue
			}
			c[k] = v
		}
		return credential.NewConfig(c)
	}
	chained := map[string]string{"client_id": "", "client_secret": "", "resource_client_id": "", "resource_client_secret": "", "secret_spec": "xaa-clients"}
	with := func(a, b map[string]string) map[string]string {
		out := maps.Clone(a)
		maps.Copy(out, b)
		return out
	}

	for _, tc := range []struct {
		name   string
		config credential.Config
		errMsg string
	}{
		{"a secret per leg", cfg(nil), ""},
		{"a key at the IdP and no resource client", cfg(map[string]string{
			"client_auth": clientAuthPrivateKeyJWT, "client_secret": "", "private_key": key,
			"resource_client_auth": "", "resource_client_id": "", "resource_client_secret": ""}), ""},
		{"both chained", cfg(chained), ""},
		{"both chained through KMS", cfg(with(chained, map[string]string{
			"client_auth": clientAuthKMSPrivateKeyJWT, "resource_client_auth": clientAuthKMSPrivateKeyJWT})), ""},
		{"a resource assertion naming its issuer", cfg(map[string]string{
			"resource_client_auth": clientAuthPrivateKeyJWT, "resource_client_secret": "", "resource_private_key": key,
			"resource_client_assertion_aud": clientAssertionAudIssuer, "resource_issuer": "https://res.example.com"}), ""},

		{"a secret at the IdP and no resource client", cfg(map[string]string{
			"resource_client_auth": "", "resource_client_id": "", "resource_client_secret": ""}),
			"leg 2 would otherwise send the IdP's client secret to the resource authorization server"},
		{"a chained secret at the IdP and no resource client", cfg(with(chained, map[string]string{"resource_client_auth": ""})),
			"leg 2 would otherwise send the IdP's client secret"},
		{"half a resource client", cfg(map[string]string{"resource_client_auth": ""}), "resource_client_id needs resource_client_auth"},
		{"a resource client off id_jag", cfg(map[string]string{"grant": tokenExchangeGrantRFC8693, "resource_token_url": ""}),
			"resource_client_auth applies only to grant=id_jag"},
		{"a resource client without its secret", cfg(map[string]string{"resource_client_secret": ""}),
			"resource_client_secret (or secret_spec) is required for a secret-based resource_client_auth"},
		{"a public resource client", cfg(map[string]string{"resource_client_auth": clientAuthNone}), "resource_client_auth"},
		{"an inline resource client on a chained source", cfg(with(chained, map[string]string{"resource_client_id": "r"})),
			"resource_client_id must be omitted when secret_spec is set"},
		{"KMS on one leg only", cfg(with(chained, map[string]string{"client_auth": clientAuthKMSPrivateKeyJWT})),
			"must both be kms_private_key_jwt or neither"},
		{"KMS on the other leg only", cfg(with(chained, map[string]string{"resource_client_auth": clientAuthKMSPrivateKeyJWT})),
			"must both be kms_private_key_jwt or neither"},
		{"secret_field naming the resource client's secret", cfg(with(chained, map[string]string{credential.ConfigSecretField: "resource_client_secret"})),
			"names the resource client's credential"},
		// An update clears a field by storing it empty; a cleared client_auth is unset.
		{"a cleared client_auth on a secret source with no resource client", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "grant": tokenExchangeGrantIDJAG, "resource_token_url": "https://res.example.com/token",
			"client_auth": "", "client_id": "c", "client_secret": "s"}),
			"leg 2 would otherwise send the IdP's client secret"},
		{"a cleared client_auth still needs its secret", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": "", "client_id": "c"}),
			"client_secret (or secret_spec) is required for a secret-based client_auth"},
		{"a cleared client_auth on a chained source keeps no inline id", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": "", "client_id": "c", "secret_spec": "s"}),
			"client_id must be omitted when secret_spec is set"},
		{"an audience for a secret", cfg(map[string]string{"resource_client_assertion_aud": clientAssertionAudTokenURL}),
			"resource_client_assertion_aud must be omitted for resource_client_auth=client_secret_post"},
		{"the issuer audience without the issuer", cfg(map[string]string{
			"resource_client_auth": clientAuthPrivateKeyJWT, "resource_client_secret": "", "resource_private_key": key,
			"resource_client_assertion_aud": clientAssertionAudIssuer}),
			"resource_client_assertion_aud=issuer requires resource_issuer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := f.ValidateConfig(tc.config)
			if tc.errMsg == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}

	assert.ElementsMatch(t, []string{"client_secret", "resource_client_secret"}, f.StoredSecrets(cfg(nil)))
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

	// Leg 2: resource authorization server redeems the ID-JAG for an access token. The
	// request carries the grant, the assertion, the scope the IdP granted (here the one
	// asked for, since the answer names none) and the client authentication; resources
	// stay in the ID-JAG.
	resSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":     {"the-id-jag"},
			"scope":         {"files:read"},
			"client_id":     {"c"},
			"client_secret": {"s"},
		}, r.PostForm)
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
		// The IdP decides on scope and resources and writes them into the ID-JAG
		// (draft-ietf-oauth-identity-assertion-authz-grant §4.3). Resources go out
		// verbatim, trailing slash included: a value from protected resource metadata
		// must be sent unchanged.
		assert.Equal(t, "files:read", r.Form.Get("scope"))
		assertResources(t, r.Form, "https://api.example.com/", "https://files.example.com")
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
	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{
		"audience":  "https://resource-as.example.com",
		"scope":     "files:read",
		"resources": "https://api.example.com/ https://files.example.com",
	})}

	rawData, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), spec, subjectInputs(subject))
	require.NoError(t, err)
	assert.Equal(t, "final-access", rawData["api_key"], "the final resource-AS access token is returned, not the ID-JAG")
	assert.Equal(t, 600*time.Second-exchangedTokenBuffer, ttl)
}

// A source stored before token_param.* was checked for id_jag reaches the driver
// without a write. Its extras still meet the rules at mint.
func TestTokenExchangeDriver_IDJAG_StoredTokenParams(t *testing.T) {
	ctx := context.Background()
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "user"}))

	for _, key := range []string{"requested_token_type", "audience"} {
		t.Run("pinned token_param."+key+" is refused before anything is sent or signed", func(t *testing.T) {
			p := newIDJAGPair(t)
			// A key that cannot be parsed: if anything tried to sign, the error would say so.
			d := p.driver(map[string]string{
				"token_param." + key: "x",
				"client_auth":        clientAuthPrivateKeyJWT,
				"client_secret":      "",
				"private_key":        "not-a-key",
			})
			_, _, _, _, err := d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token_param."+key)
			assert.Zero(t, p.idpCalls)
			assert.Zero(t, p.resCalls)
		})
	}

	t.Run("with both pinned fields stored, the refusal always names the first", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{"token_param.audience": "x", "token_param.requested_token_type": "x"})
		for range 5 {
			_, _, _, _, err := d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token_param.requested_token_type")
		}
	})

	t.Run("token_param.scope stands in only for an empty scope", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{"token_param.scope": "files:read files:write"})

		_, _, _, _, err := d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Equal(t, []string{"files:read files:write"}, p.leg1["scope"])

		_, _, _, _, err = d.MintCredentialWithExchange(ctx, p.spec(map[string]string{"scope": "files:read"}), subject)
		require.NoError(t, err)
		assert.Equal(t, []string{"files:read"}, p.leg1["scope"], "a spec's narrower scope is never replaced")

		// The source's own scope also wins over the stored extra.
		d = p.driver(map[string]string{"token_param.scope": "files:read files:write", "scope": "files:list"})
		_, _, _, _, err = d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assert.Equal(t, []string{"files:list"}, p.leg1["scope"])
	})

	t.Run("token_param.resource never collapses repeated resources", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{"token_param.resource": "https://other.example.com https://more.example.com"})

		_, _, _, _, err := d.MintCredentialWithExchange(ctx,
			p.spec(map[string]string{"resources": "https://api.example.com https://files.example.com"}), subject)
		require.NoError(t, err)
		assertResources(t, p.leg1, "https://api.example.com", "https://files.example.com")

		// As a fallback it is split like resources: one indicator per value.
		_, _, _, _, err = d.MintCredentialWithExchange(ctx, p.spec(nil), subject)
		require.NoError(t, err)
		assertResources(t, p.leg1, "https://other.example.com", "https://more.example.com")
	})

	t.Run("other extras reach leg 1 only, and leg 2 carries only the granted scope", func(t *testing.T) {
		p := newIDJAGPair(t)
		d := p.driver(map[string]string{"token_param.tenant": "acme", "token_param.scope": "files:read"})

		_, _, _, _, err := d.MintCredentialWithExchange(ctx, p.spec(map[string]string{"resources": "https://api.example.com"}), subject)
		require.NoError(t, err)
		assert.Equal(t, "acme", p.leg1.Get("tenant"))
		assert.Equal(t, url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":     {"the-id-jag"},
			"scope":         {"files:read"},
			"client_id":     {"c"},
			"client_secret": {"s"},
		}, p.leg2)
	})
}

// The redemption asks for the scope the IdP granted: what its answer names, which may
// be less than was asked for, or nothing when the request named no scope.
func TestTokenExchangeDriver_IDJAG_RedeemsTheGrantedScope(t *testing.T) {
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "user"}))
	run := func(t *testing.T, requested, granted string) url.Values {
		var leg2 url.Values
		res := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			leg2 = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final-access", "expires_in": 600})
		}))
		t.Cleanup(res.Close)
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			answer := map[string]interface{}{"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300}
			if granted != "" {
				answer["scope"] = granted
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(answer)
		}))
		t.Cleanup(idp.Close)
		d := newExchangeDriver(map[string]string{
			"token_url": idp.URL, "resource_token_url": res.URL, "grant": tokenExchangeGrantIDJAG,
			"client_id": "c", "client_secret": "s",
		}, &http.Client{})
		cfg := map[string]string{"audience": "https://resource-as.example.com"}
		if requested != "" {
			cfg["scope"] = requested
		}
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{Config: credential.NewConfig(cfg)}, subject)
		require.NoError(t, err)
		return leg2
	}

	t.Run("less than was asked for", func(t *testing.T) {
		assert.Equal(t, []string{"files:read"}, run(t, "files:read files:write", "files:read")["scope"])
	})
	t.Run("what was asked for, unnamed in the answer", func(t *testing.T) {
		assert.Equal(t, []string{"files:read files:write"}, run(t, "files:read files:write", "")["scope"])
	})
	t.Run("none asked for, none granted", func(t *testing.T) {
		assert.NotContains(t, run(t, "", ""), "scope")
	})
}

// Each leg's refusals read by the codes the draft profiles for that leg, so an
// operator can tell what would fix them.
func TestTokenExchangeDriver_IDJAG_ErrorCodes(t *testing.T) {
	refusal := func(code string) error {
		return &tokenEndpointError{status: http.StatusBadRequest, code: code}
	}
	request := classifyIDJAGRequestError(false)
	for code, want := range map[string]string{
		"invalid_request": "the IdP refused the subject token",
		"invalid_grant":   "the IdP refused the subject token",
		"access_denied":   "the IdP does not allow this client or user an ID-JAG",
		"invalid_target":  "check audience and resources",
		"invalid_client":  "the IdP rejected Warden's client authentication",
		"server_error":    "requesting the ID-JAG from the IdP failed",
	} {
		err := request(refusal(code))
		assert.Contains(t, err.Error(), want, code)
		assert.NotErrorIs(t, err, credential.ErrUserChallenge, code)
	}
	for code, want := range map[string]string{
		"invalid_grant":  "the resource authorization server refused the ID-JAG",
		"access_denied":  "the resource authorization server does not allow this user or client",
		"invalid_client": "the resource authorization server rejected Warden's client authentication",
		"server_error":   "redeeming the ID-JAG at the resource authorization server failed",
	} {
		assert.Contains(t, classifyIDJAGRedeemError(refusal(code)).Error(), want, code)
	}

	// Only a refused subject that is the user's own token asks the user to sign in
	// again; whatever else the IdP refuses, a new user token would not help.
	err := classifyIDJAGRequestError(true)(refusal("invalid_request"))
	assert.ErrorIs(t, err, credential.ErrUserChallenge)
	var challenge *credential.UserChallengeError
	require.ErrorAs(t, err, &challenge)
	assert.Equal(t, credential.UserChallengeInvalidToken, challenge.Code)
	assert.NotErrorIs(t, classifyIDJAGRequestError(true)(refusal("access_denied")), credential.ErrUserChallenge)
	// invalid_grant is not the code the draft profiles for a refused subject; until an
	// IdP shows that it means the user's token, it asks nothing of the user.
	assert.NotErrorIs(t, classifyIDJAGRequestError(true)(refusal("invalid_grant")), credential.ErrUserChallenge)
}

func TestTokenExchangeDriver_IDJAG_ErrorsOnTheWire(t *testing.T) {
	ctx := context.Background()
	subject := subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "user"}))

	t.Run("a 403 from the resource authorization server is read", func(t *testing.T) {
		idp := newTokenStub(t, issuesIDJAGs)
		res := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusForbidden, map[string]interface{}{"error": "access_denied", "error_description": "not licensed"}
		})
		d := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.srv.URL,
			"grant": tokenExchangeGrantIDJAG, "client_id": "c", "client_secret": "s",
		}, &http.Client{})
		_, _, _, _, err := d.MintCredentialWithExchange(ctx, &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com",
		})}, subject)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow this user or client")
		assert.Contains(t, err.Error(), "not licensed")
	})

	t.Run("a refusal whose body names no OAuth2 error keeps its body", func(t *testing.T) {
		idp := newTokenStub(t, issuesIDJAGs)
		res := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusForbidden, map[string]interface{}{"message": "blocked by policy"}
		})
		d := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.srv.URL,
			"grant": tokenExchangeGrantIDJAG, "client_id": "c", "client_secret": "s",
		}, &http.Client{})
		_, _, _, _, err := d.MintCredentialWithExchange(ctx, &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com",
		})}, subject)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "blocked by policy")
		var tee *tokenEndpointError
		require.ErrorAs(t, err, &tee)
		assert.Equal(t, http.StatusForbidden, tee.HTTPStatus())
	})

	t.Run("an expired user token asks the user to authenticate again", func(t *testing.T) {
		idp := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusBadRequest, map[string]interface{}{"error": "invalid_request", "error_description": "token expired"}
		})
		res := newTokenStub(t, losesFirst)
		d := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.srv.URL,
			"grant": tokenExchangeGrantIDJAG, "client_id": "c", "client_secret": "s",
		}, &http.Client{})
		spec := func(source string) *credential.CredSpec {
			return &credential.CredSpec{Config: credential.NewConfig(map[string]string{
				"audience": "https://resource-as.example.com", credential.ConfigSubjectTokenSource: source,
			})}
		}

		_, _, _, _, err := d.MintCredentialWithExchange(ctx, spec(credential.SourceUserIdentity), subject)
		assert.ErrorIs(t, err, credential.ErrUserChallenge)
		_, _, _, _, err = d.MintCredentialWithExchange(ctx, spec(credential.SourceAgentIdentity), subject)
		require.Error(t, err)
		assert.NotErrorIs(t, err, credential.ErrUserChallenge, "the agent's own token is not the user's to renew")
		assert.Zero(t, res.count())

		// A request the IdP could refuse for something other than the user's token asks
		// nothing of the user: an actor token rides along, or extras of the source's own.
		withActor := *subject
		withActor.ActorToken = makeUnsignedJWT(map[string]interface{}{"sub": "agent"})
		withActor.ActorTokenType = credential.TokenTypeJWT
		_, _, _, _, err = d.MintCredentialWithExchange(ctx, spec(credential.SourceUserIdentity), &withActor)
		require.Error(t, err)
		assert.NotErrorIs(t, err, credential.ErrUserChallenge, "the IdP may have refused the actor token")

		withExtra := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.srv.URL,
			"grant": tokenExchangeGrantIDJAG, "client_id": "c", "client_secret": "s",
			"token_param.tenant": "acme",
		}, &http.Client{})
		_, _, _, _, err = withExtra.MintCredentialWithExchange(ctx, spec(credential.SourceUserIdentity), subject)
		require.Error(t, err)
		assert.NotErrorIs(t, err, credential.ErrUserChallenge, "the IdP may have refused the source's own extra")
	})

	t.Run("an answer that does not say it issued an ID-JAG is not redeemed", func(t *testing.T) {
		idp := newTokenStub(t, func(int) (int, map[string]interface{}) {
			return http.StatusOK, map[string]interface{}{"access_token": "something", "expires_in": 300}
		})
		res := newTokenStub(t, losesFirst)
		d := newExchangeDriver(map[string]string{
			"token_url": idp.srv.URL, "resource_token_url": res.srv.URL,
			"grant": tokenExchangeGrantIDJAG, "client_id": "c", "client_secret": "s",
		}, &http.Client{})
		_, _, _, _, err := d.MintCredentialWithExchange(ctx, &credential.CredSpec{Config: credential.NewConfig(map[string]string{
			"audience": "https://resource-as.example.com",
		})}, subject)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issued_token_type")
		assert.Zero(t, res.count())
	})
}

// The subject of an ID-JAG request is an identity assertion: the spec names its type in
// plain words, the request carries the URN, and anything else is refused before a
// request is sent.
func TestTokenExchangeDriver_IDJAG_SubjectTokenType(t *testing.T) {
	ctx := context.Background()
	idToken := makeUnsignedJWT(map[string]interface{}{"sub": "user"})
	jwtTyped := func(typ string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"` + typ + `"}`))
		return header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`)) + ".sig"
	}

	for _, tc := range []struct{ name, set, want string }{
		{"left out", "", credential.TokenTypeIDToken},
		{"id_token", "id_token", credential.TokenTypeIDToken},
		{"saml2", "saml2", credential.TokenTypeSAML2},
		{"refresh_token", "refresh_token", credential.TokenTypeRefreshToken},
		{"a stored URN", credential.TokenTypeIDToken, credential.TokenTypeIDToken},
	} {
		t.Run("sends "+tc.name, func(t *testing.T) {
			p := newIDJAGPair(t)
			_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx,
				p.spec(map[string]string{credential.ConfigSubjectTokenType: tc.set}), subjectInputs(idToken))
			require.NoError(t, err)
			assert.Equal(t, tc.want, p.leg1.Get("subject_token_type"))
		})
	}

	for _, set := range []string{"jwt", "access_token", credential.TokenTypeJWT, credential.TokenTypeAccessToken, tokenTypeIDJAG, "id-token"} {
		t.Run("refuses "+set, func(t *testing.T) {
			p := newIDJAGPair(t)
			_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx,
				p.spec(map[string]string{credential.ConfigSubjectTokenType: set}), subjectInputs(idToken))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot be used with grant=id_jag")
			assert.Zero(t, p.idpCalls)
		})
	}

	t.Run("refuses a subject Warden signs", func(t *testing.T) {
		p := newIDJAGPair(t)
		_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx,
			p.spec(map[string]string{credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity}), subjectInputs(idToken))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject_token_source=warden_identity cannot be used with grant=id_jag")
		assert.Zero(t, p.idpCalls)
	})

	header := func(json string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(json)) + ".e30.sig"
	}
	for name, subject := range map[string]string{
		"not a JWT":                               "opaque-token",
		"two segments":                            "a.b",
		"four segments":                           "a.b.c.d",
		"a header that does not decode":           "!!!.e30.sig",
		"a header that is not JSON":               header("not json"),
		"an access token":                         jwtTyped("at+jwt"),
		"an access token, by its full media type": jwtTyped("application/AT+JWT"),
		"an access token, with a parameter":       jwtTyped("at+jwt; v=1"),
		"an ID-JAG":                               jwtTyped("oauth-id-jag+jwt"),
	} {
		t.Run("refuses an ID token that is "+name, func(t *testing.T) {
			p := newIDJAGPair(t)
			_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx, p.spec(nil), subjectInputs(subject))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "the caller must present an ID token issued to this source's client")
			assert.Zero(t, p.idpCalls)
		})
	}

	for name, subject := range map[string]string{
		"typ left out":      header(`{"alg":"RS256"}`),
		"typ not a string":  header(`{"alg":"RS256","typ":1}`),
		"typ in lowercase":  jwtTyped("jwt"),
		"an encrypted one":  base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","typ":"JWT"}`)) + ".k.iv.ct.tag",
		"a vendor's typ":    jwtTyped("id_token+jwt"),
		"the plain JWT typ": idToken,
	} {
		t.Run("sends an ID token with "+name, func(t *testing.T) {
			p := newIDJAGPair(t)
			_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx, p.spec(nil), subjectInputs(subject))
			require.NoError(t, err)
			assert.Equal(t, credential.TokenTypeIDToken, p.leg1.Get("subject_token_type"))
		})
	}

	t.Run("a refresh token is not read as a JWT", func(t *testing.T) {
		p := newIDJAGPair(t)
		_, _, _, _, err := p.driver(nil).MintCredentialWithExchange(ctx,
			p.spec(map[string]string{credential.ConfigSubjectTokenType: "refresh_token"}), subjectInputs("opaque-refresh-token"))
		require.NoError(t, err)
		assert.Equal(t, credential.TokenTypeRefreshToken, p.leg1.Get("subject_token_type"))
	})

	t.Run("a spec-less mint sends an ID token", func(t *testing.T) {
		// The audience then comes from the source, as for any key resolve reads.
		p := newIDJAGPair(t)
		_, _, _, _, err := p.driver(map[string]string{"audience": "https://resource-as.example.com"}).
			MintCredentialWithExchange(ctx, nil, subjectInputs(idToken))
		require.NoError(t, err)
		assert.Equal(t, credential.TokenTypeIDToken, p.leg1.Get("subject_token_type"))
	})
}

// A spec may name its subject and actor token types by short name under every grant;
// the request carries the URN, and a type Warden does not know goes out as written.
func TestTokenExchangeDriver_TokenTypeShortNames(t *testing.T) {
	var got url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()
	d := newExchangeDriver(map[string]string{"token_url": sts.URL, "client_id": "c", "client_secret": "s"}, &http.Client{})
	mint := func(subjectType, actorType string) {
		t.Helper()
		inputs := &credential.ExchangeInputs{
			SubjectToken: "subject", SubjectTokenType: subjectType,
			ActorToken: "actor", ActorTokenType: actorType,
		}
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
		require.NoError(t, err)
	}

	mint("id_token", "jwt")
	assert.Equal(t, credential.TokenTypeIDToken, got.Get("subject_token_type"))
	assert.Equal(t, credential.TokenTypeJWT, got.Get("actor_token_type"))

	mint(credential.TokenTypeAccessToken, credential.TokenTypeJWT)
	assert.Equal(t, credential.TokenTypeAccessToken, got.Get("subject_token_type"), "a URN goes out as it is")
	assert.Equal(t, credential.TokenTypeJWT, got.Get("actor_token_type"))

	mint("urn:example:token-type:custom", "urn:example:token-type:agent")
	assert.Equal(t, "urn:example:token-type:custom", got.Get("subject_token_type"), "an STS-defined type goes out as written")
	assert.Equal(t, "urn:example:token-type:agent", got.Get("actor_token_type"))
}

// A stored id_jag source that carries a field a write would now refuse is logged each
// time its driver is built, with the endpoints that identify it.
func TestTokenExchangeDriver_IDJAG_StoredTokenParamsWarn(t *testing.T) {
	build := func(cfg map[string]string) string {
		var buf bytes.Buffer
		config := logger.DefaultConfig()
		config.Format = logger.JSONFormat
		config.Environment = "production"
		log, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{Underlying: &buf, InitialState: logger.GateOpen})
		newTokenExchangeDriver(credential.NewConfig(cfg), &http.Client{}, log)
		return buf.String()
	}

	out := build(map[string]string{
		"grant":                tokenExchangeGrantIDJAG,
		"token_url":            "https://idp.example.com/token",
		"resource_token_url":   "https://as.example.com/token",
		"client_auth":          clientAuthPrivateKeyJWT,
		"token_param.audience": "x",
		"token_param.scope":    "files:read",
		"token_param.tenant":   "acme",
	})
	assert.Equal(t, 2, strings.Count(out, `"level":"warn"`), out)
	assert.Contains(t, out, "cannot mint")
	assert.Contains(t, out, "token_param.audience")
	assert.Contains(t, out, `"config_key":"scope"`)
	assert.Contains(t, out, "https://idp.example.com/token")
	assert.Contains(t, out, "https://as.example.com/token")
	assert.NotContains(t, out, `"token_param":"tenant"`, "an ordinary extra is not warned about")

	out = build(map[string]string{
		"grant":              tokenExchangeGrantIDJAG,
		"token_url":          "https://idp.example.com/token",
		"resource_token_url": "https://as.example.com/token",
		"client_auth":        clientAuthNone,
	})
	assert.Equal(t, 1, strings.Count(out, `"level":"warn"`), out)
	assert.Contains(t, out, "client_auth=none cannot be used with grant=id_jag")

	// A secret-based source with no resource client keeps minting, sending the IdP's
	// secret to the resource authorization server, and says so.
	out = build(map[string]string{
		"grant":              tokenExchangeGrantIDJAG,
		"token_url":          "https://idp.example.com/token",
		"resource_token_url": "https://as.example.com/token",
		"client_id":          "c", "client_secret": "s",
	})
	assert.Equal(t, 1, strings.Count(out, `"level":"warn"`), out)
	assert.Contains(t, out, "sends the IdP's client secret to the resource authorization server")
	assert.Empty(t, build(map[string]string{
		"grant":              tokenExchangeGrantIDJAG,
		"token_url":          "https://idp.example.com/token",
		"resource_token_url": "https://as.example.com/token",
		"client_id":          "c", "client_secret": "s",
		"resource_client_auth": clientAuthSecretPost, "resource_client_id": "r", "resource_client_secret": "rs",
	}), "a resource client of its own")

	assert.Empty(t, build(map[string]string{
		"grant":                tokenExchangeGrantJWTBearer,
		"token_url":            "https://idp.example.com/token",
		"token_param.audience": "x",
	}), "jwt_bearer keeps token_param.audience")
	assert.Empty(t, build(map[string]string{
		"token_url": "https://idp.example.com/token", "client_auth": clientAuthNone,
	}), "rfc8693 keeps client_auth=none")
}

// idJAGPair is an IdP and a resource authorization server for one id_jag test. It
// records the last form each leg received and how often each was called.
type idJAGPair struct {
	idp, res           *httptest.Server
	leg1, leg2         url.Values
	leg1Auth, leg2Auth string // each leg's Authorization header
	idpCalls, resCalls int
}

func newIDJAGPair(t *testing.T) *idJAGPair {
	p := &idJAGPair{}
	p.res = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		p.resCalls++
		p.leg2 = r.PostForm
		p.leg2Auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final-access", "expires_in": 600})
	}))
	p.idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		p.idpCalls++
		p.leg1 = r.PostForm
		p.leg1Auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300})
	}))
	t.Cleanup(func() { p.idp.Close(); p.res.Close() })
	return p
}

// driver builds an id_jag driver for the pair, as a stored source: no write check runs.
// An empty value in extra removes the key.
func (p *idJAGPair) driver(extra map[string]string) *TokenExchangeDriver {
	cfg := map[string]string{
		"token_url":          p.idp.URL,
		"resource_token_url": p.res.URL,
		"grant":              tokenExchangeGrantIDJAG,
		"client_id":          "c",
		"client_secret":      "s",
	}
	for k, v := range extra {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return newExchangeDriver(cfg, &http.Client{})
}

func (p *idJAGPair) spec(kv map[string]string) *credential.CredSpec {
	cfg := map[string]string{"audience": "https://resource-as.example.com"}
	for k, v := range kv {
		cfg[k] = v
	}
	return &credential.CredSpec{Config: credential.NewConfig(cfg)}
}

func TestTokenExchangeDriverFactory_Basics(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	assert.Equal(t, credential.SourceTypeTokenExchange, f.Type())
	ct, err := f.InferCredentialType(credential.NewConfig(nil))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, ct)
	assert.ElementsMatch(t, []string{"client_secret", "private_key", "resource_client_secret", "resource_private_key", "ca_data"}, f.SensitiveConfigFields())
}
