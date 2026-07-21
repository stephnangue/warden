package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestTokenExchangeDriver_ActorRejected(t *testing.T) {
	d := newExchangeDriver(map[string]string{
		"token_url": "https://idp.example.com", "client_id": "c", "client_secret": "s",
	}, http.DefaultClient)
	inputs := verifiedSubject(makeUnsignedJWT(map[string]interface{}{"sub": "u"}))
	inputs.ActorToken = makeUnsignedJWT(map[string]interface{}{"sub": "agent"})
	inputs.ActorTokenType = credential.TokenTypeJWT

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{}, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor tokens are not yet supported")
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
	t.Run("non-https token_url", func(t *testing.T) {
		c := base()
		c["token_url"] = "http://idp.example.com/token"
		assert.Error(t, f.ValidateConfig(c))
	})
}

func TestTokenExchangeDriverFactory_Basics(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	assert.Equal(t, credential.SourceTypeTokenExchange, f.Type())
	ct, err := f.InferCredentialType(nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, ct)
	assert.ElementsMatch(t, []string{"client_secret", "ca_data"}, f.SensitiveConfigFields())
}
