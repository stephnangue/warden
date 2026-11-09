package playground

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asFixture is an authorization server whose Warden is a second IdP standing in
// for Warden's OIDC issuer, serving its keys over TLS like the real one may.
type asFixture struct {
	as     *AuthServer
	server *httptest.Server
	warden *IdP
	idp    *IdP
}

const (
	testBankMCP = "https://localhost:8420/mcp"
	testBankAPI = "https://localhost:8420/api"
)

func newASFixture(t *testing.T) *asFixture {
	t.Helper()
	warden, err := NewIdP("https://warden.test")
	require.NoError(t, err)
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, warden.JWKS())
	}))
	t.Cleanup(jwks.Close)
	wardenCA := string(certPEM(jwks.Certificate().Raw))

	idp, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)
	as, err := NewAuthServer(AuthServerConfig{
		IdP:           idp,
		WardenIssuer:  warden.Issuer(),
		WardenJWKSURL: jwks.URL,
		WardenCAPEM:   wardenCA,
		Audiences:     []string{testBankMCP, testBankAPI},
	})
	require.NoError(t, err)
	server := httptest.NewServer(as.Handler())
	t.Cleanup(server.Close)
	return &asFixture{as: as, server: server, warden: warden, idp: idp}
}

// assertion signs claims as Warden would, for the authorization server.
func (f *asFixture) assertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = f.idp.Issuer()
	}
	token, err := f.warden.sign(claims, time.Minute)
	require.NoError(t, err)
	return token
}

func (f *asFixture) exchange(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(f.server.URL+"/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func exchangeForm(subject, audience string) url.Values {
	return url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
		"audience":           {audience},
		"client_id":          {"warden"},
	}
}

func TestAuthServer_ExchangesAWardenAssertion(t *testing.T) {
	f := newASFixture(t)
	subject := f.assertion(t, map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"})

	status, body := f.exchange(t, exchangeForm(subject, testBankMCP))
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, tokenTypeAccessToken, body["issued_token_type"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, float64(300), body["expires_in"])

	claims := verifyWith(t, f.idp, body["access_token"].(string), testBankMCP)
	assert.Equal(t, "wid:root:auth_jwt_1:agent-1", claims["sub"])
	assert.Equal(t, "bank", claims["scope"])
	assert.Equal(t, "warden", claims["client_id"])
	assert.NotContains(t, claims, "act")

	// The scope it grants may be asked for by name, and an access_token-typed
	// subject is the same assertion.
	form := exchangeForm(subject, testBankMCP)
	form.Set("scope", "bank")
	form.Set("subject_token_type", tokenTypeAccessToken)
	status, body = f.exchange(t, form)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, "bank", body["scope"])
}

// A delegation assertion's person and agent both reach the bank token.
func TestAuthServer_CopiesTheActor(t *testing.T) {
	f := newASFixture(t)
	subject := f.assertion(t, map[string]any{
		"sub": "alice",
		"act": map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"},
	})

	status, body := f.exchange(t, exchangeForm(subject, testBankAPI))
	require.Equal(t, http.StatusOK, status, "%v", body)
	claims := verifyWith(t, f.idp, body["access_token"].(string), testBankAPI)
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"}, claims["act"])
}

func TestAuthServer_Refuses(t *testing.T) {
	f := newASFixture(t)
	valid := f.assertion(t, map[string]any{"sub": "agent-1"})

	// A token from the playground IdP itself is not a Warden assertion.
	selfSigned, err := f.idp.Mint(Identity{Kind: KindAgent, Subject: "agent-1"})
	require.NoError(t, err)
	wrongAudience := f.assertion(t, map[string]any{"sub": "agent-1", "aud": "https://elsewhere.test"})
	expired, err := f.warden.sign(map[string]any{"sub": "agent-1", "aud": f.idp.Issuer()}, -2*time.Minute)
	require.NoError(t, err)
	// Within the JWT library's default minute of leeway, past the server's own.
	justExpired, err := f.warden.sign(map[string]any{"sub": "agent-1", "aud": f.idp.Issuer()}, -30*time.Second)
	require.NoError(t, err)

	with := func(form url.Values, key, value string) url.Values {
		form.Set(key, value)
		return form
	}
	tests := []struct {
		name    string
		form    url.Values
		wantErr string
	}{
		{"client credentials grant", url.Values{"grant_type": {"client_credentials"}}, "unsupported_grant_type"},
		{"no client id", with(exchangeForm(valid, testBankMCP), "client_id", ""), "invalid_client"},
		{"another client", with(exchangeForm(valid, testBankMCP), "client_id", "mallory"), "invalid_client"},
		{"no subject", exchangeForm("", testBankMCP), "invalid_request"},
		{"subject sent as a SAML assertion", with(exchangeForm(valid, testBankMCP), "subject_token_type", "urn:ietf:params:oauth:token-type:saml2"), "invalid_request"},
		{"no subject token type", with(exchangeForm(valid, testBankMCP), "subject_token_type", ""), "invalid_request"},
		{"unknown audience", exchangeForm(valid, "https://other.test"), "invalid_target"},
		{"a scope it does not grant", with(exchangeForm(valid, testBankMCP), "scope", "bank admin"), "invalid_scope"},
		{"not signed by Warden", exchangeForm(selfSigned, testBankMCP), "invalid_grant"},
		{"assertion for another server", exchangeForm(wrongAudience, testBankMCP), "invalid_grant"},
		{"expired assertion", exchangeForm(expired, testBankMCP), "invalid_grant"},
		{"assertion expired 30s ago", exchangeForm(justExpired, testBankMCP), "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := f.exchange(t, tt.form)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tt.wantErr, body["error"])
			assert.NotEmpty(t, body["error_description"])
		})
	}
}

func TestAuthServer_Metadata(t *testing.T) {
	f := newASFixture(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		resp, err := http.Get(f.server.URL + path)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
		resp.Body.Close()
		assert.Equal(t, "https://localhost:8410", doc["issuer"], path)
		assert.Equal(t, "https://localhost:8410/jwks", doc["jwks_uri"], path)
		assert.Equal(t, []any{"none"}, doc["token_endpoint_auth_methods_supported"], path)
	}

	resp, err := http.Get(f.server.URL + "/jwks")
	require.NoError(t, err)
	defer resp.Body.Close()
	var jwks map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	assert.Len(t, jwks["keys"], 1)
	assert.False(t, strings.Contains(jwksString(jwks), `"d"`), "only the public key is published")
}

func jwksString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
