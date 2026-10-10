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

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenExchangeDriverFactory_ValidateConfig_AssertionAudience(t *testing.T) {
	key := newOAuth2TestKey(t)
	base := func(over map[string]string) credential.Config {
		cfg := map[string]string{
			"token_url":   "https://idp.example.com/token",
			"client_auth": clientAuthPrivateKeyJWT,
			"client_id":   "c",
			"private_key": key.pem,
		}
		for k, v := range over {
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}
	idJAG := map[string]string{"grant": tokenExchangeGrantIDJAG, "resource_token_url": "https://res.example.com/token"}
	with := func(a, b map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range a {
			out[k] = v
		}
		for k, v := range b {
			out[k] = v
		}
		return out
	}

	cases := []struct {
		name   string
		config credential.Config
		errMsg string
	}{
		{"default audience", base(nil), ""},
		{"explicit token_url", base(map[string]string{"client_assertion_aud": "token_url"}), ""},
		{"issuer", base(map[string]string{"client_assertion_aud": "issuer", "issuer": "https://idp.example.com"}), ""},
		{"issuer on both id_jag legs", base(with(idJAG, map[string]string{
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com", "resource_issuer": "https://res.example.com"})), ""},
		{"kms with issuer", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": clientAuthKMSPrivateKeyJWT, "secret_spec": "signer",
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com"}), ""},
		{"unknown mode", base(map[string]string{"client_assertion_aud": "both"}), "client_assertion_aud"},
		{"issuer without an issuer", base(map[string]string{"client_assertion_aud": "issuer"}), "client_assertion_aud=issuer requires issuer"},
		{"id_jag without the resource issuer", base(with(idJAG, map[string]string{
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com"})), "resource_issuer is required for grant=id_jag"},
		{"resource issuer off id_jag", base(map[string]string{
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com", "resource_issuer": "https://res.example.com"}), "resource_issuer applies only to grant=id_jag"},
		{"an audience with no assertion", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "client_id": "c", "client_secret": "s",
			"client_assertion_aud": "token_url"}), "client_assertion_aud must be omitted for client_auth=client_secret_post"},
		{"an audience on a public client", credential.NewConfig(map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": clientAuthNone,
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com"}), "client_assertion_aud must be omitted for client_auth=none"},
		{"an issuer nothing reads", base(map[string]string{"issuer": "https://idp.example.com"}), "issuer is read only when client_assertion_aud=issuer"},
		{"a resource issuer nothing reads", base(with(idJAG, map[string]string{
			"client_assertion_aud": "token_url", "resource_issuer": "https://res.example.com"})), "resource_issuer is read only when client_assertion_aud=issuer"},
		{"issuer must be a URL", base(map[string]string{"client_assertion_aud": "issuer", "issuer": "ftp://idp.example.com"}), "issuer must use https"},
		{"issuer over http", base(map[string]string{"client_assertion_aud": "issuer", "issuer": "http://idp.example.com"}), "issuer must use https"},
		{"issuer over http in development", base(map[string]string{"client_assertion_aud": "issuer", "issuer": "http://127.0.0.1:8080", "tls_skip_verify": "true", "token_url": "http://127.0.0.1:8080/token"}), ""},
		{"issuer with a query", base(map[string]string{"client_assertion_aud": "issuer", "issuer": "https://idp.example.com?tenant=a"}), "issuer must be an issuer identifier, which has no query or fragment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&TokenExchangeDriverFactory{}).ValidateConfig(tc.config)
			if tc.errMsg == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// Moving a key-authenticated source to a secret-based method clears its client-assertion
// settings, so the planned config validates instead of carrying over what the new method
// refuses.
func TestKeylessPlan_LeavingClientAssertionsClearsTheirSettings(t *testing.T) {
	inputs := map[string]string{"client_auth": clientAuthSecretPost, credential.ConfigSecretSpec: "idp-client-secret"}
	pemKey := newOAuth2TestKey(t).pem

	type planner interface {
		PlanKeyless(credential.Config, map[string]string) (*credential.KeylessSourcePlan, error)
		ValidateConfig(credential.Config) error
	}
	cases := map[string]struct {
		factory planner
		current map[string]string
	}{
		"oauth2": {&OAuth2DriverFactory{}, map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
			"client_id": "c", "private_key": pemKey, "client_assertion_alg": "RS256",
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com",
		}},
		"token_exchange": {&TokenExchangeDriverFactory{}, map[string]string{
			"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
			"client_id": "c", "private_key": pemKey,
			"client_assertion_aud": "issuer", "issuer": "https://idp.example.com",
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			current := credential.NewConfig(tc.current)
			require.NoError(t, tc.factory.ValidateConfig(current), "precondition: the source as it stands is valid")
			plan, err := tc.factory.PlanKeyless(current, inputs)
			require.NoError(t, err)
			planned := current.WithAll(plan.Delta)
			assert.NoError(t, tc.factory.ValidateConfig(planned), "the planned config validates: %v", plan.Delta)
		})
	}
}

// assertionAudience reads aud out of the client assertion a request carried.
func assertionAudience(t *testing.T, r *http.Request) string {
	t.Helper()
	require.NoError(t, r.ParseForm())
	parts := strings.Split(r.Form.Get("client_assertion"), ".")
	require.Len(t, parts, 3, "the request must carry a signed assertion")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &claims))
	aud, _ := claims["aud"].(string)
	return aud
}

// An authorization server enforcing RFC 7523bis accepts only its issuer identifier as
// the audience.
func TestTokenExchangeDriver_IssuerAudience(t *testing.T) {
	key := newOAuth2TestKey(t)
	var (
		mu     sync.Mutex
		gotAud string
	)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud := assertionAudience(t, r)
		mu.Lock()
		gotAud = aud
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "t", "expires_in": 60})
	}))
	defer sts.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":            sts.URL,
		"client_auth":          clientAuthPrivateKeyJWT,
		"client_id":            "warden-gateway",
		"private_key":          key.pem,
		"client_assertion_aud": "issuer",
		"issuer":               "https://idp.example.com",
	}, sts.Client())

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), &credential.CredSpec{},
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})))
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "https://idp.example.com", gotAud, "the issuer, as the sole audience")
}

// id_jag authenticates to two servers, so each leg names its own server's issuer.
func TestTokenExchangeDriver_IDJAGIssuerAudiencePerLeg(t *testing.T) {
	_, kmsURL := newFakeSigningBackend(t)
	var (
		mu         sync.Mutex
		leg1, leg2 string
	)
	resSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud := assertionAudience(t, r)
		mu.Lock()
		leg2 = aud
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final", "expires_in": 600})
	}))
	defer resSrv.Close()
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud := assertionAudience(t, r)
		mu.Lock()
		leg1 = aud
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300})
	}))
	defer idpSrv.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":            idpSrv.URL,
		"resource_token_url":   resSrv.URL,
		"grant":                tokenExchangeGrantIDJAG,
		"client_auth":          clientAuthKMSPrivateKeyJWT,
		"secret_spec":          "idp-client-signer",
		"client_assertion_aud": "issuer",
		"issuer":               "https://idp.example.com",
		"resource_issuer":      "https://res.example.com",
	}, &http.Client{})
	spec := &credential.CredSpec{Config: credential.NewConfig(map[string]string{"audience": "https://res.example.com"})}

	rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec,
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u"})),
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err)
	assert.Equal(t, "final", rawData["api_key"])

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "https://idp.example.com", leg1, "leg 1 names the home IdP's issuer")
	assert.Equal(t, "https://res.example.com", leg2, "leg 2 names the resource server's issuer")
}
