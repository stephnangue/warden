package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deliberately non-real values, so secret scanners have nothing to match.
const (
	openaiTestProvider = "example-identity-provider"
	openaiTestAccount  = "example-service-account"
	openaiTestToken    = "openai-federated-test-token"
	openaiTestAgentSub = "wid:root:auth/jwt/:agent-1"
)

// openaiTestAssertion is an agent-only assertion in the default profile's shape:
// the agent's composite sub at the top, no act.
var openaiTestAssertion = makeUnsignedJWT(map[string]interface{}{
	"iss": "https://warden.example.com",
	"sub": openaiTestAgentSub,
	"aud": "https://warden.example.com/openai",
})

// openaiTokenStub stands in for OpenAI's token endpoint. It records every grant it
// receives, with its headers, and answers with respond — so a test can assert both
// what the driver sent and how it treats what came back.
type openaiTokenStub struct {
	server  *httptest.Server
	respond func(w http.ResponseWriter)

	mu      sync.Mutex
	grants  []map[string]string
	headers []http.Header
}

func newOpenAITokenStub(t *testing.T, respond func(w http.ResponseWriter)) *openaiTokenStub {
	t.Helper()
	s := &openaiTokenStub{respond: respond}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != openaiTokenPath {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		var grant map[string]string
		if err := json.NewDecoder(r.Body).Decode(&grant); err != nil {
			http.Error(w, "body is not a JSON object", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.grants = append(s.grants, grant)
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		s.respond(w)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *openaiTokenStub) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.grants)
}

func (s *openaiTokenStub) last() (map[string]string, http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants[len(s.grants)-1], s.headers[len(s.headers)-1]
}

// openaiRespond answers with status and a JSON body.
func openaiRespond(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// openaiTokenResponse is a successful exchange answer with the given lifetime,
// shaped as OpenAI documents it.
func openaiTokenResponse(expiresIn int) func(w http.ResponseWriter) {
	body, _ := json.Marshal(map[string]any{
		"access_token":      openaiTestToken,
		"issued_token_type": credential.TokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
		"expires_at":        time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
	})
	return openaiRespond(http.StatusOK, string(body))
}

// openaiTestSourceConfig is a minimal valid source config with overrides applied.
// An override set to "" removes the key, so each case isolates one field.
func openaiTestSourceConfig(overrides map[string]string) map[string]string {
	cfg := map[string]string{
		"auth_method":          openaiAuthMethodOIDCFederation,
		"identity_provider_id": openaiTestProvider,
	}
	for k, v := range overrides {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return cfg
}

// newTestOpenAIDriver builds a driver pointed at baseURL. It goes through Create
// only — not ValidateConfig — so a test can hand it a record validation would have
// refused, the way a stored record that predates a rule would arrive.
func newTestOpenAIDriver(t *testing.T, baseURL string, source map[string]string) *OpenAIDriver {
	t.Helper()
	overrides := map[string]string{"openai_auth_url": baseURL}
	for k, v := range source {
		overrides[k] = v
	}
	d, err := (&OpenAIDriverFactory{}).Create(credential.NewConfig(openaiTestSourceConfig(overrides)), testDriverLogger())
	require.NoError(t, err)
	return d.(*OpenAIDriver)
}

// openaiTestSpec is a spec naming a full exchange target, with overrides applied.
// An override set to "" removes the key.
func openaiTestSpec(overrides map[string]string) *credential.CredSpec {
	cfg := map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		"service_account_id":                openaiTestAccount,
	}
	for k, v := range overrides {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return &credential.CredSpec{
		Name:   "openai-ops",
		Type:   credential.TypeOAuthBearerToken,
		Source: "openai-wif",
		Config: credential.NewConfig(cfg),
	}
}

func openaiTestInputs(assertion string) *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:     assertion,
		SubjectTokenType: credential.TokenTypeJWT,
		AgentClaims:      map[string]string{"sub": "agent-1"},
	}
}

// --- Factory tests ---

func TestOpenAIDriverFactory_Type(t *testing.T) {
	assert.Equal(t, credential.SourceTypeOpenAI, (&OpenAIDriverFactory{}).Type())
}

func TestOpenAIDriverFactory_ValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		wantErr   string
	}{
		{name: "auth method and identity provider are enough"},
		{
			name: "every source field",
			overrides: map[string]string{
				"audience":        "https://warden.example.com/openai",
				"openai_auth_url": "https://auth.openai.com",
				"tls_skip_verify": "false",
			},
		},
		{
			// Required although it has one value: the config store keys federation
			// on it being written out. See openaiAuthMethodOIDCFederation.
			name:      "auth method is required",
			overrides: map[string]string{"auth_method": ""},
			wantErr:   "field 'auth_method' is required",
		},
		{
			// A static key belongs on an apikey source, not here.
			name:      "federation is the only auth method",
			overrides: map[string]string{"auth_method": "static"},
			wantErr:   "field 'auth_method'",
		},
		{
			name:      "identity provider is required",
			overrides: map[string]string{"identity_provider_id": ""},
			wantErr:   "field 'identity_provider_id' is required",
		},
		{
			name:      "openai_auth_url must be a URL",
			overrides: map[string]string{"openai_auth_url": "auth.openai.com"},
			wantErr:   "field 'openai_auth_url'",
		},
		{
			name:      "service account belongs on the spec",
			overrides: map[string]string{"service_account_id": openaiTestAccount},
			wantErr:   "service_account_id belongs on the spec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&OpenAIDriverFactory{}).ValidateConfig(credential.NewConfig(openaiTestSourceConfig(tt.overrides)))
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestOpenAIDriverFactory_SensitiveFieldsAndStoredSecrets(t *testing.T) {
	f := &OpenAIDriverFactory{}
	// The source holds no key; only the CA bundle is masked, as on every other driver.
	assert.Equal(t, []string{"ca_data"}, f.SensitiveConfigFields())
	// Keyless: nothing for keyless_enforcement_level to object to.
	assert.Nil(t, f.StoredSecrets(credential.NewConfig(openaiTestSourceConfig(nil))))
}

func TestOpenAIDriverFactory_InferCredentialType(t *testing.T) {
	credType, err := (&OpenAIDriverFactory{}).InferCredentialType(credential.NewConfig(nil))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, credType)
}

func TestOpenAIDriverFactory_Create_ResolvesTokenURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string // "" leaves openai_auth_url unset
		want    string
	}{
		// The auth host, not api.openai.com: the mount proxies to the latter.
		{name: "default endpoint", want: "https://auth.openai.com/oauth/token"},
		{name: "override", baseURL: "https://openai-auth.internal.example.com", want: "https://openai-auth.internal.example.com/oauth/token"},
		{name: "trailing slash trimmed", baseURL: "https://openai-auth.internal.example.com/", want: "https://openai-auth.internal.example.com/oauth/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := openaiTestSourceConfig(nil)
			if tt.baseURL != "" {
				cfg["openai_auth_url"] = tt.baseURL
			}
			d, err := (&OpenAIDriverFactory{}).Create(credential.NewConfig(cfg), testDriverLogger())
			require.NoError(t, err)
			assert.Equal(t, tt.want, d.(*OpenAIDriver).tokenURL)
		})
	}
}

// --- Mint tests ---

func TestOpenAIDriver_MintCredentialWithExchange(t *testing.T) {
	stub := newOpenAITokenStub(t, openaiTokenResponse(3600))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)

	rawData, metadata, ttl, leaseID, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(openaiTestAssertion))
	require.NoError(t, err)

	grant, headers := stub.last()
	assert.Equal(t, map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
		"subject_token":        openaiTestAssertion,
		"identity_provider_id": openaiTestProvider,
		"service_account_id":   openaiTestAccount,
	}, grant)
	assert.Equal(t, "application/json", headers.Get("Content-Type"))
	assert.Equal(t, "application/json", headers.Get("Accept"))
	// The assertion is the whole proof: OpenAI's exchange takes no client authentication.
	assert.Empty(t, headers.Get("Authorization"))

	// The oauth_bearer_token type's primary field, which the provider injects.
	assert.Equal(t, map[string]interface{}{"api_key": openaiTestToken}, rawData)
	assert.Equal(t, 3540*time.Second, ttl, "lease ends a minute before the token")
	assert.Empty(t, leaseID, "openai issues no revocable lease")

	assert.Equal(t, openaiTestProvider, metadata["identity_provider_id"])
	assert.Equal(t, openaiTestAccount, metadata["service_account_id"])
	assert.Equal(t, openaiTestAgentSub, metadata["subject"], "the sub OpenAI verified, read off the assertion")
	assert.NotContains(t, metadata, "actor", "an agent-only assertion has no actor")
	assert.NotContains(t, metadata, "scope", "the response carried none")
	expiration, err := time.Parse(time.RFC3339, metadata["expiration"].(string))
	require.NoError(t, err)
	// The token's own expiry, not the lease's: an hour out, give or take the test.
	assert.WithinDuration(t, time.Now().Add(time.Hour), expiration, time.Minute)
	for _, v := range metadata {
		assert.NotEqual(t, openaiTestToken, v, "the token must never reach audit metadata")
		assert.NotEqual(t, openaiTestAssertion, v, "the assertion must never reach audit metadata")
	}
}

func TestOpenAIDriver_MintCredentialWithExchange_DelegationMetadata(t *testing.T) {
	// Under the delegation shape the upstream sees the user's id as sub, and the
	// agent as the actor. Metadata names both as the upstream saw them — not the
	// agent as subject, which would attribute the token to the wrong party.
	stub := newOpenAITokenStub(t, openaiTokenResponse(3600))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)
	delegation := makeUnsignedJWT(map[string]interface{}{
		"sub":              "user-42",
		"warden_namespace": "root",
		"act": map[string]interface{}{
			"sub": openaiTestAgentSub,
			"iss": "https://warden.example.com",
		},
	})

	_, metadata, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(delegation))
	require.NoError(t, err)
	assert.Equal(t, "user-42", metadata["subject"])
	assert.Equal(t, openaiTestAgentSub, metadata["actor"])
}

func TestOpenAIDriver_MintCredentialWithExchange_RecordsScope(t *testing.T) {
	// A mapping with permissions reports them as scope; worth keeping for audit.
	stub := newOpenAITokenStub(t, openaiRespond(http.StatusOK,
		`{"access_token":"`+openaiTestToken+`","token_type":"Bearer","expires_in":3600,"scope":"model.request"}`))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)

	rawData, metadata, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(openaiTestAssertion))
	require.NoError(t, err)
	assert.Equal(t, "model.request", metadata["scope"])
	assert.NotContains(t, rawData, "scope", "no provider reads it, so it stays out of the credential")
}

func TestOpenAIDriver_MintCredentialWithExchange_Lifetimes(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		maxTTL time.Duration
		want   time.Duration
	}{
		{
			// expires_in is optional in RFC 6749; the short fallback can only re-mint early.
			name: "absent expires_in takes the fallback",
			body: `{"access_token":"` + openaiTestToken + `","token_type":"Bearer"}`,
			want: 30 * time.Second,
		},
		{
			name:   "capped at MaxTTL",
			body:   `{"access_token":"` + openaiTestToken + `","expires_in":3600}`,
			maxTTL: 10 * time.Minute,
			want:   10 * time.Minute,
		},
		{
			// Past OpenAI's documented hour is drift or malformed; capping only re-mints early.
			name: "past an hour is capped",
			body: `{"access_token":"` + openaiTestToken + `","expires_in":86400}`,
			want: time.Hour - openaiRefreshBuffer,
		},
		{
			// Multiplied out uncapped, this would wrap time.Duration to a small value.
			name: "an overflowing value is capped",
			body: `{"access_token":"` + openaiTestToken + `","expires_in":18446744074}`,
			want: time.Hour - openaiRefreshBuffer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := newOpenAITokenStub(t, openaiRespond(http.StatusOK, tt.body))
			d := newTestOpenAIDriver(t, stub.server.URL, nil)
			spec := openaiTestSpec(nil)
			spec.MaxTTL = tt.maxTTL

			_, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), spec, openaiTestInputs(openaiTestAssertion))
			require.NoError(t, err)
			assert.Equal(t, tt.want, ttl)
		})
	}
}

func TestOpenAIDriver_MintCredentialWithExchange_SurfacesOAuthError(t *testing.T) {
	stub := newOpenAITokenStub(t, openaiRespond(http.StatusBadRequest,
		`{"error":"invalid_grant","error_description":"no service account mapping matched"}`))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(openaiTestAssertion))
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		`openai token exchange: token endpoint error "invalid_grant": no service account mapping matched`)

	// Classified, not a bare string, so a caller can branch on the code.
	var tee *tokenEndpointError
	require.True(t, errors.As(err, &tee))
	assert.Equal(t, "invalid_grant", tee.code)
	assert.Equal(t, 1, stub.calls(), "a rejected grant is not retried")

	// The upstream status survives the wrapping, so the request is answered as a
	// refusal (403) rather than a server error.
	status, ok := credential.UpstreamStatus(fmt.Errorf("mint: %w", err))
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestOpenAIDriver_MintCredentialWithExchange_RejectsMalformedResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "missing access token",
			body:    `{"token_type":"Bearer","expires_in":3600}`,
			wantErr: "response missing access_token",
		},
		{
			// Not the bearer the provider will inject.
			name:    "wrong issued token type",
			body:    `{"access_token":"` + openaiTestToken + `","issued_token_type":"urn:ietf:params:oauth:token-type:id_token","expires_in":3600}`,
			wantErr: `unexpected issued_token_type "urn:ietf:params:oauth:token-type:id_token"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := newOpenAITokenStub(t, openaiRespond(http.StatusOK, tt.body))
			d := newTestOpenAIDriver(t, stub.server.URL, nil)

			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(openaiTestAssertion))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestOpenAIDriver_MintCredentialWithExchange_RequiresSubjectToken(t *testing.T) {
	stub := newOpenAITokenStub(t, openaiTokenResponse(3600))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)

	for name, inputs := range map[string]*credential.ExchangeInputs{
		"nil inputs":          nil,
		"empty subject token": {SubjectTokenType: credential.TokenTypeJWT},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), inputs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no subject token")
		})
	}
	assert.Zero(t, stub.calls(), "nothing to exchange, so nothing sent")
}

func TestOpenAIDriver_MintCredentialWithExchange_FailsClosedOnIncompleteTarget(t *testing.T) {
	// Validation refuses each of these at write time; a record that arrives without
	// one anyway must fail naming the field, before anything reaches OpenAI.
	tests := []struct {
		name    string
		source  map[string]string
		spec    map[string]string
		wantErr string
	}{
		{name: "no identity provider", source: map[string]string{"identity_provider_id": ""}, wantErr: "openai: identity_provider_id is not set"},
		{name: "no service account", spec: map[string]string{"service_account_id": ""}, wantErr: "openai: service_account_id is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := newOpenAITokenStub(t, openaiTokenResponse(3600))
			d := newTestOpenAIDriver(t, stub.server.URL, tt.source)

			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(tt.spec), openaiTestInputs(openaiTestAssertion))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Zero(t, stub.calls())
		})
	}
}

func TestOpenAIDriver_MintCredentialWithExchange_Concurrent(t *testing.T) {
	// The driver holds no mutable state and takes no lock. Run under -race, this is
	// what backs that claim: every mint shares the one driver and its client.
	stub := newOpenAITokenStub(t, openaiTokenResponse(3600))
	d := newTestOpenAIDriver(t, stub.server.URL, nil)

	const mints = 32
	var wg sync.WaitGroup
	errs := make(chan error, mints)
	for i := 0; i < mints; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), openaiTestSpec(nil), openaiTestInputs(openaiTestAssertion))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	// One exchange per call: coalescing concurrent requests is the credential
	// manager's job, not the driver's.
	assert.Equal(t, mints, stub.calls())
}

func TestOpenAIDriver_MintCredential_RequiresExchange(t *testing.T) {
	d := newTestOpenAIDriver(t, "https://auth.openai.com", nil)
	_, _, _, _, err := d.MintCredential(context.Background(), openaiTestSpec(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set subject_token_source=warden_identity")
}

func TestOpenAIDriver_RevokeAndCleanup(t *testing.T) {
	d := newTestOpenAIDriver(t, "https://auth.openai.com", nil)
	assert.Equal(t, credential.SourceTypeOpenAI, d.Type())
	assert.NoError(t, d.Revoke(context.Background(), ""))
	// Called again at every step-down and seal over the process's life.
	assert.NoError(t, d.Cleanup(context.Background()))
	assert.NoError(t, d.Cleanup(context.Background()))
	// A driver whose Create failed part-way has no client; Cleanup must still be safe.
	assert.NoError(t, (&OpenAIDriver{}).Cleanup(context.Background()))
}
