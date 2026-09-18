package drivers

import (
	"context"
	"encoding/json"
	"errors"
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
	anthropicTestOrg       = "00000000-0000-0000-0000-000000000000"
	anthropicTestRule      = "fdrl_01ExampleRule"
	anthropicTestAccount   = "svac_01ExampleAccount"
	anthropicTestWorkspace = "wrkspc_01ExampleWorkspace"
	anthropicTestAssertion = "header.payload.signature"
	anthropicTestToken     = "sk-ant-oat01-test"
)

// anthropicTokenStub stands in for Anthropic's token endpoint. It records every
// grant it receives, with its headers, and answers with respond — so a test can
// assert both what the driver sent and how it treats what came back.
type anthropicTokenStub struct {
	server  *httptest.Server
	respond func(w http.ResponseWriter)

	mu      sync.Mutex
	grants  []map[string]string
	headers []http.Header
}

func newAnthropicTokenStub(t *testing.T, respond func(w http.ResponseWriter)) *anthropicTokenStub {
	t.Helper()
	s := &anthropicTokenStub{respond: respond}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != anthropicTokenPath {
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

func (s *anthropicTokenStub) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.grants)
}

func (s *anthropicTokenStub) last() (map[string]string, http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants[len(s.grants)-1], s.headers[len(s.headers)-1]
}

// anthropicRespond answers with status and a JSON body.
func anthropicRespond(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// anthropicTokenResponse is a successful exchange answer with the given lifetime.
func anthropicTokenResponse(expiresIn int) func(w http.ResponseWriter) {
	body, _ := json.Marshal(map[string]any{
		"access_token": anthropicTestToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
	return anthropicRespond(http.StatusOK, string(body))
}

// newTestAnthropicDriver builds a driver pointed at baseURL. It goes through Create
// only — not ValidateConfig — so a test can hand it a record validation would have
// refused, the way a stored record that predates a rule would arrive.
func newTestAnthropicDriver(t *testing.T, baseURL string, source map[string]string) *AnthropicDriver {
	t.Helper()
	overrides := map[string]string{"anthropic_url": baseURL}
	for k, v := range source {
		overrides[k] = v
	}
	cfg := anthropicTestSourceConfig(overrides)
	d, err := (&AnthropicDriverFactory{}).Create(credential.NewConfig(cfg), testDriverLogger())
	require.NoError(t, err)
	return d.(*AnthropicDriver)
}

// anthropicTestSpec is a spec naming a full exchange target, with overrides applied.
// An override set to "" removes the key.
func anthropicTestSpec(overrides map[string]string) *credential.CredSpec {
	cfg := map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		"federation_rule_id":                anthropicTestRule,
		"service_account_id":                anthropicTestAccount,
	}
	for k, v := range overrides {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return &credential.CredSpec{
		Name:   "anthropic-ops",
		Type:   credential.TypeOAuthBearerToken,
		Source: "anthropic-wif",
		Config: credential.NewConfig(cfg),
	}
}

func anthropicTestInputs() *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:     anthropicTestAssertion,
		SubjectTokenType: credential.TokenTypeJWT,
		AgentClaims:      map[string]string{"sub": "agent-1"},
	}
}

// --- Factory tests ---

func TestAnthropicDriverFactory_Type(t *testing.T) {
	assert.Equal(t, credential.SourceTypeAnthropic, (&AnthropicDriverFactory{}).Type())
}

// anthropicTestSourceConfig is a minimal valid source config with overrides
// applied. An override set to "" removes the key, so each case isolates one field.
func anthropicTestSourceConfig(overrides map[string]string) map[string]string {
	cfg := map[string]string{
		"auth_method":     anthropicAuthMethodOIDCFederation,
		"organization_id": anthropicTestOrg,
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

func TestAnthropicDriverFactory_ValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		wantErr   string
	}{
		{name: "auth method and organization are enough"},
		{
			name: "every source field",
			overrides: map[string]string{
				"audience":        "https://warden.example.com/anthropic",
				"anthropic_url":   "https://api.anthropic.com",
				"tls_skip_verify": "false",
			},
		},
		{
			// Required although it has one value: the config store keys federation
			// on it being written out. See anthropicAuthMethodOIDCFederation.
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
			name:      "organization is required",
			overrides: map[string]string{"organization_id": ""},
			wantErr:   "field 'organization_id' is required",
		},
		{
			name:      "organization must be a UUID",
			overrides: map[string]string{"organization_id": "my-org"},
			wantErr:   "field 'organization_id': must be a UUID",
		},
		{
			name:      "anthropic_url must be a URL",
			overrides: map[string]string{"anthropic_url": "api.anthropic.com"},
			wantErr:   "field 'anthropic_url'",
		},
		{
			name:      "federation rule belongs on the spec",
			overrides: map[string]string{"federation_rule_id": anthropicTestRule},
			wantErr:   "federation_rule_id belongs on the spec",
		},
		{
			name:      "service account belongs on the spec",
			overrides: map[string]string{"service_account_id": anthropicTestAccount},
			wantErr:   "service_account_id belongs on the spec",
		},
		{
			name:      "workspace belongs on the spec",
			overrides: map[string]string{"workspace_id": anthropicTestWorkspace},
			wantErr:   "workspace_id belongs on the spec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&AnthropicDriverFactory{}).ValidateConfig(credential.NewConfig(anthropicTestSourceConfig(tt.overrides)))
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestAnthropicDriverFactory_SensitiveConfigFields(t *testing.T) {
	// The source holds no key; only the CA bundle is masked, as on every other driver.
	assert.Equal(t, []string{"ca_data"}, (&AnthropicDriverFactory{}).SensitiveConfigFields())
}

func TestAnthropicDriverFactory_InferCredentialType(t *testing.T) {
	credType, err := (&AnthropicDriverFactory{}).InferCredentialType(credential.NewConfig(nil))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, credType)
}

func TestAnthropicDriverFactory_Create_ResolvesTokenURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string // "" leaves anthropic_url unset
		want    string
	}{
		{name: "default endpoint", want: "https://api.anthropic.com/v1/oauth/token"},
		{name: "override", baseURL: "https://anthropic.internal.example.com", want: "https://anthropic.internal.example.com/v1/oauth/token"},
		{name: "trailing slash trimmed", baseURL: "https://anthropic.internal.example.com/", want: "https://anthropic.internal.example.com/v1/oauth/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := anthropicTestSourceConfig(nil)
			if tt.baseURL != "" {
				cfg["anthropic_url"] = tt.baseURL
			}
			d, err := (&AnthropicDriverFactory{}).Create(credential.NewConfig(cfg), testDriverLogger())
			require.NoError(t, err)
			assert.Equal(t, tt.want, d.(*AnthropicDriver).tokenURL)
		})
	}
}

// --- Mint tests ---

func TestAnthropicDriver_MintCredentialWithExchange(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)
	spec := anthropicTestSpec(map[string]string{"workspace_id": anthropicTestWorkspace})

	rawData, metadata, ttl, leaseID, err := d.MintCredentialWithExchange(context.Background(), spec, anthropicTestInputs())
	require.NoError(t, err)

	grant, headers := stub.last()
	assert.Equal(t, map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":          anthropicTestAssertion,
		"organization_id":    anthropicTestOrg,
		"federation_rule_id": anthropicTestRule,
		"service_account_id": anthropicTestAccount,
		"workspace_id":       anthropicTestWorkspace,
	}, grant)
	assert.Equal(t, "application/json", headers.Get("Content-Type"))
	assert.Equal(t, "application/json", headers.Get("Accept"))
	// The assertion is the grant: RFC 7523 sends no client authentication.
	assert.Empty(t, headers.Get("Authorization"))

	// The oauth_bearer_token type's primary field, which the provider injects.
	assert.Equal(t, map[string]interface{}{"api_key": anthropicTestToken}, rawData)
	assert.Equal(t, 3540*time.Second, ttl, "lease ends a minute before the token")
	assert.Empty(t, leaseID, "anthropic issues no revocable lease")

	assert.Equal(t, anthropicTestOrg, metadata["organization_id"])
	assert.Equal(t, anthropicTestRule, metadata["federation_rule_id"])
	assert.Equal(t, anthropicTestAccount, metadata["service_account_id"])
	assert.Equal(t, anthropicTestWorkspace, metadata["workspace_id"])
	assert.Equal(t, "agent-1", metadata["subject"])
	expiration, err := time.Parse(time.RFC3339, metadata["expiration"].(string))
	require.NoError(t, err)
	// The token's own expiry, not the lease's: an hour out, give or take the test.
	assert.WithinDuration(t, time.Now().Add(time.Hour), expiration, time.Minute)
	for _, v := range metadata {
		assert.NotEqual(t, anthropicTestToken, v, "the token must never reach audit metadata")
		assert.NotEqual(t, anthropicTestAssertion, v, "the assertion must never reach audit metadata")
	}
}

func TestAnthropicDriver_MintCredentialWithExchange_OmitsUnsetWorkspace(t *testing.T) {
	// A rule covering one workspace acts in it without being told; sending an
	// empty workspace_id would be a malformed request, not an absent one.
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	_, metadata, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
	require.NoError(t, err)

	grant, _ := stub.last()
	assert.NotContains(t, grant, "workspace_id")
	assert.NotContains(t, metadata, "workspace_id")
}

func TestAnthropicDriver_MintCredentialWithExchange_FallbackLifetime(t *testing.T) {
	// expires_in is optional in RFC 6749. The fallback is Anthropic's shortest
	// lifetime, so an omitted value can only cause an early re-mint.
	stub := newAnthropicTokenStub(t, anthropicRespond(http.StatusOK,
		`{"access_token":"`+anthropicTestToken+`","token_type":"Bearer"}`))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	_, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, ttl)
}

func TestAnthropicDriver_MintCredentialWithExchange_CapsLeaseAtMaxTTL(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)
	spec := anthropicTestSpec(nil)
	spec.MaxTTL = 10 * time.Minute

	_, _, ttl, _, err := d.MintCredentialWithExchange(context.Background(), spec, anthropicTestInputs())
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, ttl)
}

func TestAnthropicDriver_MintCredentialWithExchange_SurfacesOAuthError(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicRespond(http.StatusBadRequest,
		`{"error":"invalid_grant","error_description":"assertion does not satisfy the federation rule"}`))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		`anthropic token exchange: token endpoint error "invalid_grant": assertion does not satisfy the federation rule`)

	// Classified, not a bare string, so a caller can branch on the code.
	var tee *tokenEndpointError
	require.True(t, errors.As(err, &tee))
	assert.Equal(t, "invalid_grant", tee.code)
	assert.Equal(t, 1, stub.calls(), "a rejected grant is not retried")
}

func TestAnthropicDriver_MintCredentialWithExchange_MissingAccessToken(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicRespond(http.StatusOK, `{"token_type":"Bearer","expires_in":3600}`))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response missing access_token")
}

func TestAnthropicDriver_MintCredentialWithExchange_RequiresSubjectToken(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	for name, inputs := range map[string]*credential.ExchangeInputs{
		"nil inputs":          nil,
		"empty subject token": {SubjectTokenType: credential.TokenTypeJWT},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), inputs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no subject token")
		})
	}
	assert.Zero(t, stub.calls(), "nothing to exchange, so nothing sent")
}

func TestAnthropicDriver_MintCredentialWithExchange_FailsClosedOnIncompleteTarget(t *testing.T) {
	// Validation refuses each of these at write time; a record that arrives without
	// one anyway must fail naming the field, before anything reaches Anthropic.
	tests := []struct {
		name    string
		source  map[string]string
		spec    map[string]string
		wantErr string
	}{
		{name: "no organization", source: map[string]string{"organization_id": ""}, wantErr: "anthropic: organization_id is not set"},
		{name: "no federation rule", spec: map[string]string{"federation_rule_id": ""}, wantErr: "anthropic: federation_rule_id is not set"},
		{name: "no service account", spec: map[string]string{"service_account_id": ""}, wantErr: "anthropic: service_account_id is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
			d := newTestAnthropicDriver(t, stub.server.URL, tt.source)

			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(tt.spec), anthropicTestInputs())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Zero(t, stub.calls())
		})
	}
}

func TestAnthropicDriver_MintCredentialWithExchange_Concurrent(t *testing.T) {
	// The driver holds no mutable state and takes no lock. Run under -race, this is
	// what backs that claim: every mint shares the one driver and its client.
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(3600))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	const mints = 32
	var wg sync.WaitGroup
	errs := make(chan error, mints)
	for i := 0; i < mints; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
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

func TestAnthropicLeaseTTL(t *testing.T) {
	tests := []struct {
		name     string
		lifetime time.Duration
		maxTTL   time.Duration
		want     time.Duration
	}{
		{name: "an hour-long token re-mints a minute early", lifetime: time.Hour, want: 59 * time.Minute},
		{name: "the shortest lifetime keeps half", lifetime: 60 * time.Second, want: 30 * time.Second},
		{name: "the buffer never takes more than half", lifetime: 100 * time.Second, want: 50 * time.Second},
		{name: "exactly twice the buffer", lifetime: 120 * time.Second, want: 60 * time.Second},
		{name: "capped at MaxTTL", lifetime: time.Hour, maxTTL: 10 * time.Minute, want: 10 * time.Minute},
		{name: "MaxTTL above the lease is not a floor", lifetime: 10 * time.Minute, maxTTL: time.Hour, want: 9 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, anthropicLeaseTTL(tt.lifetime, tt.maxTTL))
		})
	}
}

func TestAnthropicLifetime(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn int
		want      time.Duration
	}{
		{name: "an hour", expiresIn: 3600, want: time.Hour},
		{name: "the longest a rule issues", expiresIn: 86400, want: 24 * time.Hour},
		{name: "missing takes the fallback", expiresIn: 0, want: anthropicFallbackLifetime},
		{name: "negative takes the fallback", expiresIn: -1, want: anthropicFallbackLifetime},
		{name: "past a day is capped", expiresIn: 86401, want: 24 * time.Hour},
		{
			// Multiplied out uncapped, this wraps time.Duration to +290ms — a lease of
			// 145ms that would pass for a real one.
			name: "a value that would overflow is capped", expiresIn: 18446744074, want: 24 * time.Hour,
		},
		{name: "the largest int is capped", expiresIn: int(^uint(0) >> 1), want: 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, anthropicLifetime(tt.expiresIn))
		})
	}
}

func TestAnthropicDriver_MintCredentialWithExchange_CapsAnOverflowingLifetime(t *testing.T) {
	stub := newAnthropicTokenStub(t, anthropicTokenResponse(18446744074))
	d := newTestAnthropicDriver(t, stub.server.URL, nil)

	_, metadata, ttl, _, err := d.MintCredentialWithExchange(context.Background(), anthropicTestSpec(nil), anthropicTestInputs())
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour-anthropicRefreshBuffer, ttl)

	// The expiry recorded for audit is the capped day, not a wrapped instant.
	expiration, err := time.Parse(time.RFC3339, metadata["expiration"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), expiration, time.Minute)
}

func TestAnthropicDriver_MintCredential_RequiresExchange(t *testing.T) {
	d := newTestAnthropicDriver(t, "https://api.anthropic.com", nil)
	_, _, _, _, err := d.MintCredential(context.Background(), anthropicTestSpec(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set subject_token_source=warden_identity")
}

func TestAnthropicDriver_RevokeAndCleanup(t *testing.T) {
	d := newTestAnthropicDriver(t, "https://api.anthropic.com", nil)
	assert.Equal(t, credential.SourceTypeAnthropic, d.Type())
	assert.NoError(t, d.Revoke(context.Background(), ""))
	assert.NoError(t, d.Cleanup(context.Background()))
	// A driver whose Create failed part-way has no client; Cleanup must still be safe.
	assert.NoError(t, (&AnthropicDriver{}).Cleanup(context.Background()))
}
