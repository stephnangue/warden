package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKVVault   = "acme-prod-kv"
	testKVVersion = "0123456789abcdef0123456789abcdef"
	testKVPayload = `{"api_key":"dd-key","application_key":"dd-app"}`
)

// kvStub stands in for both legs of a Key Vault read: the Entra token grant and the
// secret GET. It records what arrived at each so a test can check the whole shape.
type kvStub struct {
	*httptest.Server

	mu sync.Mutex
	// bundles maps a secret path (/secrets/<name>[/<version>]) to the SecretBundle
	// JSON returned for it; a missing path answers 404.
	bundles map[string]string
	// status, when non-zero, is returned for every secret read.
	status int

	tokenForms []url.Values
	reads      []kvRead
}

type kvRead struct {
	Path       string
	APIVersion string
	Bearer     string
}

func newKVStub(t *testing.T) *kvStub {
	t.Helper()
	s := &kvStub{bundles: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *kvStub) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		s.mu.Lock()
		s.tokenForms = append(s.tokenForms, r.PostForm)
		s.mu.Unlock()
		token := "static-token"
		if r.PostForm.Get("client_assertion") != "" {
			token = "federated-token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 3600})

	case strings.HasPrefix(r.URL.Path, "/secrets/"):
		s.mu.Lock()
		s.reads = append(s.reads, kvRead{
			Path:       r.URL.Path,
			APIVersion: r.URL.Query().Get("api-version"),
			Bearer:     strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		})
		bundle, ok := s.bundles[r.URL.Path]
		status := s.status
		s.mu.Unlock()
		if status != 0 {
			http.Error(w, `{"error":{"code":"Forbidden","message":"denied"}}`, status)
			return
		}
		if !ok {
			http.Error(w, `{"error":{"code":"SecretNotFound"}}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bundle))

	default:
		http.Error(w, "unexpected call "+r.URL.Path, http.StatusBadRequest)
	}
}

// put stores a secret with the given value and optional attributes.
func (s *kvStub) put(path, value string, attrs map[string]any) {
	id := "https://" + testKVVault + ".vault.azure.net" + path
	if !strings.Contains(strings.TrimPrefix(path, "/secrets/"), "/") {
		id += "/" + testKVVersion
	}
	body, _ := json.Marshal(map[string]any{"value": value, "id": id, "attributes": attrs})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[path] = string(body)
}

func (s *kvStub) seen() ([]url.Values, []kvRead) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.tokenForms...), append([]kvRead(nil), s.reads...)
}

// newKVFederatedDriver is a keyless driver whose token and Key Vault calls reach stub.
func newKVFederatedDriver(stub *kvStub) *AzureDriver {
	return &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: credential.NewConfig(map[string]string{
			"auth_method": "oidc_federation",
		})},
		tokenCache:       NewTokenCache(),
		httpClient:       &http.Client{Timeout: 5 * time.Second},
		loginHost:        stub.URL,
		keyVaultEndpoint: stub.URL,
	}
}

// newKVStaticDriver is a static driver whose token and Key Vault calls reach stub.
func newKVStaticDriver(stub *kvStub) *AzureDriver {
	d := newTestAzureDriver()
	d.loginHost = stub.URL
	d.keyVaultEndpoint = stub.URL
	d.httpClient = &http.Client{Timeout: 5 * time.Second}
	return d
}

func kvSpec(extra map[string]string) *credential.CredSpec {
	cfg := map[string]string{
		"mint_method": "secret_read",
		"vault_name":  testKVVault,
		"secret_name": "datadog-keys",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return &credential.CredSpec{Name: "kv-spec", Type: credential.TypeKeyValue, Config: credential.NewConfig(cfg)}
}

func federatedKVSpec(extra map[string]string) *credential.CredSpec {
	cfg := map[string]string{
		"tenant_id":                         testAzureTenant,
		"client_id":                         testAzureClient,
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return kvSpec(cfg)
}

var testKVInputs = &credential.ExchangeInputs{SubjectToken: "eyJ.warden.assertion", SubjectTokenType: credential.TokenTypeJWT}

// =============================================================================
// URL resolution
// =============================================================================

func TestAzureDriver_KeyVaultSecretURL(t *testing.T) {
	d := newTestAzureDriver()

	u, err := d.keyVaultSecretURL(kvSpec(nil), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://acme-prod-kv.vault.azure.net/secrets/datadog-keys?api-version=7.4", u,
		"with no override the vault is the host")

	u, err = d.keyVaultSecretURL(kvSpec(map[string]string{"secret_version": testKVVersion}), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://acme-prod-kv.vault.azure.net/secrets/datadog-keys/"+testKVVersion+"?api-version=7.4", u)

	d.keyVaultEndpoint = "http://127.0.0.1:9999"
	u, err = d.keyVaultSecretURL(kvSpec(nil), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:9999/secrets/datadog-keys?api-version=7.4", u,
		"an override replaces the whole base")
}

// The write-time checks make these unwritable; the read checks again so a config that
// drifted past them still cannot send the Key Vault token elsewhere or read another
// object.
func TestAzureDriver_KeyVaultSecretURL_RejectsHostileNames(t *testing.T) {
	d := newTestAzureDriver()
	for _, tc := range []map[string]string{
		{"vault_name": "evil.example/x#"},
		{"vault_name": "evil.example"},
		{"vault_name": "a--b"},
		{"vault_name": ""},
		{"secret_name": "a/b"},
		{"secret_name": "a?b"},
		{"secret_name": "a#b"},
		{"secret_name": "../other"},
		{"secret_name": "a.b"},
		{"secret_version": "latest"},
		{"secret_version": testKVVersion + "/x"},
	} {
		_, err := d.keyVaultSecretURL(kvSpec(tc), nil, nil)
		assert.Errorf(t, err, "%v must be refused", tc)
	}
}

func TestAzureDriver_KeyVaultSecretURL_Templated(t *testing.T) {
	d := newTestAzureDriver()
	spec := kvSpec(map[string]string{"secret_name": "agent-{{agent.sub}}"})

	u, err := d.keyVaultSecretURL(spec, nil, map[string]string{"sub": "checkout-7"})
	require.NoError(t, err)
	assert.Contains(t, u, "/secrets/agent-checkout-7?")

	// The claim allow-list admits '.', '_' and '@'; Key Vault does not, so the
	// resolved name is checked again rather than left to come back as a 404.
	for _, sub := range []string{"first.last", "svc_bot", "a@b"} {
		_, err := d.keyVaultSecretURL(spec, nil, map[string]string{"sub": sub})
		require.Errorf(t, err, "sub %q resolves to a name Key Vault cannot hold", sub)
		assert.Contains(t, err.Error(), "resolved")
	}

	// No claims at all fails closed instead of sending the template literally.
	_, err = d.keyVaultSecretURL(spec, nil, nil)
	require.Error(t, err)
}

// =============================================================================
// Mint paths
// =============================================================================

func TestAzureDriver_SecretRead_Federated(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/datadog-keys", testKVPayload, map[string]any{"enabled": true})
	d := newKVFederatedDriver(stub)

	data, meta, ttl, lease, err := d.MintCredentialWithExchange(context.Background(), federatedKVSpec(nil), testKVInputs)
	require.NoError(t, err)

	assert.Equal(t, map[string]interface{}{"api_key": "dd-key", "application_key": "dd-app"}, data)
	assert.Zero(t, ttl, "a secret with no expiry has no lifetime")
	assert.Empty(t, lease, "nothing here can revoke a stored secret")
	assert.Equal(t, testKVVault, meta["vault_name"])
	assert.Equal(t, "datadog-keys", meta["secret_name"])
	assert.Equal(t, testKVVersion, meta["secret_version"], "the version actually served is recorded")

	forms, reads := stub.seen()
	require.Len(t, forms, 1)
	form := forms[0]
	assert.Equal(t, "eyJ.warden.assertion", form.Get("client_assertion"))
	assert.Equal(t, clientAssertionType, form.Get("client_assertion_type"))
	assert.Equal(t, testAzureClient, form.Get("client_id"))
	assert.Equal(t, "https://vault.azure.net/.default", form.Get("scope"))
	assert.False(t, form.Has("client_secret"), "a federated read must not send a client_secret")

	require.Len(t, reads, 1)
	assert.Equal(t, "/secrets/datadog-keys", reads[0].Path)
	assert.Equal(t, "7.4", reads[0].APIVersion)
	assert.Equal(t, "federated-token", reads[0].Bearer, "the read is authorized by the exchanged token")

	// The exchanged token is the caller's, used for this one read. Filed in the
	// source's token cache it would be served to the next caller.
	_, _, cached := d.tokenCache.Get(keyVaultResource, 0)
	assert.False(t, cached, "a federated read must never populate the source token cache")
}

// An override that carries a path keeps it: the secret path is appended to the base.
func TestAzureDriver_KeyVaultSecretURL_EndpointWithPath(t *testing.T) {
	d := newTestAzureDriver()
	d.keyVaultEndpoint = "https://egress.internal.example/keyvault"
	u, err := d.keyVaultSecretURL(kvSpec(nil), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://egress.internal.example/keyvault/secrets/datadog-keys?api-version=7.4", u)
}

func TestAzureDriver_SecretRead_FederatedRequiresApp(t *testing.T) {
	d := newKVFederatedDriver(newKVStub(t))
	for _, key := range []string{"client_id", "tenant_id"} {
		spec := federatedKVSpec(nil)
		spec.Config = spec.Config.With(key, "")
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, testKVInputs)
		require.Errorf(t, err, "missing %s", key)
		assert.Contains(t, err.Error(), "'client_id' and 'tenant_id'")
	}
}

func TestAzureDriver_SecretRead_Static(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/datadog-keys", testKVPayload, nil)
	d := newKVStaticDriver(stub)

	for i := 0; i < 2; i++ {
		data, _, _, _, err := d.MintCredential(context.Background(), kvSpec(nil))
		require.NoError(t, err)
		assert.Equal(t, "dd-key", data["api_key"])
	}

	forms, reads := stub.seen()
	require.Len(t, forms, 1, "the source's Key Vault token is cached across reads")
	assert.Equal(t, "test-secret", forms[0].Get("client_secret"), "a static source reads as itself")
	assert.Equal(t, "https://vault.azure.net/.default", forms[0].Get("scope"))
	require.Len(t, reads, 2)
	assert.Equal(t, "static-token", reads[1].Bearer)
}

func TestAzureDriver_SecretRead_StaticRefusesSpecIdentity(t *testing.T) {
	stub := newKVStub(t)
	d := newKVStaticDriver(stub)
	for _, key := range []string{"client_id", "tenant_id"} {
		_, _, _, _, err := d.MintCredential(context.Background(), kvSpec(map[string]string{key: testAzureClient}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "a static source reads as itself")
	}
	forms, reads := stub.seen()
	assert.Empty(t, forms)
	assert.Empty(t, reads)
}

// A static source reads with no claims, so a templated name fails closed rather than
// reading a secret literally named after the template.
func TestAzureDriver_SecretRead_StaticTemplateFailsClosed(t *testing.T) {
	stub := newKVStub(t)
	d := newKVStaticDriver(stub)
	_, _, _, _, err := d.MintCredential(context.Background(), kvSpec(map[string]string{"secret_name": "agent-{{agent.sub}}"}))
	require.Error(t, err)
	_, reads := stub.seen()
	assert.Empty(t, reads)
}

func TestAzureDriver_SecretRead_TemplatedFederated(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/agent-checkout-7", `{"api_key":"k-for-checkout-7"}`, nil)
	d := newKVFederatedDriver(stub)

	inputs := *testKVInputs
	inputs.AgentClaims = map[string]string{"sub": "checkout-7"}
	data, _, _, _, err := d.MintCredentialWithExchange(context.Background(),
		federatedKVSpec(map[string]string{"secret_name": "agent-{{agent.sub}}"}), &inputs)
	require.NoError(t, err)
	assert.Equal(t, "k-for-checkout-7", data["api_key"])
}

func TestAzureDriver_SecretRead_JSONKeyMapAndPinnedVersion(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/datadog-keys/"+testKVVersion, `{"dd_api":"k","dd_app":"a","other":"x"}`, nil)
	d := newKVStaticDriver(stub)

	data, meta, _, _, err := d.MintCredential(context.Background(), kvSpec(map[string]string{
		"secret_version": testKVVersion,
		"json_key_map":   "dd_api=api_key,dd_app=application_key",
	}))
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"api_key": "k", "application_key": "a"}, data,
		"only the mapped fields are vended")
	assert.Equal(t, testKVVersion, meta["secret_version"])

	_, _, _, _, err = d.MintCredential(context.Background(), kvSpec(map[string]string{
		"secret_version": testKVVersion,
		"json_key_map":   "missing=api_key",
	}))
	require.Error(t, err, "a key map selecting nothing must not vend an empty credential")
}

func TestAzureDriver_SecretRead_PayloadAndAttributes(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()

	for _, tc := range []struct {
		name    string
		value   string
		attrs   map[string]any
		wantErr string
	}{
		{"empty value", "", nil, "empty value"},
		{"oversized value", strings.Repeat("a", keyVaultMaxSecretSize+1), nil, "beyond"},
		{"nested document", `{"api_key":"k","meta":{"env":"prod"}}`, nil, "nested"},
		{"null field", `{"api_key":null}`, nil, "null"},
		{"empty object", `{}`, nil, "empty JSON object"},
		{"disabled", "v", map[string]any{"enabled": false}, "disabled"},
		{"not yet valid", "v", map[string]any{"nbf": future}, "not valid before"},
		{"expired", "v", map[string]any{"exp": past}, "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newKVStub(t)
			stub.put("/secrets/datadog-keys", tc.value, tc.attrs)
			d := newKVStaticDriver(stub)
			_, _, _, _, err := d.MintCredential(context.Background(), kvSpec(nil))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("a plain value is one opaque secret", func(t *testing.T) {
		stub := newKVStub(t)
		stub.put("/secrets/datadog-keys", "sk-plain", nil)
		d := newKVStaticDriver(stub)
		data, _, _, _, err := d.MintCredential(context.Background(), kvSpec(nil))
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"value": "sk-plain"}, data)
	})

	t.Run("an expiry bounds the lifetime", func(t *testing.T) {
		stub := newKVStub(t)
		stub.put("/secrets/datadog-keys", "v", map[string]any{"exp": future})
		d := newKVStaticDriver(stub)
		_, meta, ttl, _, err := d.MintCredential(context.Background(), kvSpec(nil))
		require.NoError(t, err)
		assert.Greater(t, ttl, 55*time.Minute)
		assert.LessOrEqual(t, ttl, time.Hour)
		assert.Contains(t, meta, "expiration")
	})
}

// A refusal from Key Vault keeps its status through the wrapping, so the caller is
// answered 403/404 rather than a generic failure.
func TestAzureDriver_SecretRead_UpstreamStatusPreserved(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		stub := newKVStub(t)
		if status == http.StatusForbidden {
			stub.status = status
		}
		d := newKVStaticDriver(stub)
		_, _, _, _, err := d.MintCredential(context.Background(), kvSpec(nil))
		require.Error(t, err)
		got, ok := credential.UpstreamStatus(err)
		require.True(t, ok, "status %d must survive the wrapping", status)
		assert.Equal(t, status, got)
	}
}

// =============================================================================
// Factory
// =============================================================================

func TestAzureDriverFactory_SecretRead(t *testing.T) {
	f := &AzureDriverFactory{}

	typ, err := f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "secret_read"}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKeyValue, typ)

	// The retired method points at its replacement.
	_, err = f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "key_vault_secret"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_read")
}

func TestAzureDriverFactory_EndpointOverrides(t *testing.T) {
	f := &AzureDriverFactory{}
	fed := func(extra map[string]string) credential.Config {
		cfg := map[string]string{"auth_method": "oidc_federation"}
		for k, v := range extra {
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}

	require.NoError(t, f.ValidateConfig(fed(map[string]string{
		"login_endpoint":     "http://127.0.0.1:8080",
		"key_vault_endpoint": "https://kv.internal.example",
	})))
	for _, key := range []string{"login_endpoint", "key_vault_endpoint"} {
		for _, bad := range []string{
			"ftp://x", "not a url", "https://",
			// A query or fragment would swallow the path appended to the base.
			"https://kv.internal/?x=1", "https://kv.internal/#frag", "https://user:pass@kv.internal",
		} {
			require.Errorf(t, f.ValidateConfig(fed(map[string]string{key: bad})), "%s=%q", key, bad)
		}
	}

	// Create fixes the overrides on the driver, trimmed, without any network call
	// for a keyless source.
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := f.Create(fed(map[string]string{
		"login_endpoint":     "http://127.0.0.1:8080/",
		"key_vault_endpoint": "https://kv.internal.example/",
	}), log)
	require.NoError(t, err)
	az := drv.(*AzureDriver)
	assert.Equal(t, "http://127.0.0.1:8080", az.loginHost)
	assert.Equal(t, "https://kv.internal.example", az.keyVaultEndpoint)
}

// Rotation writes to the real tenant through Graph, which neither override redirects.
func TestAzureDriverFactory_ValidateRotationConfig(t *testing.T) {
	f := &AzureDriverFactory{}
	require.NoError(t, f.ValidateRotationConfig(credential.NewConfig(map[string]string{})))
	for _, key := range []string{"login_endpoint", "key_vault_endpoint"} {
		err := f.ValidateRotationConfig(credential.NewConfig(map[string]string{key: "http://127.0.0.1:1"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), key)
	}
}

func TestAzureAssertionResource_SecretRead(t *testing.T) {
	res, ok := azureAssertionResource(credential.NewConfig(map[string]string{
		"mint_method": "secret_read", "vault_name": testKVVault, "secret_name": "agent-{{agent.sub}}",
	}))
	require.True(t, ok)
	assert.Equal(t, "azure-keyvault:acme-prod-kv/agent-{{agent.sub}}", res,
		"a template is carried unresolved: this runs before the claims exist")

	_, ok = azureAssertionResource(credential.NewConfig(map[string]string{"mint_method": "secret_read"}))
	assert.False(t, ok, "no vault or secret, no resource")
}

// =============================================================================
// Chaining
// =============================================================================

// TestChaining_AzureKeyVaultSecretReadBacksAnAPIKeyConsumer drives a real chain
// through two real drivers: an azure secret_read spec is the referenced secret, and a
// static apikey spec carries none of its own and reads one field out of that payload.
// What it pins is that a Key Vault read satisfies what the chaining machinery demands
// of a referenced spec: a multi-field payload with no lease.
func TestChaining_AzureKeyVaultSecretReadBacksAnAPIKeyConsumer(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/datadog-keys", testKVPayload, map[string]any{"enabled": true})

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	typeRegistry := credential.NewTypeRegistry()
	require.NoError(t, typeRegistry.Register(types.NewKeyValueCredType()))
	require.NoError(t, typeRegistry.Register(types.NewAPIKeyCredType()))

	driverRegistry := credential.NewDriverRegistry(log)
	require.NoError(t, driverRegistry.RegisterFactory(&AzureDriverFactory{}))
	require.NoError(t, driverRegistry.RegisterFactory(&StaticAPIKeyDriverFactory{}))

	store := newChainStore()
	store.sources["azure-fed"] = &credential.CredSource{
		Name: "azure-fed", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method":        "oidc_federation",
			"login_endpoint":     stub.URL,
			"key_vault_endpoint": stub.URL,
		}),
	}
	store.specs["datadog-keys-in-kv"] = &credential.CredSpec{
		Name: "datadog-keys-in-kv", Type: credential.TypeKeyValue, Source: "azure-fed",
		Config: federatedKVSpec(nil).Config,
	}
	store.sources["datadog-src"] = &credential.CredSource{
		Name: "datadog-src", Type: credential.SourceTypeAPIKey,
		Config: credential.NewConfig(map[string]string{"credential_fields": "application_key"}),
	}
	store.specs["datadog-cred"] = &credential.CredSpec{
		Name: "datadog-cred", Type: credential.TypeAPIKey, Source: "datadog-src",
		Config: credential.NewConfig(map[string]string{
			credential.ConfigSecretSpec:  "datadog-keys-in-kv",
			credential.ConfigSecretField: "api_key",
		}),
	}

	manager, err := credential.NewManager(typeRegistry, driverRegistry, store, log)
	require.NoError(t, err)

	caller := credential.Caller{
		TokenID:  "agent-token",
		TokenTTL: time.Hour,
		ResolveInputs: func(_ context.Context, specName string) (*credential.ExchangeInputs, error) {
			if specName != "datadog-keys-in-kv" {
				return nil, nil
			}
			return testKVInputs, nil
		},
	}

	cred, err := manager.IssueCredential(chainNamespaceContext(), caller, "datadog-cred", nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, cred.Type)
	assert.Equal(t, "dd-key", cred.Data["api_key"], "the consumer must carry the field its secret_field named")
	assert.Equal(t, "dd-app", cred.Data["application_key"], "and the field its source declared")

	_, reads := stub.seen()
	assert.Len(t, reads, 1, "one issuance must read the stored secret once")
}

// Concurrent static reads share the source token while a rotation commits; run under
// -race.
func TestAzureDriver_SecretRead_ConcurrentWithCommitRotation(t *testing.T) {
	stub := newKVStub(t)
	stub.put("/secrets/datadog-keys", testKVPayload, nil)
	d := newKVStaticDriver(stub)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, _, _, err := d.MintCredential(context.Background(), kvSpec(nil))
				assert.NoError(t, err)
			}
		}()
	}
	for gen := 0; gen < 20; gen++ {
		require.NoError(t, d.CommitRotation(context.Background(), map[string]string{
			"tenant_id": testAzureTenant, "client_id": testAzureClient,
			"client_secret": "rotated", "secret_id": "k",
		}))
	}
	close(stop)
	wg.Wait()
}
