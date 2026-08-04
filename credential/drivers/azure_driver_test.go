package drivers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAzureDriver creates an AzureDriver suitable for unit testing
func newTestAzureDriver() *AzureDriver {
	return &AzureDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAzure,
			Config: map[string]string{
				"tenant_id":     "test-tenant",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		},
		objectIDCache: make(map[string]string),
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

func TestAzureDriverFactory_Type(t *testing.T) {
	factory := &AzureDriverFactory{}
	assert.Equal(t, credential.SourceTypeAzure, factory.Type())
}

func TestAzureDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &AzureDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "client_secret")
	assert.Contains(t, fields, "ca_data")
	assert.Len(t, fields, 2)
}

func TestAzureDriverFactory_ValidateConfig(t *testing.T) {
	factory := &AzureDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: map[string]string{
				"tenant_id":     "00000000-0000-0000-0000-000000000001",
				"client_id":     "00000000-0000-0000-0000-000000000002",
				"client_secret": "test-secret",
				"secret_id":     "00000000-0000-0000-0000-000000000099",
			},
			wantErr: false,
		},
		{
			name: "valid config with subscription_id",
			config: map[string]string{
				"tenant_id":       "00000000-0000-0000-0000-000000000001",
				"client_id":       "00000000-0000-0000-0000-000000000002",
				"client_secret":   "test-secret",
				"secret_id":       "00000000-0000-0000-0000-000000000099",
				"subscription_id": "00000000-0000-0000-0000-000000000003",
			},
			wantErr: false,
		},
		{
			name: "missing tenant_id",
			config: map[string]string{
				"client_id":     "00000000-0000-0000-0000-000000000002",
				"client_secret": "test-secret",
				"secret_id":     "00000000-0000-0000-0000-000000000099",
			},
			wantErr: true,
			errMsg:  "tenant_id",
		},
		{
			name: "missing client_id",
			config: map[string]string{
				"tenant_id":     "00000000-0000-0000-0000-000000000001",
				"client_secret": "test-secret",
				"secret_id":     "00000000-0000-0000-0000-000000000099",
			},
			wantErr: true,
			errMsg:  "client_id",
		},
		{
			name: "missing client_secret",
			config: map[string]string{
				"tenant_id": "00000000-0000-0000-0000-000000000001",
				"client_id": "00000000-0000-0000-0000-000000000002",
				"secret_id": "00000000-0000-0000-0000-000000000099",
			},
			wantErr: true,
			errMsg:  "client_secret",
		},
		{
			name: "missing secret_id",
			config: map[string]string{
				"tenant_id":     "00000000-0000-0000-0000-000000000001",
				"client_id":     "00000000-0000-0000-0000-000000000002",
				"client_secret": "test-secret",
			},
			wantErr: true,
			errMsg:  "secret_id",
		},
		{
			name:    "empty config",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "tenant_id",
		},
		{
			name: "invalid tenant_id format",
			config: map[string]string{
				"tenant_id":     "not-a-uuid",
				"client_id":     "00000000-0000-0000-0000-000000000002",
				"client_secret": "test-secret",
				"secret_id":     "00000000-0000-0000-0000-000000000099",
			},
			wantErr: true,
			errMsg:  "invalid tenant_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAzureDriver_Type(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeAzure, driver.Type())
}

func TestAzureDriver_Cleanup(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: map[string]string{},
		},
	}
	err := driver.Cleanup(context.TODO())
	assert.NoError(t, err)
}

func TestAzureDriver_Revoke_NoOp(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: map[string]string{},
		},
	}
	// Azure tokens can't be revoked - should be no-op
	err := driver.Revoke(context.TODO(), "any-lease-id")
	assert.NoError(t, err)

	err = driver.Revoke(context.TODO(), "")
	assert.NoError(t, err)
}

func TestAzureDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	driver := newTestAzureDriver()

	// Invalid mint_method
	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			"mint_method": "invalid_method",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method 'invalid_method'")
}

func TestAzureDriver_MintCredential_BearerToken_MissingCredentials(t *testing.T) {
	driver := newTestAzureDriver()

	// Missing client_id in spec
	spec := &credential.CredSpec{
		Name: "test-bearer",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			"mint_method":   "bearer_token",
			"client_secret": "test-secret",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'client_id' and 'client_secret'")

	// Missing client_secret in spec
	spec2 := &credential.CredSpec{
		Name: "test-bearer",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			"mint_method": "bearer_token",
			"client_id":   "test-client",
		},
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'client_id' and 'client_secret'")
}

func TestAzureDriver_MintCredential_KeyVaultSecret_MissingConfig(t *testing.T) {
	driver := newTestAzureDriver()

	// Missing vault_name
	spec := &credential.CredSpec{
		Name: "test-kv",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			"mint_method":   "key_vault_secret",
			"client_id":     "test-client",
			"client_secret": "test-secret",
			"secret_name":   "test-secret",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'vault_name' and 'secret_name'")

	// Missing secret_name
	spec2 := &credential.CredSpec{
		Name: "test-kv",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			"mint_method":   "key_vault_secret",
			"client_id":     "test-client",
			"client_secret": "test-secret",
			"vault_name":    "test-vault",
		},
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'vault_name' and 'secret_name'")
}

func TestAzureDriver_SupportsRotation(t *testing.T) {
	// Without Graph permissions, rotation is not supported
	driver := newTestAzureDriver()

	// hasGraphPermissions() will fail without a real Azure connection
	// So SupportsRotation() should return false
	assert.False(t, driver.SupportsRotation())
}

func TestAzureDriver_SupportsSpecRotation(t *testing.T) {
	driver := newTestAzureDriver()

	// hasGraphPermissions() will fail without a real Azure connection
	// So SupportsSpecRotation() should return false
	assert.False(t, driver.SupportsSpecRotation())
}

func TestAzureDriver_PrepareSpecRotation_MissingClientID(t *testing.T) {
	driver := newTestAzureDriver()

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAzureBearerToken,
		Config: map[string]string{
			// Missing client_id
		},
	}

	_, _, _, err := driver.PrepareSpecRotation(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'client_id'")
}

func TestAzureDriver_CommitSpecRotation(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAzure,
			Config: map[string]string{
				"tenant_id":     "test-tenant",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAzureBearerToken,
	}

	// CommitSpecRotation is a no-op - just logs
	err := driver.CommitSpecRotation(context.TODO(), spec, map[string]string{
		"client_secret": "new-secret",
	})
	assert.NoError(t, err)
}

func TestAzureDriver_CleanupSpecRotation_EmptyConfig(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAzure,
			Config: map[string]string{
				"tenant_id":     "test-tenant",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		},
	}

	// Empty client_id or old_secret_id should be a no-op
	err := driver.CleanupSpecRotation(context.TODO(), map[string]string{})
	assert.NoError(t, err)

	err = driver.CleanupSpecRotation(context.TODO(), map[string]string{
		"client_id": "test-client",
		// Missing old_secret_id
	})
	assert.NoError(t, err)

	err = driver.CleanupSpecRotation(context.TODO(), map[string]string{
		// Missing client_id
		"old_secret_id": "test-key",
	})
	assert.NoError(t, err)
}

func TestTruncateID(t *testing.T) {
	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{"abcdefghijklmnop", 8, "abcdefgh..."},
		{"abcd", 8, "abcd"},
		{"abcdefgh", 8, "abcdefgh"},
		{"", 8, ""},
		{"ab", 0, "..."},
	}
	for _, tt := range tests {
		result := truncateID(tt.input, tt.n)
		assert.Equal(t, tt.expected, result)
	}
}

func TestAzureDriver_CommitRotation_ResetsSourceVerified(t *testing.T) {
	driver := newTestAzureDriver()
	driver.sourceVerified = true

	// CommitRotation will fail (no real Azure) but should reset sourceVerified first
	err := driver.CommitRotation(context.TODO(), map[string]string{
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "new-secret",
	})
	// Expected to fail because there's no real Azure AD to verify against
	require.Error(t, err)

	// sourceVerified must be false after rotation, regardless of verify outcome
	assert.False(t, driver.sourceVerified, "sourceVerified should be reset after CommitRotation")
}

func TestAzureDriver_TokenCacheGeneration(t *testing.T) {
	driver := newTestAzureDriver()
	driver.tokenCache = make(map[string]*cachedAzureToken)

	// Seed the cache with a token at generation 0
	driver.tokenMu.Lock()
	driver.tokenCache["https://management.azure.com/"] = &cachedAzureToken{
		accessToken: "old-token",
		expiresAt:   time.Now().Add(1 * time.Hour),
		generation:  0,
	}
	driver.tokenMu.Unlock()

	// Bump generation (simulates CommitRotation)
	driver.tokenMu.Lock()
	driver.credGeneration++
	driver.tokenMu.Unlock()

	// Cache lookup should miss because generation is stale
	driver.tokenMu.Lock()
	gen := driver.credGeneration
	cached, ok := driver.tokenCache["https://management.azure.com/"]
	hit := ok && cached.generation == gen && time.Now().Add(5*time.Minute).Before(cached.expiresAt)
	driver.tokenMu.Unlock()

	assert.False(t, hit, "stale-generation token should not be a cache hit")
}

func TestValidateTenantID(t *testing.T) {
	tests := []struct {
		tenantID string
		wantErr  bool
	}{
		{"00000000-0000-0000-0000-000000000001", false},
		{"abcdef12-3456-7890-abcd-ef1234567890", false},
		{"ABCDEF12-3456-7890-ABCD-EF1234567890", false},
		{"not-a-uuid", true},
		{"", true},
		{"00000000-0000-0000-0000-00000000000", true},   // too short
		{"00000000-0000-0000-0000-0000000000001", true}, // too long
		{"../../../etc/passwd", true},
	}
	for _, tt := range tests {
		err := validateTenantID(tt.tenantID)
		if tt.wantErr {
			assert.Error(t, err, "expected error for tenantID: %s", tt.tenantID)
		} else {
			assert.NoError(t, err, "expected no error for tenantID: %s", tt.tenantID)
		}
	}
}

func TestAzureDriver_ReadLimitedBody(t *testing.T) {
	// readLimitedBody should work with any io.Reader
	data, err := readLimitedBody(http.NoBody)
	require.NoError(t, err)
	assert.Empty(t, data)
}

// =============================================================================
// AzureDriver doAzureRequest edge case
// =============================================================================

func TestAzureDriver_Cleanup_Nil(t *testing.T) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.TODO())
	assert.NoError(t, err)
}

// =============================================================================
// db_helpers tests (if any coverage gaps)
// =============================================================================

func TestTokenCache_Expiry(t *testing.T) {
	driver := newTestAzureDriver()
	driver.tokenCache = make(map[string]*cachedAzureToken)

	driver.tokenMu.Lock()
	driver.tokenCache["scope"] = &cachedAzureToken{
		accessToken: "token",
		expiresAt:   time.Now().Add(-1 * time.Minute), // expired
		generation:  driver.credGeneration,
	}
	driver.tokenMu.Unlock()

	// Expired token should not be a cache hit
	driver.tokenMu.Lock()
	cached, ok := driver.tokenCache["scope"]
	gen := driver.credGeneration
	hit := ok && cached.generation == gen && time.Now().Add(5*time.Minute).Before(cached.expiresAt)
	driver.tokenMu.Unlock()

	assert.False(t, hit)
}

func TestAzureBearerTokenMetadata(t *testing.T) {
	now := time.Date(2026, 6, 9, 15, 4, 5, 0, time.UTC)
	clientID := "11111111-2222-3333-4444-555555555555"
	tenantID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	meta := azureBearerTokenMetadata(clientID, tenantID, "https://management.azure.com/", time.Hour, now)

	// subject is the service principal (client/app id).
	assert.Equal(t, clientID, meta["subject"])
	assert.Equal(t, tenantID, meta["tenant_id"])
	assert.Equal(t, "https://management.azure.com/", meta["resource_uri"])
	assert.Equal(t, "2026-06-09T16:04:05Z", meta["expiration"])

	// Secret material never lands in the clear-logged metadata, and every value
	// is a string (Metadata parsing rejects non-strings).
	assert.NotContains(t, meta, "access_token")
	assert.NotContains(t, meta, "client_secret")
	for k, v := range meta {
		_, ok := v.(string)
		assert.Truef(t, ok, "metadata[%q] is %T, expected string", k, v)
	}
}

// TestAzureDriverFactory_ValidateConfig_Federation covers the per-auth_method
// cross-field rules for a keyless (oidc_federation) source.
func TestAzureDriverFactory_ValidateConfig_Federation(t *testing.T) {
	factory := &AzureDriverFactory{}

	// A keyless source needs no client_secret/secret_id.
	require.NoError(t, factory.ValidateConfig(map[string]string{
		"auth_method": "oidc_federation",
		"tenant_id":   "00000000-0000-0000-0000-000000000001",
		"client_id":   "00000000-0000-0000-0000-000000000002",
	}))

	// A keyless source with no identity at all is still valid (tenant/client_id
	// come from the spec at mint time).
	require.NoError(t, factory.ValidateConfig(map[string]string{
		"auth_method": "oidc_federation",
	}))

	// A stray static secret must be rejected so modes cannot silently mix.
	err := factory.ValidateConfig(map[string]string{
		"auth_method":   "oidc_federation",
		"client_secret": "leftover",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be set for auth_method=oidc_federation")

	err = factory.ValidateConfig(map[string]string{
		"auth_method": "oidc_federation",
		"secret_id":   "leftover",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be set for auth_method=oidc_federation")

	// An unknown auth_method is rejected by the schema.
	err = factory.ValidateConfig(map[string]string{"auth_method": "bogus"})
	require.Error(t, err)
}

// TestAzureDriver_Create_Federation_Keyless verifies an oidc_federation source is
// constructed with no client_secret and without an eager token probe (no network).
func TestAzureDriver_Create_Federation_Keyless(t *testing.T) {
	factory := &AzureDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := factory.Create(map[string]string{
		"auth_method": "oidc_federation",
		"tenant_id":   "00000000-0000-0000-0000-000000000001",
		"client_id":   "00000000-0000-0000-0000-000000000002",
	}, log)
	require.NoError(t, err)
	require.NotNil(t, drv)

	azureDrv := drv.(*AzureDriver)
	assert.False(t, azureDrv.sourceVerified, "a keyless source performs no eager probe")
	// A keyless source has nothing to rotate and never probes Graph.
	assert.False(t, azureDrv.SupportsRotation())
	assert.False(t, azureDrv.SupportsSpecRotation())
}

// TestAzureDriver_MintCredential_Federation_FailsClosed verifies the non-exchange
// path refuses to mint for a keyless source (which carries no credential material).
func TestAzureDriver_MintCredential_Federation_FailsClosed(t *testing.T) {
	drv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "oidc_federation"}},
	}
	_, _, _, _, err := drv.MintCredential(context.TODO(), &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "bearer_token"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source (warden_identity or auth_token)")
}

// TestAzureDriver_MintCredentialWithExchange_Guards covers the exchange-path guards
// before any network call.
func TestAzureDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	fedDrv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "oidc_federation"}},
	}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "bearer_token", "tenant_id": "00000000-0000-0000-0000-000000000001", "client_id": "app"}}
	verified := &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginVerified}

	// A static source must not reach the federation path.
	staticDrv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "static"}},
	}
	_, _, _, _, err := staticDrv.MintCredentialWithExchange(context.TODO(), spec, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")

	// Missing subject token.
	_, _, _, _, err = fedDrv.MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no subject token")

	// Unverified origin must be rejected (only Warden-minted assertions allowed).
	_, _, _, _, err = fedDrv.MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginUnverified})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verified subject")

	// An unsupported mint_method is rejected before any network call.
	kvSpec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "key_vault_secret", "tenant_id": "00000000-0000-0000-0000-000000000001", "client_id": "app"}}
	_, _, _, _, err = fedDrv.MintCredentialWithExchange(context.TODO(), kvSpec, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")

	// A federated bearer_token spec missing tenant_id fails with a clear message
	// (defense in depth — spec validation also requires it at create time).
	noTenant := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "bearer_token", "client_id": "app"}}
	_, _, _, _, err = fedDrv.MintCredentialWithExchange(context.TODO(), noTenant, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'client_id' and 'tenant_id'")
}

// TestAzureDriver_MintCredentialWithExchange_HappyPath drives mint_method=bearer_token
// over a keyless source against a mocked Entra token endpoint, asserting the Warden
// assertion is forwarded as a client_assertion (and no client_secret is sent).
func TestAzureDriver_MintCredentialWithExchange_HappyPath(t *testing.T) {
	var gotAssertion, gotAssertionType, gotClientID, gotScope, gotGrant, gotSecret string
	var sawSecretKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.PostForm.Get("client_assertion")
		gotAssertionType = r.PostForm.Get("client_assertion_type")
		gotClientID = r.PostForm.Get("client_id")
		gotScope = r.PostForm.Get("scope")
		gotGrant = r.PostForm.Get("grant_type")
		gotSecret, sawSecretKey = r.PostForm.Get("client_secret"), r.PostForm.Has("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"eyJ.azure.token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	drv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "oidc_federation"}},
		httpClient: &http.Client{Timeout: 30 * time.Second},
		loginHost:  srv.URL,
	}
	spec := &credential.CredSpec{Name: "azure-mgmt", Config: map[string]string{
		"mint_method":  "bearer_token",
		"tenant_id":    "00000000-0000-0000-0000-000000000001",
		"client_id":    "11111111-1111-1111-1111-111111111111",
		"resource_uri": "https://management.azure.com/",
	}}
	inputs := &credential.ExchangeInputs{
		SubjectToken:       "eyJ.warden.assertion",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
	}

	rawData, metadata, ttl, leaseID, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)

	// The Warden assertion is presented as a client_assertion (JWT-bearer), never a secret.
	assert.Equal(t, "eyJ.warden.assertion", gotAssertion)
	assert.Equal(t, clientAssertionType, gotAssertionType)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", gotClientID)
	assert.Equal(t, "https://management.azure.com/.default", gotScope)
	assert.Equal(t, "client_credentials", gotGrant)
	assert.False(t, sawSecretKey, "a federated exchange must not send a client_secret")
	assert.Empty(t, gotSecret)

	// The minted bearer token surfaces as the credential.
	assert.Equal(t, "eyJ.azure.token", rawData["access_token"])
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", metadata["subject"])
	assert.Equal(t, time.Hour, ttl)
	assert.Empty(t, leaseID, "bearer tokens expire naturally; no lease")
}

// TestAzureDriver_MintCredentialWithExchange_ForwardedSubject_HappyPath drives the
// auth_token federation topology: the subject is the caller's origin-verified inbound JWT
// that Warden forwards untouched (not a Warden-minted assertion), so ResolveSubjectToken
// and CacheIdentity are unset. The driver treats any verified subject the same, so this
// must reach Entra and be presented as the client_assertion verbatim. It guards the
// supported contract against a future change that re-gates federation to Warden-minted
// subjects only.
func TestAzureDriver_MintCredentialWithExchange_ForwardedSubject_HappyPath(t *testing.T) {
	var gotAssertion, gotAssertionType string
	var sawSecretKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.PostForm.Get("client_assertion")
		gotAssertionType = r.PostForm.Get("client_assertion_type")
		_, sawSecretKey = r.PostForm.Get("client_secret"), r.PostForm.Has("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"eyJ.azure.token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	drv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "oidc_federation"}},
		httpClient: &http.Client{Timeout: 30 * time.Second},
		loginHost:  srv.URL,
	}
	spec := &credential.CredSpec{Name: "azure-mgmt", Config: map[string]string{
		"mint_method": "bearer_token",
		"tenant_id":   "00000000-0000-0000-0000-000000000001",
		"client_id":   "11111111-1111-1111-1111-111111111111",
	}}
	// A forwarded inbound JWT: verified origin, no ResolveSubjectToken, no CacheIdentity.
	inputs := &credential.ExchangeInputs{
		SubjectToken:       "eyJ.inbound.idp.jwt",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
	}

	rawData, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "eyJ.inbound.idp.jwt", gotAssertion, "the forwarded inbound JWT must be presented as the client_assertion verbatim")
	assert.Equal(t, clientAssertionType, gotAssertionType)
	assert.False(t, sawSecretKey, "a federated exchange must not send a client_secret")
	assert.Equal(t, "eyJ.azure.token", rawData["access_token"])
}

// TestAzureDriver_MintBearerToken_Static_HappyPath exercises the static client_secret
// path through the refactored postTokenRequest helper: the secret is sent (never a
// client_assertion) and the minted token surfaces.
func TestAzureDriver_MintBearerToken_Static_HappyPath(t *testing.T) {
	var gotSecret, gotAssertion, gotGrant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.PostForm.Get("client_secret")
		gotAssertion = r.PostForm.Get("client_assertion")
		gotGrant = r.PostForm.Get("grant_type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"eyJ.static.token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	drv := &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure, Config: map[string]string{"auth_method": "static"}},
		httpClient: &http.Client{Timeout: 30 * time.Second},
		loginHost:  srv.URL,
	}
	spec := &credential.CredSpec{Name: "azure-static", Config: map[string]string{
		"mint_method":   "bearer_token",
		"tenant_id":     "00000000-0000-0000-0000-000000000001",
		"client_id":     "11111111-1111-1111-1111-111111111111",
		"client_secret": "the-secret",
	}}

	rawData, _, _, _, err := drv.MintCredential(context.TODO(), spec)
	require.NoError(t, err)
	assert.Equal(t, "the-secret", gotSecret)
	assert.Empty(t, gotAssertion, "static path must not send a client_assertion")
	assert.Equal(t, "client_credentials", gotGrant)
	assert.Equal(t, "eyJ.static.token", rawData["access_token"])
}
