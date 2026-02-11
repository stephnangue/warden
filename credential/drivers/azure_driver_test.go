package drivers

import (
	"net/http"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
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
	assert.Len(t, fields, 1)
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
	err := driver.Cleanup(nil)
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
	err := driver.Revoke(nil, "any-lease-id")
	assert.NoError(t, err)

	err = driver.Revoke(nil, "")
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
	_, _, _, err := driver.MintCredential(nil, spec)
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
	_, _, _, err := driver.MintCredential(nil, spec)
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
	_, _, _, err = driver.MintCredential(nil, spec2)
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
	_, _, _, err := driver.MintCredential(nil, spec)
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
	_, _, _, err = driver.MintCredential(nil, spec2)
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
		Name: "test-spec",
		Type: credential.TypeAzureBearerToken,
		Config: map[string]string{
			// Missing client_id
		},
	}

	_, _, _, err := driver.PrepareSpecRotation(nil, spec)
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
	err := driver.CommitSpecRotation(nil, spec, map[string]string{
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
	err := driver.CleanupSpecRotation(nil, map[string]string{})
	assert.NoError(t, err)

	err = driver.CleanupSpecRotation(nil, map[string]string{
		"client_id": "test-client",
		// Missing old_secret_id
	})
	assert.NoError(t, err)

	err = driver.CleanupSpecRotation(nil, map[string]string{
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
	err := driver.CommitRotation(nil, map[string]string{
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
		{"00000000-0000-0000-0000-00000000000", true},  // too short
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

