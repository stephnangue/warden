package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureBearerTokenCredType_Metadata(t *testing.T) {
	credType := &AzureBearerTokenCredType{}
	metadata := credType.Metadata()

	assert.Equal(t, credential.TypeAzureBearerToken, metadata.Name)
	assert.Equal(t, credential.CategoryCloudIAM, metadata.Category)
	assert.Equal(t, 1*time.Hour, metadata.DefaultTTL)
	assert.NotEmpty(t, metadata.Description)
}

func TestAzureBearerTokenCredType_ValidateConfig(t *testing.T) {
	credType := &AzureBearerTokenCredType{}

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid azure source with bearer_token",
			config: map[string]string{
				"mint_method":   "bearer_token",
				"client_id":     "test-client-id",
				"client_secret": "test-secret",
				"secret_id":     "test-secret-id",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    false,
		},
		{
			name: "valid azure source with default mint_method",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-secret",
				"secret_id":     "test-secret-id",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    false,
		},
		{
			name: "missing client_id",
			config: map[string]string{
				"mint_method":   "bearer_token",
				"client_secret": "test-secret",
				"secret_id":     "test-secret-id",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    true,
			errMsg:     "client_id",
		},
		{
			name: "missing client_secret",
			config: map[string]string{
				"mint_method": "bearer_token",
				"client_id":   "test-client-id",
				"secret_id":   "test-secret-id",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    true,
			errMsg:     "client_secret",
		},
		{
			name: "missing secret_id",
			config: map[string]string{
				"mint_method":   "bearer_token",
				"client_id":     "test-client-id",
				"client_secret": "test-secret",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    true,
			errMsg:     "secret_id",
		},
		{
			name: "unsupported mint_method",
			config: map[string]string{
				"mint_method":   "invalid",
				"client_id":     "test-client-id",
				"client_secret": "test-secret",
				"secret_id":     "test-secret-id",
			},
			sourceType: credential.SourceTypeAzure,
			wantErr:    true,
			errMsg:     "unsupported mint_method",
		},
		{
			name: "unsupported source type",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-secret",
				"secret_id":     "test-secret-id",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "unsupported source type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := credType.ValidateConfig(tt.config, tt.sourceType)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAzureBearerTokenCredType_Parse(t *testing.T) {
	credType := &AzureBearerTokenCredType{}

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid bearer token",
			rawData: map[string]interface{}{
				"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
				"resource_uri": "https://management.azure.com/",
				"tenant_id":    "test-tenant",
				"client_id":    "test-client",
				"token_type":   "Bearer",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "minimal valid bearer token",
			rawData: map[string]interface{}{
				"access_token": "test-token",
			},
			leaseTTL: 30 * time.Minute,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "missing access_token",
			rawData: map[string]interface{}{
				"resource_uri": "https://management.azure.com/",
			},
			leaseTTL: 1 * time.Hour,
			wantErr:  true,
			errMsg:   "access_token",
		},
		{
			name: "empty access_token",
			rawData: map[string]interface{}{
				"access_token": "",
			},
			leaseTTL: 1 * time.Hour,
			wantErr:  true,
			errMsg:   "access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := credType.Parse(tt.rawData, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, credential.TypeAzureBearerToken, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.False(t, cred.Revocable) // Azure tokens are not revocable
				assert.NotEmpty(t, cred.Data["access_token"])
			}
		})
	}
}

func TestAzureBearerTokenCredType_Validate(t *testing.T) {
	credType := &AzureBearerTokenCredType{}

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{
					"access_token": "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"access_token": "test-token",
				},
			},
			wantErr: true,
			errMsg:  "expected type",
		},
		{
			name: "missing access_token",
			cred: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "access_token",
		},
		{
			name: "empty access_token",
			cred: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{
					"access_token": "",
				},
			},
			wantErr: true,
			errMsg:  "access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := credType.Validate(tt.cred)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAzureBearerTokenCredType_Revoke(t *testing.T) {
	credType := &AzureBearerTokenCredType{}

	cred := &credential.Credential{
		Type:    credential.TypeAzureBearerToken,
		LeaseID: "test-lease",
		Data: map[string]string{
			"access_token": "test-token",
		},
	}

	// Revoke should be a no-op for Azure bearer tokens
	err := credType.Revoke(nil, cred, nil)
	assert.NoError(t, err)
}

func TestAzureBearerTokenCredType_RequiresSpecRotation(t *testing.T) {
	credType := &AzureBearerTokenCredType{}
	assert.True(t, credType.RequiresSpecRotation())
}

func TestAzureBearerTokenCredType_FieldSchemas(t *testing.T) {
	credType := &AzureBearerTokenCredType{}
	schemas := credType.FieldSchemas()

	// access_token should be sensitive
	assert.True(t, schemas["access_token"].Sensitive)

	// resource_uri should not be sensitive
	assert.False(t, schemas["resource_uri"].Sensitive)

	// tenant_id should not be sensitive
	assert.False(t, schemas["tenant_id"].Sensitive)
}
