package types

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudflareKeysCredType_Metadata(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	m := ct.Metadata()

	assert.Equal(t, credential.TypeCloudflareKeys, m.Name)
	assert.Equal(t, credential.CategoryCloudIAM, m.Category)
	assert.Contains(t, m.Description, "Cloudflare")
	assert.Equal(t, time.Duration(0), m.DefaultTTL)
}

func TestCloudflareKeysCredType_ValidateConfig_LocalSource(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid full config",
			config: map[string]string{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
				"api_token":         "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "valid API-only config",
			config: map[string]string{
				"api_token": "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "valid R2-only config",
			config: map[string]string{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
			},
			wantErr: false,
		},
		{
			name: "partial R2 - missing secret_access_key",
			config: map[string]string{
				"access_key_id": "test-access-key-id",
			},
			wantErr: true,
			errMsg:  "secret_access_key",
		},
		{
			name: "partial R2 - missing access_key_id",
			config: map[string]string{
				"secret_access_key": "test-secret-access-key",
			},
			wantErr: true,
			errMsg:  "access_key_id",
		},
		{
			name:    "empty config",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "at least one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeLocal)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCloudflareKeysCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid vault config",
			config: map[string]string{
				"mint_method": "static_cloudflare",
				"kv2_mount":   "secret",
				"secret_path": "cloudflare/prod/keys",
			},
			wantErr: false,
		},
		{
			name: "missing mint_method",
			config: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "cloudflare/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "wrong mint_method",
			config: map[string]string{
				"mint_method": "static_keys",
				"kv2_mount":   "secret",
				"secret_path": "cloudflare/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "missing kv2_mount",
			config: map[string]string{
				"mint_method": "static_cloudflare",
				"secret_path": "cloudflare/prod/keys",
			},
			wantErr: true,
			errMsg:  "kv2_mount",
		},
		{
			name: "missing secret_path",
			config: map[string]string{
				"mint_method": "static_cloudflare",
				"kv2_mount":   "secret",
			},
			wantErr: true,
			errMsg:  "secret_path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeVault)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCloudflareKeysCredType_ValidateConfig_UnsupportedSource(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"access_key_id":     "test-access-key-id",
		"secret_access_key": "test-secret-access-key",
		"api_token":         "test-api-token",
	}, credential.SourceTypeAWS)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local or vault")
}

func TestCloudflareKeysCredType_Parse(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid full credentials",
			rawData: map[string]interface{}{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
				"api_token":         "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "valid API-only credentials",
			rawData: map[string]interface{}{
				"api_token": "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "valid R2-only credentials",
			rawData: map[string]interface{}{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
			},
			wantErr: false,
		},
		{
			name: "with lease",
			rawData: map[string]interface{}{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
				"api_token":         "test-api-token",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name: "partial R2 - missing secret_access_key",
			rawData: map[string]interface{}{
				"access_key_id": "test-access-key-id",
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name: "partial R2 - missing access_key_id",
			rawData: map[string]interface{}{
				"secret_access_key": "test-secret-access-key",
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name:    "empty raw data",
			rawData: map[string]interface{}{},
			wantErr: true,
			errMsg:  "at least one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := ct.Parse(tt.rawData, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, credential.TypeCloudflareKeys, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				if tt.leaseTTL > 0 {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
				// Only check fields that were provided
				if v, ok := tt.rawData["api_token"]; ok {
					assert.Equal(t, v, cred.Data["api_token"])
				}
				if v, ok := tt.rawData["access_key_id"]; ok {
					assert.Equal(t, v, cred.Data["access_key_id"])
				}
				if v, ok := tt.rawData["secret_access_key"]; ok {
					assert.Equal(t, v, cred.Data["secret_access_key"])
				}
			}
		})
	}
}

func TestCloudflareKeysCredType_Validate(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid full credential",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{
					"access_key_id":     "test-access-key-id",
					"secret_access_key": "test-secret-access-key",
					"api_token":         "test-api-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid API-only credential",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{
					"api_token": "test-api-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid R2-only credential",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{
					"access_key_id":     "test-access-key-id",
					"secret_access_key": "test-secret-access-key",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"api_token": "test-api-token",
				},
			},
			wantErr: true,
			errMsg:  "expected type",
		},
		{
			name: "partial R2 - missing secret_access_key",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{
					"access_key_id": "test-access-key-id",
				},
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name: "partial R2 - missing access_key_id",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{
					"secret_access_key": "test-secret-access-key",
				},
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name: "empty data",
			cred: &credential.Credential{
				Type: credential.TypeCloudflareKeys,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "at least one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.Validate(tt.cred)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCloudflareKeysCredType_Revoke(t *testing.T) {
	ct := &CloudflareKeysCredType{}

	t.Run("no lease - noop", func(t *testing.T) {
		cred := &credential.Credential{
			Type:    credential.TypeCloudflareKeys,
			LeaseID: "",
		}
		err := ct.Revoke(context.Background(), cred, nil)
		assert.NoError(t, err)
	})
}

func TestCloudflareKeysCredType_RequiresSpecRotation(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	assert.False(t, ct.RequiresSpecRotation())
}

func TestCloudflareKeysCredType_SensitiveConfigFields(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	fields := ct.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_access_key")
	assert.Contains(t, fields, "api_token")
}

func TestCloudflareKeysCredType_FieldSchemas(t *testing.T) {
	ct := &CloudflareKeysCredType{}
	schemas := ct.FieldSchemas()

	require.Contains(t, schemas, "access_key_id")
	assert.False(t, schemas["access_key_id"].Sensitive)

	require.Contains(t, schemas, "secret_access_key")
	assert.True(t, schemas["secret_access_key"].Sensitive)

	require.Contains(t, schemas, "api_token")
	assert.True(t, schemas["api_token"].Sensitive)
}
