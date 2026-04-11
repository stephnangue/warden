package types

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOVHKeysCredType_Metadata(t *testing.T) {
	ct := &OVHKeysCredType{}
	m := ct.Metadata()

	assert.Equal(t, credential.TypeOVHKeys, m.Name)
	assert.Equal(t, credential.CategoryCloudIAM, m.Category)
	assert.Contains(t, m.Description, "OVH")
	assert.Equal(t, time.Duration(0), m.DefaultTTL)
}

func TestOVHKeysCredType_ValidateConfig_LocalSource(t *testing.T) {
	ct := &OVHKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid local config",
			config: map[string]string{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
				"api_token":  "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "missing access_key",
			config: map[string]string{
				"secret_key": "test-secret-key",
				"api_token":  "test-api-token",
			},
			wantErr: true,
			errMsg:  "access_key",
		},
		{
			name: "missing secret_key",
			config: map[string]string{
				"access_key": "test-access-key",
				"api_token":  "test-api-token",
			},
			wantErr: true,
			errMsg:  "secret_key",
		},
		{
			name: "missing api_token",
			config: map[string]string{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
			},
			wantErr: true,
			errMsg:  "api_token",
		},
		{
			name:    "empty config",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "access_key",
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

func TestOVHKeysCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &OVHKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid vault config",
			config: map[string]string{
				"mint_method": "static_ovh",
				"kv2_mount":   "secret",
				"secret_path": "ovh/prod/keys",
			},
			wantErr: false,
		},
		{
			name: "missing mint_method",
			config: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "ovh/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "wrong mint_method",
			config: map[string]string{
				"mint_method": "static_keys",
				"kv2_mount":   "secret",
				"secret_path": "ovh/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "missing kv2_mount",
			config: map[string]string{
				"mint_method": "static_ovh",
				"secret_path": "ovh/prod/keys",
			},
			wantErr: true,
			errMsg:  "kv2_mount",
		},
		{
			name: "missing secret_path",
			config: map[string]string{
				"mint_method": "static_ovh",
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

func TestOVHKeysCredType_ValidateConfig_UnsupportedSource(t *testing.T) {
	ct := &OVHKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"access_key": "test-access-key",
		"secret_key": "test-secret-key",
		"api_token":  "test-api-token",
	}, credential.SourceTypeAWS)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local or vault")
}

func TestOVHKeysCredType_Parse(t *testing.T) {
	ct := &OVHKeysCredType{}
	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid credentials",
			rawData: map[string]interface{}{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
				"api_token":  "test-api-token",
			},
			wantErr: false,
		},
		{
			name: "with lease",
			rawData: map[string]interface{}{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
				"api_token":  "test-api-token",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name: "missing access_key",
			rawData: map[string]interface{}{
				"secret_key": "test-secret-key",
				"api_token":  "test-api-token",
			},
			wantErr: true,
			errMsg:  "access_key",
		},
		{
			name: "missing secret_key",
			rawData: map[string]interface{}{
				"access_key": "test-access-key",
				"api_token":  "test-api-token",
			},
			wantErr: true,
			errMsg:  "secret_key",
		},
		{
			name: "missing api_token",
			rawData: map[string]interface{}{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
			},
			wantErr: true,
			errMsg:  "api_token",
		},
		{
			name:    "empty raw data",
			rawData: map[string]interface{}{},
			wantErr: true,
			errMsg:  "access_key",
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
				assert.Equal(t, credential.TypeOVHKeys, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.rawData["access_key"], cred.Data["access_key"])
				assert.Equal(t, tt.rawData["secret_key"], cred.Data["secret_key"])
				assert.Equal(t, tt.rawData["api_token"], cred.Data["api_token"])
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				if tt.leaseTTL > 0 {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
			}
		})
	}
}

func TestOVHKeysCredType_Validate(t *testing.T) {
	ct := &OVHKeysCredType{}
	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"access_key": "test-access-key",
					"secret_key": "test-secret-key",
					"api_token":  "test-api-token",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"access_key": "test-access-key",
					"secret_key": "test-secret-key",
					"api_token":  "test-api-token",
				},
			},
			wantErr: true,
			errMsg:  "expected type",
		},
		{
			name: "missing access_key",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"secret_key": "test-secret-key",
					"api_token":  "test-api-token",
				},
			},
			wantErr: true,
			errMsg:  "missing access_key",
		},
		{
			name: "missing secret_key",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"access_key": "test-access-key",
					"api_token":  "test-api-token",
				},
			},
			wantErr: true,
			errMsg:  "missing secret_key",
		},
		{
			name: "missing api_token",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"access_key": "test-access-key",
					"secret_key": "test-secret-key",
				},
			},
			wantErr: true,
			errMsg:  "missing api_token",
		},
		{
			name: "empty data",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing access_key",
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

func TestOVHKeysCredType_Revoke(t *testing.T) {
	ct := &OVHKeysCredType{}

	t.Run("no lease - noop", func(t *testing.T) {
		cred := &credential.Credential{
			Type:    credential.TypeOVHKeys,
			LeaseID: "",
		}
		err := ct.Revoke(context.Background(), cred, nil)
		assert.NoError(t, err)
	})
}

func TestOVHKeysCredType_RequiresSpecRotation(t *testing.T) {
	ct := &OVHKeysCredType{}
	assert.False(t, ct.RequiresSpecRotation())
}

func TestOVHKeysCredType_SensitiveConfigFields(t *testing.T) {
	ct := &OVHKeysCredType{}
	fields := ct.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_key")
	assert.Contains(t, fields, "api_token")
}

func TestOVHKeysCredType_FieldSchemas(t *testing.T) {
	ct := &OVHKeysCredType{}
	schemas := ct.FieldSchemas()

	require.Contains(t, schemas, "access_key")
	assert.False(t, schemas["access_key"].Sensitive)

	require.Contains(t, schemas, "secret_key")
	assert.True(t, schemas["secret_key"].Sensitive)

	require.Contains(t, schemas, "api_token")
	assert.True(t, schemas["api_token"].Sensitive)
}
