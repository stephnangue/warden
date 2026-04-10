package types

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScalewayKeysCredType_Metadata(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	m := ct.Metadata()

	assert.Equal(t, credential.TypeScalewayKeys, m.Name)
	assert.Equal(t, credential.CategoryCloudIAM, m.Category)
	assert.Contains(t, m.Description, "Scaleway")
	assert.Equal(t, time.Duration(0), m.DefaultTTL)
}

func TestScalewayKeysCredType_ValidateConfig_LocalSource(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid local config",
			config: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: false,
		},
		{
			name: "missing access_key",
			config: map[string]string{
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: true,
			errMsg:  "access_key",
		},
		{
			name: "missing secret_key",
			config: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
			},
			wantErr: true,
			errMsg:  "secret_key",
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

func TestScalewayKeysCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid vault config",
			config: map[string]string{
				"mint_method": "static_scaleway",
				"kv2_mount":   "secret",
				"secret_path": "scaleway/prod/keys",
			},
			wantErr: false,
		},
		{
			name: "missing mint_method",
			config: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "scaleway/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "wrong mint_method",
			config: map[string]string{
				"mint_method": "dynamic_aws",
				"kv2_mount":   "secret",
				"secret_path": "scaleway/prod/keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "missing kv2_mount",
			config: map[string]string{
				"mint_method": "static_scaleway",
				"secret_path": "scaleway/prod/keys",
			},
			wantErr: true,
			errMsg:  "kv2_mount",
		},
		{
			name: "missing secret_path",
			config: map[string]string{
				"mint_method": "static_scaleway",
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

func TestScalewayKeysCredType_ValidateConfig_ScalewaySource(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid static_keys",
			config: map[string]string{
				"mint_method": "static_keys",
				"access_key":  "SCWXXXXXXXXXXXXXXXXX",
				"secret_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: false,
		},
		{
			name: "valid dynamic_keys",
			config: map[string]string{
				"mint_method":    "dynamic_keys",
				"application_id": "app-123",
			},
			wantErr: false,
		},
		{
			name: "dynamic_keys missing application_id",
			config: map[string]string{
				"mint_method": "dynamic_keys",
			},
			wantErr: true,
			errMsg:  "application_id",
		},
		{
			name: "missing mint_method",
			config: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "invalid mint_method",
			config: map[string]string{
				"mint_method": "unknown",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeScaleway)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScalewayKeysCredType_ValidateConfig_UnsupportedSource(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"access_key": "SCWXXXXXXXXXXXXXXXXX",
		"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
	}, credential.SourceTypeAWS)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local, vault, or scaleway")
}

func TestScalewayKeysCredType_Parse(t *testing.T) {
	ct := &ScalewayKeysCredType{}
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
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: false,
		},
		{
			name: "with lease",
			rawData: map[string]interface{}{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name: "missing access_key",
			rawData: map[string]interface{}{
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: true,
			errMsg:  "access_key",
		},
		{
			name: "missing secret_key",
			rawData: map[string]interface{}{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
			},
			wantErr: true,
			errMsg:  "secret_key",
		},
		{
			name: "empty access_key",
			rawData: map[string]interface{}{
				"access_key": "",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: true,
			errMsg:  "access_key",
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
				assert.Equal(t, credential.TypeScalewayKeys, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.rawData["access_key"], cred.Data["access_key"])
				assert.Equal(t, tt.rawData["secret_key"], cred.Data["secret_key"])
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

func TestScalewayKeysCredType_Validate(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type",
		},
		{
			name: "missing access_key",
			cred: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "missing access_key",
		},
		{
			name: "invalid access_key prefix",
			cred: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "AKIAIOSFODNN7EXAMPLE",
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "must start with SCW",
		},
		{
			name: "missing secret_key",
			cred: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
				},
			},
			wantErr: true,
			errMsg:  "missing secret_key",
		},
		{
			name: "empty data",
			cred: &credential.Credential{
				Type: credential.TypeScalewayKeys,
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

func TestScalewayKeysCredType_Revoke(t *testing.T) {
	ct := &ScalewayKeysCredType{}

	t.Run("no lease - noop", func(t *testing.T) {
		cred := &credential.Credential{
			Type:    credential.TypeScalewayKeys,
			LeaseID: "",
		}
		err := ct.Revoke(context.Background(), cred, nil)
		assert.NoError(t, err)
	})
}

func TestScalewayKeysCredType_RequiresSpecRotation(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	assert.False(t, ct.RequiresSpecRotation())
}

func TestScalewayKeysCredType_SensitiveConfigFields(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	fields := ct.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_key")
}

func TestScalewayKeysCredType_FieldSchemas(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	schemas := ct.FieldSchemas()

	require.Contains(t, schemas, "access_key")
	assert.False(t, schemas["access_key"].Sensitive)

	require.Contains(t, schemas, "secret_key")
	assert.True(t, schemas["secret_key"].Sensitive)
}
