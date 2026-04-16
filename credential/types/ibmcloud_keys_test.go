package types

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIBMCloudKeysCredType_Metadata(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	m := ct.Metadata()

	assert.Equal(t, credential.TypeIBMCloudKeys, m.Name)
	assert.Equal(t, credential.CategoryCloudIAM, m.Category)
	assert.Contains(t, m.Description, "IBM Cloud")
	assert.Equal(t, time.Duration(0), m.DefaultTTL)
}

func TestIBMCloudKeysCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid dynamic_ibm config",
			config: map[string]string{
				"mint_method": "dynamic_ibm",
				"ibm_mount":   "ibmcloud",
				"role_name":   "my-role",
			},
			wantErr: false,
		},
		{
			name: "dynamic_ibm with COS keys",
			config: map[string]string{
				"mint_method":       "dynamic_ibm",
				"ibm_mount":        "ibmcloud",
				"role_name":        "my-role",
				"access_key_id":     "cos-access-key",
				"secret_access_key": "cos-secret-key",
			},
			wantErr: false,
		},
		{
			name: "wrong mint_method for vault",
			config: map[string]string{
				"mint_method": "iam_with_cos",
				"ibm_mount":   "ibmcloud",
				"role_name":   "my-role",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "dynamic_ibm missing ibm_mount",
			config: map[string]string{
				"mint_method": "dynamic_ibm",
				"role_name":   "my-role",
			},
			wantErr: true,
			errMsg:  "ibm_mount",
		},
		{
			name: "dynamic_ibm missing role_name",
			config: map[string]string{
				"mint_method": "dynamic_ibm",
				"ibm_mount":   "ibmcloud",
			},
			wantErr: true,
			errMsg:  "role_name",
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

func TestIBMCloudKeysCredType_ValidateConfig_IBMSource(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid iam_with_cos",
			config: map[string]string{
				"mint_method":       "iam_with_cos",
				"access_key_id":     "cos-key",
				"secret_access_key": "cos-secret",
			},
			wantErr: false,
		},
		{
			name: "valid iam_with_cos API-only",
			config: map[string]string{
				"mint_method": "iam_with_cos",
			},
			wantErr: false,
		},
		{
			name: "default mint_method for ibm source",
			config: map[string]string{
				"access_key_id":     "cos-key",
				"secret_access_key": "cos-secret",
			},
			wantErr: false,
		},
		{
			name: "wrong mint_method for ibm source",
			config: map[string]string{
				"mint_method": "static_keys",
			},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name: "partial COS - missing secret_access_key",
			config: map[string]string{
				"mint_method":   "iam_with_cos",
				"access_key_id": "cos-key",
			},
			wantErr: true,
			errMsg:  "secret_access_key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeIBM)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIBMCloudKeysCredType_ValidateConfig_UnsupportedSource(t *testing.T) {
	ct := &IBMCloudKeysCredType{}

	for _, source := range []string{credential.SourceTypeLocal, credential.SourceTypeAWS, credential.SourceTypeGCP} {
		t.Run(source, func(t *testing.T) {
			err := ct.ValidateConfig(map[string]string{
				"access_token": "test-token",
			}, source)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "vault or ibm")
		})
	}
}

func TestIBMCloudKeysCredType_Parse(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
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
				"access_token":      "test-access-token",
			},
			wantErr: false,
		},
		{
			name: "valid API-only credentials",
			rawData: map[string]interface{}{
				"access_token": "test-access-token",
			},
			wantErr: false,
		},
		{
			name: "valid COS-only credentials",
			rawData: map[string]interface{}{
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
			},
			wantErr: false,
		},
		{
			name: "with lease",
			rawData: map[string]interface{}{
				"access_token":      "test-access-token",
				"access_key_id":     "test-access-key-id",
				"secret_access_key": "test-secret-access-key",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name: "partial COS - missing secret_access_key",
			rawData: map[string]interface{}{
				"access_key_id": "test-access-key-id",
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name: "partial COS - missing access_key_id",
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
				assert.Equal(t, credential.TypeIBMCloudKeys, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				if tt.leaseTTL > 0 {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
				if v, ok := tt.rawData["access_token"]; ok {
					assert.Equal(t, v, cred.Data["access_token"])
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

func TestIBMCloudKeysCredType_Validate(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid full credential",
			cred: &credential.Credential{
				Type: credential.TypeIBMCloudKeys,
				Data: map[string]string{
					"access_key_id":     "test-access-key-id",
					"secret_access_key": "test-secret-access-key",
					"access_token":      "test-access-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid API-only credential",
			cred: &credential.Credential{
				Type: credential.TypeIBMCloudKeys,
				Data: map[string]string{
					"access_token": "test-access-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid COS-only credential",
			cred: &credential.Credential{
				Type: credential.TypeIBMCloudKeys,
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
					"access_token": "test-access-token",
				},
			},
			wantErr: true,
			errMsg:  "expected type",
		},
		{
			name: "partial COS - missing secret_access_key",
			cred: &credential.Credential{
				Type: credential.TypeIBMCloudKeys,
				Data: map[string]string{
					"access_key_id": "test-access-key-id",
				},
			},
			wantErr: true,
			errMsg:  "both access_key_id and secret_access_key",
		},
		{
			name: "partial COS - missing access_key_id",
			cred: &credential.Credential{
				Type: credential.TypeIBMCloudKeys,
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
				Type: credential.TypeIBMCloudKeys,
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

func TestIBMCloudKeysCredType_Revoke(t *testing.T) {
	ct := &IBMCloudKeysCredType{}

	t.Run("no lease - noop", func(t *testing.T) {
		cred := &credential.Credential{
			Type:    credential.TypeIBMCloudKeys,
			LeaseID: "",
		}
		err := ct.Revoke(context.Background(), cred, nil)
		assert.NoError(t, err)
	})
}

func TestIBMCloudKeysCredType_RequiresSpecRotation(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	assert.False(t, ct.RequiresSpecRotation())
}

func TestIBMCloudKeysCredType_SensitiveConfigFields(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	fields := ct.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_access_key")
	assert.Contains(t, fields, "access_token")
}

func TestIBMCloudKeysCredType_FieldSchemas(t *testing.T) {
	ct := &IBMCloudKeysCredType{}
	schemas := ct.FieldSchemas()

	require.Contains(t, schemas, "access_key_id")
	assert.False(t, schemas["access_key_id"].Sensitive)

	require.Contains(t, schemas, "secret_access_key")
	assert.True(t, schemas["secret_access_key"].Sensitive)

	require.Contains(t, schemas, "access_token")
	assert.True(t, schemas["access_token"].Sensitive)
}
