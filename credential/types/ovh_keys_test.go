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

func TestOVHKeysCredType_ValidateConfig_OVHSource(t *testing.T) {
	ct := &OVHKeysCredType{}
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid: oauth2_token",
			config:  map[string]string{"mint_method": "oauth2_token"},
			wantErr: false,
		},
		{
			name:    "valid: dynamic_s3",
			config:  map[string]string{"mint_method": "dynamic_s3"},
			wantErr: false,
		},
		{
			name:    "valid: oauth2_token_and_s3",
			config:  map[string]string{"mint_method": "oauth2_token_and_s3"},
			wantErr: false,
		},
		{
			name:    "valid: dynamic_s3 with project_id and user_id overrides",
			config:  map[string]string{"mint_method": "dynamic_s3", "project_id": "proj-123", "user_id": "user-456"},
			wantErr: false,
		},
		{
			name:    "invalid: missing mint_method",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "mint_method",
		},
		{
			name:    "invalid: wrong mint_method",
			config:  map[string]string{"mint_method": "static_keys"},
			wantErr: true,
			errMsg:  "mint_method",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeOVH)
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

	for _, sourceType := range []string{credential.SourceTypeLocal, credential.SourceTypeVault, credential.SourceTypeAWS} {
		t.Run(sourceType, func(t *testing.T) {
			err := ct.ValidateConfig(map[string]string{"mint_method": "oauth2_token"}, sourceType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ovh source")
		})
	}
}

func TestOVHKeysCredType_Parse(t *testing.T) {
	ct := &OVHKeysCredType{}

	t.Run("valid: all three (dual mode)", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"access_key": "test-access-key",
			"secret_key": "test-secret-key",
			"api_token":  "test-api-token",
		}, 0, "")
		require.NoError(t, err)
		assert.Equal(t, credential.TypeOVHKeys, cred.Type)
		assert.Equal(t, "test-access-key", cred.Data["access_key"])
		assert.Equal(t, "test-secret-key", cred.Data["secret_key"])
		assert.Equal(t, "test-api-token", cred.Data["api_token"])
		assert.Len(t, cred.Data, 3)
	})

	t.Run("valid: api_token only (API mode)", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"api_token": "test-api-token",
		}, 0, "")
		require.NoError(t, err)
		assert.Equal(t, "test-api-token", cred.Data["api_token"])
		assert.Len(t, cred.Data, 1)
		_, hasAccessKey := cred.Data["access_key"]
		assert.False(t, hasAccessKey)
	})

	t.Run("valid: S3 only", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"access_key": "test-access-key",
			"secret_key": "test-secret-key",
		}, 0, "")
		require.NoError(t, err)
		assert.Equal(t, "test-access-key", cred.Data["access_key"])
		assert.Equal(t, "test-secret-key", cred.Data["secret_key"])
		assert.Len(t, cred.Data, 2)
		_, hasAPIToken := cred.Data["api_token"]
		assert.False(t, hasAPIToken)
	})

	t.Run("valid: with lease", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"access_key": "test-access-key",
			"secret_key": "test-secret-key",
			"api_token":  "test-api-token",
		}, 1*time.Hour, "lease-123")
		require.NoError(t, err)
		assert.Equal(t, 1*time.Hour, cred.LeaseTTL)
		assert.Equal(t, "lease-123", cred.LeaseID)
		assert.True(t, cred.Revocable)
	})

	t.Run("invalid: access_key without secret_key", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{
			"access_key": "test-access-key",
		}, 0, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_key")
	})

	t.Run("invalid: secret_key without access_key", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{
			"secret_key": "test-secret-key",
		}, 0, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key")
	})

	t.Run("invalid: empty raw data", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{}, 0, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one mode")
	})
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
			name: "valid: all three (dual mode)",
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
			name: "valid: api_token only",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"api_token": "test-api-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid: S3 only",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"access_key": "test-access-key",
					"secret_key": "test-secret-key",
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
			name: "invalid: access_key without secret_key",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"access_key": "test-access-key",
				},
			},
			wantErr: true,
			errMsg:  "secret_key",
		},
		{
			name: "invalid: secret_key without access_key",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{
					"secret_key": "test-secret-key",
				},
			},
			wantErr: true,
			errMsg:  "access_key",
		},
		{
			name: "invalid: empty data",
			cred: &credential.Credential{
				Type: credential.TypeOVHKeys,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "at least one mode",
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
	assert.Nil(t, ct.SensitiveConfigFields())
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
