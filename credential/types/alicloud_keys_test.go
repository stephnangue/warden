package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlicloudKeysCredType_Metadata(t *testing.T) {
	ct := &AlicloudKeysCredType{}
	md := ct.Metadata()
	assert.Equal(t, credential.TypeAlicloudKeys, md.Name)
	assert.Equal(t, credential.CategoryCloudIAM, md.Category)
}

func TestAlicloudKeysCredType_ValidateConfig_AlicloudSource(t *testing.T) {
	ct := &AlicloudKeysCredType{}
	tests := []struct {
		name   string
		config map[string]string
		errMsg string
	}{
		{
			name: "valid assume_role config",
			config: map[string]string{
				"mint_method": "assume_role",
				"role_arn":    "acs:ram::123456789012:role/warden",
			},
		},
		{
			name: "valid with optional fields",
			config: map[string]string{
				"mint_method":       "assume_role",
				"role_arn":          "acs:ram::123456789012:role/warden",
				"role_session_name": "warden-session",
				"duration_seconds":  "3600s",
			},
		},
		{
			name:   "missing mint_method",
			config: map[string]string{"role_arn": "acs:ram::123456789012:role/warden"},
			errMsg: "mint_method",
		},
		{
			name: "missing role_arn",
			config: map[string]string{
				"mint_method": "assume_role",
			},
			errMsg: "role_arn",
		},
		{
			// duration_seconds is a duration field, so a bare integer is not
			// accepted — it needs the unit.
			name: "duration_seconds without a unit",
			config: map[string]string{
				"mint_method":      "assume_role",
				"role_arn":         "acs:ram::123456789012:role/warden",
				"duration_seconds": "3600",
			},
			errMsg: "duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeAlicloud)
			if tt.errMsg == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// A vault source needed a static_alicloud mint method that the Vault driver never
// implemented, so such a spec passed validation here and then failed at its first
// mint. It is refused at create now.
func TestAlicloudKeysCredType_ValidateConfig_VaultSourceRejected(t *testing.T) {
	ct := &AlicloudKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"mint_method": "static_alicloud",
		"kv2_mount":   "secret",
		"secret_path": "alicloud/prod/keys",
	}, credential.SourceTypeVault)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alicloud source")
}

func TestAlicloudKeysCredType_ValidateConfig_UnsupportedSource(t *testing.T) {
	ct := &AlicloudKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"mint_method": "assume_role",
		"role_arn":    "acs:ram::123456789012:role/warden",
	}, credential.SourceTypeAWS)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alicloud source")
}

func TestAlicloudKeysCredType_Parse(t *testing.T) {
	ct := &AlicloudKeysCredType{}

	t.Run("STS credentials with a security token", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"access_key_id":     "STS.abc",
			"access_key_secret": "sts-secret",
			"security_token":    "sts-token",
		}, nil, time.Hour, "")
		require.NoError(t, err)
		assert.Equal(t, credential.TypeAlicloudKeys, cred.Type)
		assert.Equal(t, "STS.abc", cred.Data["access_key_id"])
		assert.Equal(t, "sts-secret", cred.Data["access_key_secret"])
		assert.Equal(t, "sts-token", cred.Data["security_token"])
		assert.Equal(t, time.Hour, cred.LeaseTTL)
	})

	t.Run("security_token is omitted when empty", func(t *testing.T) {
		cred, err := ct.Parse(map[string]interface{}{
			"access_key_id":     "LTAI.abc",
			"access_key_secret": "secret",
		}, nil, time.Hour, "")
		require.NoError(t, err)
		assert.NotContains(t, cred.Data, "security_token")
	})

	t.Run("missing fields are rejected", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{
			"access_key_secret": "secret",
		}, nil, time.Hour, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key_id")

		_, err = ct.Parse(map[string]interface{}{
			"access_key_id": "LTAI.abc",
		}, nil, time.Hour, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key_secret")
	})
}

func TestAlicloudKeysCredType_SensitiveConfigFields(t *testing.T) {
	ct := &AlicloudKeysCredType{}
	fields := ct.SensitiveConfigFields()
	assert.Contains(t, fields, "access_key_secret")
	assert.Contains(t, fields, "security_token")
}
