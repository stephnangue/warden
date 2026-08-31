package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyValueCredType_Metadata(t *testing.T) {
	ct := NewKeyValueCredType()
	md := ct.Metadata()

	assert.Equal(t, credential.TypeKeyValue, md.Name)
	assert.Equal(t, credential.CategoryAPI, md.Category)
	assert.Equal(t, time.Duration(0), md.DefaultTTL)
}

func TestKeyValueCredType_ValidateConfig(t *testing.T) {
	ct := NewKeyValueCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			// The narrow role is mandatory: without its own, the spec would inherit the
			// source's, which is the one thing this mint method must not do.
			name:       "transit_signer without a role",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'jwt_role' is required",
		},
		{
			// transit_signer produces the same multi-field, no-primary-field payload
			// this type exists to carry, but needs none of the kv2 locators.
			name:       "valid transit_signer",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "client-assertion", "jwt_role": "warden-transit-signer"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "transit_signer without a key",
			config:     map[string]string{"mint_method": "transit_signer", "jwt_role": "r"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'transit_key' is required",
		},
		{
			// The kv2 locators belong to kv2_read alone; requiring them of every mint
			// method is what kept transit_signer from being expressible at all.
			name:       "transit_signer needs no kv2 locators",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k", "jwt_role": "r", "kv2_mount": "", "secret_path": ""},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "valid kv2_read",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "valid kv2_read with a field selection and a pinned version",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "json_key_map": "token=api_key", "secret_version": "3"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			// GetInt falls back to its default on an unparseable value, so a
			// typo'd version would silently read the current revision. The
			// schema is what stops it reaching the driver.
			name:       "non-numeric version",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "secret_version": "latest"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_version",
		},
		{
			name:       "version below the first revision",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "secret_version": "0"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_version",
		},
		{
			name:       "unsupported source type",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "require an hvault source",
		},
		{
			name:       "wrong mint_method",
			config:     map[string]string{"mint_method": "static_apikey", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "kv2_read",
		},
		{
			name:       "missing kv2_mount",
			config:     map[string]string{"mint_method": "kv2_read", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "kv2_mount",
		},
		{
			name:       "missing secret_path",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, tt.sourceType)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestKeyValueCredType_Parse_PreservesAllKeys is the crux: unlike BaseTokenType,
// key_value must copy every string field verbatim (no primary field, no dropping).
func TestKeyValueCredType_Parse_PreservesAllKeys(t *testing.T) {
	ct := NewKeyValueCredType()

	rawData := map[string]interface{}{
		"admin_token": "glsa_ABC",
		"private_key": "-----BEGIN...",
		"note":        "arbitrary",
		"count":       42, // non-string values are skipped, not errored
	}

	cred, err := ct.Parse(rawData, nil, 0, "")
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, credential.TypeKeyValue, cred.Type)
	assert.False(t, cred.Revocable)
	assert.Equal(t, time.Duration(0), cred.LeaseTTL)
	assert.Equal(t, "glsa_ABC", cred.Data["admin_token"])
	assert.Equal(t, "-----BEGIN...", cred.Data["private_key"])
	assert.Equal(t, "arbitrary", cred.Data["note"])
	_, hasCount := cred.Data["count"]
	assert.False(t, hasCount, "non-string values should be skipped")
	assert.Len(t, cred.Data, 3)
}

func TestKeyValueCredType_Parse_Errors(t *testing.T) {
	ct := NewKeyValueCredType()

	t.Run("empty rawData", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{}, nil, 0, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrInvalidCredential)
	})

	t.Run("no string fields", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{"n": 1, "b": true}, nil, 0, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrInvalidCredential)
	})
}

func TestKeyValueCredType_Validate(t *testing.T) {
	ct := NewKeyValueCredType()

	t.Run("valid", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeKeyValue,
			Data: map[string]string{"anything": "x"},
		})
		assert.NoError(t, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"anything": "x"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected type key_value")
	})

	t.Run("empty data", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeKeyValue,
			Data: map[string]string{},
		})
		require.Error(t, err)
	})
}

func TestKeyValueCredType_NoSecretInConfig(t *testing.T) {
	ct := NewKeyValueCredType()
	assert.False(t, ct.RequiresSpecRotation())
	// The secret lives only in minted Data, never in persisted config.
	assert.Nil(t, ct.SensitiveConfigFields())
	assert.Nil(t, ct.FieldSchemas())
}
