package types

import (
	"context"
	"strings"
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

// A vault source needed a static_scaleway mint method that the Vault driver never
// implemented, so such a spec passed validation here and then failed at its first
// mint. It is refused at create now.
func TestScalewayKeysCredType_ValidateConfig_VaultSourceRejected(t *testing.T) {
	ct := &ScalewayKeysCredType{}
	err := ct.ValidateConfig(map[string]string{
		"mint_method": "static_scaleway",
		"kv2_mount":   "secret",
		"secret_path": "scaleway/prod/keys",
	}, credential.SourceTypeVault)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local or scaleway")
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
			// A non-positive ttl parses, so it used to reach the mint and produce a
			// key born expired — with a lease TTL of 0, making it unrevocable and so
			// never cleaned up.
			name: "dynamic_keys rejects a non-positive ttl",
			config: map[string]string{
				"mint_method":    "dynamic_keys",
				"application_id": "app-123",
				"ttl":            "0s",
			},
			wantErr: true,
			errMsg:  "ttl must be positive",
		},
		{
			name: "dynamic_keys rejects an over-long description",
			config: map[string]string{
				"mint_method":    "dynamic_keys",
				"application_id": "app-123",
				"description":    strings.Repeat("x", scalewayMaxDescriptionLength+1),
			},
			wantErr: true,
			errMsg:  "at most 200 characters",
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

		// --- Credential chaining ---
		{
			name: "chained static_keys carries no pair",
			config: map[string]string{
				"mint_method": "static_keys",
				"secret_spec": "scw-pair",
			},
			wantErr: false,
		},
		{
			name: "chained static_keys rejects an inline access_key",
			config: map[string]string{
				"mint_method": "static_keys",
				"secret_spec": "scw-pair",
				"access_key":  "SCWXXXXXXXXXXXXXXXXX",
			},
			wantErr: true,
			errMsg:  "'access_key' must be omitted",
		},
		{
			name: "chained static_keys rejects an inline secret_key",
			config: map[string]string{
				"mint_method": "static_keys",
				"secret_spec": "scw-pair",
				"secret_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			wantErr: true,
			errMsg:  "'secret_key' must be omitted",
		},
		{
			// secret_field names one secret and a pair is not one, so anything set
			// here was set deliberately and would do nothing.
			name: "chained static_keys rejects secret_field",
			config: map[string]string{
				"mint_method":  "static_keys",
				"secret_spec":  "scw-pair",
				"secret_field": "secret_key",
			},
			wantErr: true,
			errMsg:  "does not apply to static_keys",
		},
		{
			// Naming both remedies is the point: on a chained source, an error that
			// only asked for inline keys would send an operator to add config the
			// next rule rejects.
			name: "static_keys with neither a pair nor a reference names both remedies",
			config: map[string]string{
				"mint_method": "static_keys",
			},
			wantErr: true,
			errMsg:  "or a 'secret_spec' naming a spec that yields them",
		},
		{
			// The management key authenticates the SOURCE's IAM calls, and the driver
			// factory only ever sees source config.
			name: "dynamic_keys rejects a spec-level secret_spec",
			config: map[string]string{
				"mint_method":    "dynamic_keys",
				"application_id": "app-123",
				"secret_spec":    "scw-mgmt-key",
			},
			wantErr: true,
			errMsg:  "set 'secret_spec' on the source",
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
	assert.Contains(t, err.Error(), "local or scaleway")
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
			// What a chained mint returns: a TTL bounding how long the fetched
			// material may be reused, but no lease — nothing here can be revoked,
			// and registering it for revocation would schedule a call that must fail.
			name: "TTL without a lease is not revocable",
			rawData: map[string]interface{}{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			leaseTTL: 30 * time.Minute,
			leaseID:  "",
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
			cred, err := ct.Parse(tt.rawData, nil, tt.leaseTTL, tt.leaseID)
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
				// Both halves matter: a chained mint reports a TTL bounding reuse of
				// its material but hands out no leaseID, having no key of its own to
				// revoke with.
				if tt.leaseTTL > 0 && tt.leaseID != "" {
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
