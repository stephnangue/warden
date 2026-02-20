package drivers

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultDriverFactory_Type(t *testing.T) {
	factory := &VaultDriverFactory{}
	assert.Equal(t, credential.SourceTypeVault, factory.Type())
}

func TestVaultDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &VaultDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "token")
	assert.Contains(t, fields, "secret_id")
	assert.Contains(t, fields, "secret_id_accessor")
	assert.Len(t, fields, 3)
}

func TestVaultDriverFactory_ValidateConfig(t *testing.T) {
	factory := &VaultDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config (no auth)",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
			wantErr: false,
		},
		{
			name: "valid config with approle auth",
			config: map[string]string{
				"vault_address":  "http://127.0.0.1:8200",
				"auth_method":    "approle",
				"role_id":        "test-role-id",
				"secret_id":      "test-secret-id",
				"approle_mount":  "warden_approle",
				"role_name":      "test-role",
			},
			wantErr: false,
		},
		{
			name: "valid config with namespace",
			config: map[string]string{
				"vault_address":   "http://127.0.0.1:8200",
				"vault_namespace": "admin/team",
			},
			wantErr: false,
		},
		{
			name:    "missing vault_address",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "vault_address",
		},
		{
			name: "unsupported auth_method",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "userpass",
			},
			wantErr: true,
			errMsg:  "must be one of",
		},
		{
			name: "approle missing role_id",
			config: map[string]string{
				"vault_address":  "http://127.0.0.1:8200",
				"auth_method":    "approle",
				"secret_id":      "test-secret-id",
				"approle_mount":  "warden_approle",
				"role_name":      "test-role",
			},
			wantErr: true,
			errMsg:  "role_id",
		},
		{
			name: "approle missing secret_id",
			config: map[string]string{
				"vault_address":  "http://127.0.0.1:8200",
				"auth_method":    "approle",
				"role_id":        "test-role-id",
				"approle_mount":  "warden_approle",
				"role_name":      "test-role",
			},
			wantErr: true,
			errMsg:  "secret_id",
		},
		{
			name: "approle missing approle_mount",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"role_name":     "test-role",
			},
			wantErr: true,
			errMsg:  "approle_mount",
		},
		{
			name: "approle missing role_name",
			config: map[string]string{
				"vault_address":  "http://127.0.0.1:8200",
				"auth_method":    "approle",
				"role_id":        "test-role-id",
				"secret_id":      "test-secret-id",
				"approle_mount":  "warden_approle",
			},
			wantErr: true,
			errMsg:  "role_name",
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

func TestVaultDriver_Type(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeVault,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeVault, driver.Type())
}

func TestVaultDriver_Cleanup(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeVault,
			Config: map[string]string{},
		},
	}
	err := driver.Cleanup(nil)
	assert.NoError(t, err)
}

func TestVaultDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeVault,
			Config: map[string]string{},
		},
	}
	// Empty lease ID should be a no-op
	err := driver.Revoke(nil, "")
	assert.NoError(t, err)
}

func TestVaultDriver_SupportsRotation(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]string
		wantResult bool
	}{
		{
			name: "approle with role_name supports rotation",
			config: map[string]string{
				"auth_method": "approle",
				"role_name":   "test-role",
			},
			wantResult: true,
		},
		{
			name: "approle without role_name does not support rotation",
			config: map[string]string{
				"auth_method": "approle",
			},
			wantResult: false,
		},
		{
			name: "no auth_method does not support rotation",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
			wantResult: false,
		},
		{
			name:       "empty config does not support rotation",
			config:     map[string]string{},
			wantResult: false,
		},
		{
			name: "token auth does not support rotation",
			config: map[string]string{
				"auth_method": "token",
			},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &VaultDriver{
				credSource: &credential.CredSource{
					Type:   credential.SourceTypeVault,
					Config: tt.config,
				},
			}
			assert.Equal(t, tt.wantResult, driver.SupportsRotation())
		})
	}
}

func TestContainsSlash(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"no-slash", false},
		{"has/slash", true},
		{"/leading", true},
		{"trailing/", true},
		{"multiple/slashes/here", true},
		{"accessor-uuid-1234", false},
		{"database/creds/my-role/abc123", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, containsSlash(tt.input))
		})
	}
}

func TestVaultDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// Missing mint_method
	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		Config: map[string]string{},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method ''")

	// Invalid mint_method
	spec2 := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "invalid",
		},
	}
	_, _, _, err = driver.MintCredential(nil, spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method 'invalid'")
}

func TestVaultDriver_MintCredential_DatabaseRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// kv2_static without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-db",
		Type: credential.TypeVaultToken,
		Config: map[string]string{
			"mint_method": "kv2_static",
		},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")

	// dynamic_database without role_name should fail on missing fields
	spec2 := &credential.CredSpec{
		Name: "test-db-dynamic",
		Type: credential.TypeVaultToken,
		Config: map[string]string{
			"mint_method":    "dynamic_database",
			"database_mount": "database",
		},
	}
	_, _, _, err = driver.MintCredential(nil, spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database_mount and role_name are required")
}

func TestVaultDriver_MintCredential_AWSRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// kv2_static without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-aws",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "kv2_static",
		},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")

	// dynamic_aws without role_name should fail on validation
	spec2 := &credential.CredSpec{
		Name: "test-aws-dynamic",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
		},
	}
	_, _, _, err = driver.MintCredential(nil, spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws_mount and role_name are required")
}

func TestVaultDriver_MintCredential_VaultTokenRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// vault_token without token_role should fail with validation error
	spec := &credential.CredSpec{
		Name: "test-token",
		Type: credential.TypeVaultToken,
		Config: map[string]string{
			"mint_method": "vault_token",
		},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_role is required")
}

func TestVaultDriver_FetchDynamicAWSCreds_InvalidTTL(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-aws-bad-ttl",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "not-a-duration",
		},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl format")
}

func TestVaultDriver_FetchDynamicVaultToken_InvalidTTL(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-token-bad-ttl",
		Type: credential.TypeVaultToken,
		Config: map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "bad",
		},
	}
	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl format")
}

func TestVaultDriver_Authenticate_UnsupportedMethod(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"auth_method": "userpass",
			},
		},
	}

	err := driver.authenticate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

func TestVaultDriver_Authenticate_NoMethod(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// No auth method should be a no-op
	err := driver.authenticate(nil)
	assert.NoError(t, err)
}

func TestVaultDriver_PrepareRotation_NonApprole(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	_, _, _, err := driver.PrepareRotation(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation only supported for approle")
}

func TestVaultDriver_PrepareRotation_MissingRoleName(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
			},
		},
	}

	_, _, _, err := driver.PrepareRotation(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_name is required")
}

func TestVaultDriver_CleanupRotation_EmptyAccessor(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// Empty accessor should be a no-op
	err := driver.CleanupRotation(nil, map[string]string{
		"secret_id_accessor": "",
	})
	assert.NoError(t, err)

	// Missing key should also be a no-op
	err = driver.CleanupRotation(nil, map[string]string{})
	assert.NoError(t, err)
}

func TestVaultDriver_FetchDynamicAWSCreds_TTLBelowMinimum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-aws-min-ttl",
		Type:   credential.TypeAWSAccessKeys,
		MinTTL: 2 * time.Hour,
		Config: map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		},
	}

	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestVaultDriver_FetchDynamicAWSCreds_TTLExceedsMaximum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-aws-max-ttl",
		Type:   credential.TypeAWSAccessKeys,
		MaxTTL: 1 * time.Hour,
		Config: map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		},
	}

	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestVaultDriver_FetchDynamicVaultToken_TTLBelowMinimum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-token-min-ttl",
		Type:   credential.TypeVaultToken,
		MinTTL: 2 * time.Hour,
		Config: map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		},
	}

	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestVaultDriver_FetchDynamicVaultToken_TTLExceedsMaximum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-token-max-ttl",
		Type:   credential.TypeVaultToken,
		MaxTTL: 1 * time.Hour,
		Config: map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		},
	}

	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}
