package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
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
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
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
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
			},
			wantErr: true,
			errMsg:  "role_id",
		},
		{
			name: "approle missing secret_id",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
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
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
			},
			wantErr: true,
			errMsg:  "role_name",
		},
		{
			name: "valid oidc_federation config",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"jwt_mount":     "jwt",
				"audience":      "https://vault.example.com/warden",
			},
			wantErr: false,
		},
		{
			name: "oidc_federation missing jwt_role",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
			},
			wantErr: true,
			errMsg:  "jwt_role",
		},
		{
			name: "oidc_federation rejects approle secret_id",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"secret_id":     "leftover",
			},
			wantErr: true,
			errMsg:  "must not be set for auth_method=oidc_federation",
		},
		{
			name: "approle rejects federation jwt_role",
			config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
				"jwt_role":      "warden-agents",
			},
			wantErr: true,
			errMsg:  "only valid for auth_method=oidc_federation",
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
	err := driver.Cleanup(context.TODO())
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
	err := driver.Revoke(context.TODO(), "")
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
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method 'invalid'")
}

func TestVaultDriver_MintCredential_StaticRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// static_aws without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-static-aws",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "static_aws",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")

	// static_apikey without kv2_mount should fail on missing fields
	spec2 := &credential.CredSpec{
		Name: "test-static-apikey",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"mint_method": "static_apikey",
		},
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")
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

	// static_aws without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-aws",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "static_aws",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
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
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_role is required")
}

func TestVaultDriver_FetchDynamicVaultToken_Metadata(t *testing.T) {
	tests := []struct {
		name            string
		entityID        string
		expectSubject   bool
		expectedSubject string
	}{
		{name: "with entity", entityID: "8d2c-entity-id", expectSubject: true, expectedSubject: "8d2c-entity-id"},
		{name: "no entity", entityID: "", expectSubject: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "hvs.secret-token",
						"accessor":       "hvs.accessor",
						"policies":       []string{"default", "ci-deploy"},
						"renewable":      true,
						"entity_id":      tt.entityID,
						"lease_duration": 3600,
					},
				})
			}))
			defer srv.Close()

			client, err := api.NewClient(&api.Config{Address: srv.URL})
			require.NoError(t, err)

			driver := &VaultDriver{
				vault: client,
				credSource: &credential.CredSource{
					Type:   credential.SourceTypeVault,
					Config: map[string]string{"vault_address": srv.URL},
				},
			}
			spec := &credential.CredSpec{
				Name: "test-token",
				Type: credential.TypeVaultToken,
				Config: map[string]string{
					"mint_method": "vault_token",
					"token_role":  "ci-deployer",
				},
			}

			rawData, metadata, _, leaseID, err := driver.fetchDynamicVaultToken(context.TODO(), client, spec)
			require.NoError(t, err)

			// Metadata carries non-secret subject identity only.
			assert.Equal(t, "ci-deployer", metadata["role"])
			if tt.expectSubject {
				assert.Equal(t, tt.expectedSubject, metadata["subject"])
			} else {
				assert.NotContains(t, metadata, "subject")
			}
			// Never leak token material into the clear-logged metadata map.
			for _, k := range []string{"token", "client_token", "accessor", "policies"} {
				assert.NotContains(t, metadata, k)
			}

			// Secret stays in rawData; the accessor is the lease ID.
			assert.Equal(t, "hvs.secret-token", rawData["token"])
			assert.Equal(t, "hvs.accessor", leaseID)
		})
	}
}

func TestVaultDriver_MintCredential_DynamicGCPRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// dynamic_gcp without gcp_mount should fail
	spec := &credential.CredSpec{
		Name: "test-gcp",
		Type: credential.TypeGCPAccessToken,
		Config: map[string]string{
			"mint_method": "dynamic_gcp",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gcp_mount and role_name are required")

	// dynamic_gcp with invalid role_type should fail
	spec2 := &credential.CredSpec{
		Name: "test-gcp-bad-type",
		Type: credential.TypeGCPAccessToken,
		Config: map[string]string{
			"mint_method": "dynamic_gcp",
			"gcp_mount":   "gcp",
			"role_name":   "my-role",
			"role_type":   "invalid",
		},
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported role_type")
}

func TestVaultDriver_MintCredential_DynamicIBMRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// dynamic_ibm without ibm_mount/role_name should fail before hitting Vault
	spec := &credential.CredSpec{
		Name: "test-ibm",
		Type: credential.TypeIBMCloudKeys,
		Config: map[string]string{
			"mint_method": "dynamic_ibm",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ibm_mount and role_name are required")
}

func TestVaultDriver_MintCredential_OAuth2Routing(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			},
		},
	}

	// oauth2 without oauth2_mount should fail
	spec := &credential.CredSpec{
		Name: "test-oauth2",
		Type: credential.TypeOAuthBearerToken,
		Config: map[string]string{
			"mint_method": "oauth2",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth2_mount and credential_name are required")
}

func TestVaultDriverFactory_InferCredentialType(t *testing.T) {
	factory := &VaultDriverFactory{}

	tests := []struct {
		name       string
		mintMethod string
		wantType   string
		wantErr    bool
	}{
		{"static_aws", "static_aws", credential.TypeAWSAccessKeys, false},
		{"dynamic_aws", "dynamic_aws", credential.TypeAWSAccessKeys, false},
		{"static_apikey", "static_apikey", credential.TypeAPIKey, false},
		{"dynamic_gcp", "dynamic_gcp", credential.TypeGCPAccessToken, false},
		{"dynamic_ibm", "dynamic_ibm", credential.TypeIBMCloudKeys, false},
		{"oauth2", "oauth2", credential.TypeOAuthBearerToken, false},
		{"vault_token", "vault_token", credential.TypeVaultToken, false},
		{"empty defaults to vault_token", "", credential.TypeVaultToken, false},
		{"unsupported", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credType, err := factory.InferCredentialType(map[string]string{"mint_method": tt.mintMethod})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantType, credType)
			}
		})
	}
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
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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

	err := driver.authenticate(context.TODO())
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
	err := driver.authenticate(context.TODO())
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

	_, _, _, err := driver.PrepareRotation(context.TODO())
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

	_, _, _, err := driver.PrepareRotation(context.TODO())
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
	err := driver.CleanupRotation(context.TODO(), map[string]string{
		"secret_id_accessor": "",
	})
	assert.NoError(t, err)

	// Missing key should also be a no-op
	err = driver.CleanupRotation(context.TODO(), map[string]string{})
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

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// federationDriver builds a VaultDriver whose client points at srv, configured as a
// keyless oidc_federation source.
func federationDriver(t *testing.T, srvURL string) *VaultDriver {
	t.Helper()
	client, err := api.NewClient(&api.Config{Address: srvURL})
	require.NoError(t, err)
	return &VaultDriver{
		vault: client,
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"vault_address": srvURL,
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"jwt_mount":     "jwt",
				"audience":      "https://vault.example.com/warden",
			},
		},
	}
}

func verifiedInputs() *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:       "eyJhbGciOiJSUzI1NiJ9.assertion.sig",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
	}
}

func TestVaultDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "vault_token"}}

	// Non-federation source rejects the exchange path.
	static := &VaultDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeVault,
		Config: map[string]string{"auth_method": "approle"},
	}}
	_, _, _, _, err := static.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires auth_method=oidc_federation")

	fed := &VaultDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeVault,
		Config: map[string]string{"auth_method": "oidc_federation", "jwt_role": "warden-agents"},
	}}

	// Empty subject token.
	_, _, _, _, err = fed.MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no subject token")

	// Unverified subject origin.
	_, _, _, _, err = fed.MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{
		SubjectToken:       "x",
		SubjectTokenOrigin: credential.ExchangeOriginUnverified,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verified subject")
}

func TestVaultDriver_MintCredentialWithExchange_VaultToken(t *testing.T) {
	// An operator's env token must never be sent on the login request.
	t.Setenv("VAULT_TOKEN", "env-operator-token")

	var loginBody map[string]interface{}
	var loginTokenHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/jwt/login" {
			loginTokenHeader = r.Header.Get("X-Vault-Token")
			_ = json.NewDecoder(r.Body).Decode(&loginBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "hvs.childtoken",
					"accessor":       "acc-123",
					"lease_duration": 900,
					"policies":       []string{"default", "agent-readonly"},
					"renewable":      true,
					"entity_id":      "ent-1",
				},
			})
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{Name: "vault-session", Config: map[string]string{"mint_method": "vault_token"}}

	rawData, metadata, ttl, leaseID, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.NoError(t, err)

	// The assertion was posted with the role and jwt.
	assert.Equal(t, "warden-agents", loginBody["role"])
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.assertion.sig", loginBody["jwt"])

	// The login token itself is vended.
	assert.Equal(t, "hvs.childtoken", rawData["token"])
	assert.Equal(t, "hvs.childtoken", rawData["client_token"])
	assert.Equal(t, "acc-123", rawData["accessor"])
	assert.Equal(t, 900*time.Second, ttl)
	assert.Equal(t, "warden-agents", metadata["role"])
	assert.Equal(t, "ent-1", metadata["subject"])

	// Keyless: no revoke-on-demand — leaseID is always empty.
	assert.Empty(t, leaseID)

	// The login request carried no token — the operator's env VAULT_TOKEN was dropped
	// (SetToken("") on the per-request clone), so it is never presented to Vault.
	assert.Empty(t, loginTokenHeader)
	// The per-request login token never leaks onto the shared driver client (which
	// keeps whatever it had — here the env token — untouched by the exchange).
	assert.NotEqual(t, "hvs.childtoken", driver.vault.Token())
}

func TestVaultDriver_MintCredentialWithExchange_DynamicAWS_CapsTTLAndEmptyLease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "hvs.childtoken",
					"accessor":       "acc-123",
					"lease_duration": 300, // login token shorter than the AWS lease
				},
			})
		case "/v1/aws/creds/dev-role":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"lease_id":       "aws/creds/dev-role/abc123",
				"lease_duration": 3600, // longer than the login token
				"data":           map[string]interface{}{"access_key": "AKIA", "secret_key": "sk"},
			})
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{
		Name: "aws-dynamic",
		Config: map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "dev-role",
		},
	}

	rawData, _, ttl, leaseID, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.NoError(t, err)
	assert.Equal(t, "AKIA", rawData["access_key"])
	// TTL capped to the login token's 300s (a child lease cannot outlive its parent).
	assert.Equal(t, 300*time.Second, ttl)
	// leaseID empty: the dynamic lease is revoked when the parent login token expires.
	assert.Empty(t, leaseID)
}

func TestVaultDriver_MintCredentialWithExchange_StaticKV_EmptyLease(t *testing.T) {
	var revokeSelfToken string
	revokedSelf := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "hvs.childtoken", "accessor": "acc-123", "lease_duration": 900},
			})
		case "/v1/secret/data/prod/aws":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     map[string]interface{}{"access_key_id": "AKIA", "secret_access_key": "sk"},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		case "/v1/auth/token/revoke-self":
			// The transient login token revokes ITSELF (default policy grants
			// revoke-self, not revoke-accessor), so the request carries the login token.
			revokedSelf = true
			revokeSelfToken = r.Header.Get("X-Vault-Token")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{
		Name: "kv-static",
		Config: map[string]string{
			"mint_method": "static_aws",
			"kv2_mount":   "secret",
			"secret_path": "prod/aws",
		},
	}

	rawData, _, ttl, leaseID, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.NoError(t, err)
	assert.Equal(t, "AKIA", rawData["access_key_id"])
	// Static read: no lease, and the empty leaseID keeps it out of the revoke path.
	assert.Equal(t, time.Duration(0), ttl)
	assert.Empty(t, leaseID)
	// The transient login token is best-effort revoked (via revoke-self) after the read.
	assert.True(t, revokedSelf)
	assert.Equal(t, "hvs.childtoken", revokeSelfToken)
}

func TestVaultDriver_MintCredentialWithExchange_StaticKV_BatchTokenSkipsRevoke(t *testing.T) {
	revokeAttempted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			// A JWT role configured token_type=batch issues an hvb.-prefixed token.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "hvb.batchtoken", "accessor": "", "lease_duration": 900},
			})
		case "/v1/secret/data/prod/aws":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     map[string]interface{}{"access_key_id": "AKIA", "secret_access_key": "sk"},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		case "/v1/auth/token/revoke-self":
			revokeAttempted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{
		Name: "kv-static",
		Config: map[string]string{
			"mint_method": "static_aws",
			"kv2_mount":   "secret",
			"secret_path": "prod/aws",
		},
	}

	rawData, _, _, leaseID, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.NoError(t, err)
	assert.Equal(t, "AKIA", rawData["access_key_id"])
	assert.Empty(t, leaseID)
	// A batch token cannot be revoked, so no revoke-self call is attempted.
	assert.False(t, revokeAttempted)
}

func TestVaultDriver_MintCredentialWithExchange_MissingJWTRole(t *testing.T) {
	driver := &VaultDriver{
		vault: func() *api.Client { c, _ := api.NewClient(&api.Config{Address: "http://127.0.0.1:8200"}); return c }(),
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: map[string]string{
				"auth_method": "oidc_federation",
				// jwt_role deliberately omitted
			},
		},
	}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "vault_token"}}
	_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwt_role is required")
}

func TestVaultDriver_MintCredentialWithExchange_UnsupportedMintMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/jwt/login" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "hvs.childtoken", "accessor": "acc-123", "lease_duration": 900},
			})
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "not_a_method"}}
	_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")
}
