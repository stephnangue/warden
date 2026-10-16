package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
		config  credential.Config
		wantErr bool
		errMsg  string
	}{
		{
			// Without one the client would log in with the server environment's
			// VAULT_TOKEN, sent to whatever vault_address this config names.
			name: "auth_method is required",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
			}),
			wantErr: true,
			errMsg:  "auth_method",
		},
		{
			name: "http vault_address is refused without tls_skip_verify",
			config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
			}),
			wantErr: true,
			errMsg:  "https://",
		},
		{
			name: "http vault_address is accepted with tls_skip_verify",
			config: credential.NewConfig(map[string]string{
				"vault_address":   "http://127.0.0.1:8200",
				"tls_skip_verify": "true",
				"auth_method":     "oidc_federation",
				"jwt_role":        "warden-agents",
			}),
			wantErr: false,
		},
		{
			name: "ca_data must be base64 PEM",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"ca_data":       "not base64!",
			}),
			wantErr: true,
			errMsg:  "ca_data",
		},
		{
			name: "valid config with approle auth",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
			}),
			wantErr: false,
		},
		{
			name: "valid config with namespace",
			config: credential.NewConfig(map[string]string{
				"vault_address":   "https://127.0.0.1:8200",
				"vault_namespace": "admin/team",
				"auth_method":     "oidc_federation",
				"jwt_role":        "warden-agents",
			}),
			wantErr: false,
		},
		{
			name:    "missing vault_address",
			config:  credential.NewConfig(map[string]string{}),
			wantErr: true,
			errMsg:  "vault_address",
		},
		{
			name: "unsupported auth_method",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "userpass",
			}),
			wantErr: true,
			errMsg:  "must be one of",
		},
		{
			name: "approle missing role_id",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
			}),
			wantErr: true,
			errMsg:  "role_id",
		},
		{
			name: "approle missing secret_id",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
			}),
			wantErr: true,
			errMsg:  "secret_id",
		},
		{
			name: "approle missing approle_mount",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"role_name":     "test-role",
			}),
			wantErr: true,
			errMsg:  "approle_mount",
		},
		{
			name: "approle missing role_name",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
			}),
			wantErr: true,
			errMsg:  "role_name",
		},
		{
			name: "valid oidc_federation config",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"jwt_mount":     "jwt",
				"audience":      "https://vault.example.com/warden",
			}),
			wantErr: false,
		},
		{
			name: "oidc_federation missing jwt_role",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
			}),
			wantErr: true,
			errMsg:  "jwt_role",
		},
		{
			name: "oidc_federation rejects approle secret_id",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"secret_id":     "leftover",
			}),
			wantErr: true,
			errMsg:  "must not be set for auth_method=oidc_federation",
		},
		{
			name: "approle rejects federation jwt_role",
			config: credential.NewConfig(map[string]string{
				"vault_address": "https://127.0.0.1:8200",
				"auth_method":   "approle",
				"role_id":       "test-role-id",
				"secret_id":     "test-secret-id",
				"approle_mount": "warden_approle",
				"role_name":     "test-role",
				"jwt_role":      "warden-agents",
			}),
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
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	assert.Equal(t, credential.SourceTypeVault, driver.Type())
}

func TestVaultDriver_Cleanup(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	err := driver.Cleanup(context.TODO())
	assert.NoError(t, err)
}

func TestVaultDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	// Empty lease ID should be a no-op
	err := driver.Revoke(context.TODO(), "")
	assert.NoError(t, err)
}

func TestVaultDriver_SupportsRotation(t *testing.T) {
	tests := []struct {
		name       string
		config     credential.Config
		wantResult bool
	}{
		{
			name: "approle with role_name supports rotation",
			config: credential.NewConfig(map[string]string{
				"auth_method": "approle",
				"role_name":   "test-role",
			}),
			wantResult: true,
		},
		{
			name: "approle without role_name does not support rotation",
			config: credential.NewConfig(map[string]string{
				"auth_method": "approle",
			}),
			wantResult: false,
		},
		{
			name: "no auth_method does not support rotation",
			config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
			wantResult: false,
		},
		{
			name:       "empty config does not support rotation",
			config:     credential.NewConfig(map[string]string{}),
			wantResult: false,
		},
		{
			name: "token auth does not support rotation",
			config: credential.NewConfig(map[string]string{
				"auth_method": "token",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// Missing mint_method
	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method ''")

	// Invalid mint_method
	spec2 := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "invalid",
		}),
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method 'invalid'")
}

func TestVaultDriver_MintCredential_StaticRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// static_aws without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-static-aws",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "static_aws",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")

	// static_apikey without kv2_mount should fail on missing fields
	spec2 := &credential.CredSpec{
		Name: "test-static-apikey",
		Type: credential.TypeAPIKey,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "static_apikey",
		}),
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")
}

func TestVaultDriver_MintCredential_AWSRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// static_aws without kv2_mount should fail on missing fields
	spec := &credential.CredSpec{
		Name: "test-aws",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "static_aws",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kv2_mount and secret_path are required")

	// dynamic_aws without role_name should fail on validation
	spec2 := &credential.CredSpec{
		Name: "test-aws-dynamic",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
		}),
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws_mount and role_name are required")
}

func TestVaultDriver_MintCredential_VaultTokenRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// vault_token without token_role should fail with validation error
	spec := &credential.CredSpec{
		Name: "test-token",
		Type: credential.TypeVaultToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "vault_token",
		}),
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
					Config: credential.NewConfig(map[string]string{"vault_address": srv.URL}),
				},
			}
			spec := &credential.CredSpec{
				Name: "test-token",
				Type: credential.TypeVaultToken,
				Config: credential.NewConfig(map[string]string{
					"mint_method": "vault_token",
					"token_role":  "ci-deployer",
				}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// dynamic_gcp without gcp_mount should fail
	spec := &credential.CredSpec{
		Name: "test-gcp",
		Type: credential.TypeGCPAccessToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_gcp",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gcp_mount and role_name are required")

	// dynamic_gcp with invalid role_type should fail
	spec2 := &credential.CredSpec{
		Name: "test-gcp-bad-type",
		Type: credential.TypeGCPAccessToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_gcp",
			"gcp_mount":   "gcp",
			"role_name":   "my-role",
			"role_type":   "invalid",
		}),
	}
	_, _, _, _, err = driver.MintCredential(context.TODO(), spec2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported role_type")
}

func TestVaultDriver_MintCredential_DynamicIBMRouting(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// dynamic_ibm without ibm_mount/role_name should fail before hitting Vault
	spec := &credential.CredSpec{
		Name: "test-ibm",
		Type: credential.TypeIBMCloudKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_ibm",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ibm_mount and role_name are required")
}

func TestVaultDriver_MintCredential_OAuth2Routing(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	// oauth2 without oauth2_mount should fail
	spec := &credential.CredSpec{
		Name: "test-oauth2",
		Type: credential.TypeOAuthBearerToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "oauth2",
		}),
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
		{"kv2_read", "kv2_read", credential.TypeKeyValue, false},
		{"dynamic_gcp", "dynamic_gcp", credential.TypeGCPAccessToken, false},
		{"dynamic_ibm", "dynamic_ibm", credential.TypeIBMCloudKeys, false},
		{"oauth2", "oauth2", credential.TypeOAuthBearerToken, false},
		{"vault_token", "vault_token", credential.TypeVaultToken, false},
		{"empty defaults to vault_token", "", credential.TypeVaultToken, false},
		{"unsupported", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credType, err := factory.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": tt.mintMethod}))
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name: "test-aws-bad-ttl",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "not-a-duration",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl format")
}

func TestVaultDriver_FetchDynamicVaultToken_InvalidTTL(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name: "test-token-bad-ttl",
		Type: credential.TypeVaultToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "bad",
		}),
	}
	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl format")
}

func TestVaultDriver_Authenticate_UnsupportedMethod(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"auth_method": "userpass",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
				"auth_method":   "approle",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-aws-min-ttl",
		Type:   credential.TypeAWSAccessKeys,
		MinTTL: 2 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestVaultDriver_FetchDynamicAWSCreds_TTLExceedsMaximum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-aws-max-ttl",
		Type:   credential.TypeAWSAccessKeys,
		MaxTTL: 1 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestVaultDriver_FetchDynamicVaultToken_TTLBelowMinimum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-token-min-ttl",
		Type:   credential.TypeVaultToken,
		MinTTL: 2 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestVaultDriver_FetchDynamicVaultToken_TTLExceedsMaximum(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"vault_address": "http://127.0.0.1:8200",
			}),
		},
	}

	spec := &credential.CredSpec{
		Name:   "test-token-max-ttl",
		Type:   credential.TypeVaultToken,
		MaxTTL: 1 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "vault_token",
			"token_role":  "test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		}),
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
			Config: credential.NewConfig(map[string]string{
				"vault_address": srvURL,
				"auth_method":   "oidc_federation",
				"jwt_role":      "warden-agents",
				"jwt_mount":     "jwt",
				"audience":      "https://vault.example.com/warden",
			}),
		},
	}
}

func verifiedInputs() *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken:     "eyJhbGciOiJSUzI1NiJ9.assertion.sig",
		SubjectTokenType: credential.TokenTypeJWT,
	}
}

func TestVaultDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "vault_token"})}

	// Non-federation source rejects the exchange path.
	static := &VaultDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeVault,
		Config: credential.NewConfig(map[string]string{"auth_method": "approle"}),
	}}
	_, _, _, _, err := static.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires auth_method=oidc_federation")

	fed := &VaultDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeVault,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "jwt_role": "warden-agents"}),
	}}

	// Empty subject token.
	_, _, _, _, err = fed.MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no subject token")

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
	spec := &credential.CredSpec{Name: "vault-session", Config: credential.NewConfig(map[string]string{"mint_method": "vault_token"})}

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
		Config: credential.NewConfig(map[string]string{
			"mint_method": "dynamic_aws",
			"aws_mount":   "aws",
			"role_name":   "dev-role",
		}),
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
		Config: credential.NewConfig(map[string]string{
			"mint_method": "static_aws",
			"kv2_mount":   "secret",
			"secret_path": "prod/aws",
		}),
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
		Config: credential.NewConfig(map[string]string{
			"mint_method": "static_aws",
			"kv2_mount":   "secret",
			"secret_path": "prod/aws",
		}),
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
			Config: credential.NewConfig(map[string]string{
				"auth_method": "oidc_federation",
				// jwt_role deliberately omitted
			}),
		},
	}
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "vault_token"})}
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
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "not_a_method"})}
	_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")
}

// credential_name from the caller's projected claims — one spec, per-user OpenBao OAuth
// engine credentials (scoped by a templated policy on oauth2/creds/<sub>).
func TestVaultDriver_OAuth2_PerUserCredentialName(t *testing.T) {
	future := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	var credsPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "hvs.child", "accessor": "acc", "lease_duration": 900},
			})
		default: // the oauth2/creds/<name> read
			credsPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"access_token": "at-alice", "expire_time": future},
			})
		}
	}))
	defer srv.Close()

	driver := federationDriver(t, srv.URL)
	spec := &credential.CredSpec{Name: "gh-oauth", Config: credential.NewConfig(map[string]string{
		"mint_method": "oauth2", "oauth2_mount": "oauth2", "credential_name": "{{user.sub}}",
	})}
	inputs := &credential.ExchangeInputs{
		SubjectToken:     "eyJhbGciOiJSUzI1NiJ9.assertion.sig",
		SubjectTokenType: credential.TokenTypeJWT,
		UserClaims:       map[string]string{"sub": "alice"},
	}

	rawData, _, ttl, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "/v1/oauth2/creds/alice", credsPath, "credential_name resolved to the caller's own sub")
	assert.Equal(t, "at-alice", rawData["access_token"])
	assert.Greater(t, ttl, time.Duration(0), "TTL derived from expire_time")
}

// A templated credential_name on the non-federation path (no user claims) fails closed.
func TestVaultDriver_OAuth2_TemplatedNameFailsClosedWithoutClaims(t *testing.T) {
	driver := &VaultDriver{credSource: &credential.CredSource{Type: credential.SourceTypeVault, Config: credential.NewConfig(map[string]string{})}}
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{
		"mint_method": "oauth2", "oauth2_mount": "oauth2", "credential_name": "{{user.sub}}",
	})}
	_, _, _, _, err := driver.fetchOAuth2Creds(context.TODO(), nil, spec, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_name")
	assert.Contains(t, err.Error(), "absent")
	// A spec that cannot project claims is an operator config error. Carrying
	// the missing-user sentinel here would turn it into a 401 challenge and send
	// the caller into an OAuth loop that cannot fix a spec.
	assert.NotErrorIs(t, err, credential.ErrUserRequired)
}

// staticKVServer serves one multi-key secret, recording the version query the driver
// sent so a pinned read can be told apart from a current-revision one.
func staticKVServer(t *testing.T, gotVersion *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "hvs.childtoken", "accessor": "acc-123", "lease_duration": 900},
			})
		case "/v1/secret/data/team/shared":
			*gotVersion = r.URL.Query().Get("version")
			if *gotVersion == "99" {
				// A destroyed or never-written revision comes back as a 404 with
				// no body, which the client surfaces as "secret not found".
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
				return
			}
			if *gotVersion == "42" {
				// A soft-deleted revision answers 200 with its metadata and a null
				// data block, so the read succeeds and carries nothing.
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"data": nil,
						"metadata": map[string]interface{}{
							"version":       42,
							"deletion_time": "2026-01-02T03:04:05Z",
						},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"token":       "sk-abc123",
						"accessKeyId": "AKIA123",
						"admin_token": "root-secret",
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

// A static KV read projects through json_key_map: the spec selects which of the
// stored secret's fields it vends and renames them to what the credential type
// expects. Fields the spec does not name are not vended at all. The same body backs
// static_aws, static_apikey and kv2_read, so all three are covered here.
func TestVaultDriver_StaticKVSecret_JSONKeyMap(t *testing.T) {
	tests := []struct {
		name       string
		mintMethod string
		keyMap     string
		expected   map[string]interface{}
	}{
		{
			name:       "kv2_read selects one field out of a shared path",
			mintMethod: "kv2_read",
			keyMap:     "token=slack_token",
			expected:   map[string]interface{}{"slack_token": "sk-abc123"},
		},
		{
			name:       "static_apikey renames into the type's primary field",
			mintMethod: "static_apikey",
			keyMap:     "token=api_key",
			expected:   map[string]interface{}{"api_key": "sk-abc123"},
		},
		{
			name:       "static_aws renames into the type's fields",
			mintMethod: "static_aws",
			keyMap:     "accessKeyId=access_key_id,token=secret_access_key",
			expected:   map[string]interface{}{"access_key_id": "AKIA123", "secret_access_key": "sk-abc123"},
		},
		{
			name:       "no selection vends the stored payload verbatim",
			mintMethod: "kv2_read",
			keyMap:     "",
			expected: map[string]interface{}{
				"token":       "sk-abc123",
				"accessKeyId": "AKIA123",
				"admin_token": "root-secret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotVersion string
			srv := staticKVServer(t, &gotVersion)
			defer srv.Close()

			driver := federationDriver(t, srv.URL)
			spec := &credential.CredSpec{
				Name: "kv-mapped",
				Config: credential.NewConfig(map[string]string{
					"mint_method":  tt.mintMethod,
					"kv2_mount":    "secret",
					"secret_path":  "team/shared",
					"json_key_map": tt.keyMap,
				}),
			}

			rawData, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
			require.NoError(t, err)
			assert.Equal(t, tt.expected, rawData)
			// Unpinned specs read the current revision.
			assert.Empty(t, gotVersion)
		})
	}
}

// A spec may pin a numbered revision of the stored secret; without one it reads the
// current revision.
func TestVaultDriver_StaticKVSecret_Version(t *testing.T) {
	t.Run("pinned revision is requested", func(t *testing.T) {
		var gotVersion string
		srv := staticKVServer(t, &gotVersion)
		defer srv.Close()

		driver := federationDriver(t, srv.URL)
		spec := &credential.CredSpec{
			Name: "kv-pinned",
			Config: credential.NewConfig(map[string]string{
				"mint_method":    "kv2_read",
				"kv2_mount":      "secret",
				"secret_path":    "team/shared",
				"secret_version": "3",
			}),
		}

		rawData, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
		require.NoError(t, err)
		assert.Equal(t, "3", gotVersion)
		assert.Equal(t, "sk-abc123", rawData["token"])
	})

	t.Run("a missing revision surfaces the error", func(t *testing.T) {
		var gotVersion string
		srv := staticKVServer(t, &gotVersion)
		defer srv.Close()

		driver := federationDriver(t, srv.URL)
		spec := &credential.CredSpec{
			Name: "kv-pinned",
			Config: credential.NewConfig(map[string]string{
				"mint_method":    "kv2_read",
				"kv2_mount":      "secret",
				"secret_path":    "team/shared",
				"secret_version": "99",
			}),
		}

		_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version 99")
	})

	// A soft-deleted revision reads back successfully with no data, so the failure
	// has to name the revision — the path it was read from is fine, and pointing at
	// the path sends the operator looking in the wrong place.
	t.Run("a soft-deleted revision names the revision, not the path", func(t *testing.T) {
		var gotVersion string
		srv := staticKVServer(t, &gotVersion)
		defer srv.Close()

		driver := federationDriver(t, srv.URL)
		spec := &credential.CredSpec{
			Name: "kv-pinned",
			Config: credential.NewConfig(map[string]string{
				"mint_method":    "kv2_read",
				"kv2_mount":      "secret",
				"secret_path":    "team/shared",
				"secret_version": "42",
			}),
		}

		_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(), spec, verifiedInputs())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version 42")
		assert.Contains(t, err.Error(), "deleted")
	})
}

// vaultEnvRecorder is a Vault stand-in that records the headers of the last request
// and answers a JWT login and any read.
type vaultEnvRecorder struct {
	mu   sync.Mutex
	last http.Header
}

func (v *vaultEnvRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.last = r.Header.Clone()
		v.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = w.Write([]byte(`{"auth":{"client_token":"s.login","accessor":"acc","lease_duration":60}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	})
}

func (v *vaultEnvRecorder) lastHeader() http.Header {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.last
}

// setVaultEnvironment fills every VAULT_* variable that could steer, widen or
// authenticate a client built from the process environment.
func setVaultEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("VAULT_TOKEN", "hvs.server-token")
	t.Setenv("VAULT_NAMESPACE", "tenant-from-the-environment")
	t.Setenv("VAULT_HEADERS", `{"X-Leak":"from-the-environment"}`)
	t.Setenv("VAULT_AGENT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_WRAP_TTL", "5m")
	t.Setenv("VAULT_SKIP_VERIFY", "true")
}

func caDataFor(srv *httptest.Server) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// A source's Vault client is built from the source's config alone. The server
// process's VAULT_* environment would otherwise send the server's own token, and its
// headers and namespace, to the vault_address the source's author chose, steer the
// request to an agent address, wrap the response, and switch TLS verification off.
func TestNewVaultAPIClient_IgnoresTheServerEnvironment(t *testing.T) {
	setVaultEnvironment(t)
	rec := &vaultEnvRecorder{}
	srv := httptest.NewTLSServer(rec.handler())
	t.Cleanup(srv.Close)

	federated := func(extra map[string]string) credential.Config {
		m := map[string]string{
			"vault_address": srv.URL,
			"auth_method":   vaultAuthMethodOIDCFederation,
			"jwt_role":      "agents",
		}
		for k, v := range extra {
			m[k] = v
		}
		return credential.NewConfig(m)
	}

	t.Run("VAULT_SKIP_VERIFY does not switch verification off", func(t *testing.T) {
		client, err := newVaultAPIClient(federated(nil))
		require.NoError(t, err)
		_, err = client.Logical().ReadWithContext(context.Background(), "secret/x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate")
	})

	t.Run("ca_data is honoured and nothing from the environment is sent", func(t *testing.T) {
		client, err := newVaultAPIClient(federated(map[string]string{"ca_data": caDataFor(srv)}))
		require.NoError(t, err)
		_, err = client.Logical().ReadWithContext(context.Background(), "secret/x")
		require.NoError(t, err, "the request must reach vault_address, not VAULT_AGENT_ADDR")

		got := rec.lastHeader()
		assert.Empty(t, got.Get("X-Vault-Token"), "the server's VAULT_TOKEN left the process")
		assert.Empty(t, got.Get("X-Vault-Namespace"))
		assert.Empty(t, got.Get("X-Leak"))
		assert.Empty(t, got.Get("X-Vault-Wrap-TTL"))
		assert.Equal(t, "true", got.Get(api.RequestHeaderName))
	})

	t.Run("vault_namespace still applies", func(t *testing.T) {
		client, err := newVaultAPIClient(federated(map[string]string{"ca_data": caDataFor(srv), "vault_namespace": "team"}))
		require.NoError(t, err)
		_, err = client.Logical().ReadWithContext(context.Background(), "secret/x")
		require.NoError(t, err)
		assert.Equal(t, "team", rec.lastHeader().Get("X-Vault-Namespace"))
	})

	t.Run("the per-request JWT login clone stays isolated", func(t *testing.T) {
		raw, err := (&VaultDriverFactory{}).Create(federated(map[string]string{"ca_data": caDataFor(srv)}), testGatedLogger())
		require.NoError(t, err)
		d := raw.(*VaultDriver)
		_, _, err = d.loginViaJWT(context.Background(), &credential.CredSpec{Config: credential.NewConfig(nil)}, "assertion")
		require.NoError(t, err)

		got := rec.lastHeader()
		assert.Empty(t, got.Get("X-Vault-Token"))
		assert.Empty(t, got.Get("X-Vault-Wrap-TTL"), "a clone does not inherit the pinned wrapping lookup")
		assert.Empty(t, got.Get("X-Leak"))
	})
}

// A source stored before auth_method became required has no credential but the
// environment's token, so it keeps the environment-derived client and keeps minting.
// Writes refuse such a source, so no new one can point that token anywhere.
func TestNewVaultAPIClient_LegacySourceKeepsTheEnvironmentToken(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "hvs.server-token")
	rec := &vaultEnvRecorder{}
	srv := httptest.NewServer(rec.handler())
	t.Cleanup(srv.Close)

	client, err := newVaultAPIClient(credential.NewConfig(map[string]string{"vault_address": srv.URL}))
	require.NoError(t, err)
	_, err = client.Logical().ReadWithContext(context.Background(), "secret/x")
	require.NoError(t, err)
	assert.Equal(t, "hvs.server-token", rec.lastHeader().Get("X-Vault-Token"))
}
