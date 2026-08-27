package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
)

const testAudGCPProvider = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/w"

// TestDeriveAssertionAudience covers the cross-source dispatch and the invariant
// that an audience is only ever derived for an oidc_federation source.
func TestDeriveAssertionAudience(t *testing.T) {
	cases := []struct {
		name       string
		sourceType string
		sourceCfg  map[string]string
		wantAud    string
		wantOK     bool
	}{
		{
			name:       "gcp federation derives https audience from provider",
			sourceType: credential.SourceTypeGCP,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": testAudGCPProvider},
			wantAud:    "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/w",
			wantOK:     true,
		},
		{
			name:       "gcp without provider derives nothing",
			sourceType: credential.SourceTypeGCP,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation"},
			wantOK:     false,
		},
		{
			name:       "aws federation default audience",
			sourceType: credential.SourceTypeAWS,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation"},
			wantAud:    "sts.amazonaws.com",
			wantOK:     true,
		},
		{
			name:       "aws federation explicit override",
			sourceType: credential.SourceTypeAWS,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation", "audience": "custom-client-id"},
			wantAud:    "custom-client-id",
			wantOK:     true,
		},
		{
			name:       "aws static derives nothing",
			sourceType: credential.SourceTypeAWS,
			sourceCfg:  map[string]string{"auth_method": "static"},
			wantOK:     false,
		},
		{
			name:       "azure federation default audience",
			sourceType: credential.SourceTypeAzure,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation"},
			wantAud:    "api://AzureADTokenExchange",
			wantOK:     true,
		},
		{
			name:       "azure static derives nothing",
			sourceType: credential.SourceTypeAzure,
			sourceCfg:  map[string]string{"auth_method": "static"},
			wantOK:     false,
		},
		{
			name:       "vault federation derives explicit audience",
			sourceType: credential.SourceTypeVault,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation", "audience": "https://vault.example.com/warden"},
			wantAud:    "https://vault.example.com/warden",
			wantOK:     true,
		},
		{
			name:       "vault federation without audience derives nothing (no default)",
			sourceType: credential.SourceTypeVault,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation"},
			wantOK:     false,
		},
		{
			name:       "vault approle derives nothing even with audience",
			sourceType: credential.SourceTypeVault,
			sourceCfg:  map[string]string{"auth_method": "approle", "audience": "https://vault.example.com/warden"},
			wantOK:     false,
		},
		{
			name:       "kubernetes federation derives explicit audience",
			sourceType: credential.SourceTypeKubernetes,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation", "audience": "https://kubernetes.example.com"},
			wantAud:    "https://kubernetes.example.com",
			wantOK:     true,
		},
		{
			name:       "kubernetes federation without audience derives nothing (no default)",
			sourceType: credential.SourceTypeKubernetes,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation"},
			wantOK:     false,
		},
		{
			name:       "kubernetes static derives nothing even with audience",
			sourceType: credential.SourceTypeKubernetes,
			sourceCfg:  map[string]string{"auth_method": "static", "audience": "https://kubernetes.example.com"},
			wantOK:     false,
		},
		{
			name:       "kubernetes absent auth_method derives nothing",
			sourceType: credential.SourceTypeKubernetes,
			sourceCfg:  map[string]string{"audience": "https://kubernetes.example.com"},
			wantOK:     false,
		},
		{
			name:       "unknown source type derives nothing",
			sourceType: credential.SourceTypeGitHub,
			sourceCfg:  map[string]string{"auth_method": "oidc_federation", "audience": "x"},
			wantOK:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aud, ok := DeriveAssertionAudience(tc.sourceType, tc.sourceCfg, map[string]string{})
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantAud, aud)
			} else {
				assert.Empty(t, aud)
			}
		})
	}
}

// TestDeriveAssertionResource covers the cross-source dispatch for the resource claim.
func TestDeriveAssertionResource(t *testing.T) {
	tests := []struct {
		name       string
		sourceType string
		sourceCfg  map[string]string
		specCfg    map[string]string
		want       string
		wantOK     bool
	}{
		{
			name:       "aws secrets_manager names the secret",
			sourceType: credential.SourceTypeAWS,
			specCfg:    map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/db"},
			want:       "aws-secretsmanager:prod/db",
			wantOK:     true,
		},
		{
			name:       "aws secrets_manager with ARN secret_id carried verbatim after prefix",
			sourceType: credential.SourceTypeAWS,
			specCfg:    map[string]string{"mint_method": "secrets_manager", "secret_id": "arn:aws:secretsmanager:us-east-1:1234:secret:prod/db-AbCdEf"},
			want:       "aws-secretsmanager:arn:aws:secretsmanager:us-east-1:1234:secret:prod/db-AbCdEf",
			wantOK:     true,
		},
		{
			name:       "aws sts_assume_role names the role",
			sourceType: credential.SourceTypeAWS,
			specCfg:    map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1234:role/reader"},
			want:       "aws-iam:arn:aws:iam::1234:role/reader",
			wantOK:     true,
		},
		{
			name:       "aws unset mint_method has no single federated target",
			sourceType: credential.SourceTypeAWS,
			specCfg:    map[string]string{"role_arn": "arn:aws:iam::1234:role/reader"},
			wantOK:     false,
		},
		{
			name:       "aws secrets_manager without secret_id omits",
			sourceType: credential.SourceTypeAWS,
			specCfg:    map[string]string{"mint_method": "secrets_manager"},
			wantOK:     false,
		},
		{
			name:       "azure bearer_token defaults to management API",
			sourceType: credential.SourceTypeAzure,
			specCfg:    map[string]string{"mint_method": "bearer_token"},
			want:       "azure:https://management.azure.com/",
			wantOK:     true,
		},
		{
			name:       "azure bearer_token honors resource_uri",
			sourceType: credential.SourceTypeAzure,
			specCfg:    map[string]string{"resource_uri": "https://vault.azure.net/"},
			want:       "azure:https://vault.azure.net/",
			wantOK:     true,
		},
		{
			name:       "azure non-bearer mint_method omits",
			sourceType: credential.SourceTypeAzure,
			specCfg:    map[string]string{"mint_method": "key_vault_secret"},
			wantOK:     false,
		},
		{
			name:       "gcp impersonation names the target service account",
			sourceType: credential.SourceTypeGCP,
			sourceCfg:  map[string]string{"workload_identity_provider": testAudGCPProvider},
			specCfg:    map[string]string{"mint_method": "impersonated_access_token", "target_service_account": "sa@p.iam.gserviceaccount.com"},
			want:       "gcp-iam:sa@p.iam.gserviceaccount.com",
			wantOK:     true,
		},
		{
			name:       "gcp federated names the provider from source config",
			sourceType: credential.SourceTypeGCP,
			sourceCfg:  map[string]string{"workload_identity_provider": testAudGCPProvider},
			specCfg:    map[string]string{"mint_method": "access_token"},
			want:       "gcp-wif:" + testAudGCPProvider,
			wantOK:     true,
		},
		{
			name:       "gcp impersonation without target omits",
			sourceType: credential.SourceTypeGCP,
			specCfg:    map[string]string{"mint_method": "impersonated_access_token"},
			wantOK:     false,
		},
		{
			name:       "kubernetes names the target service account",
			sourceType: credential.SourceTypeKubernetes,
			specCfg:    map[string]string{"namespace": "prod", "service_account": "payments"},
			want:       "prod/payments",
			wantOK:     true,
		},
		{
			name:       "kubernetes without namespace omits",
			sourceType: credential.SourceTypeKubernetes,
			specCfg:    map[string]string{"service_account": "payments"},
			wantOK:     false,
		},
		{
			name:       "kubernetes without service_account omits",
			sourceType: credential.SourceTypeKubernetes,
			specCfg:    map[string]string{"namespace": "prod"},
			wantOK:     false,
		},
		{
			name:       "token_exchange single resource from spec",
			sourceType: credential.SourceTypeTokenExchange,
			specCfg:    map[string]string{"resources": "https://api.internal.example.com"},
			want:       "oauth-resource:https://api.internal.example.com",
			wantOK:     true,
		},
		{
			name:       "token_exchange single resource falls back to source config",
			sourceType: credential.SourceTypeTokenExchange,
			sourceCfg:  map[string]string{"resources": "https://api.internal.example.com"},
			specCfg:    map[string]string{},
			want:       "oauth-resource:https://api.internal.example.com",
			wantOK:     true,
		},
		{
			name:       "token_exchange multiple resources omit (scalar claim can't hold a set)",
			sourceType: credential.SourceTypeTokenExchange,
			specCfg:    map[string]string{"resources": "https://api.example.com https://reports.example.com"},
			wantOK:     false,
		},
		{
			name:       "token_exchange no resources omits",
			sourceType: credential.SourceTypeTokenExchange,
			specCfg:    map[string]string{},
			wantOK:     false,
		},
		{
			name:       "vault_token names the effective jwt_role from spec override",
			sourceType: credential.SourceTypeVault,
			sourceCfg:  map[string]string{"jwt_role": "source-role"},
			specCfg:    map[string]string{"mint_method": "vault_token", "jwt_role": "spec-role"},
			want:       "spec-role",
			wantOK:     true,
		},
		{
			name:       "vault_token falls back to source jwt_role",
			sourceType: credential.SourceTypeVault,
			sourceCfg:  map[string]string{"jwt_role": "source-role"},
			specCfg:    map[string]string{"mint_method": "vault_token"},
			want:       "source-role",
			wantOK:     true,
		},
		{
			name:       "vault static_aws names the KV path",
			sourceType: credential.SourceTypeVault,
			specCfg:    map[string]string{"mint_method": "static_aws", "kv2_mount": "secret", "secret_path": "prod/aws"},
			want:       "secret/prod/aws",
			wantOK:     true,
		},
		{
			name:       "vault kv2_read names the KV path",
			sourceType: credential.SourceTypeVault,
			specCfg:    map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			want:       "secret/github/ci",
			wantOK:     true,
		},
		{
			name:       "vault dynamic_aws names the engine role",
			sourceType: credential.SourceTypeVault,
			specCfg:    map[string]string{"mint_method": "dynamic_aws", "aws_mount": "aws", "role_name": "dev-role"},
			want:       "aws/dev-role",
			wantOK:     true,
		},
		{
			name:       "vault oauth2 names the credential",
			sourceType: credential.SourceTypeVault,
			specCfg:    map[string]string{"mint_method": "oauth2", "oauth2_mount": "oauth2", "credential_name": "github"},
			want:       "oauth2/github",
			wantOK:     true,
		},
		{
			name:       "vault vault_token without any role omits",
			sourceType: credential.SourceTypeVault,
			specCfg:    map[string]string{"mint_method": "vault_token"},
			wantOK:     false,
		},
		{
			name:       "unknown source type omits",
			sourceType: credential.SourceTypeGitHub,
			specCfg:    map[string]string{"mint_method": "secrets_manager", "secret_id": "x"},
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DeriveAssertionResource(tc.sourceType, tc.sourceCfg, tc.specCfg)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (value %q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Errorf("resource = %q, want %q", got, tc.want)
			}
			if !ok && got != "" {
				t.Errorf("resource = %q, want empty when !ok", got)
			}
		})
	}
}
