package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
)

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
