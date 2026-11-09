package types

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type specStoredSecretsCase struct {
	name   string
	config map[string]string
	want   []string
}

// specStoredSecretsCases covers every built-in credential type: a keyless row,
// and where the type can hold a secret, a keyed row and a cleared row. Locators
// and identifiers must not be reported.
var specStoredSecretsCases = map[string][]specStoredSecretsCase{
	credential.TypeAPIKey: {
		{name: "chained", config: map[string]string{"secret_spec": "ref", "organization_id": "org"}, want: nil},
		{name: "inline", config: map[string]string{"api_key": "k", "application_key": "a"}, want: []string{"api_key", "application_key"}},
		{name: "cleared", config: map[string]string{"api_key": ""}, want: nil},
	},
	credential.TypeAWSAccessKeys: {
		{name: "secrets manager locator", config: map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/key"}, want: nil},
		{name: "local", config: map[string]string{"access_key_id": "AKIA", "secret_access_key": "s"}, want: []string{"secret_access_key"}},
	},
	credential.TypeAzureBearerToken: {
		{name: "federated", config: map[string]string{"subject_token_source": "warden_identity", "tenant_id": "t"}, want: nil},
		{name: "static", config: map[string]string{"client_secret": "s", "secret_id": "id"}, want: []string{"client_secret"}},
	},
	credential.TypeGitHubToken: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "pat", config: map[string]string{"token": "t"}, want: []string{"token"}},
		{name: "app", config: map[string]string{"app_id": "1", "private_key": "pem"}, want: []string{"private_key"}},
	},
	credential.TypeCloudflareKeys: {
		{name: "api token", config: map[string]string{"api_token": "t"}, want: []string{"api_token"}},
		{name: "r2", config: map[string]string{"access_key_id": "id", "secret_access_key": "s"}, want: []string{"secret_access_key"}},
		{name: "chained", config: map[string]string{"secret_spec": "ref", "secret_field": "token"}, want: nil},
	},
	credential.TypeScalewayKeys: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"access_key": "id", "secret_key": "s"}, want: []string{"secret_key"}},
	},
	credential.TypeIBMCloudKeys: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"access_key_id": "id", "secret_access_key": "s", "access_token": "t"}, want: []string{"secret_access_key", "access_token"}},
	},
	credential.TypeAlicloudKeys: {
		{name: "role", config: map[string]string{"role_arn": "acs:ram::1:role/r"}, want: nil},
		{name: "stored", config: map[string]string{"access_key_secret": "s", "security_token": "t"}, want: []string{"access_key_secret", "security_token"}},
	},
	credential.TypeOAuthBearerToken: {
		{name: "client credentials", config: map[string]string{"scope": "read"}, want: nil},
		{name: "exchange", config: map[string]string{"subject_token_source": "warden_identity"}, want: nil},
		{name: "authorization_code not connected", config: map[string]string{"auth_method": "authorization_code", "client_id": "id"}, want: []string{"refresh_token (sealed by connect)"}},
		{name: "authorization_code with client secret", config: map[string]string{"auth_method": "authorization_code", "client_secret": "s"}, want: []string{"client_secret", "refresh_token (sealed by connect)"}},
		{name: "authorization_code connected", config: map[string]string{"auth_method": "authorization_code", "refresh_token": "r"}, want: []string{"refresh_token"}},
		{name: "static access token connected", config: map[string]string{"auth_method": "authorization_code", "access_token": "a"}, want: []string{"access_token"}},
	},
	credential.TypeKeyValue:          {{name: "locator", config: map[string]string{"secret_id": "prod/key", "secret_path": "p"}, want: nil}},
	credential.TypeOVHKeys:           {{name: "chained", config: map[string]string{"mint_method": "access_keys", "secret_spec": "ref"}, want: nil}},
	credential.TypeGCPAccessToken:    {{name: "scopes", config: map[string]string{"scopes": "cloud-platform"}, want: nil}},
	credential.TypeGitLabAccessToken: {{name: "scopes", config: map[string]string{"scopes": "api"}, want: nil}},
	credential.TypeKubernetesToken:   {{name: "service account", config: map[string]string{"service_account": "sa"}, want: nil}},
	credential.TypeDBAuthToken:       {{name: "role", config: map[string]string{"db_user": "u"}, want: nil}},
	credential.TypeVaultToken:        {{name: "role", config: map[string]string{"role": "r"}, want: nil}},
}

func TestSpecStoredSecrets(t *testing.T) {
	registry := credential.NewTypeRegistry()
	require.NoError(t, RegisterBuiltinTypes(registry))

	for _, typeName := range registry.ListTypes() {
		cases, ok := specStoredSecretsCases[typeName]
		// A new type must say what it stores; failing here is the reminder.
		require.Truef(t, ok, "no StoredSecrets cases for credential type %q", typeName)

		credType, err := registry.GetByName(typeName)
		require.NoError(t, err)
		for _, tc := range cases {
			t.Run(typeName+"/"+tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, credType.StoredSecrets(credential.NewConfig(tc.config)))
			})
		}
	}
}
