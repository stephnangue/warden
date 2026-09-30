package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storedSecretsCase is one config and what a source of that type holds with it.
type storedSecretsCase struct {
	name   string
	config map[string]string
	want   []string
}

// storedSecretsCases covers every built-in source type. Each type has a keyless
// row and, where it can hold a secret, a keyed row, a cleared row, and a row
// where a keyless marker sits beside a leftover secret — the case the classifier
// exists for, since it must answer from the fields present and not the marker.
var storedSecretsCases = map[string][]storedSecretsCase{
	credential.SourceTypeLocal: {
		{name: "empty", config: nil, want: nil},
	},
	credential.SourceTypeVault: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation", "jwt_role": "r"}, want: nil},
		{name: "approle", config: map[string]string{"auth_method": "approle", "role_id": "id", "secret_id": "s", "secret_id_accessor": "acc"}, want: []string{"secret_id"}},
		{name: "approle cleared", config: map[string]string{"auth_method": "approle", "secret_id": ""}, want: nil},
		{name: "environment token", config: map[string]string{"vault_address": "https://v"}, want: []string{"vault token from the server environment"}},
		{name: "stored token", config: map[string]string{"token": "t"}, want: []string{"token"}},
		{name: "federation with leftover secret", config: map[string]string{"auth_method": "oidc_federation", "secret_id": "s"}, want: []string{"secret_id"}},
	},
	credential.SourceTypeAWS: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}, want: nil},
		{name: "static", config: map[string]string{"access_key_id": "AKIA", "secret_access_key": "s"}, want: []string{"secret_access_key"}},
		{name: "static cleared", config: map[string]string{"auth_method": "oidc_federation", "access_key_id": "", "secret_access_key": ""}, want: nil},
		{name: "secret_spec with leftover secret", config: map[string]string{"secret_spec": "ref", "secret_access_key": "s"}, want: []string{"secret_access_key"}},
	},
	credential.SourceTypeAzure: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation"}, want: nil},
		{name: "static", config: map[string]string{"client_secret": "s", "ca_data": "pem"}, want: []string{"client_secret"}},
	},
	credential.SourceTypeGCP: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation"}, want: nil},
		{name: "static", config: map[string]string{"service_account_key": "{}"}, want: []string{"service_account_key"}},
	},
	credential.SourceTypeKubernetes: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation"}, want: nil},
		{name: "static", config: map[string]string{"token": "t"}, want: []string{"token"}},
	},
	credential.SourceTypeAlicloud: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation"}, want: nil},
		{name: "static", config: map[string]string{"access_key_id": "id", "access_key_secret": "s"}, want: []string{"access_key_secret"}},
	},
	credential.SourceTypeAnthropic: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation", "ca_data": "pem"}, want: nil},
	},
	credential.SourceTypeOpenAI: {
		{name: "federation", config: map[string]string{"auth_method": "oidc_federation", "ca_data": "pem"}, want: nil},
	},
	credential.SourceTypeOAuth2: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"client_id": "id", "client_secret": "s"}, want: []string{"client_secret"}},
	},
	credential.SourceTypeTokenExchange: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "client secret", config: map[string]string{"client_secret": "s"}, want: []string{"client_secret"}},
		{name: "private key", config: map[string]string{"private_key": "pem"}, want: []string{"private_key"}},
		{name: "chained with leftover private key", config: map[string]string{"secret_spec": "ref", "private_key": "pem"}, want: []string{"private_key"}},
	},
	credential.SourceTypeGitLab: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "pat", config: map[string]string{"personal_access_token": "p"}, want: []string{"personal_access_token"}},
		{name: "chained pat with leftover application secret", config: map[string]string{"secret_spec": "ref", "application_secret": "s"}, want: []string{"application_secret"}},
	},
	credential.SourceTypeElastic: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"api_key": "k"}, want: []string{"api_key"}},
	},
	credential.SourceTypeGrafana: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"admin_token": "t"}, want: []string{"admin_token"}},
		{name: "stray federation marker with leftover token", config: map[string]string{"auth_method": "oidc_federation", "admin_token": "t"}, want: []string{"admin_token"}},
	},
	credential.SourceTypeIBM: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "access_keys only", config: nil, want: nil},
		{name: "inline", config: map[string]string{"api_key": "k"}, want: []string{"api_key"}},
	},
	credential.SourceTypeOVH: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"client_id": "id", "client_secret": "s"}, want: []string{"client_secret"}},
	},
	credential.SourceTypeScaleway: {
		{name: "chained", config: map[string]string{"secret_spec": "ref"}, want: nil},
		{name: "inline", config: map[string]string{"management_access_key": "id", "management_secret_key": "s"}, want: []string{"management_secret_key"}},
	},
	credential.SourceTypeGitHub: {
		{name: "url only", config: map[string]string{"github_url": "https://api.github.com", "ca_data": "pem"}, want: nil},
	},
	credential.SourceTypeAPIKey: {
		{name: "url only", config: map[string]string{"api_url": "https://api.example.com", "ca_data": "pem"}, want: nil},
	},
	credential.SourceTypeCloudflare: {
		{name: "empty", config: map[string]string{}, want: nil},
	},
}

func TestSourceStoredSecrets(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := credential.NewDriverRegistry(log)
	require.NoError(t, RegisterBuiltinDrivers(registry))

	for _, sourceType := range registry.ListFactories() {
		cases, ok := storedSecretsCases[sourceType]
		// A new driver must say what it stores; failing here is the reminder.
		require.Truef(t, ok, "no StoredSecrets cases for source type %q", sourceType)

		factory, err := registry.GetFactory(sourceType)
		require.NoError(t, err)
		for _, tc := range cases {
			t.Run(sourceType+"/"+tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, factory.StoredSecrets(credential.NewConfig(tc.config)))
			})
		}
	}
}

// ca_data is masked on read but is not a secret, so no source reports it.
func TestSourceStoredSecrets_IgnoresCAData(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := credential.NewDriverRegistry(log)
	require.NoError(t, RegisterBuiltinDrivers(registry))

	for _, sourceType := range registry.ListFactories() {
		if sourceType == credential.SourceTypeVault {
			continue // reports the environment token for a config with no auth_method
		}
		factory, err := registry.GetFactory(sourceType)
		require.NoError(t, err)
		got := factory.StoredSecrets(credential.NewConfig(map[string]string{"ca_data": "pem"}))
		assert.Nilf(t, got, "source type %q reported ca_data", sourceType)
	}
}
