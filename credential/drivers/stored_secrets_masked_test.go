package drivers

import (
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every secret a driver says a source holds is one its reads mask: the two
// are declared apart, and a stored secret missing from SensitiveConfigFields
// would be returned in clear on a source read. A name with a space describes a
// secret held outside the config, not a config field.
//
// A driver has no config schema, so each is given a config naming every field
// any driver reports as sensitive, and the secret fields drivers commonly hold.
func TestSourceStoredSecretsAreSensitive(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	registry := credential.NewDriverRegistry(log)
	require.NoError(t, RegisterBuiltinDrivers(registry))

	full := map[string]string{"auth_method": "x"}
	for _, name := range registry.ListFactories() {
		factory, err := registry.GetFactory(name)
		require.NoError(t, err)
		for _, field := range factory.SensitiveConfigFields() {
			full[field] = "x"
		}
	}
	// Fields a driver could hold without listing them anywhere a test can read.
	for _, field := range []string{
		"secret_access_key", "access_key_secret", "client_secret", "private_key", "service_account_key",
		"api_key", "token", "secret_id", "admin_token", "personal_access_token", "application_secret",
		"management_secret_key", "password", "refresh_token", "access_token",
	} {
		full[field] = "x"
	}
	config := credential.NewConfig(full)

	for _, name := range registry.ListFactories() {
		factory, err := registry.GetFactory(name)
		require.NoError(t, err)
		sensitive := factory.SensitiveConfigFields()
		for _, secret := range factory.StoredSecrets(config) {
			if strings.Contains(secret, " ") {
				continue
			}
			assert.Contains(t, sensitive, secret, "%s source: stored secret %q is not masked on read", name, secret)
		}
	}
}
