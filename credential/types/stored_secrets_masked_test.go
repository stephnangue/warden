package types

import (
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isSecretDescription reports whether a name StoredSecrets returns describes a
// secret held outside the config, such as one sealed by connect, rather than
// naming a config field. Those carry spaces; a config field never does.
func isSecretDescription(name string) bool {
	return strings.Contains(name, " ")
}

// Every secret a type says a spec holds is one its reads mask. The two are
// declared apart, and aws_access_keys once listed secret_access_key as stored
// but not as sensitive, so a spec read returned it in clear.
func TestStoredSecretsAreSensitive(t *testing.T) {
	registry := credential.NewTypeRegistry()
	require.NoError(t, RegisterBuiltinTypes(registry))

	for _, name := range registry.ListTypes() {
		credType, err := registry.GetByName(name)
		require.NoError(t, err)

		// A config holding every field the type knows, so StoredSecrets reports
		// each secret it could hold.
		full := map[string]string{}
		for _, field := range credType.ConfigSchema() {
			full[field.FieldName()] = "x"
		}
		config := credential.NewConfig(full)

		sensitive := credType.SensitiveConfigFields()
		if dynamic, ok := credType.(credential.ConfigSensitivity); ok {
			sensitive = dynamic.SensitiveConfigFieldsFor(config)
		}
		for _, secret := range credType.StoredSecrets(config) {
			if isSecretDescription(secret) {
				continue
			}
			_, isField := full[secret]
			assert.True(t, isField, "%s: stored secret %q is not in the config schema, so this test cannot see it", name, secret)
			assert.Contains(t, sensitive, secret, "%s: stored secret %q is not masked on read", name, secret)
		}
	}
}
