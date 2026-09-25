package drivers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A store of opaque strings has no single right shape. A flat object of strings is
// the multi-field secret a chained consumer reads by name; anything else is vended
// whole, because the key_value type keeps only string fields and admitting a nested
// document would silently drop part of it.
func TestParseSecretPayload(t *testing.T) {
	t.Run("object of scalars is vended under its own keys", func(t *testing.T) {
		got, err := parseSecretPayload([]byte(`{"api_key":"k1","port":5432,"tls":true}`))
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"api_key": "k1",
			"port":    "5432",
			"tls":     "true",
		}, got, "numbers render without a decimal point, as stored")
	})

	for name, payload := range map[string]string{
		"a plain api key":    "not-json-at-all",
		"a JSON array":       `["a","b"]`,
		"a bare JSON string": `"just-a-string"`,
		"a JSON number":      `12345`,
		"JSON null":          `null`,
	} {
		t.Run(name+" is one opaque secret", func(t *testing.T) {
			got, err := parseSecretPayload([]byte(payload))
			require.NoError(t, err)
			assert.Equal(t, map[string]interface{}{"value": payload}, got)
		})
	}

	// A consuming spec naming no secret_field takes the sole key when there is only
	// one, so blobbing a document under "value" would send every secret stored beside
	// the wanted one upstream as the credential. Dropping the nested field instead
	// would be quietly lossy. Neither is acceptable, so the shape is refused.
	t.Run("a nested document is refused, not blobbed", func(t *testing.T) {
		for _, payload := range []string{
			`{"api_key":"k","meta":{"env":"prod"}}`,
			`{"api_key":"k","hosts":["a","b"]}`,
		} {
			_, err := parseSecretPayload([]byte(payload))
			require.Errorf(t, err, "%s must be refused", payload)
			assert.Contains(t, err.Error(), "nested")
		}
	})

	t.Run("a null field is refused", func(t *testing.T) {
		_, err := parseSecretPayload([]byte(`{"api_key":null}`))
		require.Error(t, err)
	})

	t.Run("an empty object carries no secret", func(t *testing.T) {
		_, err := parseSecretPayload([]byte(`{}`))
		require.Error(t, err)
	})
}
