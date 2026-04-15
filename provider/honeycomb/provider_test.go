package honeycomb

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHoneycombExtractor_IngestKey(t *testing.T) {
	headers, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key": "hcxik_my_ingest_key",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "hcxik_my_ingest_key", headers["X-Honeycomb-Team"])
	assert.Empty(t, headers["Authorization"])
}

func TestHoneycombExtractor_ManagementKey(t *testing.T) {
	headers, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"key_id":     "hcxmk_01abc123",
				"key_secret": "mgmt-secret-value",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer hcxmk_01abc123:mgmt-secret-value", headers["Authorization"])
	assert.Empty(t, headers["X-Honeycomb-Team"])
}

func TestHoneycombExtractor_ManagementKey_MissingSecret(t *testing.T) {
	_, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"key_id": "hcxmk_01abc123",
			},
		},
	})
	assert.ErrorContains(t, err, "missing key_secret")
}

func TestHoneycombExtractor_NoCredential(t *testing.T) {
	_, err := honeycombExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestHoneycombExtractor_WrongType(t *testing.T) {
	_, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{Type: "vault_token"},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestHoneycombExtractor_MissingAPIKey(t *testing.T) {
	_, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "honeycomb", Spec.Name)
	assert.Equal(t, "https://api.honeycomb.io", Spec.DefaultURL)
	assert.Equal(t, "honeycomb_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
}
