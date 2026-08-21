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
				"key_id":  "hcxmk_01abc123",
				"api_key": "mgmt-secret-value",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer hcxmk_01abc123:mgmt-secret-value", headers["Authorization"])
	assert.Empty(t, headers["X-Honeycomb-Team"])
}

// TestHoneycombExtractor_ManagementKeyNeedsNoSeparateSecret pins the reason
// management mode is reachable at all: the secret half is api_key, which the
// credential type guarantees. Reading a distinct key_secret made this branch
// unconfigurable — the field could not be carried, so a mount with key_id set
// failed every request with "missing key_secret field".
func TestHoneycombExtractor_ManagementKeyNeedsNoSeparateSecret(t *testing.T) {
	headers, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"key_id":  "hcxmk_01abc123",
				"api_key": "mgmt-secret-value",
				// No key_secret, and none needed.
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer hcxmk_01abc123:mgmt-secret-value", headers["Authorization"])
}

// TestHoneycombExtractor_ManagementKeyWithoutAPIKey fails closed rather than
// emitting "Bearer <key_id>:". Not reachable in production — Parse and Validate
// both require a non-empty api_key — but the extractor must not assume it.
func TestHoneycombExtractor_ManagementKeyWithoutAPIKey(t *testing.T) {
	_, err := honeycombExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"key_id": "hcxmk_01abc123",
			},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
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

// TestSpec_StripsNativeCredentialHeader pins the strip. X-Honeycomb-Team is
// injected only in ingest mode, so without it a caller's own value would reach
// the upstream in management mode, pairing an inbound credential with the
// mount's identity.
func TestSpec_StripsNativeCredentialHeader(t *testing.T) {
	assert.Contains(t, Spec.ExtraHeadersToRemove, "X-Honeycomb-Team")
}
