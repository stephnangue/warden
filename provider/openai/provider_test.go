package openai

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The extractor has two optional fields, so its positive branches are a lattice
// rather than a single case: each optional header must appear when its field is
// set and be absent — not empty — when it is not. An empty header would still
// carry the key, and would still read as "present" to the upstream.

func TestOpenAICredentialExtractor_KeyOnly(t *testing.T) {
	headers, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": "openai-not-a-real-key"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer openai-not-a-real-key", headers["Authorization"])
	assert.NotContains(t, headers, "OpenAI-Organization")
	assert.NotContains(t, headers, "OpenAI-Project")
}

func TestOpenAICredentialExtractor_WithOrganization(t *testing.T) {
	headers, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":         "openai-not-a-real-key",
				"organization_id": "org-abc123",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer openai-not-a-real-key", headers["Authorization"])
	assert.Equal(t, "org-abc123", headers["OpenAI-Organization"])
	assert.NotContains(t, headers, "OpenAI-Project")
}

func TestOpenAICredentialExtractor_WithProject(t *testing.T) {
	headers, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":    "openai-not-a-real-key",
				"project_id": "proj-xyz789",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "proj-xyz789", headers["OpenAI-Project"])
	assert.NotContains(t, headers, "OpenAI-Organization")
}

func TestOpenAICredentialExtractor_WithBoth(t *testing.T) {
	headers, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":         "openai-not-a-real-key",
				"organization_id": "org-abc123",
				"project_id":      "proj-xyz789",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"Authorization":       "Bearer openai-not-a-real-key",
		"OpenAI-Organization": "org-abc123",
		"OpenAI-Project":      "proj-xyz789",
	}, headers)
}

// An explicitly empty optional field takes the same branch as an absent one.
// Worth pinning separately: a credential source that returns a field it could
// not populate must not turn into a header that overrides the account default.
func TestOpenAICredentialExtractor_EmptyOptionalFieldsOmitted(t *testing.T) {
	headers, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":         "openai-not-a-real-key",
				"organization_id": "",
				"project_id":      "",
			},
		},
	})
	require.NoError(t, err)
	assert.NotContains(t, headers, "OpenAI-Organization")
	assert.NotContains(t, headers, "OpenAI-Project")
}

func TestOpenAICredentialExtractor_NoCredential(t *testing.T) {
	_, err := openaiCredentialExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestOpenAICredentialExtractor_WrongType(t *testing.T) {
	_, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken,
			Data: map[string]string{"api_key": "openai-not-a-real-key"},
		},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestOpenAICredentialExtractor_MissingAPIKey(t *testing.T) {
	_, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"organization_id": "org-abc123"},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestOpenAICredentialExtractor_EmptyAPIKey(t *testing.T) {
	_, err := openaiCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": ""},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

// The optional headers are also the ones a caller could otherwise set for
// itself, so the spec must list them for removal — the extractor injecting them
// is only half of the guarantee.
func TestSpec(t *testing.T) {
	assert.Equal(t, "openai", Spec.Name)
	assert.Equal(t, "openai_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
	assert.ElementsMatch(t,
		[]string{"OpenAI-Organization", "OpenAI-Project"},
		Spec.ExtraHeadersToRemove)
}
