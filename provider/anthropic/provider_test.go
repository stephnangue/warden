package anthropic

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The extractor branches on credential type before it looks at any field, so its
// cases are a lattice rather than a sequence: each auth shape has to be pinned
// for what it injects AND for what it must not. The bearer branch in particular
// is defined as much by the absent workspace header as by the token it sets.

const notARealKey = "anthropic-not-a-real-key"

func TestAnthropicCredentialExtractor_KeyOnly(t *testing.T) {
	headers, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": notARealKey},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"x-api-key": notARealKey}, headers)
}

func TestAnthropicCredentialExtractor_WithWorkspace(t *testing.T) {
	headers, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":      notARealKey,
				"workspace_id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"x-api-key":              notARealKey,
		"anthropic-workspace-id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ",
	}, headers)
}

// An explicitly empty workspace takes the same branch as an absent one. Pinned
// separately because the upstream refuses an empty value: a source that returned
// a field it could not populate would turn an optional header into a request
// that cannot succeed.
func TestAnthropicCredentialExtractor_EmptyWorkspaceOmitted(t *testing.T) {
	headers, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":      notARealKey,
				"workspace_id": "",
			},
		},
	})
	require.NoError(t, err)
	assert.NotContains(t, headers, "anthropic-workspace-id")
}

// A bearer credential is issued for one workspace and carries that binding, so
// the header is not read for it. Emitting one would assert a workspace twice and
// let the two disagree — hence the workspace_id here, which must be ignored.
func TestAnthropicCredentialExtractor_BearerSuppressesWorkspace(t *testing.T) {
	headers, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeOAuthBearerToken,
			Data: map[string]string{
				"api_key":      notARealKey,
				"workspace_id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"Authorization": "Bearer " + notARealKey}, headers)
	assert.NotContains(t, headers, "anthropic-workspace-id")
	// Nothing injects over x-api-key on this branch, which is what makes its
	// presence in ExtraHeadersToRemove load-bearing rather than tidy: inbound it
	// is this provider's agent-token channel.
	assert.NotContains(t, headers, "x-api-key")
}

func TestAnthropicCredentialExtractor_NoCredential(t *testing.T) {
	_, err := anthropicCredentialExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestAnthropicCredentialExtractor_WrongType(t *testing.T) {
	_, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken,
			Data: map[string]string{"api_key": notARealKey},
		},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestAnthropicCredentialExtractor_MissingAPIKey(t *testing.T) {
	_, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"workspace_id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestAnthropicCredentialExtractor_EmptyAPIKey(t *testing.T) {
	_, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": ""},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

// The error names both fields the token can arrive under, since a source that
// returned access_token has it renamed to api_key when the credential is parsed.
func TestAnthropicCredentialExtractor_BearerMissingToken(t *testing.T) {
	_, err := anthropicCredentialExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeOAuthBearerToken,
			Data: map[string]string{},
		},
	})
	assert.ErrorContains(t, err, "missing bearer token")
	assert.ErrorContains(t, err, "access_token")
}

// The extractor injecting a header is only half the guarantee: a name it sets
// conditionally must also be stripped, or the branch that does not set it leaves
// a client's own value in place. anthropic-version is here so a client cannot
// pin its own; the workspace so a client cannot choose where our credential
// spends; anthropic-beta so the mount's policy, not the client, decides.
func TestSpec(t *testing.T) {
	assert.Equal(t, "anthropic", Spec.Name)
	assert.Equal(t, "anthropic_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
	assert.ElementsMatch(t,
		[]string{"x-api-key", "anthropic-version", "anthropic-workspace-id", "anthropic-beta"},
		Spec.ExtraHeadersToRemove)

	// The version now comes from DynamicHeaders. A static header applied after
	// the credential headers is what could silently overwrite one of them, so it
	// must not come back.
	assert.Empty(t, Spec.DefaultHeaders)
	assert.NotNil(t, Spec.DynamicHeaders)
	assert.NotNil(t, Spec.ResolveUpstream)
	assert.NotNil(t, Spec.OnConfigWrite)
	assert.NotNil(t, Spec.OnConfigRead)
	assert.NotNil(t, Spec.OnInitialize)
	assert.NotNil(t, Spec.ValidateExtraConfig)
	for _, f := range []string{"anthropic_version", "beta_allowlist", "beta_required"} {
		assert.Contains(t, Spec.ExtraConfigFields, f)
	}
}
