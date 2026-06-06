package mcp_github

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractBearerToken(t *testing.T) {
	t.Run("github_token (App/PAT) → Bearer", func(t *testing.T) {
		h, err := extractBearerToken(&logical.Request{Credential: &credential.Credential{
			Type: credential.TypeGitHubToken,
			Data: map[string]string{"token": "ghp_abc"},
		}})
		require.NoError(t, err)
		assert.Equal(t, "Bearer ghp_abc", h["Authorization"])
	})

	t.Run("oauth_bearer_token (authorization_code) → Bearer", func(t *testing.T) {
		h, err := extractBearerToken(&logical.Request{Credential: &credential.Credential{
			Type: credential.TypeOAuthBearerToken,
			Data: map[string]string{"api_key": "gho_xyz"},
		}})
		require.NoError(t, err)
		assert.Equal(t, "Bearer gho_xyz", h["Authorization"])
	})

	t.Run("unsupported credential type", func(t *testing.T) {
		_, err := extractBearerToken(&logical.Request{Credential: &credential.Credential{
			Type: credential.TypeAWSAccessKeys,
			Data: map[string]string{"access_key_id": "x"},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential type")
	})

	t.Run("nil credential", func(t *testing.T) {
		_, err := extractBearerToken(&logical.Request{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("missing token field", func(t *testing.T) {
		_, err := extractBearerToken(&logical.Request{Credential: &credential.Credential{
			Type: credential.TypeOAuthBearerToken,
			Data: map[string]string{},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing token")
	})
}
