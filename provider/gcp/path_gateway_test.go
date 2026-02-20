package gcp

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGCPCredentialInfo(t *testing.T) {
	b := &gcpBackend{}

	t.Run("valid credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGCPAccessToken,
				Data: map[string]string{
					"access_token": "ya29.test-token",
				},
			},
		}

		info, err := b.getGCPCredentialInfo(req)
		require.NoError(t, err)
		assert.Equal(t, "ya29.test-token", info.bearerToken)
	})

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: nil,
		}

		_, err := b.getGCPCredentialInfo(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential available")
	})

	t.Run("wrong credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{
					"access_token": "some-token",
				},
			},
		}

		_, err := b.getGCPCredentialInfo(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential type")
	})

	t.Run("missing access_token", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGCPAccessToken,
				Data: map[string]string{},
			},
		}

		_, err := b.getGCPCredentialInfo(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing access_token")
	})
}
