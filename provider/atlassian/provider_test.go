package atlassian

import (
	"encoding/base64"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAtlassianExtractor_BasicAuth(t *testing.T) {
	headers, err := atlassianExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"email":   "fred@example.com",
				"api_key": "ATATT3xFfGF0abc123",
			},
		},
	})
	require.NoError(t, err)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("fred@example.com:ATATT3xFfGF0abc123"))
	assert.Equal(t, expected, headers["Authorization"])
}

func TestAtlassianExtractor_Bearer(t *testing.T) {
	headers, err := atlassianExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key": "eyJraWQiOiJhdXRoLnN0ZyIsImFsZyI6IlJTMjU2In0",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer eyJraWQiOiJhdXRoLnN0ZyIsImFsZyI6IlJTMjU2In0", headers["Authorization"])
}

func TestAtlassianExtractor_NoCredential(t *testing.T) {
	_, err := atlassianExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestAtlassianExtractor_WrongType(t *testing.T) {
	_, err := atlassianExtractor(&logical.Request{
		Credential: &credential.Credential{Type: "vault_token"},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestAtlassianExtractor_MissingAPIKey(t *testing.T) {
	_, err := atlassianExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"email": "fred@example.com"},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestAtlassianExtractor_EmptyEmail_FallsBackToBearer(t *testing.T) {
	headers, err := atlassianExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"email":   "",
				"api_key": "my-pat-token",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-pat-token", headers["Authorization"])
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "atlassian", Spec.Name)
	assert.Equal(t, "atlassian_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
}
