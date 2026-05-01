package dualgateway

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Default API credential extraction ---

func TestDefaultExtractAPICredential(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	t.Run("valid credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "test_keys",
				Data: map[string]string{"secret_key": "my-secret"},
			},
		}
		val, err := b.extractAPICredential(req)
		require.NoError(t, err)
		assert.Equal(t, "my-secret", val)
	})

	t.Run("nil credential", func(t *testing.T) {
		_, err := b.extractAPICredential(&logical.Request{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("wrong credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "wrong_type",
				Data: map[string]string{"secret_key": "val"},
			},
		}
		_, err := b.extractAPICredential(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential type")
	})

	t.Run("missing field", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "test_keys",
				Data: map[string]string{"other_field": "val"},
			},
		}
		_, err := b.extractAPICredential(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_key")
	})
}

// --- Default S3 credential extraction ---

func TestDefaultExtractS3Credentials(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	t.Run("valid credentials", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "test_keys",
				Data: map[string]string{"access_key": "AK", "secret_key": "SK"},
			},
		}
		creds, err := b.extractS3Credentials(req)
		require.NoError(t, err)
		assert.Equal(t, "AK", creds.AccessKeyID)
		assert.Equal(t, "SK", creds.SecretAccessKey)
	})

	t.Run("nil credential", func(t *testing.T) {
		_, err := b.extractS3Credentials(&logical.Request{})
		require.Error(t, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "wrong_type",
				Data: map[string]string{"access_key": "AK", "secret_key": "SK"},
			},
		}
		_, err := b.extractS3Credentials(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})

	t.Run("missing access_key", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "test_keys",
				Data: map[string]string{"secret_key": "SK"},
			},
		}
		_, err := b.extractS3Credentials(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key or secret_key")
	})
}

// --- Custom override: API credential ---

func TestCustomExtractAPICredential(t *testing.T) {
	spec := &ProviderSpec{
		Name: "custom", HelpText: "h", CredentialType: "c",
		DefaultURL: "https://x.com", URLConfigKey: "custom_url",
		DefaultTimeout: 30e9, UserAgent: "u",
		APIAuth:    APIAuthStrategy{HeaderName: "X", HeaderValueFormat: "%s", CredentialField: "unused"},
		S3Endpoint: func(_ map[string]any, r string) string { return r },
		ExtractAPICredential: func(req *logical.Request) (string, error) {
			return "custom-value", nil
		},
	}
	b := createBackend(t, spec)

	val, err := b.extractAPICredential(&logical.Request{
		Credential: &credential.Credential{Type: "anything", Data: map[string]string{}},
	})
	require.NoError(t, err)
	assert.Equal(t, "custom-value", val)
}

// --- Custom override: S3 credentials ---

func TestCustomExtractS3Credentials(t *testing.T) {
	spec := &ProviderSpec{
		Name: "custom", HelpText: "h", CredentialType: "c",
		DefaultURL: "https://x.com", URLConfigKey: "custom_url",
		DefaultTimeout: 30e9, UserAgent: "u",
		APIAuth:    APIAuthStrategy{HeaderName: "X", HeaderValueFormat: "%s", CredentialField: "unused"},
		S3Endpoint: func(_ map[string]any, r string) string { return r },
		ExtractS3Credentials: func(req *logical.Request) (awssdk.Credentials, error) {
			return awssdk.Credentials{AccessKeyID: "CUSTOM-AK", SecretAccessKey: "CUSTOM-SK"}, nil
		},
	}
	b := createBackend(t, spec)

	creds, err := b.extractS3Credentials(&logical.Request{
		Credential: &credential.Credential{Type: "anything", Data: map[string]string{}},
	})
	require.NoError(t, err)
	assert.Equal(t, "CUSTOM-AK", creds.AccessKeyID)
	assert.Equal(t, "CUSTOM-SK", creds.SecretAccessKey)
}
