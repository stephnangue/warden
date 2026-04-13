package prometheus

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrometheusExtractor_Bearer_Default(t *testing.T) {
	headers, err := prometheusExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key": "my-bearer-token",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-bearer-token", headers["Authorization"])
}

func TestPrometheusExtractor_Bearer_Explicit(t *testing.T) {
	headers, err := prometheusExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":   "my-bearer-token",
				"auth_type": "bearer",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-bearer-token", headers["Authorization"])
}

func TestPrometheusExtractor_BasicAuth(t *testing.T) {
	// api_key is pre-encoded base64("admin:secret") = "YWRtaW46c2VjcmV0"
	headers, err := prometheusExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{
				"api_key":   "YWRtaW46c2VjcmV0",
				"auth_type": "basic",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Basic YWRtaW46c2VjcmV0", headers["Authorization"])
}

func TestPrometheusExtractor_NoCredential(t *testing.T) {
	_, err := prometheusExtractor(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestPrometheusExtractor_WrongType(t *testing.T) {
	_, err := prometheusExtractor(&logical.Request{
		Credential: &credential.Credential{Type: "vault_token"},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestPrometheusExtractor_MissingAPIKey(t *testing.T) {
	_, err := prometheusExtractor(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"auth_type": "basic"},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "prometheus", Spec.Name)
	assert.Equal(t, "prometheus_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
}
