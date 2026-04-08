package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubernetesTokenCredType_Metadata(t *testing.T) {
	ct := NewKubernetesTokenCredType()
	meta := ct.Metadata()

	assert.Equal(t, credential.TypeKubernetesToken, meta.Name)
	assert.Equal(t, credential.CategoryK8s, meta.Category)
	assert.Equal(t, 1*time.Hour, meta.DefaultTTL)
	assert.NotEmpty(t, meta.Description)
}

func TestKubernetesTokenCredType_Parse_Valid(t *testing.T) {
	ct := NewKubernetesTokenCredType()

	rawData := map[string]interface{}{
		"token":           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
		"namespace":       "default",
		"service_account": "my-sa",
		"audiences":       "https://my-app.example.com",
	}

	cred, err := ct.Parse(rawData, 1*time.Hour, "")
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKubernetesToken, cred.Type)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test", cred.Data["token"])
	assert.Equal(t, "default", cred.Data["namespace"])
	assert.Equal(t, "my-sa", cred.Data["service_account"])
	assert.Equal(t, "https://my-app.example.com", cred.Data["audiences"])
}

func TestKubernetesTokenCredType_Parse_MissingToken(t *testing.T) {
	ct := NewKubernetesTokenCredType()

	rawData := map[string]interface{}{
		"namespace":       "default",
		"service_account": "my-sa",
	}

	_, err := ct.Parse(rawData, 1*time.Hour, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestKubernetesTokenCredType_Revocable(t *testing.T) {
	ct := NewKubernetesTokenCredType()

	rawData := map[string]interface{}{
		"token": "test-token",
	}

	cred, err := ct.Parse(rawData, 1*time.Hour, "some-lease-id")
	require.NoError(t, err)
	assert.False(t, cred.Revocable)
}

func TestKubernetesTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewKubernetesTokenCredType()

	t.Run("valid minimal config", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
		}, credential.SourceTypeKubernetes)
		require.NoError(t, err)
	})

	t.Run("valid full config", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "production",
			"audiences":       "https://my-app.example.com",
			"ttl":             "2h",
		}, credential.SourceTypeKubernetes)
		require.NoError(t, err)
	})

	t.Run("missing service_account", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"namespace": "default",
		}, credential.SourceTypeKubernetes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account")
	})

	t.Run("missing namespace", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
		}, credential.SourceTypeKubernetes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace")
	})

	t.Run("unsupported source type", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
		}, "aws")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require a kubernetes source")
	})

	t.Run("ttl too short", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"ttl":             "5m",
		}, credential.SourceTypeKubernetes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 10m")
	})

	t.Run("ttl too long", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"ttl":             "100h",
		}, credential.SourceTypeKubernetes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not exceed 48h")
	})

	t.Run("ttl at min boundary", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"ttl":             "10m",
		}, credential.SourceTypeKubernetes)
		require.NoError(t, err)
	})

	t.Run("ttl at max boundary", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"ttl":             "48h",
		}, credential.SourceTypeKubernetes)
		require.NoError(t, err)
	})
}

func TestKubernetesTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewKubernetesTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestKubernetesTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewKubernetesTokenCredType()
	assert.Empty(t, ct.SensitiveConfigFields())
}

func TestKubernetesTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewKubernetesTokenCredType()
	schemas := ct.FieldSchemas()

	tokenSchema, ok := schemas["token"]
	require.True(t, ok)
	assert.True(t, tokenSchema.Sensitive)

	nsSchema, ok := schemas["namespace"]
	require.True(t, ok)
	assert.False(t, nsSchema.Sensitive)

	saSchema, ok := schemas["service_account"]
	require.True(t, ok)
	assert.False(t, saSchema.Sensitive)
}
