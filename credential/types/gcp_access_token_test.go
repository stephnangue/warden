package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPAccessTokenCredType_Metadata(t *testing.T) {
	ct := NewGCPAccessTokenCredType()
	meta := ct.Metadata()

	assert.Equal(t, credential.TypeGCPAccessToken, meta.Name)
	assert.Equal(t, credential.CategoryCloudIAM, meta.Category)
	assert.Equal(t, 1*time.Hour, meta.DefaultTTL)
	assert.NotEmpty(t, meta.Description)
}

func TestGCPAccessTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewGCPAccessTokenCredType()

	t.Run("valid access_token method", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"mint_method": "access_token",
			"scopes":      "https://www.googleapis.com/auth/cloud-platform",
		}, credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("default mint_method is access_token", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{}, credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("valid impersonated_access_token method", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "target@project.iam.gserviceaccount.com",
		}, credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("impersonated_access_token missing target", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"mint_method": "impersonated_access_token",
		}, credential.SourceTypeGCP)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_service_account")
	})

	t.Run("unsupported mint_method", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{
			"mint_method": "invalid_method",
		}, credential.SourceTypeGCP)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be one of:")
	})

	t.Run("unsupported source type", func(t *testing.T) {
		err := ct.ValidateConfig(map[string]string{}, "azure")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require a gcp source")
	})
}

func TestGCPAccessTokenCredType_Parse(t *testing.T) {
	ct := NewGCPAccessTokenCredType()

	t.Run("valid token", func(t *testing.T) {
		rawData := map[string]interface{}{
			"access_token":           "ya29.test-token",
			"project_id":             "my-project",
			"scopes":                 "https://www.googleapis.com/auth/cloud-platform",
			"token_type":             "Bearer",
			"target_service_account": "target@project.iam.gserviceaccount.com",
		}

		cred, err := ct.Parse(rawData, 1*time.Hour, "")
		require.NoError(t, err)
		assert.Equal(t, credential.TypeGCPAccessToken, cred.Type)
		assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
		assert.Equal(t, "ya29.test-token", cred.Data["access_token"])
		assert.Equal(t, "my-project", cred.Data["project_id"])
		assert.Equal(t, "Bearer", cred.Data["token_type"])
		assert.Equal(t, "target@project.iam.gserviceaccount.com", cred.Data["target_service_account"])
		assert.False(t, cred.Revocable)
	})

	t.Run("missing access_token", func(t *testing.T) {
		rawData := map[string]interface{}{
			"project_id": "my-project",
		}

		_, err := ct.Parse(rawData, 1*time.Hour, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_token")
	})

	t.Run("empty access_token", func(t *testing.T) {
		rawData := map[string]interface{}{
			"access_token": "",
		}

		_, err := ct.Parse(rawData, 1*time.Hour, "")
		require.Error(t, err)
	})
}

func TestGCPAccessTokenCredType_Validate(t *testing.T) {
	ct := NewGCPAccessTokenCredType()

	t.Run("valid credential", func(t *testing.T) {
		cred := &credential.Credential{
			Type: credential.TypeGCPAccessToken,
			Data: map[string]string{
				"access_token": "ya29.test-token",
			},
		}
		require.NoError(t, ct.Validate(cred))
	})

	t.Run("wrong type", func(t *testing.T) {
		cred := &credential.Credential{
			Type: credential.TypeAzureBearerToken,
			Data: map[string]string{
				"access_token": "ya29.test-token",
			},
		}
		require.Error(t, ct.Validate(cred))
	})

	t.Run("missing access_token", func(t *testing.T) {
		cred := &credential.Credential{
			Type: credential.TypeGCPAccessToken,
			Data: map[string]string{},
		}
		require.Error(t, ct.Validate(cred))
	})
}

func TestGCPAccessTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewGCPAccessTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestGCPAccessTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewGCPAccessTokenCredType()
	assert.Empty(t, ct.SensitiveConfigFields())
}

func TestGCPAccessTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewGCPAccessTokenCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "access_token")
	assert.True(t, schemas["access_token"].Sensitive)

	assert.Contains(t, schemas, "project_id")
	assert.False(t, schemas["project_id"].Sensitive)

	assert.Contains(t, schemas, "scopes")
	assert.Contains(t, schemas, "token_type")
	assert.Contains(t, schemas, "target_service_account")
}
