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
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "access_token",
			"scopes":      "https://www.googleapis.com/auth/cloud-platform",
		}), credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("default mint_method is access_token", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{}), credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("valid impersonated_access_token method", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "target@project.iam.gserviceaccount.com",
		}), credential.SourceTypeGCP)
		require.NoError(t, err)
	})

	t.Run("impersonated_access_token missing target", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "impersonated_access_token",
		}), credential.SourceTypeGCP)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_service_account")
	})

	t.Run("unsupported mint_method", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "invalid_method",
		}), credential.SourceTypeGCP)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be one of:")
	})

	t.Run("unsupported source type", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{}), "azure")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require a gcp or vault source")
	})

	t.Run("vault source - valid dynamic_gcp config", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "dynamic_gcp",
			"gcp_mount":   "gcp",
			"role_name":   "my-roleset",
		}), credential.SourceTypeVault)
		require.NoError(t, err)
	})

	t.Run("vault source - wrong mint_method", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "access_token",
			"gcp_mount":   "gcp",
			"role_name":   "my-roleset",
		}), credential.SourceTypeVault)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'mint_method' must be 'dynamic_gcp'")
	})

	t.Run("vault source - missing gcp_mount", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "dynamic_gcp",
			"role_name":   "my-roleset",
		}), credential.SourceTypeVault)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'gcp_mount' is required")
	})

	t.Run("vault source - missing role_name", func(t *testing.T) {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "dynamic_gcp",
			"gcp_mount":   "gcp",
		}), credential.SourceTypeVault)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'role_name' is required")
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

		cred, err := ct.Parse(rawData, nil, 1*time.Hour, "")
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

		_, err := ct.Parse(rawData, nil, 1*time.Hour, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_token")
	})

	t.Run("empty access_token", func(t *testing.T) {
		rawData := map[string]interface{}{
			"access_token": "",
		}

		_, err := ct.Parse(rawData, nil, 1*time.Hour, "")
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

// A key naming a Workspace user belongs to a gcp_delegated_token; on an ordinary
// token it would be stored and never read.
func TestGCPAccessTokenCredType_RefusesDelegatedUserKeys(t *testing.T) {
	ct := NewGCPAccessTokenCredType()
	for _, key := range []string{"delegated_user_claim", "delegated_user_domains"} {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@proj.iam.gserviceaccount.com",
			key:                      "v",
		}), credential.SourceTypeGCP)
		require.Errorf(t, err, "%s must be refused", key)
		assert.Contains(t, err.Error(), "applies only to mint_method=delegated_access_token")
	}

	err := ct.ValidateConfig(credential.NewConfig(map[string]string{
		"mint_method": "delegated_access_token",
	}), credential.SourceTypeGCP)
	require.Error(t, err, "a delegated mint is never an ordinary gcp_access_token")
}

func TestGCPDelegatedTokenCredType(t *testing.T) {
	ct := NewGCPDelegatedTokenCredType()
	meta := ct.Metadata()
	assert.Equal(t, credential.TypeGCPDelegatedToken, meta.Name)
	assert.Equal(t, 1*time.Hour, meta.DefaultTTL)
	assert.True(t, ct.FieldSchemas()["access_token"].Sensitive)
	assert.Empty(t, ct.StoredSecrets(credential.NewConfig(nil)))

	valid := map[string]string{
		"mint_method":            "delegated_access_token",
		"target_service_account": "dwd@proj.iam.gserviceaccount.com",
		"scopes":                 "https://www.googleapis.com/auth/gmail.readonly",
		"delegated_user_claim":   "email",
		"delegated_user_domains": "example.com, example.org",
	}
	with := func(key, value string) credential.Config {
		cfg := map[string]string{}
		for k, v := range valid {
			cfg[k] = v
		}
		if value == "" {
			delete(cfg, key)
		} else {
			cfg[key] = value
		}
		return credential.NewConfig(cfg)
	}
	require.NoError(t, ct.ValidateConfig(credential.NewConfig(valid), credential.SourceTypeGCP))

	tests := []struct {
		name    string
		config  credential.Config
		source  string
		wantErr string
	}{
		{"vault source", credential.NewConfig(valid), credential.SourceTypeVault, "require a gcp source"},
		{"no mint method", with("mint_method", ""), credential.SourceTypeGCP, "mint_method"},
		{"other mint method", with("mint_method", "access_token"), credential.SourceTypeGCP, "mint_method"},
		{"no account", with("target_service_account", ""), credential.SourceTypeGCP, "target_service_account"},
		{"no scopes", with("scopes", ""), credential.SourceTypeGCP, "scopes"},
		{"scopes that name nothing", with("scopes", " , "), credential.SourceTypeGCP, "at least one scope"},
		{"no claim", with("delegated_user_claim", ""), credential.SourceTypeGCP, "delegated_user_claim"},
		{"two claims", with("delegated_user_claim", "email,upn"), credential.SourceTypeGCP, "names one claim"},
		{"no domains", with("delegated_user_domains", ""), credential.SourceTypeGCP, "delegated_user_domains"},
		{"a lifetime", with("lifetime", "1800s"), credential.SourceTypeGCP, "max_ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, tt.source)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseDelegatedUserDomains(t *testing.T) {
	got, err := ParseDelegatedUserDomains(" example.com,eng.example.org ,, ")
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com", "eng.example.org"}, got)

	for _, bad := range []string{
		"", " , ",
		"Example.com",   // stored as matched: lowercase only
		"*.example.com", // no wildcards
		".example.com", "example.com.", "example..com",
		"localhost", // a Workspace domain has two or more labels
		"-example.com", "example-.com",
		"exa mple.com", "example.com/x", "user@example.com",
	} {
		_, err := ParseDelegatedUserDomains(bad)
		assert.Errorf(t, err, "%q must be refused", bad)
	}
}
