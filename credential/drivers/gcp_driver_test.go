package drivers

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPAccessTokenMetadata(t *testing.T) {
	expiry := time.Date(2026, 6, 9, 15, 4, 5, 0, time.UTC)
	saKey := &serviceAccountKey{
		ClientEmail: "warden-src@my-project.iam.gserviceaccount.com",
		ProjectID:   "my-project",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----",
	}

	meta := gcpAccessTokenMetadata(saKey, "https://www.googleapis.com/auth/cloud-platform", expiry)

	assert.Equal(t, "warden-src@my-project.iam.gserviceaccount.com", meta["subject"])
	assert.Equal(t, "my-project", meta["project_id"])
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform", meta["scopes"])
	assert.Equal(t, "2026-06-09T15:04:05Z", meta["expiration"])

	// Secret material never lands in the clear-logged metadata, and every value
	// is a string (Metadata parsing rejects non-strings).
	assert.NotContains(t, meta, "private_key")
	assert.NotContains(t, meta, "access_token")
	for k, v := range meta {
		_, ok := v.(string)
		assert.Truef(t, ok, "metadata[%q] is %T, expected string", k, v)
	}
}

func TestGCPAccessTokenMetadata_NilKey(t *testing.T) {
	expiry := time.Date(2026, 6, 9, 15, 4, 5, 0, time.UTC)

	meta := gcpAccessTokenMetadata(nil, "scope", expiry)

	// Non-key source auth: no SA identity fields, but token context still present.
	assert.NotContains(t, meta, "subject")
	assert.NotContains(t, meta, "project_id")
	assert.Equal(t, "scope", meta["scopes"])
	assert.Equal(t, "2026-06-09T15:04:05Z", meta["expiration"])
}

func TestGCPImpersonatedMetadata(t *testing.T) {
	saKey := &serviceAccountKey{
		ClientEmail: "warden-src@my-project.iam.gserviceaccount.com",
		ProjectID:   "my-project",
	}

	meta := gcpImpersonatedMetadata(saKey,
		"app-backend@my-project.iam.gserviceaccount.com",
		"https://www.googleapis.com/auth/cloud-platform", "3600s", "2026-06-09T16:04:05Z")

	// subject is the impersonated target; the source SA is the authority.
	assert.Equal(t, "app-backend@my-project.iam.gserviceaccount.com", meta["subject"])
	assert.Equal(t, "warden-src@my-project.iam.gserviceaccount.com", meta["source_service_account"])
	assert.Equal(t, "my-project", meta["project_id"])
	assert.Equal(t, "3600s", meta["lifetime"])
	assert.Equal(t, "2026-06-09T16:04:05Z", meta["expiration"])
}

func TestGCPImpersonatedMetadata_NilKeyAndNoExpiry(t *testing.T) {
	meta := gcpImpersonatedMetadata(nil, "app-backend@x.iam.gserviceaccount.com", "scope", "3600s", "")

	assert.Equal(t, "app-backend@x.iam.gserviceaccount.com", meta["subject"])
	assert.NotContains(t, meta, "source_service_account")
	assert.NotContains(t, meta, "project_id")
	assert.NotContains(t, meta, "expiration")
}

func TestGCPDriverFactory_Type(t *testing.T) {
	f := &GCPDriverFactory{}
	assert.Equal(t, credential.SourceTypeGCP, f.Type())
}

func TestGCPDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &GCPDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "service_account_key")
}

func TestGCPDriverFactory_ValidateConfig(t *testing.T) {
	f := &GCPDriverFactory{}

	t.Run("missing service_account_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_key")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": "not-json",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid JSON")
	})

	t.Run("missing client_email", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n"}`,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_email")
	})

	t.Run("missing private_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{"client_email": "test@project.iam.gserviceaccount.com"}`,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private_key")
	})

	t.Run("valid config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{
				"type": "service_account",
				"project_id": "my-project",
				"private_key_id": "key-id",
				"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
				"client_email": "test@my-project.iam.gserviceaccount.com",
				"client_id": "123456789"
			}`,
		})
		require.NoError(t, err)
	})
}

func TestGCPDriver_Type(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeGCP, d.Type())
}

func TestGCPDriver_Cleanup(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Cleanup(context.TODO()))
}

func TestGCPDriver_Revoke_NoOp(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Revoke(context.TODO(), "some-lease-id"))
}

func TestGCPDriver_SupportsRotation(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	assert.True(t, d.SupportsRotation())
}

func TestGCPDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "invalid_method",
		},
	}

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

func TestGCPDriver_MintCredential_ImpersonationMissingTarget(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
		tokenCache: NewTokenCache(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "impersonated_access_token",
		},
	}

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target_service_account")
}

func TestGCPDriver_ParseServiceAccountKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"service_account_key": `{
						"type": "service_account",
						"project_id": "my-project",
						"private_key_id": "key-123",
						"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
						"client_email": "test@my-project.iam.gserviceaccount.com",
						"client_id": "123456789"
					}`,
				},
			},
		}

		saKey, err := d.parseServiceAccountKey()
		require.NoError(t, err)
		assert.Equal(t, "my-project", saKey.ProjectID)
		assert.Equal(t, "key-123", saKey.PrivateKeyID)
		assert.Equal(t, "test@my-project.iam.gserviceaccount.com", saKey.ClientEmail)
	})

	t.Run("empty key", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{},
			},
		}

		_, err := d.parseServiceAccountKey()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"service_account_key": "not-json",
				},
			},
		}

		_, err := d.parseServiceAccountKey()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})
}

func TestSplitScopes(t *testing.T) {
	t.Run("single scope", func(t *testing.T) {
		scopes := splitScopes("https://www.googleapis.com/auth/cloud-platform")
		assert.Equal(t, []string{"https://www.googleapis.com/auth/cloud-platform"}, scopes)
	})

	t.Run("multiple scopes", func(t *testing.T) {
		scopes := splitScopes("https://www.googleapis.com/auth/compute, https://www.googleapis.com/auth/devstorage.read_only")
		assert.Equal(t, []string{
			"https://www.googleapis.com/auth/compute",
			"https://www.googleapis.com/auth/devstorage.read_only",
		}, scopes)
	})
}
