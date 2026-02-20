package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	require.NoError(t, d.Cleanup(nil))
}

func TestGCPDriver_Revoke_NoOp(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Revoke(nil, "some-lease-id"))
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

	_, _, _, err := d.MintCredential(nil, spec)
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

	_, _, _, err := d.MintCredential(nil, spec)
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
