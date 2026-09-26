package types

import (
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyValueCredType_Metadata(t *testing.T) {
	ct := NewKeyValueCredType()
	md := ct.Metadata()

	assert.Equal(t, credential.TypeKeyValue, md.Name)
	assert.Equal(t, credential.CategoryAPI, md.Category)
	assert.Equal(t, time.Duration(0), md.DefaultTTL)
}

func TestKeyValueCredType_ValidateConfig(t *testing.T) {
	ct := NewKeyValueCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			// The narrow role is mandatory: without its own, the spec would inherit the
			// source's, which is the one thing this mint method must not do.
			name:       "transit_signer without a role",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'jwt_role' is required",
		},
		{
			// transit_signer produces the same multi-field, no-primary-field payload
			// this type exists to carry, but needs none of the kv2 locators.
			name:       "valid transit_signer",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "client-assertion", "jwt_role": "warden-transit-signer"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "transit_signer without a key",
			config:     map[string]string{"mint_method": "transit_signer", "jwt_role": "r"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'transit_key' is required",
		},
		{
			// The kv2 locators belong to kv2_read alone; requiring them of every mint
			// method is what kept transit_signer from being expressible at all.
			name:       "transit_signer needs no kv2 locators",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k", "jwt_role": "r", "kv2_mount": "", "secret_path": ""},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "valid kv2_read",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "valid kv2_read with a field selection and a pinned version",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "json_key_map": "token=api_key", "secret_version": "3"},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			// GetInt falls back to its default on an unparseable value, so a
			// typo'd version would silently read the current revision. The
			// schema is what stops it reaching the driver.
			name:       "non-numeric version",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "secret_version": "latest"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_version",
		},
		{
			name:       "version below the first revision",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "secret_version": "0"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_version",
		},
		{
			name:       "unsupported source type",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeKubernetes,
			wantErr:    true,
			errMsg:     "require an hvault, aws, gcp or azure source",
		},
		{
			name:       "wrong mint_method",
			config:     map[string]string{"mint_method": "static_apikey", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "kv2_read",
		},
		{
			name:       "missing kv2_mount",
			config:     map[string]string{"mint_method": "kv2_read", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "kv2_mount",
		},
		{
			name:       "missing secret_path",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_path",
		},

		// An aws source reads a stored secret and vends it verbatim.
		{
			name:       "aws secret_read",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/datadog/keys"},
			sourceType: credential.SourceTypeAWS,
		},
		{
			name:       "aws secret_read with selection keys",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "version_stage": "AWSCURRENT", "json_key_map": "k=api_key"},
			sourceType: credential.SourceTypeAWS,
		},
		{
			name:       "aws secret_read without secret_id",
			config:     map[string]string{"mint_method": "secret_read"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'secret_id' is required when mint_method is secret_read",
		},
		{
			name:       "keyless aws secret_read without role_arn",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "subject_token_source": "warden_identity"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'role_arn' is required for keyless secret_read",
		},
		{
			name: "keyless aws secret_read with role_arn",
			config: map[string]string{
				"mint_method": "secret_read", "secret_id": "prod/app",
				"subject_token_source": "warden_identity", "role_arn": "arn:aws:iam::1:role/R",
			},
			sourceType: credential.SourceTypeAWS,
		},

		// Neither source may claim the other's mint method.
		{
			name:       "vault mint method on an aws source",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "must be 'secret_read' for a key_value credential on an aws source",
		},
		{
			name:       "transit_signer on an aws source",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k", "jwt_role": "r"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "must be 'secret_read' for a key_value credential on an aws source",
		},
		{
			name:       "aws mint method on an hvault source",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "must be 'kv2_read' or 'transit_signer' for a key_value credential on an hvault source",
		},

		// A locator belonging to the other source would be accepted by the schema and
		// then never read, leaving a spec that reads as configured for something it
		// is not doing.
		{
			name:       "aws locator on an hvault spec",
			config:     map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "github/ci", "secret_id": "prod/app"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'secret_id' does not apply to mint_method=kv2_read",
		},
		{
			name:       "aws role_arn on a transit_signer spec",
			config:     map[string]string{"mint_method": "transit_signer", "transit_key": "k", "jwt_role": "r", "role_arn": "arn:aws:iam::1:role/R"},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'role_arn' does not apply to mint_method=transit_signer",
		},
		{
			name:       "vault locator on an aws spec",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "kv2_mount": "secret"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'kv2_mount' does not apply to mint_method=secret_read",
		},
		{
			name:       "transit locator on an aws spec",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "signing_alg": "rsa-pss-sha256"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'signing_alg' does not apply to mint_method=secret_read",
		},
		{
			name:       "pinned transit key version on an aws spec",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "transit_key_version": "3"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'transit_key_version' does not apply to mint_method=secret_read",
		},
		{
			// The passthrough bag is named by the operator, so it is refused by
			// prefix rather than by enumerating keys that cannot be enumerated.
			name:       "transit payload passthrough on an aws spec",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "payload.client_id": "abc"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'payload.client_id' does not apply to mint_method=secret_read",
		},
		{
			// The driver only refuses credential_type when the operator omits
			// `type` entirely, so an explicit key_value spec would otherwise carry
			// a shape selector that selects nothing.
			name:       "credential_type on an aws secret_read spec",
			config:     map[string]string{"mint_method": "secret_read", "secret_id": "prod/app", "credential_type": "api_key"},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "'credential_type' does not apply to mint_method=secret_read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(credential.NewConfig(tt.config), tt.sourceType)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestKeyValueCredType_Parse_PreservesAllKeys is the crux: unlike BaseTokenType,
// key_value must copy every string field verbatim (no primary field, no dropping).
func TestKeyValueCredType_Parse_PreservesAllKeys(t *testing.T) {
	ct := NewKeyValueCredType()

	rawData := map[string]interface{}{
		"admin_token": "glsa_ABC",
		"private_key": "-----BEGIN...",
		"note":        "arbitrary",
		"count":       42, // non-string values are skipped, not errored
	}

	cred, err := ct.Parse(rawData, nil, 0, "")
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, credential.TypeKeyValue, cred.Type)
	assert.False(t, cred.Revocable)
	assert.Equal(t, time.Duration(0), cred.LeaseTTL)
	assert.Equal(t, "glsa_ABC", cred.Data["admin_token"])
	assert.Equal(t, "-----BEGIN...", cred.Data["private_key"])
	assert.Equal(t, "arbitrary", cred.Data["note"])
	_, hasCount := cred.Data["count"]
	assert.False(t, hasCount, "non-string values should be skipped")
	assert.Len(t, cred.Data, 3)
}

func TestKeyValueCredType_Parse_Errors(t *testing.T) {
	ct := NewKeyValueCredType()

	t.Run("empty rawData", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{}, nil, 0, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrInvalidCredential)
	})

	t.Run("no string fields", func(t *testing.T) {
		_, err := ct.Parse(map[string]interface{}{"n": 1, "b": true}, nil, 0, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrInvalidCredential)
	})
}

func TestKeyValueCredType_Validate(t *testing.T) {
	ct := NewKeyValueCredType()

	t.Run("valid", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeKeyValue,
			Data: map[string]string{"anything": "x"},
		})
		assert.NoError(t, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"anything": "x"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected type key_value")
	})

	t.Run("empty data", func(t *testing.T) {
		err := ct.Validate(&credential.Credential{
			Type: credential.TypeKeyValue,
			Data: map[string]string{},
		})
		require.Error(t, err)
	})
}

func TestKeyValueCredType_NoSecretInConfig(t *testing.T) {
	ct := NewKeyValueCredType()
	assert.False(t, ct.RequiresSpecRotation())
	// The secret lives only in minted Data, never in persisted config.
	assert.Nil(t, ct.SensitiveConfigFields())
	assert.Nil(t, ct.FieldSchemas())
}

// A gcp source reading Secret Manager is the third shape this type carries. The rows
// below pin what distinguishes it: how a secret is addressed, and that a spec cannot
// mix one store's locators into another's.
func TestKeyValueCredType_ValidateConfig_GCP(t *testing.T) {
	ct := NewKeyValueCredType()

	validate := func(cfg map[string]string) error {
		return ct.ValidateConfig(credential.NewConfig(cfg), credential.SourceTypeGCP)
	}

	t.Run("bare id with its project", func(t *testing.T) {
		require.NoError(t, validate(map[string]string{
			"mint_method": "secret_read", "secret_name": "datadog-keys", "project": "acme-prod",
		}))
	})

	t.Run("fully qualified resource", func(t *testing.T) {
		require.NoError(t, validate(map[string]string{
			"mint_method": "secret_read", "secret_name": "projects/acme-prod/secrets/datadog-keys",
		}))
	})

	// The two spellings each name a project, and accepting both at once would leave
	// two answers to the same question with nothing to say which wins.
	t.Run("qualified resource rejects a separate project", func(t *testing.T) {
		err := validate(map[string]string{
			"mint_method": "secret_read", "secret_name": "projects/acme-prod/secrets/datadog-keys",
			"project": "other",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already names its project")
	})

	t.Run("bare id requires a project", func(t *testing.T) {
		err := validate(map[string]string{"mint_method": "secret_read", "secret_name": "datadog-keys"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'project' is required")
	})

	t.Run("secret_name is required", func(t *testing.T) {
		err := validate(map[string]string{"mint_method": "secret_read", "project": "acme-prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_name")
	})

	// A version is a separate key, so a name carrying one would address two at once.
	t.Run("a malformed qualified resource is refused", func(t *testing.T) {
		for _, name := range []string{
			"projects/acme-prod/secrets/datadog-keys/versions/3",
			"projects/acme-prod/secrets",
			"projects//secrets/x",
		} {
			err := validate(map[string]string{"mint_method": "secret_read", "secret_name": name})
			require.Errorf(t, err, "%q must be refused", name)
		}
	})

	t.Run("only secret_read is offered", func(t *testing.T) {
		err := validate(map[string]string{"mint_method": "kv2_read", "secret_name": "x", "project": "p"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be 'secret_read'")
	})

	t.Run("credential_type does not apply", func(t *testing.T) {
		err := validate(map[string]string{
			"mint_method": "secret_read", "secret_name": "x", "project": "p", "credential_type": "api_key",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential_type")
	})

	// A locator belonging to another store would be accepted and then never read,
	// leaving a spec that reads as configured for something it is not doing.
	t.Run("foreign locators are refused", func(t *testing.T) {
		for _, key := range []string{"secret_id", "role_arn", "version_stage", "kv2_mount", "secret_path", "transit_key"} {
			err := validate(map[string]string{
				"mint_method": "secret_read", "secret_name": "x", "project": "p", key: "v",
			})
			require.Errorf(t, err, "%s must be refused on a gcp spec", key)
		}
	})
}

// The rejection runs in every direction: a gcp locator on an hvault or aws spec is as
// inert as an aws locator on a gcp one.
func TestKeyValueCredType_GCPLocatorsRejectedElsewhere(t *testing.T) {
	ct := NewKeyValueCredType()

	for _, key := range []string{"secret_name", "project", "target_service_account"} {
		t.Run("hvault refuses "+key, func(t *testing.T) {
			err := ct.ValidateConfig(credential.NewConfig(map[string]string{
				"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "a/b", key: "v",
			}), credential.SourceTypeVault)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})

		t.Run("aws refuses "+key, func(t *testing.T) {
			err := ct.ValidateConfig(credential.NewConfig(map[string]string{
				"mint_method": "secret_read", "secret_id": "prod/keys", key: "v",
			}), credential.SourceTypeAWS)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}

// A locator becomes a segment of the request path, so its charset is enforced where
// the spec is written. Without this a name carrying "#" or "?" reshapes the request,
// letting a spec read a resource other than the one it appears to name.
func TestKeyValueCredType_GCP_LocatorCharsets(t *testing.T) {
	ct := NewKeyValueCredType()
	validate := func(cfg map[string]string) error {
		return ct.ValidateConfig(credential.NewConfig(cfg), credential.SourceTypeGCP)
	}

	for _, name := range []string{
		"keys/versions/2:access#", "keys?alt=media", "../../other", "with space", "keys#frag",
	} {
		t.Run("bare name rejects "+name, func(t *testing.T) {
			err := validate(map[string]string{"mint_method": "secret_read", "secret_name": name, "project": "acme-prod"})
			require.Errorf(t, err, "%q must be refused", name)
		})
	}

	for _, project := range []string{"p#x", "p?x", "p/x", "with space"} {
		t.Run("project rejects "+project, func(t *testing.T) {
			err := validate(map[string]string{"mint_method": "secret_read", "secret_name": "keys", "project": project})
			require.Errorf(t, err, "%q must be refused", project)
		})
	}

	// A template's value is constrained where it is resolved, so the literal parts
	// around it are what get checked here.
	t.Run("a claim template is allowed in a bare name", func(t *testing.T) {
		require.NoError(t, validate(map[string]string{
			"mint_method": "secret_read", "secret_name": "per-agent-{{agent.sub}}", "project": "acme-prod",
		}))
	})
}

// These configure a token mint. A stored-secret read obtains and discards its own
// token, so both would be accepted and never read.
func TestKeyValueCredType_GCP_RejectsTokenMintKeys(t *testing.T) {
	ct := NewKeyValueCredType()
	for _, key := range []string{"scopes", "lifetime"} {
		err := ct.ValidateConfig(credential.NewConfig(map[string]string{
			"mint_method": "secret_read", "secret_name": "keys", "project": "acme-prod", key: "v",
		}), credential.SourceTypeGCP)
		require.Errorf(t, err, "%s must be refused on a secret_read spec", key)
		assert.Contains(t, err.Error(), key)
	}
}

// Azure fixtures. The ids are real UUIDs so the checks under test are the only reason
// a spec could be refused.
const (
	testKVTenant  = "00000000-0000-0000-0000-000000000001"
	testKVClient  = "11111111-1111-1111-1111-111111111111"
	testKVVersion = "0123456789abcdef0123456789abcdef"
)

func TestKeyValueCredType_ValidateConfig_Azure(t *testing.T) {
	ct := NewKeyValueCredType()
	validate := func(cfg map[string]string) error {
		return ct.ValidateConfig(credential.NewConfig(cfg), credential.SourceTypeAzure)
	}
	federated := func(extra map[string]string) map[string]string {
		cfg := map[string]string{
			"mint_method":                       "secret_read",
			"vault_name":                        "acme-prod-kv",
			"secret_name":                       "datadog-keys",
			"tenant_id":                         testKVTenant,
			"client_id":                         testKVClient,
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
		}
		for k, v := range extra {
			cfg[k] = v
		}
		return cfg
	}
	static := func(extra map[string]string) map[string]string {
		cfg := map[string]string{"mint_method": "secret_read", "vault_name": "acme-prod-kv", "secret_name": "datadog-keys"}
		for k, v := range extra {
			cfg[k] = v
		}
		return cfg
	}

	t.Run("federated read naming its app", func(t *testing.T) {
		require.NoError(t, validate(federated(nil)))
	})

	t.Run("static read as the source", func(t *testing.T) {
		require.NoError(t, validate(static(nil)))
	})

	t.Run("pinned version and key map", func(t *testing.T) {
		require.NoError(t, validate(federated(map[string]string{
			"secret_version": testKVVersion, "json_key_map": "dd_api=api_key",
		})))
	})

	t.Run("templated secret name", func(t *testing.T) {
		require.NoError(t, validate(federated(map[string]string{"secret_name": "agent-{{agent.sub}}"})))
	})

	// The app is what the caller's token is exchanged at, so a federated spec cannot
	// do without it.
	for _, key := range []string{"client_id", "tenant_id"} {
		t.Run("federated requires "+key, func(t *testing.T) {
			cfg := federated(nil)
			delete(cfg, key)
			err := validate(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})

		t.Run("federated "+key+" must be a UUID", func(t *testing.T) {
			err := validate(federated(map[string]string{key: "not-a-uuid"}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be a valid UUID")
		})

		// A static source reads as itself; an app named here would never be used.
		t.Run("static refuses "+key, func(t *testing.T) {
			err := validate(static(map[string]string{key: testKVClient}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "a static source reads as itself")
		})
	}

	t.Run("vault_name and secret_name are required", func(t *testing.T) {
		for _, key := range []string{"vault_name", "secret_name"} {
			cfg := static(nil)
			delete(cfg, key)
			err := validate(cfg)
			require.Errorf(t, err, "missing %s", key)
			assert.Contains(t, err.Error(), key)
		}
	})

	// The vault name becomes the request's host, so anything outside Key Vault's
	// charset could send the Key Vault token somewhere else.
	t.Run("hostile vault names are refused", func(t *testing.T) {
		for _, name := range []string{
			"evil.example/x#", "evil.example", "a", "ab", "1abc", "abc-", "a--b",
			"abcdefghijklmnopqrstuvwxy", "with space", "kv?x", "kv#x",
		} {
			err := validate(static(map[string]string{"vault_name": name}))
			require.Errorf(t, err, "vault_name %q must be refused", name)
		}
	})

	t.Run("a templated vault name is refused", func(t *testing.T) {
		err := validate(federated(map[string]string{"vault_name": "kv-{{agent.sub}}"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not support claim templates")
	})

	t.Run("secret names outside Key Vault's charset are refused", func(t *testing.T) {
		for _, name := range []string{"a/b", "a.b", "a_b", "a?b", "a#b", "../x", strings.Repeat("a", 128)} {
			err := validate(static(map[string]string{"secret_name": name}))
			require.Errorf(t, err, "secret_name %q must be refused", name)
		}
	})

	t.Run("secret_version must be a Key Vault version", func(t *testing.T) {
		for _, v := range []string{"3", "latest", testKVVersion[:31], testKVVersion + "0", "0123456789abcdef0123456789abcde/"} {
			err := validate(static(map[string]string{"secret_version": v}))
			require.Errorf(t, err, "secret_version %q must be refused", v)
		}
	})

	t.Run("only secret_read is offered", func(t *testing.T) {
		err := validate(static(map[string]string{"mint_method": "kv2_read"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be 'secret_read'")
	})

	// key_value masks nothing on read, so a secret here would sit in the clear.
	t.Run("client_secret is refused", func(t *testing.T) {
		err := validate(static(map[string]string{"client_secret": "s"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_secret")
	})

	t.Run("foreign and token-mint keys are refused", func(t *testing.T) {
		for _, key := range []string{
			"secret_id", "role_arn", "kv2_mount", "secret_path", "transit_key",
			"project", "target_service_account", "scopes", "lifetime", "resource_uri", "credential_type",
		} {
			err := validate(static(map[string]string{key: "v"}))
			require.Errorf(t, err, "%s must be refused on an azure spec", key)
			assert.Contains(t, err.Error(), key)
		}
	})
}

// The rejection runs in every direction: an azure locator on another store's spec is
// accepted by the schema and then never read.
func TestKeyValueCredType_AzureLocatorsRejectedElsewhere(t *testing.T) {
	ct := NewKeyValueCredType()
	for _, key := range []string{"vault_name", "client_id", "tenant_id"} {
		for _, tc := range []struct {
			source string
			cfg    map[string]string
		}{
			{credential.SourceTypeVault, map[string]string{"mint_method": "kv2_read", "kv2_mount": "secret", "secret_path": "a/b"}},
			{credential.SourceTypeAWS, map[string]string{"mint_method": "secret_read", "secret_id": "prod/keys"}},
			{credential.SourceTypeGCP, map[string]string{"mint_method": "secret_read", "secret_name": "keys", "project": "acme-prod"}},
		} {
			t.Run(tc.source+" refuses "+key, func(t *testing.T) {
				cfg := map[string]string{key: "v"}
				for k, v := range tc.cfg {
					cfg[k] = v
				}
				err := ct.ValidateConfig(credential.NewConfig(cfg), tc.source)
				require.Error(t, err)
				assert.Contains(t, err.Error(), key)
			})
		}
	}
}

// secret_version is a string in the schema because stores spell a revision
// differently; the numbered stores still refuse anything but a positive integer.
func TestKeyValueCredType_SecretVersionSpelledPerStore(t *testing.T) {
	ct := NewKeyValueCredType()

	gcp := map[string]string{"mint_method": "secret_read", "secret_name": "keys", "project": "acme-prod"}
	for v, ok := range map[string]bool{"3": true, "0": false, "latest": false, testKVVersion: false} {
		cfg := map[string]string{"secret_version": v}
		for k, val := range gcp {
			cfg[k] = val
		}
		err := ct.ValidateConfig(credential.NewConfig(cfg), credential.SourceTypeGCP)
		if ok {
			assert.NoErrorf(t, err, "gcp secret_version %q", v)
		} else {
			assert.Errorf(t, err, "gcp secret_version %q", v)
		}
	}

	err := ct.ValidateConfig(credential.NewConfig(map[string]string{
		"mint_method": "secret_read", "vault_name": "acme-prod-kv", "secret_name": "keys", "secret_version": testKVVersion,
	}), credential.SourceTypeAzure)
	assert.NoError(t, err, "a Key Vault version is accepted on azure")
}
