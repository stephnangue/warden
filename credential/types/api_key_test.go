package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyCredType_Metadata(t *testing.T) {
	ct := NewAPIKeyCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeAPIKey, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Contains(t, metadata.Description, "API key")
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

// TestAPIKeyCredType_ValidateConfig_AWSSource covers an API key sourced from AWS
// Secrets Manager: the key comes from the fetched secret, so the spec validates the
// fetch config (secret_id, role_arn for keyless) instead of requiring an api_key field.
func TestAPIKeyCredType_ValidateConfig_AWSSource(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid static secrets_manager",
			config:  map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/app/openai"},
			wantErr: false,
		},
		{
			name:    "missing secret_id",
			config:  map[string]string{"mint_method": "secrets_manager"},
			wantErr: true,
			errMsg:  "secret_id",
		},
		{
			name:    "wrong mint_method for aws source",
			config:  map[string]string{"mint_method": "sts_assume_role"},
			wantErr: true,
			errMsg:  "secrets_manager",
		},
		{
			name:    "keyless requires role_arn",
			config:  map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/app/openai", "subject_token_source": "warden_identity"},
			wantErr: true,
			errMsg:  "role_arn",
		},
		{
			name:    "keyless valid with role_arn",
			config:  map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/app/openai", "subject_token_source": "warden_identity", "role_arn": "arn:aws:iam::1:role/x"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, credential.SourceTypeAWS)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPIKeyCredType_ValidateConfig(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		// --- apikey source ---
		{
			name: "apikey source - valid config",
			config: map[string]string{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - with organization_id",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - with organization_id and project_id",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
				"project_id":      "proj-456",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name:       "apikey source - missing api_key",
			config:     map[string]string{},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    true,
			errMsg:     "api_key",
		},
		// --- Local source ---
		{
			name: "local source - valid config",
			config: map[string]string{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name: "local source - with optional fields",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name:       "local source - missing api_key",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "api_key",
		},
		{
			name: "local source - empty api_key",
			config: map[string]string{
				"api_key": "",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "api_key",
		},
		// --- Sources that create the key upstream ---
		//
		// These carry no api_key in the spec: the driver creates a fresh key at
		// the upstream on every mint. Their absence from the allowlist made all
		// three drivers unreachable, since nothing else accepts their source.
		{
			name:       "elastic source - no api_key required",
			config:     map[string]string{},
			sourceType: credential.SourceTypeElastic,
			wantErr:    false,
		},
		{
			name: "elastic source - full mint config",
			config: map[string]string{
				"key_name":         "ingest-writer",
				"expiration":       "30d",
				"role_descriptors": `{"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}`,
			},
			sourceType: credential.SourceTypeElastic,
			wantErr:    false,
		},
		{
			name:       "elastic source - empty expiration is refused",
			config:     map[string]string{"expiration": ""},
			sourceType: credential.SourceTypeElastic,
			wantErr:    true,
			errMsg:     "must not be empty",
		},
		{
			name:       "elastic source - Go duration notation is refused",
			config:     map[string]string{"expiration": "1h30m"},
			sourceType: credential.SourceTypeElastic,
			wantErr:    true,
			errMsg:     "not an Elasticsearch time value",
		},
		{
			name:       "elastic source - malformed role_descriptors",
			config:     map[string]string{"role_descriptors": "{not json"},
			sourceType: credential.SourceTypeElastic,
			wantErr:    true,
			errMsg:     "role_descriptors",
		},
		{
			// elastic chains at the source, not the spec: the fetched key
			// authenticates the source's own Security API calls. "not supported"
			// would be false, so the message says where it belongs.
			name:       "elastic source - spec-level secret_spec points at the source",
			config:     map[string]string{credential.ConfigSecretSpec: "es-cluster-key"},
			sourceType: credential.SourceTypeElastic,
			wantErr:    true,
			errMsg:     "set secret_spec on the source",
		},
		{
			name:       "grafana source - no api_key required",
			config:     map[string]string{"role": "Viewer"},
			sourceType: credential.SourceTypeGrafana,
			wantErr:    false,
		},
		{
			name:       "honeycomb source - no api_key required",
			config:     map[string]string{"key_type": "ingest"},
			sourceType: credential.SourceTypeHoneycomb,
			wantErr:    false,
		},
		// --- Unsupported source types ---
		{
			name: "unsupported source type - github",
			config: map[string]string{
				"api_key": "sk-test",
			},
			sourceType: "github",
			wantErr:    true,
			errMsg:     "require an apikey, local, vault, aws, elastic, grafana, or honeycomb source",
		},
		// --- Vault source ---
		{
			name: "vault source - valid static_apikey config",
			config: map[string]string{
				"mint_method": "static_apikey",
				"kv2_mount":   "secret",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name: "vault source - missing mint_method",
			config: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'mint_method' must be 'static_apikey'",
		},
		{
			name: "vault source - missing kv2_mount",
			config: map[string]string{
				"mint_method": "static_apikey",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'kv2_mount' is required",
		},
		{
			name: "vault source - missing secret_path",
			config: map[string]string{
				"mint_method": "static_apikey",
				"kv2_mount":   "secret",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'secret_path' is required",
		},
		// --- Credential chaining (secret_spec) ---
		{
			name: "apikey source - chained (secret_spec, no api_key)",
			config: map[string]string{
				"secret_spec":  "openai-key-in-vault",
				"secret_field": "api_key",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - chained without secret_field (single-key auto-detect)",
			config: map[string]string{
				"secret_spec": "openai-key-in-vault",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - api_key and secret_spec are mutually exclusive",
			config: map[string]string{
				"api_key":     "sk-inline",
				"secret_spec": "openai-key-in-vault",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    true,
			errMsg:     "mutually exclusive",
		},
		{
			name: "local source - secret_spec not supported",
			config: map[string]string{
				"secret_spec": "openai-key-in-vault",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "not supported with a local source",
		},
		{
			name: "vault source - secret_spec not supported",
			config: map[string]string{
				"mint_method": "static_apikey",
				"kv2_mount":   "secret",
				"secret_path": "apikeys/my-service",
				"secret_spec": "openai-key-in-vault",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "not supported with a hvault source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, tt.sourceType)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPIKeyCredType_Parse(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		metadata map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid api_key",
			rawData: map[string]interface{}{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			metadata: nil,
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid api_key with optional fields",
			rawData: map[string]interface{}{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"key_id":          "key-123",
				"key_name":        "production-key",
				"organization_id": "org-456",
			},
			metadata: nil,
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name:     "missing api_key",
			rawData:  map[string]interface{}{},
			metadata: map[string]interface{}{},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid api_key",
		},
		{
			name: "empty api_key",
			rawData: map[string]interface{}{
				"api_key": "",
			},
			metadata: nil,
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := ct.Parse(tt.rawData, tt.metadata, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
				assert.Equal(t, credential.TypeAPIKey, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["api_key"])
				// Static keys are never revocable
				assert.False(t, cred.Revocable)
			}
		})
	}
}

// TestAPIKeyCredType_Parse_CarriesOnlyTheKey pins that this type owns exactly one
// field. Adjuncts reach a credential through operator-declared carriage, applied
// by the parser after Parse — not through a list here, which could only ever hold
// the fields anticipated when the type was written.
//
// The inversion is the point: these same names used to be copied, and a
// reinstated OptionalFields list would make this test fail rather than silently
// reintroduce the ceiling that left provider extractors unreachable.
func TestAPIKeyCredType_Parse_CarriesOnlyTheKey(t *testing.T) {
	ct := NewAPIKeyCredType()

	rawData := map[string]interface{}{
		"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
		"key_id":          "key-123",
		"key_name":        "production-key",
		"organization_id": "org-456",
		"project_id":      "proj-789",
	}

	cred, err := ct.Parse(rawData, nil, 0, "")
	require.NoError(t, err)

	assert.Equal(t, "sk-xxxxxxxxxxxxxxxxxxxx", cred.Data["api_key"])
	assert.Len(t, cred.Data, 1, "Parse must carry api_key and nothing else: %v", cred.Data)
}

func TestAPIKeyCredType_Validate(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type api_key",
		},
		{
			name: "missing api_key",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
		{
			name: "empty api_key",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"api_key": "",
				},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.Validate(tt.cred)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPIKeyCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewAPIKeyCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestAPIKeyCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewAPIKeyCredType()
	fields := ct.SensitiveConfigFields()
	assert.Len(t, fields, 2)
	assert.Contains(t, fields, "api_key")
	// A second secret, so it must be named: masking is the one thing an operator
	// cannot be asked to declare, since forgetting would print the key.
	assert.Contains(t, fields, "application_key")
}

// TestAPIKeyCredType_SensitiveConfigFieldsFor covers the three outcomes of
// config-aware masking, which a fixed list cannot express.
func TestAPIKeyCredType_SensitiveConfigFieldsFor(t *testing.T) {
	ct := NewAPIKeyCredType()

	fields := ct.SensitiveConfigFieldsFor(map[string]string{
		"api_key":         "sk-xxxx",
		"application_key": "app-xxxx",
		"organization_id": "org-1",
		"mint_method":     "static_apikey",
		"secret_path":     "apikeys/thing",
		"totally_unknown": "could be anything",
	})

	// Known secrets.
	assert.Contains(t, fields, "api_key")
	assert.Contains(t, fields, "application_key")

	// Declared adjunct: readable, because the type knows what it is.
	assert.NotContains(t, fields, "organization_id")

	// Mint locators: readable, because masking where a credential comes from
	// hides useful information and protects nothing.
	assert.NotContains(t, fields, "mint_method")
	assert.NotContains(t, fields, "secret_path")

	// Undeclared: the type cannot vouch for it, so it fails safe.
	assert.Contains(t, fields, "totally_unknown")
}

// TestAPIKeyCredType_SensitiveConfigFieldsFor_UnderscorePrefixIsNotTrusted pins
// the one exemption that must not apply here.
//
// The "__" namespace belongs to the mint pipeline, and carriage treats it as
// reserved for exactly that reason. Spec config is different: nothing rejects a
// key called "__whatever", so trusting the prefix would leave the single shape of
// unknown key that reads back in the clear.
func TestAPIKeyCredType_SensitiveConfigFieldsFor_UnderscorePrefixIsNotTrusted(t *testing.T) {
	ct := NewAPIKeyCredType()
	fields := ct.SensitiveConfigFieldsFor(map[string]string{
		"api_key":          "sk-xxxx",
		"__adjunct_fields": "organization_id",
		"__anything":       "could be a secret",
	})
	assert.Contains(t, fields, "__adjunct_fields")
	assert.Contains(t, fields, "__anything")
}

func TestAPIKeyCredType_FieldSchemas(t *testing.T) {
	ct := NewAPIKeyCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "api_key")
	assert.True(t, schemas["api_key"].Sensitive)
	assert.NotEmpty(t, schemas["api_key"].Description)

	// The adjuncts are no longer type-owned data fields, so they have no schema
	// here — they are declared in ConfigSchema, which is what documents them and
	// keeps them readable on a spec read.
	assert.Len(t, schemas, 1)
}

// TestAPIKeyCredType_KnownAdjunctFieldsAreDeclared keeps the two lists in step.
// A name in KnownAdjunctFields but not in ConfigSchema would be rejected as
// undeclared when set, yet masked as unknown when read — a field the type both
// insists on and refuses to recognise.
func TestAPIKeyCredType_KnownAdjunctFieldsAreDeclared(t *testing.T) {
	ct := NewAPIKeyCredType()

	declared := make(map[string]bool)
	for _, v := range ct.ConfigSchema() {
		declared[v.FieldName()] = true
	}

	for _, field := range ct.KnownAdjunctFields() {
		assert.True(t, declared[field], "adjunct %q must be declared in ConfigSchema", field)
	}
}

func TestValidateElasticTimeValue(t *testing.T) {
	valid := []string{"1h", "24h", "30d", "90m", "45s", "500ms", "1000micros", "5nanos"}
	for _, v := range valid {
		t.Run("valid/"+v, func(t *testing.T) {
			assert.NoError(t, validateElasticTimeValue(v))
		})
	}

	// The Go-notation values are the point of having a parser of our own:
	// time.ParseDuration accepts the last three and rejects "30d", which is the
	// value the driver documentation leads with.
	invalid := []string{"", "30", "d", "1.5h", "-1h", "1h30m", "30 days", "forever", "0h"}
	for _, v := range invalid {
		t.Run("invalid/"+v, func(t *testing.T) {
			assert.Error(t, validateElasticTimeValue(v))
		})
	}
}
