package types

import (
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// APIKeyCredType handles static API key credentials (OpenAI, Anthropic, Mistral, Slack, etc.)
type APIKeyCredType struct {
	*BaseTokenType
}

// NewAPIKeyCredType creates a new API key credential type
func NewAPIKeyCredType() *APIKeyCredType {
	return &APIKeyCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeAPIKey,
				Category:    credential.CategoryAPI,
				Description: "API key for provider authentication (OpenAI, Anthropic, Mistral, Slack, etc.)",
				DefaultTTL:  0, // Static API keys have no default TTL
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "api_key",
				AlternativeFields: []string{},

				// Empty by design. api_key is the only field this type owns;
				// every adjunct — an organization, a second key, an account
				// identity — is named by the operator in the source's
				// credential_fields and carried by the parser.
				//
				// A fixed list here could only hold fields anticipated when the
				// type was written, which is what left several provider
				// extractors reading credential data nothing could supply. The
				// declared route has no such ceiling: a new provider field costs
				// no change to this type.
				OptionalFields: []string{},

				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"api_key": {
						Description: "API key for authentication",
						Sensitive:   true,
					},
				},
			},
			Revocable: false, // Static API keys are not revocable via lease
		},
	}
}

// ConfigSchema returns the declarative schema for API key credential config.
// The API key is stored at the spec level (like GitHub PATs), not on the source.
func (t *APIKeyCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("api_key").
			Describe("API key for provider authentication").
			Example("sk-xxxxxxxxxxxxxxxxxxxx"),

		// Adjunct fields: everything a credential carries beyond api_key. Declaring
		// one here documents it and marks it known — which is what keeps it
		// readable, since masking treats an undeclared spec-config key as a
		// possible secret. Declaring does NOT carry it: on an apikey source a field
		// travels only when the source's credential_fields names it.
		credential.StringField("organization_id").
			Describe("Organization ID (optional)").
			Example("org-xxxxxxxxxxxx"),

		credential.StringField("project_id").
			Describe("Project ID (optional)").
			Example("proj-xxxxxxxxxxxx"),

		credential.StringField("key_id").
			Describe("Key identifier (optional; honeycomb uses it to select management-key mode)").
			Example("hcaik_xxxxxxxxxxxx"),

		credential.StringField("key_name").
			Describe("Human-readable key name (optional)").
			Example("warden-prod"),

		credential.StringField("email").
			Describe("Account identity paired with the key (optional; atlassian uses it for Basic auth)").
			Example("svc@example.com"),

		credential.StringField("application_key").
			Describe("Second API key some providers require alongside api_key (optional; datadog)").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		// Store-backed sources (vault static_apikey, aws secrets_manager)
		credential.StringField("mint_method").
			OneOf("static_apikey", "secrets_manager").
			Describe("Mint method (required for vault or aws source)").
			Example("static_apikey"),

		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_apikey)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_apikey)").
			Example("apikeys/my-service"),

		// AWS source - Secrets Manager fields. The fetched secret must contain an
		// api_key field (or be remapped to one via json_key_map).
		credential.StringField("credential_type").
			OneOf(credential.TypeAPIKey).
			Describe("Selects the api_key shape for a Secrets Manager secret").
			Example(credential.TypeAPIKey),

		credential.StringField("secret_id").
			Describe("AWS Secrets Manager secret ID (required for secrets_manager)").
			Example("prod/app/openai"),

		credential.StringField("role_arn").
			Describe("IAM role ARN to assume via web identity (required for keyless secrets_manager)").
			Example("arn:aws:iam::123456789012:role/WardenSecretsReader"),

		credential.StringField("version_stage").
			Describe("Secrets Manager version stage (optional, defaults to AWSCURRENT)").
			Example("AWSCURRENT"),

		credential.StringField("version_id").
			Describe("Specific Secrets Manager version ID (optional)").
			Example("uuid-version-id"),

		// Credential chaining (apikey source): source the api_key from another cred spec
		// instead of storing it inline, making the spec keyless.
		credential.StringField(credential.ConfigSecretSpec).
			Describe("Name of a cred spec that yields the api_key instead of storing it inline (credential chaining)").
			Example("openai-key-in-vault"),

		credential.StringField(credential.ConfigSecretField).
			Describe("Which key of the referenced secret_spec's data holds the api_key; optional when the payload is single-key").
			Example("api_key"),

		credential.DurationField(credential.ConfigSecretCacheTTL).
			Describe("Cache the chained api_key source-wide for this duration (e.g. 30m); omit to fetch on every mint").
			Example("30m"),
	}
}

// ValidateConfig validates the Config for an API key credential spec.
// The API key is stored at the spec level (like GitHub PATs). The source only
// holds connection info (api_url). This allows multiple specs with different
// API keys to share one source.
func (t *APIKeyCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	switch sourceType {
	case credential.SourceTypeAPIKey, credential.SourceTypeLocal, credential.SourceTypeVault, credential.SourceTypeAWS:
		// Supported
	default:
		return fmt.Errorf("api_key credentials require an apikey, local, vault, or aws source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Credential chaining is only meaningful for the apikey source, whose key is
	// otherwise stored inline in the spec. The other source types fetch the key from
	// their own backend (Vault KV / Secrets Manager), and local has no keyless path —
	// reject secret_spec there rather than letting it fail late at mint time.
	if config[credential.ConfigSecretSpec] != "" && sourceType != credential.SourceTypeAPIKey {
		return fmt.Errorf("secret_spec (credential chaining) is not supported with a %s source", sourceType)
	}

	// Step 3: Source-specific validation
	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_apikey" {
			return fmt.Errorf("'mint_method' must be 'static_apikey' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_apikey")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_apikey")
		}
	case credential.SourceTypeAWS:
		// The API key is read from AWS Secrets Manager, not carried in the spec, so
		// validate the fetch config (shared with aws_access_keys) rather than requiring
		// an api_key field here. The secret's payload must contain api_key (or be
		// remapped to it via json_key_map).
		if config["mint_method"] != "secrets_manager" {
			return fmt.Errorf("'mint_method' must be 'secrets_manager' for an aws source, got: %s", config["mint_method"])
		}
		return validateAWSSecretsManagerSpecConfig(config)
	default:
		// apikey source: the api_key lives inline in the spec, unless it is sourced from
		// another cred spec via credential chaining (secret_spec) — the two are mutually
		// exclusive. (local reaches here only when secret_spec is unset; the guard above
		// rejects a chained local spec.)
		if config[credential.ConfigSecretSpec] != "" {
			if config["api_key"] != "" {
				return fmt.Errorf("'api_key' and 'secret_spec' are mutually exclusive (the key is fetched from the referenced secret_spec)")
			}
		} else if config["api_key"] == "" {
			return fmt.Errorf("'api_key' is required")
		}
	}

	return nil
}

// RequiresSpecRotation returns false — API keys live in source config, not spec.
func (t *APIKeyCredType) RequiresSpecRotation() bool {
	return false
}

// apiKeyAdjunctFields are the spec-config keys that describe the credential
// rather than the mint. Declared in ConfigSchema so they read back unmasked, and
// listed here so a spec setting one that its source will not carry is rejected
// instead of minting a credential silently missing it.
//
// A provider needing a field absent from this list still works — the operator
// names it in credential_fields and it is carried. The list only decides which
// names Warden can give a helpful error about.
var apiKeyAdjunctFields = []string{
	"organization_id", "project_id", "key_id", "key_name", "email", "application_key",
}

// KnownAdjunctFields implements credential.AdjunctCarrier.
func (t *APIKeyCredType) KnownAdjunctFields() []string { return apiKeyAdjunctFields }

// SensitiveConfigFields returns spec config keys that should be masked in output.
// The known secrets — see SensitiveConfigFieldsFor for the fields an operator adds
// that this list cannot anticipate.
func (t *APIKeyCredType) SensitiveConfigFields() []string {
	return []string{"api_key", "application_key"}
}

// SensitiveConfigFieldsFor masks the known secrets plus every spec-config key the
// type does not recognise (credential.ConfigSensitivity).
//
// An api_key spec may carry adjunct fields declared by the operator rather than by
// this type, so a fixed list cannot say which are secret. An unrecognised key is
// therefore masked: it was put there to be part of the credential, and the type
// has no basis for calling it public. Declaring a field in ConfigSchema is how it
// becomes readable — which is why the non-secret adjuncts are declared there.
//
// Reserved keys stay visible: mint locators and chaining references address the
// mint rather than describing the credential, and masking a secret_path would hide
// where a credential comes from while protecting nothing.
func (t *APIKeyCredType) SensitiveConfigFieldsFor(config map[string]string) []string {
	fields := t.SensitiveConfigFields()

	known := make(map[string]bool, len(t.ConfigSchema()))
	for _, v := range t.ConfigSchema() {
		known[v.FieldName()] = true
	}

	for key := range config {
		// Named reserved keys only. IsReservedSpecConfigKey also matches the "__"
		// prefix, which is right for carriage — those belong to the mint pipeline
		// — but wrong here: nothing rejects a spec-config key called "__whatever",
		// so exempting the prefix would leave the one shape of unknown key that
		// reads back in the clear.
		if known[key] || credential.IsReservedSpecConfigName(key) {
			continue
		}
		fields = append(fields, key)
	}
	return fields
}
