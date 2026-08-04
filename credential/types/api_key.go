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
				OptionalFields:    []string{"key_id", "key_name", "organization_id", "project_id"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"api_key": {
						Description: "API key for authentication",
						Sensitive:   true,
					},
					"key_id": {
						Description: "Key identifier (if available from provider)",
						Sensitive:   false,
					},
					"key_name": {
						Description: "Human-readable key name",
						Sensitive:   false,
					},
					"organization_id": {
						Description: "Organization identifier",
						Sensitive:   false,
					},
					"project_id": {
						Description: "Project identifier",
						Sensitive:   false,
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

		credential.StringField("organization_id").
			Describe("Organization ID (optional)").
			Example("org-xxxxxxxxxxxx"),

		credential.StringField("project_id").
			Describe("Project ID (optional)").
			Example("proj-xxxxxxxxxxxx"),

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
		if config["api_key"] == "" {
			return fmt.Errorf("'api_key' is required")
		}
	}

	return nil
}

// RequiresSpecRotation returns false — API keys live in source config, not spec.
func (t *APIKeyCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *APIKeyCredType) SensitiveConfigFields() []string {
	return []string{"api_key"}
}
