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
	}
}

// ValidateConfig validates the Config for an API key credential spec.
// The API key is stored at the spec level (like GitHub PATs). The source only
// holds connection info (api_url). This allows multiple specs with different
// API keys to share one source.
func (t *APIKeyCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	switch sourceType {
	case credential.SourceTypeMistral, credential.SourceTypeOpenAI, credential.SourceTypeAnthropic, credential.SourceTypeSlack, credential.SourceTypePagerDuty, credential.SourceTypeLocal:
		// Supported
	default:
		return fmt.Errorf("api_key credentials require a mistral, openai, anthropic, slack, pagerduty, or local source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: api_key is required for all source types
	if config["api_key"] == "" {
		return fmt.Errorf("'api_key' is required")
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
