package types

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// GCPAccessTokenCredType handles GCP OAuth2 access tokens
type GCPAccessTokenCredType struct {
	*BaseTokenType
}

// NewGCPAccessTokenCredType creates a new GCP access token credential type
func NewGCPAccessTokenCredType() *GCPAccessTokenCredType {
	return &GCPAccessTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeGCPAccessToken,
				Category:    credential.CategoryCloudIAM,
				Description: "GCP OAuth2 access token for Google Cloud API authentication",
				DefaultTTL:  1 * time.Hour,
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "access_token",
				AlternativeFields: []string{},
				OptionalFields:    []string{"project_id", "scopes", "token_type", "target_service_account"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"access_token": {
						Description: "GCP OAuth2 access token for API authentication",
						Sensitive:   true,
					},
					"project_id": {
						Description: "GCP project ID",
						Sensitive:   false,
					},
					"scopes": {
						Description: "OAuth2 scopes the token is authorized for",
						Sensitive:   false,
					},
					"token_type": {
						Description: "Token type (typically 'Bearer')",
						Sensitive:   false,
					},
					"target_service_account": {
						Description: "Impersonated service account email (if impersonation was used)",
						Sensitive:   false,
					},
				},
			},
			Revocable: false, // GCP tokens expire naturally and cannot be revoked
		},
	}
}

// ConfigSchema returns the declarative schema for GCP access token credential config
func (t *GCPAccessTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			OneOf("access_token", "impersonated_access_token").
			Describe("Method for minting GCP access tokens").
			Example("access_token"),

		credential.StringField("scopes").
			Describe("Comma-separated list of OAuth2 scopes (defaults to cloud-platform)").
			Example("https://www.googleapis.com/auth/cloud-platform"),

		credential.StringField("target_service_account").
			Describe("Service account email to impersonate (required for impersonated_access_token)").
			Example("app-backend@my-project.iam.gserviceaccount.com"),

		credential.StringField("project_id").
			Describe("GCP project ID to scope the token to").
			Example("my-gcp-project"),

		credential.StringField("lifetime").
			Describe("Requested token lifetime (max 3600s for impersonated tokens)").
			Example("3600s"),
	}
}

// ValidateConfig validates the Config for a GCP access token credential spec
// sourceType determines the validation rules:
// - "gcp": requires service account configuration for token minting
func (t *GCPAccessTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	if sourceType != credential.SourceTypeGCP {
		return fmt.Errorf("gcp_access_token credentials require a gcp source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: Conditional validation based on mint_method
	mintMethod := credential.GetString(config, "mint_method", "access_token")
	if mintMethod == "impersonated_access_token" {
		if config["target_service_account"] == "" {
			return fmt.Errorf("'target_service_account' is required when mint_method is impersonated_access_token")
		}
	}

	return nil
}

// RequiresSpecRotation indicates that GCP access token specs do NOT embed
// per-spec credentials. All specs share the source SA key, so only source-level
// rotation is needed.
func (t *GCPAccessTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *GCPAccessTokenCredType) SensitiveConfigFields() []string {
	return []string{}
}
