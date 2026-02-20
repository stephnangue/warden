package types

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// AzureBearerTokenCredType handles Azure AD Bearer tokens
type AzureBearerTokenCredType struct {
	*BaseTokenType
}

// NewAzureBearerTokenCredType creates a new Azure bearer token credential type
func NewAzureBearerTokenCredType() *AzureBearerTokenCredType {
	return &AzureBearerTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeAzureBearerToken,
				Category:    credential.CategoryCloudIAM,
				Description: "Azure AD Bearer token for Azure service authentication",
				DefaultTTL:  1 * time.Hour, // Azure tokens typically expire in 1 hour
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "access_token",
				AlternativeFields: []string{},
				OptionalFields:    []string{"resource_uri", "tenant_id", "client_id", "token_type"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"access_token": {
						Description: "Azure AD Bearer token for API authentication",
						Sensitive:   true,
					},
					"resource_uri": {
						Description: "Azure resource URI the token is valid for",
						Sensitive:   false,
					},
					"tenant_id": {
						Description: "Azure AD tenant ID",
						Sensitive:   false,
					},
					"client_id": {
						Description: "Service principal client ID",
						Sensitive:   false,
					},
					"token_type": {
						Description: "Token type (typically 'Bearer')",
						Sensitive:   false,
					},
				},
			},
			Revocable: false, // Azure tokens expire naturally and cannot be revoked
		},
	}
}

// ConfigSchema returns the declarative schema for Azure bearer token credential config
func (t *AzureBearerTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			OneOf("bearer_token", "key_vault_secret").
			Describe("Method for minting Azure credentials").
			Example("bearer_token"),

		credential.StringField("tenant_id").
			Describe("Azure AD tenant ID (optional, defaults to source tenant)").
			Example("12345678-1234-1234-1234-123456789012"),

		credential.StringField("client_id").
			Required().
			Describe("Azure AD service principal client ID (application ID)").
			Example("12345678-1234-1234-1234-123456789012"),

		credential.StringField("client_secret").
			Required().
			Describe("Azure AD service principal client secret").
			Example("my-client-secret"),

		credential.StringField("secret_id").
			Required().
			Describe("Azure AD password credential ID for rotation tracking").
			Example("uuid-secret-id"),

		credential.StringField("resource_uri").
			Describe("Azure resource URI to request token for (bearer_token method)").
			Example("https://management.azure.com/"),

		credential.StringField("scopes").
			Describe("Comma-separated list of OAuth2 scopes (bearer_token method)").
			Example("https://graph.microsoft.com/.default"),

		// Key Vault Secret fields
		credential.StringField("vault_name").
			Describe("Azure Key Vault name (required for key_vault_secret method)").
			Example("my-keyvault"),

		credential.StringField("secret_name").
			Describe("Key Vault secret name (required for key_vault_secret method)").
			Example("database-password"),

		credential.StringField("secret_version").
			Describe("Key Vault secret version (optional, defaults to latest)").
			Example("abc123def456"),
	}
}

// ValidateConfig validates the Config for an Azure Bearer token credential spec
// sourceType determines the validation rules:
// - "azure": requires service principal configuration for token minting
func (t *AzureBearerTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	if sourceType != credential.SourceTypeAzure {
		return fmt.Errorf("azure_bearer_token credentials require an azure source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	return nil
}

// RequiresSpecRotation indicates that Azure Bearer Token specs embed SP credentials
// (client_secret, secret_id) that must be rotated. rotation_period is mandatory.
func (t *AzureBearerTokenCredType) RequiresSpecRotation() bool {
	return true
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *AzureBearerTokenCredType) SensitiveConfigFields() []string {
	return []string{"client_secret", "secret_id"}
}
