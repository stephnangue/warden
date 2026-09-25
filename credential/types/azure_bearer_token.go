package types

import (
	"fmt"
	"maps"
	"slices"
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
			OneOf("bearer_token").
			Describe("Method for minting Azure credentials").
			Example("bearer_token"),

		credential.StringField("tenant_id").
			Custom(func(v string) error { return credential.ValidateUUID("tenant_id", v) }).
			Describe("Azure AD tenant ID (optional, defaults to source tenant)").
			Example("12345678-1234-1234-1234-123456789012"),

		credential.StringField("client_id").
			Required().
			Custom(func(v string) error { return credential.ValidateUUID("client_id", v) }).
			Describe("Azure AD service principal client ID (application ID)").
			Example("12345678-1234-1234-1234-123456789012"),

		credential.StringField("client_secret").
			Describe("Azure AD service principal client secret (required for static specs; omit for keyless federation)").
			Example("my-client-secret"),

		credential.StringField("secret_id").
			Describe("Azure AD password credential ID for rotation tracking (required for static specs; omit for keyless federation)").
			Example("uuid-secret-id"),

		credential.StringField("resource_uri").
			Describe("Azure resource URI to request a token for; the client-credentials grant asks for its .default scope").
			Example("https://management.azure.com/"),
	}
}

// retiredBearerTokenKeys are keys this type once declared and no longer reads. The
// schema ignores keys it does not know, so without an explicit refusal a spec
// carrying one would be accepted and the key silently ignored — a spec that reads
// as scoped, or as reading a Key Vault secret, while doing neither.
var retiredBearerTokenKeys = map[string]string{
	"scopes":         "the client-credentials grant takes a single '<resource>/.default' scope; set 'resource_uri' instead",
	"vault_name":     "Key Vault reads are no longer an azure_bearer_token mint method",
	"secret_name":    "Key Vault reads are no longer an azure_bearer_token mint method",
	"secret_version": "Key Vault reads are no longer an azure_bearer_token mint method",
}

// ValidateConfig validates the Config for an Azure Bearer token credential spec
// sourceType determines the validation rules:
// - "azure": requires service principal configuration for token minting
func (t *AzureBearerTokenCredType) ValidateConfig(config credential.Config, sourceType string) error {
	// Step 1: Validate source type compatibility
	if sourceType != credential.SourceTypeAzure {
		return fmt.Errorf("azure_bearer_token credentials require an azure source, got: %s", sourceType)
	}

	// Checked ahead of the schema so the refusal names the retirement rather than
	// listing the one method that is left.
	if config.Get("mint_method") == "key_vault_secret" {
		return fmt.Errorf("mint_method 'key_vault_secret' is no longer supported for azure_bearer_token")
	}
	for _, key := range slices.Sorted(maps.Keys(retiredBearerTokenKeys)) {
		if config.Get(key) != "" {
			return fmt.Errorf("'%s' is not supported by azure_bearer_token: %s", key, retiredBearerTokenKeys[key])
		}
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: Cross-field rules for keyless federation vs static specs.
	// A federated spec (subject_token_source set) presents a Warden assertion as a
	// client_assertion, so it holds no client_secret. The audience/algorithm rules
	// for warden_identity are enforced generically by ValidateExchangeSpecConfig.
	mintMethod := config.Get("mint_method")
	if credential.SpecRequestsExchange(config) {
		if config.Get("tenant_id") == "" {
			return fmt.Errorf("'tenant_id' is required for a keyless federated spec (a spec with subject_token_source)")
		}
		if config.Get("client_secret") != "" || config.Get("secret_id") != "" {
			return fmt.Errorf("'client_secret'/'secret_id' must not be set for a keyless federated spec")
		}
		if mintMethod != "" && mintMethod != "bearer_token" {
			return fmt.Errorf("mint_method %q is not supported over federation (supported: bearer_token)", mintMethod)
		}
	} else {
		if config.Get("client_secret") == "" || config.Get("secret_id") == "" {
			return fmt.Errorf("'client_secret' and 'secret_id' are required for a static azure spec")
		}
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
