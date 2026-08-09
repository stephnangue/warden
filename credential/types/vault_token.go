package types

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// VaultTokenCredType handles HashiCorp Vault authentication tokens
type VaultTokenCredType struct {
	*BaseTokenType
}

// NewVaultTokenCredType creates a new Vault token credential type
func NewVaultTokenCredType() *VaultTokenCredType {
	return &VaultTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeVaultToken,
				Category:    credential.CategoryAPI,
				Description: "HashiCorp Vault authentication token",
				DefaultTTL:  1 * time.Hour,
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "token",
				AlternativeFields: []string{"client_token"}, // Vault auth responses use client_token
				OptionalFields:    []string{},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"token": {
						Description: "Vault authentication token",
						Sensitive:   true,
					},
				},
			},
			Revocable: true, // Vault tokens can be revoked
		},
	}
}

// ConfigSchema returns the declarative schema for Vault token credential spec config
func (t *VaultTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			Required().
			OneOf("vault_token").
			Describe("Method for minting Vault tokens").
			Example("vault_token"),

		credential.StringField("token_role").
			Describe("Vault token role for the static path (auth/token/create/{token_role}); required unless subject_token_source is set, where the exchanged/login token is vended directly and token_role must be omitted").
			Example("app-backend"),

		credential.DurationField("ttl").
			Describe("Token time-to-live (defaults to role TTL if not specified)").
			Example("1h"),

		credential.StringField("display_name").
			Describe("Token display name for identification in Vault UI").
			Example("warden-app-backend"),

		credential.StringField("meta").
			Describe("Token metadata as comma-separated key=value pairs").
			Example("app=backend,env=prod"),
	}
}

// ValidateConfig validates the Config for a Vault token credential spec
// sourceType determines the validation rules:
// - "hvault": requires auth configuration to generate tokens
func (t *VaultTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	if sourceType != credential.SourceTypeVault {
		return fmt.Errorf("vault_token credentials require a vault source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: token_role governs only the static path, where the token is minted via
	// auth/token/create/{token_role}. Any exchange spec (subject_token_source set —
	// warden_identity, auth_token, header) vends the exchanged/login token directly
	// and never consults token_role, so require it off the exchange path and reject a
	// set-but-ignored token_role on it rather than silently dropping the operator's
	// intent (which would vend a token with the wrong policy set). The credential type
	// sees the spec config, so it distinguishes the two without the source config.
	if credential.SpecRequestsExchange(config) {
		if config["token_role"] != "" {
			return fmt.Errorf("field 'token_role' is not used when '%s' is set: an exchange-minted vault_token vends the exchanged token directly", credential.ConfigSubjectTokenSource)
		}
	} else if config["token_role"] == "" {
		return fmt.Errorf("field 'token_role' is required for mint_method=vault_token")
	}

	return nil
}

// RequiresSpecRotation returns false — Vault token specs don't embed
// rotatable credentials; the source driver handles token rotation.
func (t *VaultTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *VaultTokenCredType) SensitiveConfigFields() []string {
	return nil
}
