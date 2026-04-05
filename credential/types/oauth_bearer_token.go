package types

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// OAuthBearerTokenCredType handles OAuth2 bearer tokens minted via client credentials flow.
type OAuthBearerTokenCredType struct {
	*BaseTokenType
}

// NewOAuthBearerTokenCredType creates a new OAuth bearer token credential type.
func NewOAuthBearerTokenCredType() *OAuthBearerTokenCredType {
	return &OAuthBearerTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeOAuthBearerToken,
				Category:    credential.CategoryOAuth,
				Description: "OAuth2 bearer token for provider authentication",
				DefaultTTL:  1 * time.Hour,
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "api_key",
				AlternativeFields: []string{"access_token"},
				OptionalFields:    []string{"scope", "token_type"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"api_key": {
						Description: "OAuth2 bearer token for authentication",
						Sensitive:   true,
					},
					"scope": {
						Description: "OAuth2 scope granted",
						Sensitive:   false,
					},
					"token_type": {
						Description: "Token type (typically Bearer)",
						Sensitive:   false,
					},
				},
			},
			Revocable: false,
		},
	}
}

// ConfigSchema returns the declarative schema for OAuth bearer token spec config.
// The spec holds only the scope — the driver mints the token dynamically.
func (t *OAuthBearerTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("scope").
			Describe("OAuth2 scope to request").
			Example("read write"),

		// Vault source - OAuth2 plugin fields
		credential.StringField("mint_method").
			OneOf("oauth2").
			Describe("Mint method (required for vault source)").
			Example("oauth2"),

		credential.StringField("oauth2_mount").
			Describe("Vault OAuth2 secrets engine mount (required for oauth2 mint_method)").
			Example("oauth2"),

		credential.StringField("credential_name").
			Describe("Credential name in the OAuth2 plugin (required for oauth2 mint_method)").
			Example("my-oauth-cred"),
	}
}

// ValidateConfig validates the Config for an OAuth bearer token credential spec.
func (t *OAuthBearerTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeOAuth2, credential.SourceTypeVault:
		// Supported
	default:
		return fmt.Errorf("oauth_bearer_token credentials require an oauth2 or vault source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Vault source requires oauth2 mint_method with mount and credential_name
	if sourceType == credential.SourceTypeVault {
		if config["mint_method"] != "oauth2" {
			return fmt.Errorf("'mint_method' must be 'oauth2' for vault source, got: %s", config["mint_method"])
		}
		if config["oauth2_mount"] == "" {
			return fmt.Errorf("'oauth2_mount' is required when mint_method is oauth2")
		}
		if config["credential_name"] == "" {
			return fmt.Errorf("'credential_name' is required when mint_method is oauth2")
		}
	}

	return nil
}

// RequiresSpecRotation returns false — the driver mints fresh tokens, no
// credentials are embedded in the spec.
func (t *OAuthBearerTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output.
func (t *OAuthBearerTokenCredType) SensitiveConfigFields() []string {
	return nil
}
