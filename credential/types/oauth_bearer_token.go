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
	}
}

// ValidateConfig validates the Config for an OAuth bearer token credential spec.
func (t *OAuthBearerTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypePagerDutyOAuth:
		// Supported OAuth2 source types
	default:
		return fmt.Errorf("oauth_bearer_token credentials require an OAuth2 source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
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
