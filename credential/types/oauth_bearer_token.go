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
func (t *OAuthBearerTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("scope").
			Describe("OAuth2 scope to request (client_credentials)").
			Example("read write"),

		// OAuth2 source - authorization_code / client_credentials fields.
		credential.StringField("auth_method").
			OneOf("client_credentials", "authorization_code").
			Describe("OAuth2 flow for an oauth2 source (default client_credentials)").
			Example("authorization_code"),

		credential.StringField("client_id").
			Describe("OAuth2 client ID (per-spec for authorization_code)").
			Example("aBcD3FgHiJkLmN0pQ"),

		credential.StringField("client_secret").
			Describe("OAuth2 client secret (per-spec for authorization_code; sealed)").
			Example("@/path/to/client_secret"),

		credential.StringField("scopes").
			Describe("OAuth2 scopes for authorization_code (comma- or space-separated)").
			Example("repo,read:org"),

		credential.StringField("redirect_uri").
			Describe("Pinned loopback redirect for connect, when the provider requires an exact callback match (e.g. GitHub)").
			Example("http://127.0.0.1:8765/callback"),

		credential.BoolField("pkce").
			Describe("Send PKCE on connect (default true)").
			Example("true"),

		// Sealed by `cred spec connect`; not operator-set.
		credential.StringField("refresh_token").
			Describe("Sealed at connect time — not operator-set"),
		credential.StringField("access_token").
			Describe("Sealed at connect time for providers without refresh tokens — not operator-set"),
		credential.StringField("refresh_token_expires_at").
			Describe("Sealed at connect time (RFC3339) — not operator-set"),
		credential.StringField("access_token_expires_at").
			Describe("Sealed at connect time for an expiring static access token (RFC3339) — not operator-set"),

		// Vault source - OAuth2 plugin fields
		credential.StringField("mint_method").
			OneOf("oauth2", "iam_token").
			Describe("Mint method (required for vault/ibm source)").
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
	case credential.SourceTypeOAuth2, credential.SourceTypeVault, credential.SourceTypeIBM:
		// Supported
	default:
		return fmt.Errorf("oauth_bearer_token credentials require an oauth2, vault, or ibm source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Source-specific validation
	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "oauth2" {
			return fmt.Errorf("'mint_method' must be 'oauth2' for vault source, got: %s", config["mint_method"])
		}
		if config["oauth2_mount"] == "" {
			return fmt.Errorf("'oauth2_mount' is required when mint_method is oauth2")
		}
		if config["credential_name"] == "" {
			return fmt.Errorf("'credential_name' is required when mint_method is oauth2")
		}
	case credential.SourceTypeIBM:
		// IBM source uses iam_token mint method (default); no additional spec config needed
		if mm := config["mint_method"]; mm != "" && mm != "iam_token" {
			return fmt.Errorf("'mint_method' must be 'iam_token' for ibm source, got: %s", mm)
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
// For authorization_code specs these secrets live on the spec (resolved
// spec-over-source), so they are masked here in addition to the source-level
// masking the driver factory applies.
func (t *OAuthBearerTokenCredType) SensitiveConfigFields() []string {
	return []string{"client_secret", "refresh_token", "access_token"}
}

// Compile-time assertion that the type is connect-gated for authorization_code.
var _ credential.ConnectGated = (*OAuthBearerTokenCredType)(nil)

// RequiresConnect reports whether the spec uses the authorization_code flow, which
// needs a one-time `cred spec connect` before it can mint.
func (t *OAuthBearerTokenCredType) RequiresConnect(config map[string]string) bool {
	return config["auth_method"] == "authorization_code"
}

// IsConnected reports whether the spec has been connected — a refresh token or a
// static access token has been sealed into it.
func (t *OAuthBearerTokenCredType) IsConnected(config map[string]string) bool {
	return config["refresh_token"] != "" || config["access_token"] != ""
}
