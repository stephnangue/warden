package types

import (
	"encoding/pem"
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// GitHubTokenCredType handles GitHub tokens (App installation tokens and PATs)
type GitHubTokenCredType struct {
	*BaseTokenType
}

// NewGitHubTokenCredType creates a new GitHub token credential type
func NewGitHubTokenCredType() *GitHubTokenCredType {
	return &GitHubTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeGitHubToken,
				Category:    credential.CategoryAPI,
				Description: "GitHub token for API authentication (App installation token or PAT)",
				DefaultTTL:  0, // App tokens: 1h (set by driver), PATs: no expiry
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "token",
				AlternativeFields: []string{},
				OptionalFields:    []string{"expires_at", "permissions"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"token": {
						Description: "GitHub token for API authentication",
						Sensitive:   true,
					},
					"expires_at": {
						Description: "Token expiration time (ISO 8601)",
						Sensitive:   false,
					},
					"permissions": {
						Description: "Token permissions (JSON object for App installation tokens)",
						Sensitive:   false,
					},
				},
			},
			Revocable: true, // GitHub tokens can be revoked via LeaseID
		},
	}
}

// ConfigSchema returns the declarative schema for GitHub token credential config
func (t *GitHubTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		// Common fields (required for github source, not for local)
		credential.StringField("auth_method").
			OneOf("app", "pat").
			Describe("Authentication method for GitHub (required for github source)").
			Example("app"),

		// GitHub App fields (required when auth_method=app)
		credential.StringField("app_id").
			Describe("GitHub App ID (required for app auth)").
			Example("123456"),

		credential.StringField("private_key").
			Custom(func(value string) error {
				if value == "" {
					return nil // Optional field, skip validation if empty
				}
				// Validate PEM format
				block, _ := pem.Decode([]byte(value))
				if block == nil {
					return fmt.Errorf("must be valid PEM format")
				}
				return nil
			}).
			Describe("GitHub App private key in PEM format (required for app auth)").
			Example("-----BEGIN RSA PRIVATE KEY-----\n..."),

		credential.StringField("installation_id").
			Describe("GitHub App installation ID (required for app auth)").
			Example("12345678"),

		// PAT fields (required when auth_method=pat)
		credential.StringField("token").
			Describe("Personal access token (required for pat auth, or for local source)").
			Example("ghp_xxxxxxxxxxxxxxxxxxxx"),

		// Optional fields
		credential.StringField("repository").
			Describe("Repository to scope the token to (format: owner/repo)").
			Example("acme-corp/backend"),

		credential.StringField("permissions").
			Describe("Comma-separated list of permissions for App installation tokens").
			Example("contents:read,issues:write"),
		credential.StringField(credential.ConfigSecretSpec).
			Describe("Name of a credential spec that yields the secret (App private key or PAT) instead of storing it inline (credential chaining)").
			Example("github-app-key"),
		credential.StringField(credential.ConfigSecretField).
			Describe("Which key of the referenced secret_spec's data holds the secret; optional when the payload is single-key").
			Example("private_key"),
	}
}

// ValidateConfig validates the Config for a GitHub token credential spec.
// Auth credentials (PAT token, App private key, etc.) are stored at spec level,
// not on the source. The source only holds connection info (github_url).
func (t *GitHubTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	switch sourceType {
	case credential.SourceTypeGitHub, credential.SourceTypeLocal:
		// Supported
	default:
		return fmt.Errorf("github_token credentials require a github or local source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: Conditional validation based on source and auth_method
	if sourceType == credential.SourceTypeLocal {
		// Local source: must have static token, auth_method not needed. A local
		// source has no keyless path, so credential chaining does not apply.
		if config[credential.ConfigSecretSpec] != "" {
			return fmt.Errorf("secret_spec (credential chaining) is not supported with a local source")
		}
		if config["token"] == "" {
			return fmt.Errorf("'token' is required for local source")
		}
		return nil
	}

	// GitHub source: auth_method is required
	authMethod := config["auth_method"]
	if authMethod == "" {
		return fmt.Errorf("'auth_method' is required for github source")
	}

	// When secret_spec is set, the secret (App private key or PAT) is fetched from
	// the referenced spec at mint time rather than stored inline; the inline secret
	// field must then be absent.
	chained := config[credential.ConfigSecretSpec] != ""

	// Conditional validation based on auth_method
	switch authMethod {
	case "app":
		// App identifiers are non-secret and always required.
		if config["app_id"] == "" {
			return fmt.Errorf("'app_id' is required when auth_method is app")
		}
		if config["installation_id"] == "" {
			return fmt.Errorf("'installation_id' is required when auth_method is app")
		}
		if chained {
			if config["private_key"] != "" {
				return fmt.Errorf("'private_key' and 'secret_spec' are mutually exclusive (the private key is fetched from the referenced secret_spec)")
			}
		} else if config["private_key"] == "" {
			return fmt.Errorf("'private_key' (or 'secret_spec') is required when auth_method is app")
		}
	case "pat":
		if chained {
			if config["token"] != "" {
				return fmt.Errorf("'token' and 'secret_spec' are mutually exclusive (the token is fetched from the referenced secret_spec)")
			}
		} else if config["token"] == "" {
			return fmt.Errorf("'token' (or 'secret_spec') is required when auth_method is pat")
		}
	}

	return nil
}

// RequiresSpecRotation returns false — GitHub tokens are minted per-session;
// no embedded credentials in the spec need rotation.
func (t *GitHubTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *GitHubTokenCredType) SensitiveConfigFields() []string {
	return []string{"token", "private_key"}
}
