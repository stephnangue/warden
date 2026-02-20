package types

import (
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// GitLabAccessTokenCredType handles GitLab project and group access tokens
type GitLabAccessTokenCredType struct {
	*BaseTokenType
}

// NewGitLabAccessTokenCredType creates a new GitLab access token credential type
func NewGitLabAccessTokenCredType() *GitLabAccessTokenCredType {
	return &GitLabAccessTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeGitLabAccessToken,
				Category:    credential.CategoryAPI,
				Description: "GitLab access token for API authentication",
				DefaultTTL:  0, // Project/group tokens have explicit expiry set at creation
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "access_token",
				AlternativeFields: []string{},
				OptionalFields:    []string{"token_id", "expires_at", "scopes"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"access_token": {
						Description: "GitLab access token for API authentication",
						Sensitive:   true,
					},
					"token_id": {
						Description: "GitLab token ID for revocation",
						Sensitive:   false,
					},
					"expires_at": {
						Description: "Token expiration date (YYYY-MM-DD)",
						Sensitive:   false,
					},
					"scopes": {
						Description: "Comma-separated list of token scopes",
						Sensitive:   false,
					},
				},
			},
			Revocable: true, // GitLab tokens can be revoked via LeaseID
		},
	}
}

// ConfigSchema returns the declarative schema for GitLab access token credential config
func (t *GitLabAccessTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			Required().
			OneOf("project_access_token", "group_access_token").
			Describe("Type of GitLab token to create").
			Example("project_access_token"),

		// Project token fields (required when mint_method=project_access_token)
		credential.StringField("project_id").
			Describe("GitLab project ID (required for project tokens)").
			Example("12345"),

		// Group token fields (required when mint_method=group_access_token)
		credential.StringField("group_id").
			Describe("GitLab group ID (required for group tokens)").
			Example("67890"),

		// Common required fields
		credential.StringField("token_name").
			Required().
			Describe("Name for the access token").
			Example("warden-backend-token"),

		credential.StringField("scopes").
			Required().
			Describe("Comma-separated list of token scopes").
			Example("api,read_repository,write_repository"),

		credential.StringField("access_level").
			Required().
			OneOf("10", "20", "30", "40", "50", "guest", "reporter", "developer", "maintainer", "owner").
			Describe("Access level for the token (numeric: 10=guest, 20=reporter, 30=developer, 40=maintainer, 50=owner)").
			Example("30"),

		// Optional fields
		credential.DurationField("expires_in").
			Describe("Token expiration duration from now").
			Example("720h"),
	}
}

// ValidateConfig validates the Config for a GitLab access token credential spec
func (t *GitLabAccessTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	if sourceType != credential.SourceTypeGitLab {
		return fmt.Errorf("gitlab_access_token credentials require a gitlab source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: Conditional validation based on mint_method
	mintMethod := config["mint_method"]
	switch mintMethod {
	case "project_access_token":
		if config["project_id"] == "" {
			return fmt.Errorf("'project_id' is required when mint_method is project_access_token")
		}
	case "group_access_token":
		if config["group_id"] == "" {
			return fmt.Errorf("'group_id' is required when mint_method is group_access_token")
		}
	}

	return nil
}

// RequiresSpecRotation returns false — GitLab access tokens are dynamic and
// minted per session; the spec doesn't embed rotatable credentials.
func (t *GitLabAccessTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *GitLabAccessTokenCredType) SensitiveConfigFields() []string {
	return nil
}
