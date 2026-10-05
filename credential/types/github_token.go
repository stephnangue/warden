package types

import (
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

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
		credential.StringField("mint_method").
			OneOf("app", "pat").
			Describe("Which credential to mint: 'app' (GitHub App installation token) or 'pat' (personal access token). Required for github source.").
			Example("app"),

		// GitHub App fields (required when mint_method=app)
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

		// PAT fields (required when mint_method=pat)
		credential.StringField("token").
			Describe("Personal access token (required for pat auth, or for local source)").
			Example("ghp_xxxxxxxxxxxxxxxxxxxx"),

		// Optional fields: narrow an App installation token below what the
		// installation grants
		credential.StringField("repositories").
			Describe("Comma-separated bare repository names to scope App installation tokens to (no owner: the installation already fixes it); at most 500").
			Example("backend,frontend"),

		credential.StringField("permissions").
			Describe("Comma-separated name:level pairs to scope App installation tokens to; level is read, write or admin").
			Example("contents:read,pull_requests:write"),
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
func (t *GitHubTokenCredType) ValidateConfig(config credential.Config, sourceType string) error {
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

	// The singular key was accepted but never applied, so a spec carrying it got a
	// token for the whole installation. Reject it rather than keep that silent
	// no-op; the driver refuses to mint from a stored spec that still has it.
	if config.Get("repository") != "" {
		return ErrGitHubLegacyRepository
	}

	// Step 3: Conditional validation based on source and mint_method
	if sourceType == credential.SourceTypeLocal {
		// A static token's scope is fixed where it was issued; nothing here can
		// narrow it.
		if HasGitHubScopeKeys(config) {
			return fmt.Errorf("'repositories' and 'permissions' are not supported with a local source")
		}
		// Local source: must have static token, mint_method not needed. A local
		// source has no keyless path, so credential chaining does not apply.
		if config.Get(credential.ConfigSecretSpec) != "" {
			return fmt.Errorf("secret_spec (credential chaining) is not supported with a local source")
		}
		if config.Get("token") == "" {
			return fmt.Errorf("'token' is required for local source")
		}
		return nil
	}

	// The dispatch key was renamed auth_method -> mint_method to match the rest of
	// the credential drivers; reject the old key with a clear migration message.
	if config.Get("auth_method") != "" {
		return fmt.Errorf("'auth_method' is no longer supported for github_token; use 'mint_method' (app or pat)")
	}

	// GitHub source: mint_method is required
	mintMethod := config.Get("mint_method")
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for github source")
	}

	// When secret_spec is set, the secret (App private key or PAT) is fetched from
	// the referenced spec at mint time rather than stored inline; the inline secret
	// field must then be absent.
	chained := config.Get(credential.ConfigSecretSpec) != ""

	// Conditional validation based on mint_method
	switch mintMethod {
	case "app":
		// App identifiers are non-secret and always required.
		if config.Get("app_id") == "" {
			return fmt.Errorf("'app_id' is required when mint_method is app")
		}
		if config.Get("installation_id") == "" {
			return fmt.Errorf("'installation_id' is required when mint_method is app")
		}
		if chained {
			if config.Get("private_key") != "" {
				return fmt.Errorf("'private_key' and 'secret_spec' are mutually exclusive (the private key is fetched from the referenced secret_spec)")
			}
		} else if config.Get("private_key") == "" {
			return fmt.Errorf("'private_key' (or 'secret_spec') is required when mint_method is app")
		}
	case "pat":
		if chained {
			if config.Get("token") != "" {
				return fmt.Errorf("'token' and 'secret_spec' are mutually exclusive (the token is fetched from the referenced secret_spec)")
			}
		} else if config.Get("token") == "" {
			return fmt.Errorf("'token' (or 'secret_spec') is required when mint_method is pat")
		}
	}

	// Checked on the raw keys, as the driver checks a stored spec: a value that
	// parses to nothing (" ", ",") is still refused here rather than accepted now
	// and refused on every mint.
	if mintMethod != "app" && HasGitHubScopeKeys(config) {
		return ErrGitHubScopeRequiresApp
	}
	if _, err := ParseGitHubTokenScope(config); err != nil {
		return err
	}

	return nil
}

// ErrGitHubLegacyRepository is returned, on write and at mint, for a spec that
// still sets the singular 'repository' key.
var ErrGitHubLegacyRepository = errors.New("'repository' is no longer supported; use 'repositories' (bare repository names, comma-separated)")

// ErrGitHubScopeRequiresApp is returned, on write and at mint, for a scope set on a
// spec that does not mint App installation tokens.
var ErrGitHubScopeRequiresApp = errors.New("'repositories' and 'permissions' apply only to mint_method=app (a PAT's scope is fixed when it is created)")

// HasGitHubScopeKeys reports whether a github_token spec sets either scope key,
// whatever its value parses to. It is the test for "this spec asks to be scoped"
// wherever a scope is not allowed, so write time and mint time agree.
func HasGitHubScopeKeys(config credential.Config) bool {
	return config.Get("repositories") != "" || config.Get("permissions") != ""
}

// githubMaxScopedRepositories is GitHub's limit on repositories named in one
// installation token request.
const githubMaxScopedRepositories = 500

var (
	githubRepoNameRE       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubPermissionNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// GitHubTokenScope narrows an App installation token below what the installation
// grants. The zero value asks for everything the installation has.
type GitHubTokenScope struct {
	// Repositories are bare repository names, sorted and deduplicated without
	// regard to case, as GitHub matches them.
	Repositories []string
	// Permissions maps a permission name to read, write or admin.
	Permissions map[string]string
}

// IsZero reports whether the scope narrows nothing.
func (s GitHubTokenScope) IsZero() bool {
	return len(s.Repositories) == 0 && len(s.Permissions) == 0
}

// ParseGitHubTokenScope reads the 'repositories' and 'permissions' keys of a
// github_token spec. It checks shape only: which permission names exist, and which
// repositories the installation can reach, is GitHub's to say when the token is
// requested.
func ParseGitHubTokenScope(config credential.Config) (GitHubTokenScope, error) {
	var scope GitHubTokenScope

	seen := map[string]bool{}
	for _, name := range splitGitHubList(config.Get("repositories")) {
		if strings.Contains(name, "/") {
			return GitHubTokenScope{}, fmt.Errorf("repositories: %q must be a bare repository name; the installation already fixes the owner", name)
		}
		if name == "." || name == ".." || !githubRepoNameRE.MatchString(name) {
			return GitHubTokenScope{}, fmt.Errorf("repositories: %q is not a valid repository name", name)
		}
		// The first spelling wins: "Backend,backend" names one repository.
		if folded := strings.ToLower(name); !seen[folded] {
			seen[folded] = true
			scope.Repositories = append(scope.Repositories, name)
		}
	}
	if len(scope.Repositories) > githubMaxScopedRepositories {
		return GitHubTokenScope{}, fmt.Errorf("repositories: at most %d may be named, got %d", githubMaxScopedRepositories, len(scope.Repositories))
	}
	sort.Strings(scope.Repositories)

	for _, item := range splitGitHubList(config.Get("permissions")) {
		name, level, ok := strings.Cut(item, ":")
		name, level = strings.TrimSpace(name), strings.TrimSpace(level)
		if !ok || name == "" {
			return GitHubTokenScope{}, fmt.Errorf("permissions: %q must be name:level", item)
		}
		if !githubPermissionNameRE.MatchString(name) {
			return GitHubTokenScope{}, fmt.Errorf("permissions: %q is not a valid permission name", name)
		}
		switch level {
		case "read", "write", "admin":
		default:
			return GitHubTokenScope{}, fmt.Errorf("permissions: %q: level must be read, write or admin, got %q", name, level)
		}
		if prev, dup := scope.Permissions[name]; dup && prev != level {
			return GitHubTokenScope{}, fmt.Errorf("permissions: %q is given twice, as %q and %q", name, prev, level)
		}
		if scope.Permissions == nil {
			scope.Permissions = map[string]string{}
		}
		scope.Permissions[name] = level
	}

	return scope, nil
}

// splitGitHubList splits a comma-separated config value, trimming each item and
// dropping empty ones.
func splitGitHubList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
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

// StoredSecrets reports the secret config keys this spec holds.
func (t *GitHubTokenCredType) StoredSecrets(config credential.Config) []string {
	return config.Present("token", "private_key")
}
