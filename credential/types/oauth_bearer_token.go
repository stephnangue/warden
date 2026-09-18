package types

import (
	"fmt"
	"strings"
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

		// token_exchange source - RFC 8693 target parameters. The exchange plumbing
		// keys (subject_token_source, actor_token_source, *_token_type) are validated
		// separately by credential.ValidateExchangeSpecConfig.
		credential.StringField("audience").
			Describe("Target audience for the exchanged token (token_exchange source)").
			Example("https://api.internal.example.com"),
		credential.StringField("resources").
			Describe("RFC 8707 resource indicator(s) for the exchanged token — space-separated absolute URIs (token_exchange source)").
			Example("https://api.internal.example.com https://api2.internal.example.com"),

		// anthropic source - the workload identity federation target. Validated
		// per-source in ValidateConfig below.
		credential.StringField("federation_rule_id").
			Describe("Federation rule the Warden assertion must satisfy (anthropic source)").
			Example("fdrl_01AbCdEfGhIjKlMnOpQrStUv"),
		credential.StringField("service_account_id").
			Describe("Service account the minted token acts as (anthropic source)").
			Example("svac_01AbCdEfGhIjKlMnOpQrStUv"),
		credential.StringField("workspace_id").
			Describe("Workspace the token acts in — needed only when the federation rule covers more than one (anthropic source)").
			Example("wrkspc_01AbCdEfGhIjKlMnOpQrStUv"),
	}
}

// anthropicIDPrefixes are the type prefixes Anthropic puts on the resource ids an
// anthropic spec names. Checking them catches an id pasted into the wrong field —
// a service account into federation_rule_id — at the write that makes the mistake,
// rather than as a rejected exchange on every request after it.
//
// A slice, not a map, so the first malformed id reported is the same on every run.
var anthropicIDPrefixes = []struct{ key, prefix string }{
	{"federation_rule_id", "fdrl_"},
	{"service_account_id", "svac_"},
	{"workspace_id", "wrkspc_"},
}

// validateAnthropicSpec checks an anthropic spec's exchange target. The source
// holds the organization and the audience; the spec names what one exchange asks
// for, so the two required ids must be here, and a key belonging to the source is
// refused rather than silently ignored.
func validateAnthropicSpec(config credential.Config) error {
	// The source is keyless: it mints only by exchanging a Warden-signed assertion,
	// which is the issuer the federation rules trust. A spec that opts out of
	// exchange has nothing to mint with, and one presenting another identity would
	// be refused by every rule registered for Warden's issuer.
	switch src := config.Get(credential.ConfigSubjectTokenSource); src {
	case credential.SourceWardenIdentity:
	case "", credential.SourceNone:
		return fmt.Errorf("'%s' is required for an anthropic source: set it to '%s'",
			credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity)
	default:
		return fmt.Errorf("'%s' must be '%s' for an anthropic source, got %q: the exchange presents a Warden-signed assertion, which is what the federation rules trust",
			credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity, src)
	}

	for _, key := range []string{"federation_rule_id", "service_account_id"} {
		if config.Get(key) == "" {
			return fmt.Errorf("'%s' is required for an anthropic source", key)
		}
	}
	for _, id := range anthropicIDPrefixes {
		v := config.Get(id.key)
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, id.prefix) || len(v) == len(id.prefix) {
			return fmt.Errorf("'%s' must be an Anthropic id starting with %q, got %q", id.key, id.prefix, v)
		}
	}

	if config.Get("organization_id") != "" {
		return fmt.Errorf("'organization_id' belongs on the anthropic source, not the spec: a source holds one organization's trust relationship")
	}
	// audience is the source's key, and on a spec it is a token_exchange parameter
	// this source never reads. Set here it would look like it chose the assertion's
	// audience while the source's went out instead.
	if config.Get("audience") != "" {
		return fmt.Errorf("'audience' is not read on an anthropic spec: the assertion's audience is the source's 'audience', which a spec overrides with '%s'",
			credential.ConfigAssertionAudience)
	}
	return nil
}

// ValidateConfig validates the Config for an OAuth bearer token credential spec.
func (t *OAuthBearerTokenCredType) ValidateConfig(config credential.Config, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeOAuth2, credential.SourceTypeVault, credential.SourceTypeIBM, credential.SourceTypeTokenExchange, credential.SourceTypeAnthropic:
		// Supported
	default:
		return fmt.Errorf("oauth_bearer_token credentials require an oauth2, vault, ibm, token_exchange, or anthropic source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Source-specific validation
	switch sourceType {
	case credential.SourceTypeVault:
		if config.Get("mint_method") != "oauth2" {
			return fmt.Errorf("'mint_method' must be 'oauth2' for vault source, got: %s", config.Get("mint_method"))
		}
		if config.Get("oauth2_mount") == "" {
			return fmt.Errorf("'oauth2_mount' is required when mint_method is oauth2")
		}
		if config.Get("credential_name") == "" {
			return fmt.Errorf("'credential_name' is required when mint_method is oauth2")
		}
	case credential.SourceTypeIBM:
		// IBM source uses iam_token mint method (default); no additional spec config needed
		if mm := config.Get("mint_method"); mm != "" && mm != "iam_token" {
			return fmt.Errorf("'mint_method' must be 'iam_token' for ibm source, got: %s", mm)
		}
		// The grant runs with the source's api key, so a reference parked here would
		// describe a secret this spec never spends — and would slip past the
		// source-level checks that gate which sources may chain at all.
		if config.Get(credential.ConfigSecretSpec) != "" {
			return fmt.Errorf("for an ibm source, '%s' belongs on the source: the chained api key authenticates the source's own IAM token grant, not this spec", credential.ConfigSecretSpec)
		}
	case credential.SourceTypeTokenExchange:
		// The token_exchange driver is exchange-only: it mints solely from a
		// caller-derived subject. A spec that opts out (subject_token_source absent
		// or "none") has no identity to exchange, so reject it here rather than
		// failing opaquely at mint time.
		if src := config.Get(credential.ConfigSubjectTokenSource); src == "" || src == credential.SourceNone {
			return fmt.Errorf("'%s' is required for a token_exchange source (set '%s', '%s', or '%s')",
				credential.ConfigSubjectTokenSource, credential.SourceAgentIdentity, credential.SourceUserIdentity, credential.SourceWardenIdentity)
		}
	case credential.SourceTypeAnthropic:
		if err := validateAnthropicSpec(config); err != nil {
			return err
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

// Compile-time assertion that the sealed keys are enforced, not just documented.
var _ credential.SystemManagedConfig = (*OAuthBearerTokenCredType)(nil)

// SystemManagedConfigFields returns the keys sealed by `cred spec connect` and
// by the refresh-token write-back. They are the credential itself: an operator
// who could set one could mint against a token the server never issued, and the
// spec would report itself connected on the strength of it.
//
// These four are read from the spec config directly at mint time, never resolved
// spec-over-source, which is why guarding the spec write paths is sufficient. A
// change that starts resolving any of them from the source would need the source
// write path guarded too.
func (t *OAuthBearerTokenCredType) SystemManagedConfigFields() []string {
	return []string{
		"refresh_token",
		"access_token",
		"refresh_token_expires_at",
		"access_token_expires_at",
	}
}

// RequiresConnect reports whether the spec uses the authorization_code flow, which
// needs a one-time `cred spec connect` before it can mint.
func (t *OAuthBearerTokenCredType) RequiresConnect(config credential.Config) bool {
	return config.Get("auth_method") == "authorization_code"
}

// IsConnected reports whether the spec has been connected — a refresh token or a
// static access token has been sealed into it.
func (t *OAuthBearerTokenCredType) IsConnected(config credential.Config) bool {
	return config.Get("refresh_token") != "" || config.Get("access_token") != ""
}
