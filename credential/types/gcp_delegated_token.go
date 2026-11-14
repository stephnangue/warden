package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/stephnangue/warden/credential"
)

// GCPMintMethodDelegated is the gcp mint method for Google Workspace domain-wide
// delegation: a token that acts as one Workspace user, named by the verified user
// on the request.
const GCPMintMethodDelegated = "delegated_access_token"

// GCPDelegatedTokenCredType is a Google OAuth2 access token that acts as a
// Workspace user. It is a type of its own, not a gcp_access_token, so that only a
// provider that knows it carries a user's authority accepts it: the gcp and mcp
// providers take gcp_access_token alone and refuse this one by construction.
type GCPDelegatedTokenCredType struct {
	*BaseTokenType
}

// NewGCPDelegatedTokenCredType creates the domain-wide delegation token type.
func NewGCPDelegatedTokenCredType() *GCPDelegatedTokenCredType {
	return &GCPDelegatedTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeGCPDelegatedToken,
				Category:    credential.CategoryCloudIAM,
				Description: "Google OAuth2 access token acting as a Google Workspace user, through domain-wide delegation",
				DefaultTTL:  1 * time.Hour,
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "access_token",
				AlternativeFields: []string{},
				OptionalFields:    []string{},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"access_token": {
						Description: "Google OAuth2 access token acting as the delegated Workspace user",
						Sensitive:   true,
					},
				},
			},
			Revocable: false, // domain-wide delegation tokens cannot be revoked; they expire
		},
	}
}

// ConfigSchema returns the declarative schema for a domain-wide delegation spec.
func (t *GCPDelegatedTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			Required().
			OneOf(GCPMintMethodDelegated).
			Describe("Method for minting the token").
			Example(GCPMintMethodDelegated),

		credential.StringField("target_service_account").
			Required().
			Describe("Service account authorized for domain-wide delegation in the Workspace Admin console; it signs the delegation assertion").
			Example("workspace-dwd@dwd-project.iam.gserviceaccount.com"),

		credential.StringField("scopes").
			Required().
			Describe("Comma- or space-separated OAuth2 scopes, each authorized for the service account in the Admin console. No default: the token acts as a person").
			Example("https://www.googleapis.com/auth/gmail.readonly"),

		credential.StringField(DelegatedUserClaimKey).
			Required().
			Describe("The projected user claim holding the user's primary Workspace email; it must also be listed in assertion_user_claims. " +
				"Name a claim the user cannot change, from an identity provider that is the source of truth for the Workspace directory: whoever controls it is whoever the token acts as").
			Example("email"),

		credential.StringField(DelegatedUserDomainsKey).
			Required().
			Custom(func(v string) error {
				_, err := ParseDelegatedUserDomains(v)
				return err
			}).
			Describe("Comma-separated Workspace domains whose users the spec may act for; a user in any other domain is refused").
			Example("example.com"),
	}
}

// Spec-config keys a domain-wide delegation spec names its user with. Both mean
// nothing to any other spec, which refuses them.
const (
	DelegatedUserClaimKey   = "delegated_user_claim"
	DelegatedUserDomainsKey = "delegated_user_domains"
)

// gcpDelegatedUserFields are the delegated-user keys, refused by every other gcp
// spec type.
var gcpDelegatedUserFields = []string{DelegatedUserClaimKey, DelegatedUserDomainsKey}

// delegatedDomainPattern is a lowercase DNS name of two or more labels, with no
// leading, trailing or doubled dot. A wildcard can never match it.
var delegatedDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ParseDelegatedUserDomains parses delegated_user_domains: comma-separated,
// lowercase domains, at least one. Subdomains are not implied — a Workspace
// subdomain is a domain of its own and is listed by name — so each entry is
// matched exactly, and an uppercase entry is refused rather than folded, keeping
// what is stored the same as what is matched.
func ParseDelegatedUserDomains(raw string) ([]string, error) {
	var domains []string
	for _, d := range strings.Split(raw, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if len(d) > 253 || !delegatedDomainPattern.MatchString(d) {
			return nil, fmt.Errorf("'%s' entry %q must be a lowercase domain name such as example.com, with no wildcard or leading or trailing dot", DelegatedUserDomainsKey, d)
		}
		domains = append(domains, d)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("'%s' must name at least one domain", DelegatedUserDomainsKey)
	}
	return domains, nil
}

// ValidateConfig validates a domain-wide delegation spec. Whether its source can
// serve it (keyless, with the user projected into the assertion) needs the
// source's config and is checked where the spec is stored.
func (t *GCPDelegatedTokenCredType) ValidateConfig(config credential.Config, sourceType string) error {
	if sourceType != credential.SourceTypeGCP {
		return fmt.Errorf("%s credentials require a gcp source, got: %s", credential.TypeGCPDelegatedToken, sourceType)
	}
	if err := credential.ValidateSchema(config, t.ConfigSchema()...); err != nil {
		return err
	}
	if len(strings.FieldsFunc(config.Get("scopes"), isScopeSeparator)) == 0 {
		return fmt.Errorf("'scopes' must name at least one scope")
	}
	if claim := config.Get(DelegatedUserClaimKey); strings.ContainsAny(claim, ", \t") {
		return fmt.Errorf("'%s' names one claim, got %q", DelegatedUserClaimKey, claim)
	}
	// Google fixes a delegated token's life at one hour; max_ttl is what shortens
	// the lease. A lifetime here would be accepted and never read.
	if config.Get("lifetime") != "" {
		return fmt.Errorf("'lifetime' does not apply to mint_method=%s: Google issues the token for one hour; set max_ttl to shorten the lease", GCPMintMethodDelegated)
	}
	return nil
}

// isScopeSeparator splits a scope list on commas and whitespace, as the gcp
// driver does.
func isScopeSeparator(r rune) bool {
	return r == ',' || unicode.IsSpace(r)
}

// RequiresSpecRotation reports false: the spec holds no credential.
func (t *GCPDelegatedTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns nothing: the config holds an account, scopes and
// a domain list.
func (t *GCPDelegatedTokenCredType) SensitiveConfigFields() []string {
	return []string{}
}

// StoredSecrets reports nothing: the spec stores no secret, and the source is
// keyless.
func (t *GCPDelegatedTokenCredType) StoredSecrets(_ credential.Config) []string {
	return nil
}
