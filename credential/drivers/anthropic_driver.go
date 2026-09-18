package drivers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// anthropicAuthMethodOIDCFederation is the only way an anthropic source
// authenticates. It holds no key: it mints solely by exchanging a Warden-signed
// identity assertion through Anthropic's workload identity federation. A static
// Anthropic key belongs on an apikey source, which the provider already injects.
//
// It is required, not defaulted, despite being the only value. The config store
// recognises a federated source by this key being written out, and on that alone
// refuses it a rotation_period and keeps it out of the rotation manager. Defaulted,
// an anthropic source that omitted the key would be enrolled for rotation it can
// never complete, failing and retrying for as long as the source existed.
const anthropicAuthMethodOIDCFederation = "oidc_federation"

// defaultAnthropicURL is where the token exchange is sent unless the source
// overrides anthropic_url.
const defaultAnthropicURL = "https://api.anthropic.com"

// anthropicTokenPath is the token endpoint, relative to the API base URL.
const anthropicTokenPath = "/v1/oauth/token"

// anthropicJWTBearerGrant is the RFC 7523 grant: the assertion is itself the
// authorization grant, so the request carries no client authentication.
const anthropicJWTBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// anthropicRefreshBuffer is how long before a token's expiry its lease ends. The
// credential cache serves an entry until the lease elapses and only then mints
// again, so without this a request arriving in a token's last second would go
// upstream carrying it, and an inference stream begun just before expiry would
// outlive its credential. Ending the lease early makes the next request mint while
// the old token is still good.
const anthropicRefreshBuffer = 60 * time.Second

// anthropicFallbackLifetime is the lifetime assumed when a token response omits
// expires_in, which RFC 6749 leaves optional, or sends a non-positive one. It is the shortest lifetime Anthropic
// issues, so assuming it can only make the cache re-mint early — never serve a
// token past its real expiry, which is what guessing a longer life would risk.
const anthropicFallbackLifetime = 60 * time.Second

// anthropicMaxLifetime is the longest a federation rule can make a token live:
// token_lifetime_seconds tops out at a day. A longer expires_in is capped to it
// before conversion. Taken as-is, a value past ~292 years overflows time.Duration
// and can wrap to a small positive lifetime, which would pass as a real one.
const anthropicMaxLifetime = 24 * time.Hour

// anthropicOrganizationIDPattern matches an organization id, which Anthropic
// issues as a UUID.
var anthropicOrganizationIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// anthropicSpecOnlyKeys name one exchange target — which federation rule the
// assertion must satisfy, which service account the token acts as, which workspace
// it acts in. A source holds one trust relationship and serves many targets, so
// these live on the spec; set on a source they would be read by nothing.
var anthropicSpecOnlyKeys = []string{"federation_rule_id", "service_account_id", "workspace_id"}

// Compile-time interface assertions
var _ credential.SourceDriver = (*AnthropicDriver)(nil)
var _ credential.ExchangeMinter = (*AnthropicDriver)(nil)

// AnthropicDriver mints Anthropic access tokens through workload identity
// federation. It holds no Anthropic key: each mint presents a Warden-signed
// identity assertion to Anthropic's token endpoint and receives a short-lived
// token bound to a service account in the organization.
//
// Every field is set once in Create and never written again. The driver does not
// rotate, so nothing rewrites credSource.Config in place — a config change builds
// a new driver instead — and concurrent mints share it without a lock.
type AnthropicDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// tokenURL is the exchange endpoint, resolved from anthropic_url once.
	tokenURL string
}

// AnthropicDriverFactory creates AnthropicDriver instances.
type AnthropicDriverFactory struct{}

// Type returns the source type this factory builds drivers for.
func (f *AnthropicDriverFactory) Type() string {
	return credential.SourceTypeAnthropic
}

// ValidateConfig validates Anthropic driver configuration using declarative schema
func (f *AnthropicDriverFactory) ValidateConfig(config credential.Config) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			Required().
			OneOf(anthropicAuthMethodOIDCFederation).
			Describe("How the source authenticates: oidc_federation (workload identity federation, keyless) — the only mode").
			Example("oidc_federation"),

		credential.StringField("organization_id").
			Required().
			Custom(validateAnthropicOrganizationID).
			Describe("Anthropic organization the federation issuer and rules are registered in").
			Example("00000000-0000-0000-0000-000000000000"),

		credential.StringField("audience").
			Describe("aud the Warden assertion is minted with — the audience the federation rule matches. When unset, every spec must set assertion_audience").
			Example("https://warden.example.com/anthropic"),

		credential.StringField("anthropic_url").
			Custom(validateEndpointURL).
			Describe("Override where the token exchange is sent (default: the public Anthropic API)").
			Example("https://api.anthropic.com"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	); err != nil {
		return err
	}

	for _, key := range anthropicSpecOnlyKeys {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s belongs on the spec, not the source: it names one exchange target, and a source serves many", key)
		}
	}
	return nil
}

// validateAnthropicOrganizationID checks an organization id is a UUID, the form
// Anthropic issues. A wrong value would otherwise surface only as a rejected
// exchange, on the first request that needed a token.
func validateAnthropicOrganizationID(v string) error {
	if !anthropicOrganizationIDPattern.MatchString(v) {
		return fmt.Errorf("must be a UUID, got %q", v)
	}
	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AnthropicDriverFactory) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

// InferCredentialType returns oauth_bearer_token: the exchange yields exactly one
// kind of credential, so there is nothing in the spec to infer it from.
func (f *AnthropicDriverFactory) InferCredentialType(specConfig credential.Config) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new AnthropicDriver
func (f *AnthropicDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	baseURL := strings.TrimRight(credential.GetString(config, "anthropic_url", defaultAnthropicURL), "/")

	return &AnthropicDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAnthropic,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeAnthropic),
		httpClient: httpClient,
		tokenURL:   baseURL + anthropicTokenPath,
	}, nil
}

// Type returns the driver type
func (d *AnthropicDriver) Type() string {
	return credential.SourceTypeAnthropic
}

// MintCredential always fails: an Anthropic token is minted only by exchanging a
// caller's identity, which a plain mint carries none of. The credential manager
// routes a spec setting subject_token_source through MintCredentialWithExchange,
// and every spec on this source must set it, so reaching here means one did not.
func (d *AnthropicDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("anthropic: minting requires workload identity federation; set %s=%s on the spec",
		credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity)
}

// MintCredentialWithExchange exchanges the caller's Warden-signed identity
// assertion for an Anthropic access token acting as the spec's service account.
//
// It runs only on a credential-cache miss, inside the manager's singleflight, so
// concurrent requests for one identity share a single exchange rather than each
// making one.
func (d *AnthropicDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("anthropic: no subject token in exchange inputs")
	}
	target, err := d.target(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}

	resp, err := postOAuthTokenJSON(ctx, d.httpClient, d.tokenURL, target.grant(inputs.SubjectToken), nil)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("anthropic token exchange: %w", err)
	}
	if resp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("anthropic token exchange: response missing access_token")
	}

	lifetime := anthropicLifetime(resp.ExpiresIn)
	ttl := anthropicLeaseTTL(lifetime, spec.MaxTTL)

	// The token's real expiry, not the lease's: the lease ends early by design, and
	// an audit reader asking how long the credential stayed valid wants the former.
	metadata := map[string]interface{}{
		"organization_id":    target.organizationID,
		"federation_rule_id": target.federationRuleID,
		"service_account_id": target.serviceAccountID,
		"expiration":         time.Now().Add(lifetime).UTC().Format(time.RFC3339),
	}
	if target.workspaceID != "" {
		metadata["workspace_id"] = target.workspaceID
	}
	if sub := inputs.AgentClaims["sub"]; sub != "" {
		metadata["subject"] = sub
	}
	if d.logger != nil {
		d.logger.Debug("minted federated Anthropic access token",
			logger.String("spec", spec.Name),
			logger.String("service_account_id", target.serviceAccountID),
			logger.String("ttl", ttl.String()),
		)
	}
	return accessTokenRawData(resp), metadata, ttl, "", nil
}

// anthropicTarget is what one exchange asks for: the organization, the federation
// rule the assertion must satisfy, the service account the token acts as, and
// optionally the workspace it acts in.
type anthropicTarget struct {
	organizationID   string
	federationRuleID string
	serviceAccountID string
	workspaceID      string
}

// target assembles the exchange target: the organization from the source, the
// rest from the spec. It is the one place a target is read, so resolving these
// from per-caller claims later is a change here rather than at every call site.
//
// Both halves are validated when written; the required ones are re-checked so a
// record that bypassed validation fails closed, naming the field, rather than
// reaching Anthropic with a hole in the request.
func (d *AnthropicDriver) target(spec *credential.CredSpec) (anthropicTarget, error) {
	t := anthropicTarget{
		organizationID:   credential.GetString(d.credSource.Config, "organization_id", ""),
		federationRuleID: credential.GetString(spec.Config, "federation_rule_id", ""),
		serviceAccountID: credential.GetString(spec.Config, "service_account_id", ""),
		workspaceID:      credential.GetString(spec.Config, "workspace_id", ""),
	}
	for _, f := range []struct{ name, value string }{
		{"organization_id", t.organizationID},
		{"federation_rule_id", t.federationRuleID},
		{"service_account_id", t.serviceAccountID},
	} {
		if f.value == "" {
			return anthropicTarget{}, fmt.Errorf("anthropic: %s is not set", f.name)
		}
	}
	return t, nil
}

// grant builds the RFC 7523 token request. workspace_id is sent only when set:
// Anthropic requires it only for a federation rule covering more than one
// workspace, and otherwise acts in the rule's own.
func (t anthropicTarget) grant(assertion string) map[string]string {
	g := map[string]string{
		"grant_type":         anthropicJWTBearerGrant,
		"assertion":          assertion,
		"organization_id":    t.organizationID,
		"federation_rule_id": t.federationRuleID,
		"service_account_id": t.serviceAccountID,
	}
	if t.workspaceID != "" {
		g["workspace_id"] = t.workspaceID
	}
	return g
}

// anthropicLeaseTTL is how long the credential cache may serve a token: its
// lifetime less anthropicRefreshBuffer, so the next request re-mints before the
// token expires. A short token would be left with little or nothing after the
// buffer, so the lease never drops below half the lifetime. It is capped at the
// spec's MaxTTL; MinTTL is not applied, since Anthropic fixes the lifetime from
// the federation rule and a floor could not lengthen it.
func anthropicLeaseTTL(lifetime, maxTTL time.Duration) time.Duration {
	ttl := lifetime - anthropicRefreshBuffer
	if half := lifetime / 2; ttl < half {
		ttl = half
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

// anthropicLifetime converts a response's expires_in to how long its token lives.
// Missing or non-positive takes the fallback, and anything past the longest a rule
// can issue is capped to that before the multiply, which is what keeps an absurd
// value from overflowing into a plausible-looking one.
func anthropicLifetime(expiresIn int) time.Duration {
	switch {
	case expiresIn <= 0:
		return anthropicFallbackLifetime
	case expiresIn > int(anthropicMaxLifetime/time.Second):
		return anthropicMaxLifetime
	default:
		return time.Duration(expiresIn) * time.Second
	}
}

// Revoke is a no-op: Anthropic has no endpoint to revoke a federated token, and
// none is issued with a lease ID. The token's short lifetime is the bound.
func (d *AnthropicDriver) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

// Cleanup releases the driver's pooled connections.
func (d *AnthropicDriver) Cleanup(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}
