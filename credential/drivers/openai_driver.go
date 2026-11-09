package drivers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// openaiAuthMethodOIDCFederation is the only way an openai source authenticates.
// It holds no key: it mints solely by exchanging a Warden-signed identity
// assertion through OpenAI's workload identity federation. A static OpenAI key
// belongs on an apikey source, which the provider already injects.
//
// It is required, not defaulted, despite being the only value. The config store
// recognises a federated source by this key being written out, and on that alone
// refuses it a rotation_period and keeps it out of the rotation manager.
const openaiAuthMethodOIDCFederation = "oidc_federation"

// defaultOpenAIAuthURL is where the token exchange is sent unless the source
// overrides openai_auth_url. It is OpenAI's auth host, not the API host the
// openai mount proxies to.
const defaultOpenAIAuthURL = "https://auth.openai.com"

// openaiTokenPath is the token endpoint, relative to the auth base URL.
const openaiTokenPath = "/oauth/token"

// openaiRefreshBuffer is how long before a token's expiry its lease ends, so a
// request arriving in a token's last second, or a completion stream begun just
// before expiry, never goes upstream carrying a token about to lapse.
const openaiRefreshBuffer = 60 * time.Second

// openaiFallbackLifetime is the lifetime assumed when a token response omits
// expires_in or sends a non-positive one. Short on purpose: assuming too little
// can only make the cache re-mint early, never serve a token past its expiry.
const openaiFallbackLifetime = 60 * time.Second

// openaiMaxLifetime is the longest OpenAI issues a federated token for. A longer
// expires_in is doc drift or a malformed response; capping it can only re-mint
// early.
const openaiMaxLifetime = time.Hour

// openaiSpecOnlyKeys name one exchange target — the service account the token
// acts as. A source holds one trust relationship (the identity provider) and
// serves many targets, so this lives on the spec; set on a source it would be
// read by nothing.
var openaiSpecOnlyKeys = []string{"service_account_id"}

// Compile-time interface assertions
var _ credential.SourceDriver = (*OpenAIDriver)(nil)
var _ credential.ExchangeMinter = (*OpenAIDriver)(nil)

// OpenAIDriver mints OpenAI access tokens through workload identity federation
// (RFC 8693 token exchange). It holds no OpenAI key: each mint presents a
// Warden-signed identity assertion to OpenAI's token endpoint, naming the
// identity provider that trusts Warden's issuer and the service account to act
// as, and receives a short-lived bearer token for that service account.
//
// Only the JWT subject-token variant is supported. OpenAI's X.509 variant
// authenticates the exchange with a client certificate over mTLS, and the
// driver's HTTP client presents none.
//
// Every field is set once in Create and never written again. The driver does not
// rotate, so nothing rewrites credSource.Config in place — a config change builds
// a new driver instead — and concurrent mints share it without a lock.
type OpenAIDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// tokenURL is the exchange endpoint, resolved from openai_auth_url once.
	tokenURL string
}

// OpenAIDriverFactory creates OpenAIDriver instances.
type OpenAIDriverFactory struct{}

// Type returns the source type this factory builds drivers for.
func (f *OpenAIDriverFactory) Type() string {
	return credential.SourceTypeOpenAI
}

// ValidateConfig validates OpenAI driver configuration using declarative schema
func (f *OpenAIDriverFactory) ValidateConfig(config credential.Config) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			Required().
			OneOf(openaiAuthMethodOIDCFederation).
			Describe("How the source authenticates: oidc_federation (workload identity federation, keyless) — the only mode").
			Example("oidc_federation"),

		credential.StringField("identity_provider_id").
			Required().
			Describe("OpenAI workload identity provider that trusts Warden's issuer").
			Example("<openai-identity-provider-id>"),

		credential.StringField("audience").
			Describe("aud the Warden assertion is minted with — the audience the identity provider expects. When unset, every spec must set assertion_audience").
			Example("https://warden.example.com/openai"),

		credential.StringField("openai_auth_url").
			Custom(validateEndpointURL).
			Describe("Override where the token exchange is sent (default: https://auth.openai.com — the auth host, not the API host)").
			Example("https://auth.openai.com"),

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

	for _, key := range openaiSpecOnlyKeys {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s belongs on the spec, not the source: it names one exchange target, and a source serves many", key)
		}
	}
	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *OpenAIDriverFactory) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

// StoredSecrets reports nothing. It has no secret-bearing config: the only mode is federation.
func (f *OpenAIDriverFactory) StoredSecrets(_ credential.Config) []string {
	return nil
}

// InferCredentialType returns oauth_bearer_token: the exchange yields exactly one
// kind of credential, so there is nothing in the spec to infer it from.
func (f *OpenAIDriverFactory) InferCredentialType(specConfig credential.Config) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new OpenAIDriver
func (f *OpenAIDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	baseURL := strings.TrimRight(credential.GetString(config, "openai_auth_url", defaultOpenAIAuthURL), "/")

	return &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeOpenAI),
		httpClient: httpClient,
		tokenURL:   baseURL + openaiTokenPath,
	}, nil
}

// Type returns the driver type
func (d *OpenAIDriver) Type() string {
	return credential.SourceTypeOpenAI
}

// MintCredential always fails: an OpenAI token is minted only by exchanging a
// caller's identity, which a plain mint carries none of. The credential manager
// routes a spec setting subject_token_source through MintCredentialWithExchange,
// and every spec on this source must set it, so reaching here means one did not.
func (d *OpenAIDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("openai: minting requires workload identity federation; set %s=%s on the spec",
		credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity)
}

// MintCredentialWithExchange exchanges the caller's Warden-signed identity
// assertion for an OpenAI access token acting as the spec's service account.
//
// It runs only on a credential-cache miss, inside the manager's singleflight, so
// concurrent requests for one identity share a single exchange rather than each
// making one. A refused exchange keeps its upstream status in the error chain, so
// the request is answered as a refusal rather than a server error.
func (d *OpenAIDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("openai: no subject token in exchange inputs")
	}
	target, err := d.target(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}

	resp, err := postOAuthTokenJSON(ctx, d.httpClient, d.tokenURL, target.grant(inputs.SubjectToken), nil)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("openai token exchange: %w", err)
	}
	if resp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("openai token exchange: response missing access_token")
	}
	// OpenAI documents one issued type. An absent field is tolerated; a different
	// one means the response is not the bearer the provider will inject.
	if resp.IssuedTokenType != "" && resp.IssuedTokenType != credential.TokenTypeAccessToken {
		return nil, nil, 0, "", fmt.Errorf("openai token exchange: unexpected issued_token_type %q", resp.IssuedTokenType)
	}

	lifetime := federatedTokenLifetime(resp.ExpiresIn, openaiFallbackLifetime, openaiMaxLifetime)
	ttl := federatedLeaseTTL(lifetime, openaiRefreshBuffer, spec.MaxTTL)

	// The token's real expiry, not the lease's: the lease ends early by design, and
	// an audit reader asking how long the credential stayed valid wants the former.
	metadata := map[string]interface{}{
		"identity_provider_id": target.identityProviderID,
		"service_account_id":   target.serviceAccountID,
		"expiration":           time.Now().Add(lifetime).UTC().Format(time.RFC3339),
	}
	if resp.Scope != "" {
		metadata["scope"] = resp.Scope
	}
	for k, v := range assertionSubjectMetadata(inputs.SubjectToken) {
		metadata[k] = v
	}
	if d.logger != nil {
		d.logger.Debug("minted federated OpenAI access token",
			logger.String("spec", spec.Name),
			logger.String("service_account_id", target.serviceAccountID),
			logger.String("ttl", ttl.String()),
		)
	}
	return accessTokenRawData(resp), metadata, ttl, "", nil
}

// openaiTarget is what one exchange asks for: the identity provider that trusts
// Warden's issuer, and the service account the token acts as.
type openaiTarget struct {
	identityProviderID string
	serviceAccountID   string
}

// target assembles the exchange target: the identity provider from the source,
// the service account from the spec. It is the one place a target is read.
//
// Both halves are validated when written; they are re-checked so a record that
// bypassed validation fails closed, naming the field, rather than reaching OpenAI
// with a hole in the request.
func (d *OpenAIDriver) target(spec *credential.CredSpec) (openaiTarget, error) {
	t := openaiTarget{
		identityProviderID: credential.GetString(d.credSource.Config, "identity_provider_id", ""),
		serviceAccountID:   credential.GetString(spec.Config, "service_account_id", ""),
	}
	for _, f := range []struct{ name, value string }{
		{"identity_provider_id", t.identityProviderID},
		{"service_account_id", t.serviceAccountID},
	} {
		if f.value == "" {
			return openaiTarget{}, fmt.Errorf("openai: %s is not set", f.name)
		}
	}
	return t, nil
}

// grant builds the RFC 8693 token-exchange request. OpenAI takes it as JSON with
// no client authentication: the assertion, checked against the identity
// provider, is the whole proof.
func (t openaiTarget) grant(subjectToken string) map[string]string {
	return map[string]string{
		"grant_type":           grantTypeTokenExchange,
		"subject_token_type":   credential.TokenTypeJWT,
		"subject_token":        subjectToken,
		"identity_provider_id": t.identityProviderID,
		"service_account_id":   t.serviceAccountID,
	}
}

// Revoke is a no-op: OpenAI has no endpoint to revoke a federated token, and none
// is issued with a lease ID. The token's short lifetime is the bound.
func (d *OpenAIDriver) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

// Cleanup releases the driver's pooled connections.
func (d *OpenAIDriver) Cleanup(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}
