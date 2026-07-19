package drivers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/logger"
)

// subjectSigningAlgs are the JWT signing algorithms accepted when validating an
// unverified (header-sourced) subject or actor token.
var subjectSigningAlgs = []jwt.Alg{jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384, jwt.ES512}

// Exchange grants selected by the source's `grant` config.
const (
	tokenExchangeGrantRFC8693   = "rfc8693"
	tokenExchangeGrantJWTBearer = "jwt_bearer"
)

// Client-authentication methods selected by the source's `client_auth` config.
// private_key_jwt is added in a later change; the secret methods ship here.
const (
	clientAuthSecretBasic = "client_secret_basic"
	clientAuthSecretPost  = "client_secret_post"
)

// grant_type URNs sent in the token request.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Compile-time interface assertions.
var _ credential.SourceDriver = (*TokenExchangeDriver)(nil)
var _ credential.ExchangeMinter = (*TokenExchangeDriver)(nil)

// TokenExchangeDriver exchanges a caller-derived identity (a subject token, and
// optionally an actor token) for a scoped downstream bearer at an RFC 8693 / RFC
// 7523 token endpoint. It is exchange-only: it never mints from static source
// config, so plain MintCredential is a defensive error and all issuance flows
// through MintCredentialWithExchange.
type TokenExchangeDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// subjectValidator validates unverified (header-sourced) subject/actor tokens
	// against the source's configured JWKS/OIDC keys. It is built lazily on first
	// use (it performs network I/O) and reused; cap/jwt validators are safe for
	// concurrent use.
	validatorMu      sync.Mutex
	subjectValidator *jwt.Validator
}

// TokenExchangeDriverFactory creates TokenExchangeDriver instances.
type TokenExchangeDriverFactory struct{}

// Type returns the driver type identifier.
func (f *TokenExchangeDriverFactory) Type() string {
	return credential.SourceTypeTokenExchange
}

// ValidateConfig validates source configuration. VerifySpec never runs for
// exchange specs, so the factory is the place strict validation lives.
func (f *TokenExchangeDriverFactory) ValidateConfig(config map[string]string) error {
	skip := credential.GetBool(config, "tls_skip_verify", false)
	if err := credential.ValidateSchema(config,
		credential.StringField("token_url").
			Required().
			Custom(func(v string) error { return validateOAuth2SafeURL(v, "token_url", skip) }).
			Describe("Token endpoint (HTTPS) of the STS/IdP performing the exchange").
			Example("https://idp.example.com/oauth2/v1/token"),

		credential.StringField("grant").
			OneOf(tokenExchangeGrantRFC8693, tokenExchangeGrantJWTBearer).
			Describe("Exchange grant: rfc8693 (token-exchange) or jwt_bearer (assertion; Entra OBO)").
			Example("rfc8693"),

		credential.StringField("client_auth").
			OneOf(clientAuthSecretBasic, clientAuthSecretPost).
			Describe("How Warden authenticates to the token endpoint").
			Example("client_secret_post"),

		credential.StringField("client_id").
			Describe("OAuth2 client ID Warden presents to the token endpoint").
			Example("warden-gateway"),

		credential.StringField("client_secret").
			Describe("OAuth2 client secret (masked on read)").
			Example("****"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		// Subject-validation keys: required at mint time to accept an unverified
		// (subject_token_source=header) subject/actor token. Validated here for
		// well-formedness; enforced as fail-closed in the driver.
		credential.StringField("subject_oidc_discovery_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "subject_oidc_discovery_url", skip)
			}).
			Describe("OIDC discovery URL of the issuer that signs header-sourced subject/actor tokens").
			Example("https://login.example.com/.well-known/openid-configuration"),
		credential.StringField("subject_jwks_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "subject_jwks_url", skip)
			}).
			Describe("JWKS URL for header-sourced subject/actor token signature validation").
			Example("https://login.example.com/keys"),
		credential.StringField("subject_issuer").
			Describe("Expected issuer (iss) of a header-sourced subject/actor token").
			Example("https://login.example.com/"),
		credential.StringField("subject_audience").
			Describe("Expected audience (aud) of a header-sourced subject/actor token").
			Example("api://warden"),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	); err != nil {
		return err
	}

	// The secret-based client-auth methods require client credentials.
	switch credential.GetString(config, "client_auth", clientAuthSecretPost) {
	case clientAuthSecretBasic, clientAuthSecretPost, "":
		if credential.GetString(config, "client_id", "") == "" || credential.GetString(config, "client_secret", "") == "" {
			return fmt.Errorf("client_id and client_secret are required for a secret-based client_auth")
		}
	}

	// token_param.* must not override core token-exchange form fields.
	protected := map[string]bool{
		"grant_type": true, "client_id": true, "client_secret": true,
		"client_assertion": true, "client_assertion_type": true,
		"subject_token": true, "subject_token_type": true,
		"actor_token": true, "actor_token_type": true, "assertion": true,
	}
	for key := range credential.GetPrefixed(config, "token_param.") {
		if protected[key] {
			return fmt.Errorf("token_param.%s cannot override a core token-exchange field", key)
		}
	}
	return nil
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *TokenExchangeDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "ca_data"}
}

// InferCredentialType returns the credential type for token_exchange sources.
func (f *TokenExchangeDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new TokenExchangeDriver.
func (f *TokenExchangeDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	client, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	return &TokenExchangeDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeTokenExchange, Config: config},
		logger:     log.WithSubsystem(credential.SourceTypeTokenExchange),
		httpClient: client,
	}, nil
}

// Type returns the driver type.
func (d *TokenExchangeDriver) Type() string {
	return credential.SourceTypeTokenExchange
}

// MintCredential is a defensive error: this driver is exchange-only. Reaching it
// means a spec without a subject source slipped past validation; never forward
// without caller identity.
func (d *TokenExchangeDriver) MintCredential(_ context.Context, _ *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("token_exchange requires caller exchange inputs; set %s=%s|%s on the spec",
		credential.ConfigSubjectTokenSource, credential.SourceAuthToken, credential.SourceHeader)
}

// MintCredentialWithExchange exchanges the caller-derived subject for a scoped
// downstream bearer token.
func (d *TokenExchangeDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: no subject token in exchange inputs")
	}

	// Origin contract. A verified subject (Warden authenticated it inbound) is
	// forwarded as-is. An unverified (caller-supplied header) subject MUST be
	// validated — signature, issuer, audience, expiry — before it is forwarded to
	// the STS, and the mint fails closed if the source lacks validation config.
	if inputs.SubjectTokenOrigin != credential.ExchangeOriginVerified {
		if err := d.validateUntrustedToken(ctx, inputs.SubjectToken, "subject"); err != nil {
			return nil, nil, 0, "", err
		}
	}
	// Actor delegation is added in a follow-up change; reject rather than silently
	// dropping the actor a caller supplied.
	if inputs.ActorToken != "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: actor tokens are not yet supported by this source")
	}

	form, err := d.buildExchangeForm(spec, inputs)
	if err != nil {
		return nil, nil, 0, "", err
	}
	headers := map[string]string{}
	if err := d.applyClientAuth(form, headers); err != nil {
		return nil, nil, 0, "", err
	}

	tokenURL := credential.GetString(d.credSource.Config, "token_url", "")
	resp, err := postOAuthTokenForm(ctx, d.httpClient, tokenURL, form, headers)
	if err != nil {
		return nil, nil, 0, "", classifyExchangeError(err)
	}
	if resp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: token response missing access_token")
	}

	return accessTokenRawData(resp), d.subjectMetadata(resp, inputs), ttlFromExpiresIn(resp.ExpiresIn), "", nil
}

// buildExchangeForm assembles the token-endpoint form for the configured grant.
func (d *TokenExchangeDriver) buildExchangeForm(spec *credential.CredSpec, inputs *credential.ExchangeInputs) (url.Values, error) {
	cfg := d.credSource.Config
	form := url.Values{}

	switch credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) {
	case tokenExchangeGrantRFC8693, "":
		form.Set("grant_type", grantTypeTokenExchange)
		form.Set("subject_token", inputs.SubjectToken)
		form.Set("subject_token_type", subjectTokenType(inputs))
		if aud := d.resolve(spec, "audience"); aud != "" {
			form.Set("audience", aud)
		}
		if res := d.resolve(spec, "resource"); res != "" {
			form.Set("resource", res)
		}
	case tokenExchangeGrantJWTBearer:
		form.Set("grant_type", grantTypeJWTBearer)
		form.Set("assertion", inputs.SubjectToken)
	default:
		return nil, fmt.Errorf("token_exchange: unsupported grant %q", credential.GetString(cfg, "grant", ""))
	}

	if scope := d.resolve(spec, "scope"); scope != "" {
		form.Set("scope", scope)
	}
	// Vendor-specific extras (e.g. Entra's requested_token_use=on_behalf_of).
	for k, v := range credential.GetPrefixed(cfg, "token_param.") {
		form.Set(k, v)
	}
	return form, nil
}

// applyClientAuth decorates the request with the configured client authentication.
func (d *TokenExchangeDriver) applyClientAuth(form url.Values, headers map[string]string) error {
	cfg := d.credSource.Config
	clientID := credential.GetString(cfg, "client_id", "")
	clientSecret := credential.GetString(cfg, "client_secret", "")

	switch credential.GetString(cfg, "client_auth", clientAuthSecretPost) {
	case clientAuthSecretPost, "":
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	case clientAuthSecretBasic:
		// RFC 6749 §2.3.1: client id/secret are form-urlencoded, then Basic-encoded.
		creds := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	default:
		return fmt.Errorf("token_exchange: unsupported client_auth %q", credential.GetString(cfg, "client_auth", ""))
	}
	return nil
}

// resolve returns spec.Config[key] when set, else the source config value.
func (d *TokenExchangeDriver) resolve(spec *credential.CredSpec, key string) string {
	if spec != nil {
		if v := credential.GetString(spec.Config, key, ""); v != "" {
			return v
		}
	}
	return credential.GetString(d.credSource.Config, key, "")
}

// subjectMetadata derives the non-secret, audit-logged identity of the exchanged
// token: the subject (from the minted token's sub claim, falling back to the
// subject token's), and whether the subject's origin was verified.
func (d *TokenExchangeDriver) subjectMetadata(resp *oauth2TokenResponse, inputs *credential.ExchangeInputs) map[string]interface{} {
	meta := map[string]interface{}{
		"subject_verified": strconv.FormatBool(inputs.SubjectTokenOrigin == credential.ExchangeOriginVerified),
	}
	claims := unverifiedJWTClaims(resp.AccessToken)
	if claims == nil {
		claims = unverifiedJWTClaims(inputs.SubjectToken)
	}
	if claims != nil {
		if sub, ok := scalarClaim(claims["sub"]); ok && sub != "" {
			meta["subject"] = sub
		}
	}
	return meta
}

// Revoke is a no-op — exchanged bearer tokens expire naturally.
func (d *TokenExchangeDriver) Revoke(_ context.Context, _ string) error {
	return nil
}

// Cleanup releases resources.
func (d *TokenExchangeDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// validateUntrustedToken verifies a caller-supplied (header-sourced) token
// against the source's configured issuer, audience and signing keys before it is
// forwarded to the STS. It fails closed when the source lacks validation config:
// an unvalidated caller token must never reach the token endpoint on Warden's
// authority. `role` is "subject" or "actor" for error messages.
func (d *TokenExchangeDriver) validateUntrustedToken(ctx context.Context, token, role string) error {
	cfg := d.credSource.Config
	issuer := credential.GetString(cfg, "subject_issuer", "")
	audience := credential.GetString(cfg, "subject_audience", "")
	if issuer == "" || audience == "" {
		return fmt.Errorf("token_exchange: refusing an unverified %s token — subject_issuer and subject_audience must be configured on the source to validate it", role)
	}

	validator, err := d.getSubjectValidator(ctx)
	if err != nil {
		return fmt.Errorf("token_exchange: cannot validate the %s token (fail closed): %w", role, err)
	}

	expected := jwt.Expected{
		SigningAlgorithms: subjectSigningAlgs,
		Issuer:            issuer,
		Audiences:         []string{audience},
	}
	if _, err := validator.Validate(ctx, token, expected); err != nil {
		return fmt.Errorf("token_exchange: %s token failed validation: %w", role, err)
	}
	return nil
}

// getSubjectValidator lazily builds and caches the cap/jwt validator from the
// source's subject_oidc_discovery_url or subject_jwks_url. A build failure is not
// cached, so a transient network error is retried on the next request.
func (d *TokenExchangeDriver) getSubjectValidator(ctx context.Context) (*jwt.Validator, error) {
	d.validatorMu.Lock()
	defer d.validatorMu.Unlock()
	if d.subjectValidator != nil {
		return d.subjectValidator, nil
	}

	cfg := d.credSource.Config
	discoveryURL := credential.GetString(cfg, "subject_oidc_discovery_url", "")
	jwksURL := credential.GetString(cfg, "subject_jwks_url", "")

	var keySet jwt.KeySet
	var err error
	switch {
	case discoveryURL != "":
		keySet, err = jwt.NewOIDCDiscoveryKeySet(ctx, discoveryURL, "")
	case jwksURL != "":
		keySet, err = jwt.NewJSONWebKeySet(ctx, jwksURL, "")
	default:
		return nil, fmt.Errorf("no subject_oidc_discovery_url or subject_jwks_url configured")
	}
	if err != nil {
		return nil, err
	}

	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		return nil, err
	}
	d.subjectValidator = validator
	return validator, nil
}

// subjectTokenType returns the RFC 8693 subject_token_type, defaulting to jwt.
func subjectTokenType(inputs *credential.ExchangeInputs) string {
	if inputs.SubjectTokenType != "" {
		return inputs.SubjectTokenType
	}
	return credential.TokenTypeJWT
}

// unverifiedJWTClaims decodes a JWT's claims without verifying its signature,
// for identity extraction only. Returns nil for opaque (non-JWT) tokens.
func unverifiedJWTClaims(token string) map[string]interface{} {
	claims, err := helper.ParseJWTClaimsUnverified(token)
	if err != nil {
		return nil
	}
	return claims
}

// classifyExchangeError renders a token-endpoint failure into a legible error,
// distinguishing a rejected grant (the caller should re-authenticate) from a
// transport/server failure.
func classifyExchangeError(err error) error {
	var tee *tokenEndpointError
	if errors.As(err, &tee) && (tee.code == "invalid_grant" || tee.status == http.StatusBadRequest || tee.status == http.StatusUnauthorized) {
		return fmt.Errorf("token_exchange rejected by the IdP (the subject token may be expired or unacceptable; re-authenticate): %w", err)
	}
	return fmt.Errorf("token_exchange failed: %w", err)
}
