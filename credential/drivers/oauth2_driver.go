package drivers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// oauth2MaxRetryAttempts for retryable token endpoint calls
const oauth2MaxRetryAttempts = 3

// Valid auth_header_type values for OAuth2 token verification.
const (
	oauth2AuthBearer       = "bearer"
	oauth2AuthToken        = "token"
	oauth2AuthCustomHeader = "custom_header"
)

// auth_method selects the OAuth2 flow. It is read spec-over-source and defaults
// to client_credentials so existing sources keep working unchanged.
const (
	oauth2AuthMethodClientCredentials = "client_credentials"
	oauth2AuthMethodAuthorizationCode = "authorization_code"
)

// OAuth2 grant types sent in the token request.
const (
	oauth2GrantClientCredentials = "client_credentials"
	oauth2GrantAuthorizationCode = "authorization_code"
	oauth2GrantRefreshToken      = "refresh_token"
)

// Compile-time interface assertions
var _ credential.SourceDriver = (*OAuth2Driver)(nil)
var _ credential.SpecVerifier = (*OAuth2Driver)(nil)
var _ credential.OAuth2Authorizer = (*OAuth2Driver)(nil)
var _ credential.ChainedSecretMinter = (*OAuth2Driver)(nil)

// OAuth2Driver exchanges OAuth2 credentials for bearer tokens.
//
// The token endpoint and connection options live in the source config (token_url
// required; auth_url, default_scopes, verify_url, verify_method, auth_header_type,
// auth_header_name, display_name, ca_data, tls_skip_verify optional). The source's
// client_auth selects how the driver authenticates to the token endpoint: a client
// secret in the form (client_secret_post, the default) or in an Authorization header
// (client_secret_basic), or an RFC 7523 client assertion signed with a private key
// (private_key_jwt). The client credential — client_id with client_secret or
// private_key — may live on the source or the spec, resolved spec-over-source, or be
// fetched per mint from another cred spec (secret_spec, source-level). The spec's
// auth_method selects the flow (default client_credentials); the driver POSTs to the
// token endpoint and returns the resulting access_token as an api_key field.
type OAuth2Driver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
	// sourceKey is the source's private_key, parsed once when the driver is built: a
	// changed source builds a new driver, so it can never go stale, and a mint is
	// spared an RSA parse on the data path. nil when the source holds no key; a spec
	// or a chain may still supply one, parsed per mint.
	sourceKey *rsa.PrivateKey
}

// OAuth2DriverFactory creates OAuth2Driver instances.
type OAuth2DriverFactory struct{}

// Type returns the driver type identifier.
func (f *OAuth2DriverFactory) Type() string {
	return credential.SourceTypeOAuth2
}

// ValidateConfig validates source configuration. token_url is required.
// client_id/client_secret are optional here because the authorization_code flow
// keeps them on the spec, and a chained source (secret_spec) holds neither;
// presence is checked at mint time.
func (f *OAuth2DriverFactory) ValidateConfig(config credential.Config) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("client_id").
			Describe("OAuth2 client ID (source-level for client_credentials; may be set per-spec)").
			Example("your-client-id"),

		credential.StringField("client_secret").
			Describe("OAuth2 client secret (source-level for client_credentials; may be set per-spec)").
			Example("your-client-secret"),

		credential.StringField("client_auth").
			OneOf(clientAuthSecretPost, clientAuthSecretBasic, clientAuthPrivateKeyJWT).
			Describe("How Warden authenticates to the token endpoint: client_secret_post (default) sends the secret in the form, client_secret_basic in an Authorization header, private_key_jwt sends an RFC 7523 client assertion signed with private_key").
			Example("client_secret_post"),

		credential.StringField("private_key").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				_, err := parseRSAPrivateKey(v)
				return err
			}).
			Describe("PEM RSA private key for client_auth=private_key_jwt (masked on read; may be set per-spec; omit when secret_spec is set)").
			Example("-----BEGIN PRIVATE KEY----- ..."),

		credential.StringField("client_assertion_alg").
			OneOf("RS256").
			Describe("Signing algorithm for the private_key_jwt client assertion (RS256)").
			Example("RS256"),

		credential.StringField("client_assertion_kid").
			Describe("Optional key id (kid) header for the client assertion, naming private_key at the authorization server (may be set per-spec beside the key; when secret_spec is set it travels in the referenced payload, under 'client_assertion_kid' or 'kid')").
			Example("key-1"),

		credential.StringField("client_assertion_aud").
			OneOf(clientAssertionAudTokenURL, clientAssertionAudIssuer).
			Describe("Audience of the client assertion: token_url (default) names the token endpoint; issuer names the issuer identifier, which an authorization server enforcing RFC 7523bis requires (needs issuer)").
			Example("token_url"),

		credential.StringField("token_url").
			Required().
			Custom(func(v string) error {
				return validateOAuth2SafeURL(v, "token_url", credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("OAuth2 token endpoint (HTTPS)").
			Example("https://identity.pagerduty.com/oauth/token"),

		credential.StringField("auth_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "auth_url", credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("OAuth2 authorization endpoint (HTTPS) — required for authorization_code specs").
			Example("https://github.com/login/oauth/authorize"),

		credential.StringField("issuer").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "issuer", credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Authorization server issuer identifier (HTTPS). When set, a connect callback carrying RFC 9207 'iss' must match it exactly before the authorization code is redeemed — the mix-up defense. Never guessed from auth_url: issuers routinely differ from the authorization endpoint's origin (realm and tenant paths), and a wrong guess would refuse legitimate flows").
			Example("https://github.com/login/oauth"),

		credential.StringField("introspection_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "introspection_url", credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Userinfo/introspection endpoint (HTTPS), GET with the access token attached, called at mint to fetch identity fields for opaque tokens; JWT access tokens are decoded locally instead").
			Example("https://api.github.com/user"),

		credential.StringField("metadata_fields").
			Describe("Comma-separated identity fields (source-level) copied from the token/userinfo response into the credential's non-secret, audit-logged metadata (default: sub; empty disables)").
			Example("sub,email"),

		credential.StringField("default_scopes").
			Describe("Default OAuth2 scopes (space-separated)").
			Example("read write"),

		credential.StringField("verify_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "verify_url", credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Endpoint to verify minted tokens (skip if empty)").
			Example("https://api.pagerduty.com/users/me"),

		credential.StringField("verify_method").
			Custom(validateOAuth2VerifyMethod).
			Describe("HTTP method for verify_url (default: GET)").
			Example("GET"),

		credential.StringField("auth_header_type").
			Custom(validateOAuth2AuthHeaderType).
			Describe("How to attach token for verification: bearer, token, custom_header (default: bearer)").
			Example("bearer"),

		credential.StringField("auth_header_name").
			Describe("Header name when auth_header_type=custom_header").
			Example("X-Api-Key"),

		credential.StringField("display_name").
			Describe("Human-readable label for logs/errors (default: OAuth2)").
			Example("PagerDuty"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),

		credential.StringField("secret_spec").
			Describe("Source the whole client credential from another cred spec via credential chaining instead of storing it inline (client_id and client_secret then omitted; the referenced payload supplies both). client_credentials only").
			Example("idp-client-credential"),

		credential.StringField("secret_field").
			Describe("Which field of the referenced secret_spec's credential holds the client secret, or for client_auth=private_key_jwt the private key (when its payload has multiple keys); the client id travels beside it under 'client_id'").
			Example("client_secret"),

		credential.StringField("secret_cache_ttl").
			Describe("Cache the chained client credential source-wide for this duration (e.g. 30m); omit to fetch it on every mint").
			Example("30m"),
	); err != nil {
		return err
	}

	// The client_auth method decides which half of the client credential is meaningful.
	clientAuth := credential.GetString(config, "client_auth", clientAuthSecretPost)
	switch clientAuth {
	case clientAuthSecretPost, clientAuthSecretBasic:
		// A key left on a secret-based source would be stored, and reported as stored,
		// while never being sent.
		for _, key := range []string{"private_key", "client_assertion_alg", "client_assertion_kid", "client_assertion_aud"} {
			if credential.GetString(config, key, "") != "" {
				return fmt.Errorf("%s must be omitted for client_auth=%s; it applies to client_auth=%s", key, clientAuth, clientAuthPrivateKeyJWT)
			}
		}
	case clientAuthPrivateKeyJWT:
		// The key replaces the secret; a secret kept beside it would never be sent.
		if credential.GetString(config, "client_secret", "") != "" {
			return fmt.Errorf("client_secret must be omitted for client_auth=%s; the client authenticates with private_key", clientAuthPrivateKeyJWT)
		}
		if credential.GetString(config, "client_assertion_aud", "") == clientAssertionAudIssuer &&
			credential.GetString(config, "issuer", "") == "" {
			return fmt.Errorf("client_assertion_aud=%s requires issuer, the authorization server's issuer identifier", clientAssertionAudIssuer)
		}
		// A kid names the key stored beside it. With no key here, every spec brings its
		// own key and its own kid, so this one would name nothing that ever signs. (A
		// chained source is refused a kid outright, below.)
		if credential.GetString(config, "client_assertion_kid", "") != "" &&
			credential.GetString(config, "private_key", "") == "" &&
			credential.GetString(config, credential.ConfigSecretSpec, "") == "" {
			return fmt.Errorf("client_assertion_kid names the key stored beside it, and this source has none: set private_key beside it, or set the kid on each spec beside its own key")
		}
	}

	// A source in chaining mode holds NEITHER half of the client credential. The secret
	// is excluded because a source that reads as keyless must not still store the very
	// secret chaining exists to remove, and the id follows it because the two
	// authenticate as a pair: an id kept here beside a secret fetched from the chain
	// would name one client while presenting another's, which the token endpoint answers
	// with invalid_client and the chained path then reads as a rejected secret and
	// retries pointlessly. The key id goes with the key for the same reason: a kid names
	// one key among the several an authorization server may hold for a client, so kept
	// here it would stamp assertions signed by every agent's key with one agent's kid.
	//
	// Requiring both from the payload also lets one source and one spec serve many
	// clients, since the pair is resolved per mint rather than pinned to the source.
	if credential.GetString(config, credential.ConfigSecretSpec, "") != "" {
		if err := rejectInlineClientCredential(config, "client_secret", "private_key", "client_assertion_kid"); err != nil {
			return err
		}
		// auth_method resolves spec-over-source, and the spec-side rule lives in the
		// config store, which sees only spec config. Catch the source side here, or a
		// source setting it would leave every spec beneath it creating cleanly and
		// failing at mint.
		if am := credential.GetString(config, "auth_method", ""); am != "" && am != oauth2AuthMethodClientCredentials {
			return fmt.Errorf("auth_method=%s is not supported when secret_spec is set (chaining supports %s only); the consent flow runs without a caller and cannot fetch the chained client credential",
				am, oauth2AuthMethodClientCredentials)
		}
	}

	// Validate token_param.* keys don't override core form fields
	protectedFields := map[string]bool{
		"grant_type":            true,
		"client_id":             true,
		"client_secret":         true,
		"client_assertion":      true,
		"client_assertion_type": true,
	}
	for key := range credential.GetPrefixed(config, "token_param.") {
		if protectedFields[key] {
			return fmt.Errorf("token_param.%s cannot override core OAuth2 field", key)
		}
	}

	// auth_header_name is required when auth_header_type is custom_header
	if credential.GetString(config, "auth_header_type", "") == oauth2AuthCustomHeader {
		if credential.GetString(config, "auth_header_name", "") == "" {
			return fmt.Errorf("auth_header_name is required when auth_header_type is custom_header")
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
func (f *OAuth2DriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "private_key", "ca_data"}
}

// StoredSecrets reports the secret config keys this source holds.
func (f *OAuth2DriverFactory) StoredSecrets(config credential.Config) []string {
	return config.Present("client_secret", "private_key")
}

// InferCredentialType returns the credential type for OAuth2 sources.
func (f *OAuth2DriverFactory) InferCredentialType(_ credential.Config) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new OAuth2Driver.
func (f *OAuth2DriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOAuth2,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeOAuth2),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	if pemKey := credential.GetString(config, "private_key", ""); pemKey != "" {
		if driver.sourceKey, err = parseRSAPrivateKey(pemKey); err != nil {
			return nil, fmt.Errorf("invalid private_key: %w", err)
		}
	}

	return driver, nil
}

// Type returns the driver type.
func (d *OAuth2Driver) Type() string {
	return credential.SourceTypeOAuth2
}

// displayName returns the configured display name or "OAuth2".
func (d *OAuth2Driver) displayName() string {
	return credential.GetString(d.credSource.Config, "display_name", "OAuth2")
}

// oauth2TokenResponse is the standard OAuth2 token endpoint response.
type oauth2TokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
	// IssuedTokenType is the RFC 8693 §2.2.1 issued_token_type, naming the format
	// of the returned token. The token_exchange driver reads it (e.g. to confirm
	// an ID-JAG assertion in the cross-app flow); plain OAuth2 leaves it empty.
	IssuedTokenType string `json:"issued_token_type"`
	// Some providers (notably GitHub) report failures as HTTP 200 with an error body.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// resolve returns spec.Config.Get(key) when set, else the source config value, else def.
// This lets a spec override or supply source-level keys (e.g. client_id,
// client_secret, scopes) — needed for the authorization_code flow where those
// live on the spec.
func (d *OAuth2Driver) resolve(spec *credential.CredSpec, key, def string) string {
	if spec != nil {
		if v := credential.GetString(spec.Config, key, ""); v != "" {
			return v
		}
	}
	return credential.GetString(d.credSource.Config, key, def)
}

// rejectConsentOnChainedSource refuses the consent steps on a source that fetches its
// client credential per mint. They run on the system backend with no caller, so they
// have no identity to fetch the pair as — and without this an operator could complete a
// whole consent dance and seal tokens that no mint could ever spend, since minting from
// such a source is client_credentials only.
func (d *OAuth2Driver) rejectConsentOnChainedSource() error {
	if credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != "" {
		return fmt.Errorf("%s OAuth2 source uses secret_spec (credential chaining), which supports auth_method=%s only; the consent flow runs without a caller and cannot fetch the chained client credential",
			d.displayName(), oauth2AuthMethodClientCredentials)
	}
	return nil
}

// MintCredential mints a bearer token using the flow selected by auth_method
// (default client_credentials).
func (d *OAuth2Driver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A chained source holds no client credential, so minting here would fail on a
	// missing pair rather than saying why. Reaching this means the manager routed a
	// chained spec down the direct path; fail closed and name the cause.
	if credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != "" {
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 source uses secret_spec (credential chaining); it must mint from fetched secret material, not directly", d.displayName())
	}

	authMethod := d.resolve(spec, "auth_method", oauth2AuthMethodClientCredentials)
	switch authMethod {
	case oauth2AuthMethodClientCredentials:
		return d.mintFromClientCredentials(ctx, spec, nil)
	case oauth2AuthMethodAuthorizationCode:
		return d.mintFromRefreshToken(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 unsupported auth_method %q", d.displayName(), authMethod)
	}
}

// mintFromClientCredentials exchanges client credentials for a bearer token. chained,
// when non-nil, supplies the whole client credential from credential-chaining material
// instead of config.
func (d *OAuth2Driver) mintFromClientCredentials(ctx context.Context, spec *credential.CredSpec, chained *chainedClientAuth) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	config := d.credSource.Config
	name := d.displayName()

	if chained != nil {
		// Validation refuses a chained source or spec that also names a client, so a
		// leftover here means config drifted past it. Refusing beats presenting a
		// credential half from config and half from the chain, which the endpoint
		// rejects as invalid_client and the chained path then misreads as a stale one.
		for _, key := range []string{"client_id", "client_secret", "private_key", "client_assertion_kid"} {
			if d.resolve(spec, key, "") != "" {
				return nil, nil, 0, "", fmt.Errorf("%s OAuth2 chained mint: %s must not be configured when secret_spec is set; the referenced spec supplies the whole client credential", name, key)
			}
		}
	}
	auth, err := d.resolveClientAuth(spec, chained, "source")
	if err != nil {
		return nil, nil, 0, "", err
	}

	defaultScopes := credential.GetString(config, "default_scopes", "")
	scope := credential.GetString(spec.Config, "scope", defaultScopes)

	// Build token request body; the client authentication is added per attempt.
	form := url.Values{"grant_type": {oauth2GrantClientCredentials}}
	if scope != "" {
		form.Set("scope", scope)
	}

	// Apply extra token form parameters from source config (token_param.* keys)
	for k, v := range credential.GetPrefixed(config, "token_param.") {
		form.Set(k, v)
	}

	tokenResp, err := d.postWithClientAuth(ctx, auth, form)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 token exchange failed: %w", name, oauth2ChainedClientAuthError(err, chained != nil))
	}
	if tokenResp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 token response missing access_token", name)
	}

	return accessTokenRawData(tokenResp), d.extractMetadata(ctx, spec, tokenResp.AccessToken), ttlFromExpiresIn(tokenResp.ExpiresIn), "", nil
}

// mintFromRefreshToken exchanges the sealed refresh token for a fresh access
// token (grant_type=refresh_token). Providers that issue no refresh token seal a
// static access token at connect time, which is returned directly. When the
// provider rotates the refresh token, the new value is surfaced under the reserved
// rawData key for the minting layer to persist.
func (d *OAuth2Driver) mintFromRefreshToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	name := d.displayName()

	refreshToken := credential.GetString(spec.Config, "refresh_token", "")
	if refreshToken == "" {
		// No-refresh-token providers seal a static access token at connect time.
		if staticToken := credential.GetString(spec.Config, "access_token", ""); staticToken != "" {
			return map[string]interface{}{"api_key": staticToken}, d.extractMetadata(ctx, spec, staticToken), staticTokenTTL(spec), "", nil
		}
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 spec %q is not connected — run `warden cred spec connect %s`", name, spec.Name, spec.Name)
	}

	return d.refreshGrant(ctx, spec, refreshToken)
}

// refreshGrant exchanges a refresh token for a fresh access token
// (grant_type=refresh_token). The refresh token is passed in explicitly rather than
// read from the spec so the sealing and the spending stay separable.
func (d *OAuth2Driver) refreshGrant(ctx context.Context, spec *credential.CredSpec, refreshToken string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	name := d.displayName()

	auth, err := d.resolveClientAuth(spec, nil, "spec")
	if err != nil {
		return nil, nil, 0, "", err
	}

	form := url.Values{
		"grant_type":    {oauth2GrantRefreshToken},
		"refresh_token": {refreshToken},
	}

	tokenResp, err := d.postWithClientAuth(ctx, auth, form)
	if err != nil {
		if isRefreshTokenRejection(err) {
			// Signal the minting layer to re-read the spec and retry once (the
			// token may have been rotated by another node).
			return nil, nil, 0, "", fmt.Errorf("%s OAuth2 refresh failed: %w: %w", name, credential.ErrRefreshTokenRejected, err)
		}
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 refresh failed: %w", name, err)
	}
	if tokenResp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 refresh response missing access_token", name)
	}

	rawData := accessTokenRawData(tokenResp)
	// Surface a rotated refresh token for the minting layer to persist. A refresh
	// resets the refresh-token window, so surface the new expiry too (when the
	// provider returns one) to keep the persisted refresh_token_expires_at in step.
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		rawData[credential.RawRotatedRefreshTokenKey] = tokenResp.RefreshToken
		if tokenResp.RefreshTokenExpiresIn > 0 {
			rawData[credential.RawRotatedRefreshTokenExpiresAtKey] = expiresAt(tokenResp.RefreshTokenExpiresIn)
		}
	}
	return rawData, d.extractMetadata(ctx, spec, tokenResp.AccessToken), ttlFromExpiresIn(tokenResp.ExpiresIn), "", nil
}

// MintFromSecret implements credential.ChainedSecretMinter: it mints a bearer token
// whose client credential — both halves — comes from credential-chaining material
// (source-level secret_spec) instead of source config. A chained source stores
// neither half, so the id and the secret are read together from the fetched payload,
// which lets one source and one spec serve an OAuth client per agent.
func (d *OAuth2Driver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	name := d.displayName()

	// Chaining on an oauth2 spec used to mean "the material is a refresh token"; it now
	// means the client credential, and it is a source concern, so validation keeps the
	// reference on the source. A spec written before that change still carries the key,
	// and would otherwise fail here reporting a payload with no client id — say what
	// actually has to move instead.
	if credential.GetString(spec.Config, credential.ConfigSecretSpec, "") != "" {
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 spec %q sets %s: chaining a refresh token is no longer supported, and a chained client credential belongs on the source; move %s to the source and clear it from the spec",
			name, spec.Name, credential.ConfigSecretSpec, credential.ConfigSecretSpec)
	}

	// The consent steps that seal an authorization_code grant run without a caller, so
	// they cannot reach chained material and validation refuses the combination. Reaching
	// it means config drifted past that check.
	if authMethod := d.resolve(spec, "auth_method", oauth2AuthMethodClientCredentials); authMethod != oauth2AuthMethodClientCredentials {
		// A source-config error, not a payload one: refetching cannot change the answer,
		// so this must not carry the sentinel that asks the manager to try again.
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 credential chaining supports auth_method=%s only, got %q",
			name, oauth2AuthMethodClientCredentials, authMethod)
	}

	// The payload is read the same way token_exchange reads one: client_auth decides
	// whether it carries a client secret or a private key.
	chained, err := chainedClientAuthFromMaterial(credential.GetString(d.credSource.Config, "client_auth", ""), material)
	if err != nil {
		// %w, so the ErrChainedSecretIncomplete the manager acts on survives the wrap.
		return nil, nil, 0, "", fmt.Errorf("%s OAuth2 chained mint: %w", name, err)
	}
	return d.mintFromClientCredentials(ctx, spec, chained)
}

// oauth2ClientAuth is the client authentication one mint presents: who the client is
// and what it proves itself with. It is resolved once per mint — a key is parsed once,
// a missing credential reported before anything is sent — and then applied to every
// attempt, so each attempt signs an assertion of its own. It is built per mint and
// never stored on the shared driver, so concurrent mints cannot see each other's.
type oauth2ClientAuth struct {
	method       string
	clientID     string
	clientSecret string          // client_secret_post / client_secret_basic
	key          *rsa.PrivateKey // private_key_jwt
	kid          string          // the kid stored beside key, if any
	aud          string          // the audience a client assertion names
}

// resolveClientAuth settles the client authentication for one mint. chained, when
// non-nil, supplies the whole client credential from credential chaining in place of
// config; otherwise each half resolves spec-over-source, which is how an
// authorization_code spec brings a client of its own. where names the config a
// missing credential was expected in.
func (d *OAuth2Driver) resolveClientAuth(spec *credential.CredSpec, chained *chainedClientAuth, where string) (*oauth2ClientAuth, error) {
	cfg := d.credSource.Config
	name := d.displayName()
	auth := &oauth2ClientAuth{
		method: credential.GetString(cfg, "client_auth", clientAuthSecretPost),
		aud: clientAssertionAudience(credential.GetString(cfg, "client_assertion_aud", ""),
			d.tokenURL(), credential.GetString(cfg, "issuer", "")),
	}

	if auth.method != clientAuthPrivateKeyJWT {
		if chained != nil {
			auth.clientID, auth.clientSecret = chained.clientID, chained.secret
		} else {
			auth.clientID, auth.clientSecret = d.resolve(spec, "client_id", ""), d.resolve(spec, "client_secret", "")
		}
		if auth.clientID == "" || auth.clientSecret == "" {
			return nil, fmt.Errorf("%s OAuth2 %s missing client_id or client_secret", name, where)
		}
		return auth, nil
	}

	// The kid goes with the key it was stored beside: a spec that brings its own key
	// brings its own kid and never inherits the source's, which names another key.
	var pemKey string
	switch {
	case chained != nil:
		auth.clientID, pemKey, auth.kid = chained.clientID, chained.secret, chained.kid
	case spec != nil && credential.GetString(spec.Config, "private_key", "") != "":
		auth.clientID = d.resolve(spec, "client_id", "")
		pemKey, auth.kid = credential.GetString(spec.Config, "private_key", ""), credential.GetString(spec.Config, "client_assertion_kid", "")
	default:
		auth.clientID = d.resolve(spec, "client_id", "")
		auth.key, auth.kid = d.sourceKey, credential.GetString(cfg, "client_assertion_kid", "")
	}
	if pemKey != "" {
		key, err := parseRSAPrivateKey(pemKey)
		if err != nil {
			return nil, fmt.Errorf("%s OAuth2 invalid private_key: %w", name, err)
		}
		auth.key = key
	}
	if auth.clientID == "" || auth.key == nil {
		return nil, fmt.Errorf("%s OAuth2 %s missing client_id or private_key", name, where)
	}
	return auth, nil
}

// headers returns the headers this client authentication sends: client_secret_basic's
// Authorization header, nothing for the other methods. They do not vary between
// attempts, so they are settled once.
func (a *oauth2ClientAuth) headers() map[string]string {
	if a.method != clientAuthSecretBasic {
		return nil
	}
	return map[string]string{"Authorization": basicClientAuthHeader(a.clientID, a.clientSecret)}
}

// applyClientAuth adds the client authentication to one attempt's form. A client
// assertion is signed here, per attempt, so none is ever sent twice.
//
// client_secret_basic adds nothing: RFC 6749 §2.3 allows one authentication method per
// request, and §4.1.3 asks for client_id in the body only from a client that is not
// authenticating.
func (d *OAuth2Driver) applyClientAuth(_ context.Context, auth *oauth2ClientAuth, form url.Values) error {
	switch auth.method {
	case clientAuthSecretBasic:
		// Sent in the Authorization header (see headers).
	case clientAuthPrivateKeyJWT:
		claims, err := clientAssertionClaims(auth.clientID, auth.aud)
		if err != nil {
			return err
		}
		assertion, err := signClientAssertionLocal(auth.key, auth.kid, claims)
		if err != nil {
			return err
		}
		form.Set("client_id", auth.clientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	default:
		form.Set("client_id", auth.clientID)
		form.Set("client_secret", auth.clientSecret)
	}
	return nil
}

// postWithClientAuth POSTs form to the token endpoint authenticated as the client. The
// client authentication is applied afresh to a copy of the form on every attempt, so a
// retry presents a new client assertion: a server enforcing single use refuses a
// repeated jti as invalid_client, and one that recorded the assertion before its answer
// was lost would otherwise turn a blip into a failed mint.
func (d *OAuth2Driver) postWithClientAuth(ctx context.Context, auth *oauth2ClientAuth, form url.Values) (*oauth2TokenResponse, error) {
	return postOAuthTokenFormFunc(ctx, d.httpClient, d.tokenURL(), func() (url.Values, error) {
		attempt := maps.Clone(form)
		if err := d.applyClientAuth(ctx, auth, attempt); err != nil {
			return nil, err
		}
		return attempt, nil
	}, auth.headers())
}

// oauth2ChainedClientAuthError reports a token endpoint error as a rejected chained
// client credential, or returns it unchanged when it is anything else. Wrapping
// ErrChainedSecretRejected asks the minting layer to evict the cached secret and retry
// once with a fresh fetch.
//
// This is deliberately narrower than isRefreshTokenRejection, which treats a bare 400 as
// a rejected grant: on this path a bare 400 is far more likely invalid_scope or
// unsupported_grant_type, and refetching the secret cannot fix either.
//
// invalid_client does not say which half was refused, and it does not need to: the
// eviction refetches the payload, so the id and the secret are replaced together.
func oauth2ChainedClientAuthError(err error, chained bool) error {
	if chained && isChainedClientAuthRejection(err) {
		// Keep the underlying error (the IdP's code / description) in the chain
		// alongside the sentinel for legible diagnostics.
		return fmt.Errorf("client authentication rejected: %w (%w)", credential.ErrChainedSecretRejected, err)
	}
	return err
}

// isChainedClientAuthRejection reports whether a token endpoint error says the client
// credential itself was refused, rather than something about the grant being asked for.
//
// invalid_client is reported as HTTP 400 (credentials in the form body) or 401; a
// nonstandard IdP may return a bare 401 with no error code. Per RFC 6749 §5.2, 401 at the
// token endpoint is client-authentication-specific, so either signal counts.
//
// A bare 400 deliberately does not: on a chained path it is far more likely invalid_scope
// or unsupported_grant_type, and refetching the secret cannot fix either. That is what
// separates this from isRefreshTokenRejection, which is about the grant and does count a
// bare 400.
func isChainedClientAuthRejection(err error) bool {
	var tee *tokenEndpointError
	if !errors.As(err, &tee) {
		return false
	}
	return tee.code == "invalid_client" || tee.status == http.StatusUnauthorized
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens using the
// client secret the server holds, and returns the spec-config keys to seal.
func (d *OAuth2Driver) ExchangeAuthorizationCode(ctx context.Context, spec *credential.CredSpec, code, redirectURI, codeVerifier string) (map[string]string, error) {
	name := d.displayName()

	if err := d.rejectConsentOnChainedSource(); err != nil {
		return nil, err
	}

	auth, err := d.resolveClientAuth(spec, nil, "spec")
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":   {oauth2GrantAuthorizationCode},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	tokenResp, err := d.postWithClientAuth(ctx, auth, form)
	if err != nil {
		return nil, fmt.Errorf("%s OAuth2 authorization-code exchange failed: %w", name, err)
	}

	sealed := map[string]string{}
	switch {
	case tokenResp.RefreshToken != "":
		sealed["refresh_token"] = tokenResp.RefreshToken
		if tokenResp.RefreshTokenExpiresIn > 0 {
			sealed["refresh_token_expires_at"] = expiresAt(tokenResp.RefreshTokenExpiresIn)
		}
	case tokenResp.AccessToken != "":
		// No-refresh-token provider: seal the access token. Record its expiry when
		// the provider returns one so mint can lease it correctly (otherwise it is
		// treated as non-expiring).
		sealed["access_token"] = tokenResp.AccessToken
		if tokenResp.ExpiresIn > 0 {
			sealed["access_token_expires_at"] = expiresAt(tokenResp.ExpiresIn)
		}
	default:
		return nil, fmt.Errorf("%s OAuth2 authorization-code exchange returned neither refresh_token nor access_token", name)
	}
	return sealed, nil
}

// AuthorizationIssuer returns the source's recorded issuer identifier, empty
// when the operator recorded none.
//
// Source-only, like auth_url and token_url: they describe the authorization
// server, not the identity being authorized, and splitting the issuer from
// its siblings would leave one half of a pair configurable in a different
// place from the other.
func (d *OAuth2Driver) AuthorizationIssuer() string {
	return credential.GetString(d.credSource.Config, "issuer", "")
}

// BuildAuthorizeURL assembles the provider authorize URL. Scopes are read as
// already-normalized (space-separated) but commas are tolerated defensively.
func (d *OAuth2Driver) BuildAuthorizeURL(spec *credential.CredSpec, redirectURI, state, codeChallenge string) (string, error) {
	if err := d.rejectConsentOnChainedSource(); err != nil {
		return "", err
	}

	authURL := credential.GetString(d.credSource.Config, "auth_url", "")
	if authURL == "" {
		return "", fmt.Errorf("%s OAuth2 source missing auth_url (required for authorization_code)", d.displayName())
	}
	clientID := d.resolve(spec, "client_id", "")
	if clientID == "" {
		return "", fmt.Errorf("%s OAuth2 spec missing client_id", d.displayName())
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth_url: %w", err)
	}

	q := parsed.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	if state != "" {
		q.Set("state", state)
	}
	if scope := normalizeOAuth2Scopes(d.resolve(spec, "scopes", "")); scope != "" {
		q.Set("scope", scope)
	}
	// PKCE is on by default; honor an explicit pkce=false to omit the challenge.
	if codeChallenge != "" && pkceEnabled(d.resolve(spec, "pkce", "")) {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// tokenEndpointError is returned by postOAuthToken when the token endpoint
// rejects the request. It carries the HTTP status and, when the body was parsed,
// the OAuth2 error code, so the refresh path can classify an invalid_grant
// without fragile string matching.
type tokenEndpointError struct {
	status      int
	code        string // OAuth2 error code (e.g. "invalid_grant"); "" if unparsed
	description string
	err         error // underlying transport/status error (when code is unparsed)
}

func (e *tokenEndpointError) Error() string {
	if e.code != "" {
		if e.description != "" {
			return fmt.Sprintf("token endpoint error %q: %s", e.code, e.description)
		}
		return fmt.Sprintf("token endpoint error %q", e.code)
	}
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("token endpoint status %d", e.status)
}

func (e *tokenEndpointError) Unwrap() error { return e.err }

// HTTPStatus is the status the token endpoint answered with; 0 when it never
// answered (a transport failure, which Unwrap then carries). A parsed OAuth2
// error code is a refusal whatever the transport status — some providers
// report refusals on a 200 — so such an answer reads as the 400 RFC 6749
// gives it.
func (e *tokenEndpointError) HTTPStatus() int {
	if e.code != "" && e.status < http.StatusBadRequest {
		return http.StatusBadRequest
	}
	return e.status
}

// isRefreshTokenRejection reports whether a postOAuthToken error indicates the
// refresh token (grant) was rejected: an explicit invalid_grant code, or — when
// the body carried no code — an HTTP 400/401 status (the RFC 6749 statuses for a
// rejected grant).
func isRefreshTokenRejection(err error) bool {
	var tee *tokenEndpointError
	if !errors.As(err, &tee) {
		return false
	}
	if tee.code != "" {
		return tee.code == "invalid_grant"
	}
	return tee.status == http.StatusBadRequest || tee.status == http.StatusUnauthorized
}

// accessTokenRawData builds the rawData map returned to the credential parser.
func accessTokenRawData(resp *oauth2TokenResponse) map[string]interface{} {
	return map[string]interface{}{"api_key": resp.AccessToken}
}

// ttlFromExpiresIn converts an expires_in (seconds) into a lease TTL (0 if absent).
func ttlFromExpiresIn(expiresIn int) time.Duration {
	if expiresIn > 0 {
		return time.Duration(expiresIn) * time.Second
	}
	return 0
}

// expiresAt returns an RFC3339 UTC timestamp expiresIn seconds from now.
func expiresAt(expiresIn int) string {
	return time.Now().Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
}

// normalizeOAuth2Scopes returns scopes space-separated, tolerating comma- or
// whitespace-separated input.
func normalizeOAuth2Scopes(raw string) string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	return strings.Join(fields, " ")
}

// tokenURL returns the source-level token endpoint. It is deliberately read from
// the source only (not spec-overridable) so the SSRF-validated source endpoint
// can't be bypassed by a spec-level token_url.
func (d *OAuth2Driver) tokenURL() string {
	return credential.GetString(d.credSource.Config, "token_url", "")
}

// staticTokenTTL returns the remaining lease for a sealed static access token, or
// 0 (treated as non-expiring) when no access_token_expires_at is set or it is
// already past / unparseable.
func staticTokenTTL(spec *credential.CredSpec) time.Duration {
	raw := credential.GetString(spec.Config, "access_token_expires_at", "")
	if raw == "" {
		return 0
	}
	exp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0
	}
	if remaining := time.Until(exp); remaining > 0 {
		return remaining
	}
	return 0
}

// pkceEnabled reports whether PKCE should be sent, defaulting to true unless the
// spec explicitly sets pkce=false.
func pkceEnabled(raw string) bool {
	if raw == "" {
		return true
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return true
	}
	return enabled
}

// Revoke is a no-op for OAuth2 bearer tokens — they expire naturally.
func (d *OAuth2Driver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug(fmt.Sprintf("%s OAuth2 bearer tokens expire naturally, skipping revocation", d.displayName()),
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Cleanup releases resources.
func (d *OAuth2Driver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates the spec by minting a token and optionally calling
// the configured verification endpoint.
func (d *OAuth2Driver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	name := d.displayName()

	rawData, _, _, _, err := d.MintCredential(ctx, spec)
	if err != nil {
		return fmt.Errorf("%s OAuth2 spec verification failed: %w", name, err)
	}

	verifyURL := credential.GetString(d.credSource.Config, "verify_url", "")
	if verifyURL == "" {
		return nil
	}

	token, _ := rawData["api_key"].(string)
	headers := buildOAuth2AuthHeaders(d.credSource.Config, token)

	method := credential.GetString(d.credSource.Config, "verify_method", http.MethodGet)

	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method:  method,
		URL:     verifyURL,
		Headers: headers,
	}

	_, _, err = httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("%s OAuth2 token verification failed: %w", name, err)
	}

	return nil
}

// buildOAuth2AuthHeaders builds authentication headers based on auth_header_type config.
func buildOAuth2AuthHeaders(config credential.Config, token string) map[string]string {
	headerType := credential.GetString(config, "auth_header_type", oauth2AuthBearer)
	headers := map[string]string{"Accept": "application/json"}

	switch headerType {
	case oauth2AuthToken:
		headers["Authorization"] = "Token " + token
	case oauth2AuthCustomHeader:
		name := credential.GetString(config, "auth_header_name", "")
		if name != "" {
			headers[name] = token
		}
	default: // bearer
		headers["Authorization"] = "Bearer " + token
	}

	return headers
}

// extractMetadata derives non-secret credential metadata from the configured
// metadata_fields (default "sub"), copying each named field from the token's
// identity source: an introspection/userinfo endpoint (introspection_url) when
// set, otherwise the access token's own JWT claims. Values are stringified so
// they carry into the clear-logged Credential.Metadata. Best-effort — any failure
// (opaque token with no introspection_url, endpoint error, no matching fields)
// yields nil rather than failing the mint.
func (d *OAuth2Driver) extractMetadata(ctx context.Context, spec *credential.CredSpec, accessToken string) map[string]interface{} {
	// metadata_fields is source-only: the source operator decides which identity
	// fields are logged in clear; a spec author must not be able to name
	// sensitive claims. An empty value disables extraction.
	fields := splitMetadataFields(credential.GetString(d.credSource.Config, "metadata_fields", "sub"))
	if len(fields) == 0 {
		return nil
	}
	claims := d.fetchIdentityClaims(ctx, spec, accessToken)
	if claims == nil {
		return nil
	}
	meta := make(map[string]interface{})
	for _, f := range fields {
		v, ok := claims[f]
		if !ok {
			continue
		}
		// Only scalar identity attributes belong in clear-logged metadata;
		// composite claims (arrays/objects) are skipped to avoid dumping a
		// nested subtree (and any sensitive sub-fields) into the audit log.
		if s, ok := scalarClaim(v); ok {
			meta[f] = s
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// fetchIdentityClaims returns the claim/response map to extract metadata from:
// the introspection_url response when configured, else the access token decoded
// as a JWT, else nil (an opaque token with no introspection endpoint).
func (d *OAuth2Driver) fetchIdentityClaims(ctx context.Context, spec *credential.CredSpec, accessToken string) map[string]interface{} {
	// introspection_url is source-only (like token_url/auth_url): the server
	// fetches it with the access token attached, so it must stay under the
	// source-level SSRF guard and not be overridable per spec.
	if introspectionURL := credential.GetString(d.credSource.Config, "introspection_url", ""); introspectionURL != "" {
		claims, err := d.callIntrospection(ctx, introspectionURL, accessToken)
		if err != nil {
			d.logger.Warn("oauth2 introspection failed; credential metadata omitted",
				logger.String("spec", spec.Name), logger.Err(err))
			return nil
		}
		return claims
	}
	claims, err := helper.ParseJWTClaimsUnverified(accessToken)
	if err != nil {
		// Opaque (non-JWT) token and no introspection_url — nothing to derive.
		return nil
	}
	return claims
}

// callIntrospection fetches the user/token-info document from an introspection
// or userinfo endpoint, attaching the access token via the configured auth
// header. introspection_url is SSRF-validated at config time.
func (d *OAuth2Driver) callIntrospection(ctx context.Context, introspectionURL, accessToken string) (map[string]interface{}, error) {
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
	// GET with the access token attached (OIDC userinfo / GitHub /user style).
	httpReq := httputil.HTTPRequest{
		Method:  http.MethodGet,
		URL:     introspectionURL,
		Headers: buildOAuth2AuthHeaders(d.credSource.Config, accessToken),
	}
	body, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("introspection response is not a JSON object: %w", err)
	}
	return claims, nil
}

// scalarClaim renders a scalar claim value as a string for the metadata map,
// reporting ok=false for composite (array/object) or null values, which are
// skipped. JSON numbers (float64) are formatted without an exponent so large
// integer ids stay readable.
func scalarClaim(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case json.Number:
		return t.String(), true
	default:
		return "", false
	}
}

// splitMetadataFields splits a comma/space-separated field list.
func splitMetadataFields(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

// validateOAuth2TokenURL validates that the token_url is a well-formed HTTPS URL.
func validateOAuth2TokenURL(rawURL string) error {
	return validateOAuth2HTTPSURL(rawURL, "token_url", false)
}

// validateOAuth2HTTPSURL validates that a URL is well-formed HTTPS.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
func validateOAuth2HTTPSURL(rawURL, fieldName string, tlsSkipVerify bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", fieldName, err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("%s must use https:// scheme, got: %s", fieldName, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", fieldName)
	}
	return nil
}

// validateOAuth2SafeURL validates a URL that the server itself will call (token/
// auth/subject endpoints): well-formed HTTPS and, in production
// (tlsSkipVerify=false), not an SSRF target. Host IP literals in loopback,
// private, link-local or unspecified ranges (which includes the cloud metadata
// address 169.254.169.254) are rejected. Hostnames are not DNS-resolved here.
func validateOAuth2SafeURL(rawURL, fieldName string, tlsSkipVerify bool) error {
	if err := validateOAuth2HTTPSURL(rawURL, fieldName, tlsSkipVerify); err != nil {
		return err
	}
	if tlsSkipVerify {
		return nil // dev/test may legitimately target loopback
	}
	parsed, _ := url.Parse(rawURL) // already parsed cleanly above
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && isBlockedOAuth2IP(ip) {
		return fmt.Errorf("%s must not target a loopback/private/link-local address: %s", fieldName, parsed.Hostname())
	}
	return nil
}

// isBlockedOAuth2IP reports whether an IP literal is in a range that a
// server-side outbound OAuth call must not reach (SSRF guard).
func isBlockedOAuth2IP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// validateOAuth2VerifyMethod validates that verify_method is GET or POST.
func validateOAuth2VerifyMethod(method string) error {
	if method == "" {
		return nil
	}
	switch method {
	case http.MethodGet, http.MethodPost:
		return nil
	default:
		return fmt.Errorf("verify_method must be GET or POST, got: %s", method)
	}
}

// validateOAuth2AuthHeaderType validates the auth_header_type enum.
func validateOAuth2AuthHeaderType(headerType string) error {
	if headerType == "" {
		return nil
	}
	switch headerType {
	case oauth2AuthBearer, oauth2AuthToken, oauth2AuthCustomHeader:
		return nil
	default:
		return fmt.Errorf("auth_header_type must be one of: bearer, token, custom_header; got: %s", headerType)
	}
}
