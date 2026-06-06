package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
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

// OAuth2Driver exchanges OAuth2 credentials for bearer tokens.
//
// The token endpoint and connection options live in the source config (token_url
// required; auth_url, default_scopes, verify_url, verify_method, auth_header_type,
// auth_header_name, display_name, ca_data, tls_skip_verify optional). client_id and
// client_secret may live on the source (client_credentials) or the spec, resolved
// spec-over-source. The spec's auth_method selects the flow (default
// client_credentials); the driver POSTs to the token endpoint and returns the
// resulting access_token as an api_key field.
type OAuth2Driver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// OAuth2DriverFactory creates OAuth2Driver instances.
type OAuth2DriverFactory struct{}

// Type returns the driver type identifier.
func (f *OAuth2DriverFactory) Type() string {
	return credential.SourceTypeOAuth2
}

// ValidateConfig validates source configuration. token_url is required.
// client_id/client_secret are optional here because the authorization_code flow
// keeps them on the spec; presence is checked at mint time.
func (f *OAuth2DriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("client_id").
			Describe("OAuth2 client ID (source-level for client_credentials; may be set per-spec)").
			Example("your-client-id"),

		credential.StringField("client_secret").
			Describe("OAuth2 client secret (source-level for client_credentials; may be set per-spec)").
			Example("your-client-secret"),

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
	); err != nil {
		return err
	}

	// Validate token_param.* keys don't override core form fields
	protectedFields := map[string]bool{
		"grant_type":    true,
		"client_id":     true,
		"client_secret": true,
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
	return []string{"client_secret", "ca_data"}
}

// InferCredentialType returns the credential type for OAuth2 sources.
func (f *OAuth2DriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new OAuth2Driver.
func (f *OAuth2DriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
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
	// Some providers (notably GitHub) report failures as HTTP 200 with an error body.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// resolve returns spec.Config[key] when set, else the source config value, else def.
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

// MintCredential mints a bearer token using the flow selected by auth_method
// (default client_credentials).
func (d *OAuth2Driver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	authMethod := d.resolve(spec, "auth_method", oauth2AuthMethodClientCredentials)
	switch authMethod {
	case oauth2AuthMethodClientCredentials:
		return d.mintFromClientCredentials(ctx, spec)
	case oauth2AuthMethodAuthorizationCode:
		return d.mintFromRefreshToken(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("%s OAuth2 unsupported auth_method %q", d.displayName(), authMethod)
	}
}

// mintFromClientCredentials exchanges client credentials for a bearer token.
func (d *OAuth2Driver) mintFromClientCredentials(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	config := d.credSource.Config
	name := d.displayName()

	clientID := d.resolve(spec, "client_id", "")
	clientSecret := d.resolve(spec, "client_secret", "")
	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 source missing client_id or client_secret", name)
	}

	defaultScopes := credential.GetString(config, "default_scopes", "")
	scope := credential.GetString(spec.Config, "scope", defaultScopes)

	// Build token request body
	form := url.Values{
		"grant_type":    {oauth2GrantClientCredentials},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	// Apply extra token form parameters from source config (token_param.* keys)
	for k, v := range credential.GetPrefixed(config, "token_param.") {
		form.Set(k, v)
	}

	tokenResp, err := d.postTokenRequest(ctx, d.tokenURL(), form)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token exchange failed: %w", name, err)
	}
	if tokenResp.AccessToken == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token response missing access_token", name)
	}

	return accessTokenRawData(tokenResp), ttlFromExpiresIn(tokenResp.ExpiresIn), "", nil
}

// mintFromRefreshToken exchanges the sealed refresh token for a fresh access
// token (grant_type=refresh_token). Providers that issue no refresh token seal a
// static access token at connect time, which is returned directly. When the
// provider rotates the refresh token, the new value is surfaced under the reserved
// rawData key for the minting layer to persist.
func (d *OAuth2Driver) mintFromRefreshToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	name := d.displayName()

	refreshToken := credential.GetString(spec.Config, "refresh_token", "")
	if refreshToken == "" {
		// No-refresh-token providers seal a static access token at connect time.
		if staticToken := credential.GetString(spec.Config, "access_token", ""); staticToken != "" {
			return map[string]interface{}{"api_key": staticToken}, staticTokenTTL(spec), "", nil
		}
		return nil, 0, "", fmt.Errorf("%s OAuth2 spec %q is not connected — run `warden cred spec connect %s`", name, spec.Name, spec.Name)
	}

	clientID := d.resolve(spec, "client_id", "")
	clientSecret := d.resolve(spec, "client_secret", "")
	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 spec missing client_id or client_secret", name)
	}

	form := url.Values{
		"grant_type":    {oauth2GrantRefreshToken},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	tokenResp, err := d.postTokenRequest(ctx, d.tokenURL(), form)
	if err != nil {
		if isRefreshTokenRejection(err) {
			// Signal the minting layer to re-read the spec and retry once (the
			// token may have been rotated by another node).
			return nil, 0, "", fmt.Errorf("%s OAuth2 refresh failed: %w: %w", name, credential.ErrRefreshTokenRejected, err)
		}
		return nil, 0, "", fmt.Errorf("%s OAuth2 refresh failed: %w", name, err)
	}
	if tokenResp.AccessToken == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 refresh response missing access_token", name)
	}

	rawData := accessTokenRawData(tokenResp)
	// Surface a rotated refresh token for the minting layer to persist.
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		rawData[credential.RawRotatedRefreshTokenKey] = tokenResp.RefreshToken
	}
	return rawData, ttlFromExpiresIn(tokenResp.ExpiresIn), "", nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens using the
// client secret the server holds, and returns the spec-config keys to seal.
func (d *OAuth2Driver) ExchangeAuthorizationCode(ctx context.Context, spec *credential.CredSpec, code, redirectURI, codeVerifier string) (map[string]string, error) {
	name := d.displayName()

	clientID := d.resolve(spec, "client_id", "")
	clientSecret := d.resolve(spec, "client_secret", "")
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("%s OAuth2 spec missing client_id or client_secret", name)
	}

	form := url.Values{
		"grant_type":    {oauth2GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	tokenResp, err := d.postTokenRequest(ctx, d.tokenURL(), form)
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

// BuildAuthorizeURL assembles the provider authorize URL. Scopes are read as
// already-normalized (space-separated) but commas are tolerated defensively.
func (d *OAuth2Driver) BuildAuthorizeURL(spec *credential.CredSpec, redirectURI, state, codeChallenge string) (string, error) {
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

// postTokenRequest POSTs a form-encoded token request and decodes the response,
// treating a body that carries an "error" field (some providers, notably GitHub,
// report failures as HTTP 200 with an error body) as a failure.
func (d *OAuth2Driver) postTokenRequest(ctx context.Context, tokenURL string, form url.Values) (*oauth2TokenResponse, error) {
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
	httpReq := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    tokenURL,
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
		// RFC 6749 §5.2 returns the error body on HTTP 400 (and 401 for
		// invalid_client). Treat those as readable so the error code can be
		// parsed and classified, rather than discarded as a transport error.
		OKStatuses: []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized},
	}

	body, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		// Transport failure, or a status outside OKStatuses (e.g. 5xx after
		// retries). Carry the status so callers can classify it.
		return nil, &tokenEndpointError{status: status, err: err}
	}

	var tokenResp oauth2TokenResponse
	if jsonErr := json.Unmarshal(body, &tokenResp); jsonErr != nil {
		if status != http.StatusOK {
			// A non-2xx with an unparseable body (e.g. a proxy error page):
			// classify by status alone.
			return nil, &tokenEndpointError{status: status, err: fmt.Errorf("status %d: %s", status, string(body))}
		}
		return nil, fmt.Errorf("failed to decode token response: %w", jsonErr)
	}
	if status != http.StatusOK || tokenResp.Error != "" {
		// An OAuth2 error body — carried on HTTP 400/401, or as an HTTP 200 body
		// by providers like GitHub. Surface the parsed code for classification.
		return nil, &tokenEndpointError{status: status, code: tokenResp.Error, description: tokenResp.ErrorDescription}
	}
	return &tokenResp, nil
}

// tokenEndpointError is returned by postTokenRequest when the token endpoint
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

// isRefreshTokenRejection reports whether a postTokenRequest error indicates the
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
	rawData := map[string]interface{}{"api_key": resp.AccessToken}
	if resp.Scope != "" {
		rawData["scope"] = resp.Scope
	}
	if resp.TokenType != "" {
		rawData["token_type"] = resp.TokenType
	}
	return rawData
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

	rawData, _, _, err := d.MintCredential(ctx, spec)
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
func buildOAuth2AuthHeaders(config map[string]string, token string) map[string]string {
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
