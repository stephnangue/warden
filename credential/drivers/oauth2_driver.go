package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
const oauth2AuthMethodClientCredentials = "client_credentials"

// OAuth2 grant types sent in the token request.
const oauth2GrantClientCredentials = "client_credentials"

// Compile-time interface assertions
var _ credential.SourceDriver = (*OAuth2Driver)(nil)
var _ credential.SpecVerifier = (*OAuth2Driver)(nil)

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
				return validateOAuth2HTTPSURL(v, "token_url", credential.GetBool(config, "tls_skip_verify", false))
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
				return validateOAuth2HTTPSURL(v, "verify_url", credential.GetBool(config, "tls_skip_verify", false))
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
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
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

	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    d.resolve(spec, "token_url", ""),
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}

	body, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token exchange failed: %w", name, err)
	}

	var tokenResp oauth2TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode %s OAuth2 token response: %w", name, err)
	}

	if tokenResp.AccessToken == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token response missing access_token", name)
	}

	rawData := map[string]interface{}{
		"api_key": tokenResp.AccessToken,
	}
	if tokenResp.Scope != "" {
		rawData["scope"] = tokenResp.Scope
	}
	if tokenResp.TokenType != "" {
		rawData["token_type"] = tokenResp.TokenType
	}

	var ttl time.Duration
	if tokenResp.ExpiresIn > 0 {
		ttl = time.Duration(tokenResp.ExpiresIn) * time.Second
	}

	return rawData, ttl, "", nil
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
