package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stephnangue/warden/credential"
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

// Compile-time interface assertions
var _ credential.SourceDriver = (*OAuth2Driver)(nil)
var _ credential.SpecVerifier = (*OAuth2Driver)(nil)

// OAuth2Driver exchanges OAuth2 client credentials for bearer tokens.
//
// All provider-specific configuration lives in the source config map:
// client_id, client_secret, token_url (required); default_scopes, verify_url,
// verify_method, auth_header_type, auth_header_name, display_name (optional).
//
// The spec config holds an optional scope override. The driver POSTs to the
// token endpoint using the client_credentials grant type and returns the
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

// ValidateConfig validates source configuration.
// Requires client_id, client_secret, and token_url.
func (f *OAuth2DriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("client_id").
			Required().
			Describe("OAuth2 client ID").
			Example("your-client-id"),

		credential.StringField("client_secret").
			Required().
			Describe("OAuth2 client secret").
			Example("your-client-secret"),

		credential.StringField("token_url").
			Required().
			Custom(validateOAuth2TokenURL).
			Describe("OAuth2 token endpoint (HTTPS)").
			Example("https://identity.pagerduty.com/oauth/token"),

		credential.StringField("default_scopes").
			Describe("Default OAuth2 scopes (space-separated)").
			Example("read write"),

		credential.StringField("verify_url").
			Custom(validateOAuth2OptionalURL).
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
	return []string{"client_secret"}
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
		logger:     log.WithSubsystem(credential.SourceTypeOAuth2),
		httpClient: &http.Client{Timeout: 30 * time.Second},
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
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// MintCredential exchanges client credentials for a bearer token.
func (d *OAuth2Driver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	config := d.credSource.Config
	name := d.displayName()

	clientID := credential.GetString(config, "client_id", "")
	clientSecret := credential.GetString(config, "client_secret", "")
	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 source missing client_id or client_secret", name)
	}

	defaultScopes := credential.GetString(config, "default_scopes", "")
	scope := credential.GetString(spec.Config, "scope", defaultScopes)

	// Build token request body
	form := url.Values{
		"grant_type":    {"client_credentials"},
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

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodPost,
		URL:    credential.GetString(config, "token_url", ""),
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}

	body, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
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

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  method,
		URL:     verifyURL,
		Headers: headers,
	}

	_, _, err = ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
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
	return validateOAuth2HTTPSURL(rawURL, "token_url")
}

// validateOAuth2OptionalURL validates that verify_url, if non-empty, is a well-formed HTTPS URL.
func validateOAuth2OptionalURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	return validateOAuth2HTTPSURL(rawURL, "verify_url")
}

// validateOAuth2HTTPSURL validates that a URL is well-formed HTTPS.
func validateOAuth2HTTPSURL(rawURL, fieldName string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", fieldName, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https:// scheme, got: %s", fieldName, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", fieldName)
	}
	return nil
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
