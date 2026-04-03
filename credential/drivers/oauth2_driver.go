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

// OAuth2ProviderConfig holds the per-provider differences that parameterize
// the OAuth2 client credentials driver. Each OAuth2 provider (PagerDuty, etc.)
// is defined as a config instance rather than a separate driver type.
type OAuth2ProviderConfig struct {
	SourceType       string         // e.g. credential.SourceTypePagerDutyOAuth
	DisplayName      string         // e.g. "PagerDuty" (for error messages, logs)
	DefaultTokenURL  string         // e.g. "https://identity.pagerduty.com/oauth/token"
	DefaultScopes    string         // default OAuth2 scopes (space-separated)
	VerifyURL        string         // optional endpoint to verify minted tokens
	VerifyMethod     string         // HTTP method for verify (default GET)
	BuildAuthHeaders AuthHeaderFunc // how to attach token for verification
}

// PagerDutyOAuth2Provider defines the PagerDuty OAuth2 provider configuration.
var PagerDutyOAuth2Provider = OAuth2ProviderConfig{
	SourceType:      credential.SourceTypePagerDutyOAuth,
	DisplayName:     "PagerDuty",
	DefaultTokenURL: "https://identity.pagerduty.com/oauth/token",
	DefaultScopes:   "",
	VerifyURL:       "https://api.pagerduty.com/users/me",
	VerifyMethod:    http.MethodGet,
	BuildAuthHeaders: func(apiKey string) map[string]string {
		return map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Accept":        "application/json",
		}
	},
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*OAuth2Driver)(nil)
var _ credential.SpecVerifier = (*OAuth2Driver)(nil)

// OAuth2Driver exchanges OAuth2 client credentials for bearer tokens.
//
// The source config holds client_id, client_secret, and optionally token_url.
// The spec config holds an optional scope override. The driver POSTs to the
// token endpoint using the client_credentials grant type and returns the
// resulting access_token as an api_key field (for BearerAPIKeyExtractor
// compatibility).
type OAuth2Driver struct {
	provider   OAuth2ProviderConfig
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// OAuth2DriverFactory creates OAuth2Driver instances.
// One factory instance is registered per provider, each with a different config.
type OAuth2DriverFactory struct {
	provider OAuth2ProviderConfig
}

// NewOAuth2DriverFactory creates a factory for the given provider config.
func NewOAuth2DriverFactory(provider OAuth2ProviderConfig) *OAuth2DriverFactory {
	return &OAuth2DriverFactory{provider: provider}
}

// Type returns the driver type identifier for this provider.
func (f *OAuth2DriverFactory) Type() string {
	return f.provider.SourceType
}

// ValidateConfig validates source configuration.
// Requires client_id and client_secret; token_url is optional.
func (f *OAuth2DriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("client_id").
			Required().
			Describe(fmt.Sprintf("%s OAuth2 client ID", f.provider.DisplayName)).
			Example("your-client-id"),

		credential.StringField("client_secret").
			Required().
			Describe(fmt.Sprintf("%s OAuth2 client secret", f.provider.DisplayName)).
			Example("your-client-secret"),

		credential.StringField("token_url").
			Custom(validateOAuth2TokenURL).
			Describe(fmt.Sprintf("OAuth2 token endpoint (default: %s)", f.provider.DefaultTokenURL)).
			Example(f.provider.DefaultTokenURL),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
func (f *OAuth2DriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret"}
}

// InferCredentialType returns the credential type for OAuth2 providers.
func (f *OAuth2DriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new OAuth2Driver.
func (f *OAuth2DriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &OAuth2Driver{
		provider: f.provider,
		credSource: &credential.CredSource{
			Type:   f.provider.SourceType,
			Config: config,
		},
		logger:     log.WithSubsystem(f.provider.SourceType),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return driver, nil
}

// Type returns the driver type.
func (d *OAuth2Driver) Type() string {
	return d.provider.SourceType
}

// getTokenURL returns the token endpoint URL from source config or default.
func (d *OAuth2Driver) getTokenURL() string {
	return credential.GetString(d.credSource.Config, "token_url", d.provider.DefaultTokenURL)
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
	clientID := credential.GetString(d.credSource.Config, "client_id", "")
	clientSecret := credential.GetString(d.credSource.Config, "client_secret", "")

	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 source missing client_id or client_secret", d.provider.DisplayName)
	}

	scope := credential.GetString(spec.Config, "scope", d.provider.DefaultScopes)

	// Build token request body
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
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
		URL:    d.getTokenURL(),
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}

	body, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token exchange failed: %w", d.provider.DisplayName, err)
	}

	var tokenResp oauth2TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode %s OAuth2 token response: %w", d.provider.DisplayName, err)
	}

	if tokenResp.AccessToken == "" {
		return nil, 0, "", fmt.Errorf("%s OAuth2 token response missing access_token", d.provider.DisplayName)
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
		d.logger.Debug(fmt.Sprintf("%s OAuth2 bearer tokens expire naturally, skipping revocation", d.provider.DisplayName),
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
// the provider's verification endpoint.
func (d *OAuth2Driver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	rawData, _, _, err := d.MintCredential(ctx, spec)
	if err != nil {
		return fmt.Errorf("%s OAuth2 spec verification failed: %w", d.provider.DisplayName, err)
	}

	if d.provider.VerifyURL == "" {
		return nil
	}

	token, _ := rawData["api_key"].(string)

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	}
	if d.provider.BuildAuthHeaders != nil {
		headers = d.provider.BuildAuthHeaders(token)
	}

	method := d.provider.VerifyMethod
	if method == "" {
		method = http.MethodGet
	}

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  method,
		URL:     d.provider.VerifyURL,
		Headers: headers,
	}

	_, _, err = ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("%s OAuth2 token verification failed: %w", d.provider.DisplayName, err)
	}

	return nil
}

// validateOAuth2TokenURL validates that the token_url is a well-formed HTTPS URL.
func validateOAuth2TokenURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid token_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("token_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("token_url must include a host")
	}
	return nil
}
