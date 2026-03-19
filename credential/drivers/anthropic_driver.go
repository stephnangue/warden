package drivers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// anthropicMaxResponseBodySize limits response body reads to prevent OOM
const anthropicMaxResponseBodySize = 1 << 20 // 1MB

// anthropicMaxRetryAttempts for retryable API operations
const anthropicMaxRetryAttempts = 3

// DefaultAnthropicAPIURL is the default Anthropic API base URL
const DefaultAnthropicAPIURL = "https://api.anthropic.com"

// anthropicAPIVersion is the required Anthropic API version header value
const anthropicAPIVersion = "2023-06-01"

// Compile-time interface assertions
// Note: AnthropicDriver does not implement credential.Rotatable.
// Anthropic does not expose REST API endpoints for programmatic key management.
var _ credential.SourceDriver = (*AnthropicDriver)(nil)
var _ credential.SpecVerifier = (*AnthropicDriver)(nil)

// AnthropicDriver provides API key credentials for Anthropic.
//
// The source config holds only connection info (api_url). Auth credentials
// (api_key) live in the credential spec config and are read at MintCredential
// time. This allows multiple specs with different API keys to share one source.
//
// Key rotation must be performed manually:
//  1. Create a new API key in the Anthropic console
//  2. Update the spec config via Warden API
//  3. The old key continues to work until deleted from the console
type AnthropicDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// AnthropicDriverFactory creates AnthropicDriver instances
type AnthropicDriverFactory struct{}

// Type returns the driver type
func (f *AnthropicDriverFactory) Type() string {
	return credential.SourceTypeAnthropic
}

// ValidateConfig validates Anthropic source configuration using declarative schema.
// The source only holds connection info (api_url). Auth credentials are
// validated at spec level by AIAPIKeyCredType.ValidateConfig.
func (f *AnthropicDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(validateAnthropicURL).
			Describe("Anthropic API base URL (default: https://api.anthropic.com)").
			Example("https://api.anthropic.com"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *AnthropicDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// Create instantiates a new AnthropicDriver.
// The driver only needs the api_url from source config. Auth credentials
// are provided per-spec at MintCredential time.
func (f *AnthropicDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &AnthropicDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAnthropic,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeAnthropic),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return driver, nil
}

// getAPIURL returns the Anthropic API base URL from source config
func (d *AnthropicDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", DefaultAnthropicAPIURL), "/")
}

// MintCredential returns the Anthropic API key from spec config.
// The key is static — no TTL, no lease.
func (d *AnthropicDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no Anthropic API key configured in spec")
	}

	rawData := map[string]interface{}{
		"api_key": apiKey,
	}

	// Copy optional metadata from spec config
	if orgID := credential.GetString(spec.Config, "organization_id", ""); orgID != "" {
		rawData["organization_id"] = orgID
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// Revoke is a no-op for static API keys.
func (d *AnthropicDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("Anthropic API keys are static, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *AnthropicDriver) Type() string {
	return credential.SourceTypeAnthropic
}

// Cleanup releases resources
func (d *AnthropicDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec's API key is functional by calling
// GET /v1/models, a lightweight read-only endpoint.
func (d *AnthropicDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no Anthropic API key configured in spec")
	}

	apiURL := d.getAPIURL() + "/v1/models"

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       anthropicMaxRetryAttempts,
		MaxBodySize:       anthropicMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500}, // 429 and all 5xx
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodGet,
		URL:    apiURL,
		Headers: map[string]string{
			"x-api-key":         apiKey,
			"anthropic-version": anthropicAPIVersion,
			"Accept":            "application/json",
		},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("Anthropic API key verification failed: %w", err)
	}

	return nil
}

// validateAnthropicURL validates that the api_url is a well-formed HTTPS URL
func validateAnthropicURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid api_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("api_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("api_url must include a host")
	}
	return nil
}
