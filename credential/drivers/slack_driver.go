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

// slackMaxResponseBodySize limits response body reads to prevent OOM
const slackMaxResponseBodySize = 1 << 20 // 1MB

// slackMaxRetryAttempts for retryable API operations
const slackMaxRetryAttempts = 3

// DefaultSlackAPIURL is the default Slack API base URL
const DefaultSlackAPIURL = "https://slack.com/api"

// Compile-time interface assertions
// Note: SlackDriver does not implement credential.Rotatable.
// Slack bot tokens are tied to app installations and cannot be rotated programmatically.
var _ credential.SourceDriver = (*SlackDriver)(nil)
var _ credential.SpecVerifier = (*SlackDriver)(nil)

// SlackDriver provides API key credentials for Slack.
//
// The source config holds only connection info (api_url). Auth credentials
// (api_key) live in the credential spec config and are read at MintCredential
// time. This allows multiple specs with different tokens to share one source.
//
// Token rotation must be performed manually:
//  1. Reinstall the Slack app or regenerate the token
//  2. Update the spec config via Warden API
type SlackDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// SlackDriverFactory creates SlackDriver instances
type SlackDriverFactory struct{}

// Type returns the driver type
func (f *SlackDriverFactory) Type() string {
	return credential.SourceTypeSlack
}

// ValidateConfig validates Slack source configuration using declarative schema.
// The source only holds connection info (api_url). Auth credentials are
// validated at spec level by APIKeyCredType.ValidateConfig.
func (f *SlackDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(validateSlackURL).
			Describe("Slack API base URL (default: https://slack.com/api)").
			Example("https://slack.com/api"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *SlackDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// Create instantiates a new SlackDriver.
// The driver only needs the api_url from source config. Auth credentials
// are provided per-spec at MintCredential time.
func (f *SlackDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeSlack),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return driver, nil
}

// getAPIURL returns the Slack API base URL from source config
func (d *SlackDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", DefaultSlackAPIURL), "/")
}

// MintCredential returns the Slack bot token from spec config.
// The token is static — no TTL, no lease.
func (d *SlackDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no Slack bot token configured in spec")
	}

	rawData := map[string]interface{}{
		"api_key": apiKey,
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// Revoke is a no-op for static bot tokens.
func (d *SlackDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("Slack bot tokens are static, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *SlackDriver) Type() string {
	return credential.SourceTypeSlack
}

// Cleanup releases resources
func (d *SlackDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec's bot token is functional by calling
// auth.test, the standard Slack endpoint for token validation.
func (d *SlackDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no Slack bot token configured in spec")
	}

	apiURL := d.getAPIURL() + "/auth.test"

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       slackMaxRetryAttempts,
		MaxBodySize:       slackMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodPost,
		URL:    apiURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Content-Type":  "application/json",
		},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("Slack bot token verification failed: %w", err)
	}

	return nil
}

// validateSlackURL validates that the api_url is a well-formed HTTPS URL
func validateSlackURL(rawURL string) error {
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
