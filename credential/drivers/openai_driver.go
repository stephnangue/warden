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

// openaiMaxResponseBodySize limits response body reads to prevent OOM
const openaiMaxResponseBodySize = 1 << 20 // 1MB

// openaiMaxRetryAttempts for retryable API operations
const openaiMaxRetryAttempts = 3

// DefaultOpenAIAPIURL is the default OpenAI API base URL
const DefaultOpenAIAPIURL = "https://api.openai.com"

// Compile-time interface assertions
// Note: OpenAIDriver does not implement credential.Rotatable.
// OpenAI does not expose REST API endpoints for programmatic key management.
var _ credential.SourceDriver = (*OpenAIDriver)(nil)
var _ credential.SpecVerifier = (*OpenAIDriver)(nil)

// OpenAIDriver provides API key credentials for OpenAI.
//
// The source config holds only connection info (api_url). Auth credentials
// (api_key) live in the credential spec config and are read at MintCredential
// time. This allows multiple specs with different API keys to share one source.
//
// Key rotation must be performed manually:
//  1. Create a new API key in the OpenAI dashboard
//  2. Update the spec config via Warden API
//  3. The old key continues to work until deleted from the dashboard
type OpenAIDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// OpenAIDriverFactory creates OpenAIDriver instances
type OpenAIDriverFactory struct{}

// Type returns the driver type
func (f *OpenAIDriverFactory) Type() string {
	return credential.SourceTypeOpenAI
}

// ValidateConfig validates OpenAI source configuration using declarative schema.
// The source only holds connection info (api_url). Auth credentials are
// validated at spec level by AIAPIKeyCredType.ValidateConfig.
func (f *OpenAIDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(validateOpenAIURL).
			Describe("OpenAI API base URL (default: https://api.openai.com)").
			Example("https://api.openai.com"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *OpenAIDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// Create instantiates a new OpenAIDriver.
// The driver only needs the api_url from source config. Auth credentials
// are provided per-spec at MintCredential time.
func (f *OpenAIDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeOpenAI),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return driver, nil
}

// getAPIURL returns the OpenAI API base URL from source config
func (d *OpenAIDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", DefaultOpenAIAPIURL), "/")
}

// MintCredential returns the OpenAI API key from spec config.
// The key is static — no TTL, no lease.
func (d *OpenAIDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no OpenAI API key configured in spec")
	}

	rawData := map[string]interface{}{
		"api_key": apiKey,
	}

	// Copy optional metadata from spec config
	if orgID := credential.GetString(spec.Config, "organization_id", ""); orgID != "" {
		rawData["organization_id"] = orgID
	}
	if projectID := credential.GetString(spec.Config, "project_id", ""); projectID != "" {
		rawData["project_id"] = projectID
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// Revoke is a no-op for static API keys.
func (d *OpenAIDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("OpenAI API keys are static, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *OpenAIDriver) Type() string {
	return credential.SourceTypeOpenAI
}

// Cleanup releases resources
func (d *OpenAIDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec's API key is functional by calling
// GET /v1/models, a lightweight read-only endpoint.
func (d *OpenAIDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no OpenAI API key configured in spec")
	}

	apiURL := d.getAPIURL() + "/v1/models"

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       openaiMaxRetryAttempts,
		MaxBodySize:       openaiMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500}, // 429 and all 5xx
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodGet,
		URL:    apiURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Accept":        "application/json",
		},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("OpenAI API key verification failed: %w", err)
	}

	return nil
}

// validateOpenAIURL validates that the api_url is a well-formed HTTPS URL
func validateOpenAIURL(rawURL string) error {
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
