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

// mistralMaxResponseBodySize limits response body reads to prevent OOM
const mistralMaxResponseBodySize = 1 << 20 // 1MB

// mistralMaxRetryAttempts for retryable API operations
const mistralMaxRetryAttempts = 3

// DefaultMistralAPIURL is the default Mistral API base URL
const DefaultMistralAPIURL = "https://api.mistral.ai"

// Compile-time interface assertions
// Note: MistralDriver does not implement credential.Rotatable.
// Mistral does not expose REST API endpoints for programmatic key management.
var _ credential.SourceDriver = (*MistralDriver)(nil)
var _ credential.SpecVerifier = (*MistralDriver)(nil)

// MistralDriver provides API key credentials for Mistral AI.
//
// The source config holds only connection info (api_url). Auth credentials
// (api_key) live in the credential spec config and are read at MintCredential
// time. This allows multiple specs with different API keys to share one source.
//
// Key rotation must be performed manually:
//  1. Create a new API key in the Mistral console
//  2. Update the spec config via Warden API
//  3. The old key continues to work until deleted from the console
type MistralDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// MistralDriverFactory creates MistralDriver instances
type MistralDriverFactory struct{}

// Type returns the driver type
func (f *MistralDriverFactory) Type() string {
	return credential.SourceTypeMistral
}

// ValidateConfig validates Mistral source configuration using declarative schema.
// The source only holds connection info (api_url). Auth credentials are
// validated at spec level by AIAPIKeyCredType.ValidateConfig.
func (f *MistralDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(validateMistralURL).
			Describe("Mistral API base URL (default: https://api.mistral.ai)").
			Example("https://api.mistral.ai"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *MistralDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// Create instantiates a new MistralDriver.
// The driver only needs the api_url from source config. Auth credentials
// are provided per-spec at MintCredential time.
func (f *MistralDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &MistralDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeMistral,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeMistral),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return driver, nil
}

// getAPIURL returns the Mistral API base URL from source config
func (d *MistralDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", DefaultMistralAPIURL), "/")
}

// MintCredential returns the Mistral API key from spec config.
// The key is static — no TTL, no lease.
func (d *MistralDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no Mistral API key configured in spec")
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
func (d *MistralDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("Mistral API keys are static, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *MistralDriver) Type() string {
	return credential.SourceTypeMistral
}

// Cleanup releases resources
func (d *MistralDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec's API key is functional by calling
// GET /v1/models, a lightweight read-only endpoint.
func (d *MistralDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no Mistral API key configured in spec")
	}

	apiURL := d.getAPIURL() + "/v1/models"

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       mistralMaxRetryAttempts,
		MaxBodySize:       mistralMaxResponseBodySize,
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
		return fmt.Errorf("Mistral API key verification failed: %w", err)
	}

	return nil
}

// validateMistralURL validates that the api_url is a well-formed HTTPS URL
func validateMistralURL(rawURL string) error {
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
