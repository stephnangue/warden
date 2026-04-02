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

// apiKeyMaxResponseBodySize limits response body reads to prevent OOM
const apiKeyMaxResponseBodySize = 1 << 20 // 1MB

// apiKeyMaxRetryAttempts for retryable API operations
const apiKeyMaxRetryAttempts = 3

// AuthHeaderFunc builds authentication headers for a given API key.
type AuthHeaderFunc func(apiKey string) map[string]string

// APIKeyProviderConfig holds the per-provider differences that parameterize
// the static API key driver. Each API key provider (OpenAI, Anthropic, etc.)
// is defined as a config instance rather than a separate driver type.
type APIKeyProviderConfig struct {
	SourceType       string         // e.g. credential.SourceTypeAnthropic
	DisplayName      string         // e.g. "Anthropic" (for error messages, logs)
	DefaultAPIURL    string         // e.g. "https://api.anthropic.com"
	VerifyEndpoint   string         // e.g. "/v1/models"
	VerifyMethod     string         // e.g. http.MethodGet
	BuildAuthHeaders AuthHeaderFunc // builds the auth headers given an API key
	OptionalMetadata []string       // spec config fields to copy into rawData (e.g. ["organization_id"])
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*StaticAPIKeyDriver)(nil)
var _ credential.SpecVerifier = (*StaticAPIKeyDriver)(nil)

// StaticAPIKeyDriver provides API key credentials for any provider configured
// via APIKeyProviderConfig.
//
// The source config holds only connection info (api_url). Auth credentials
// (api_key) live in the credential spec config and are read at MintCredential
// time. This allows multiple specs with different API keys to share one source.
type StaticAPIKeyDriver struct {
	provider   APIKeyProviderConfig
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// StaticAPIKeyDriverFactory creates StaticAPIKeyDriver instances.
// One factory instance is registered per provider, each with a different config.
type StaticAPIKeyDriverFactory struct {
	provider APIKeyProviderConfig
}

// NewStaticAPIKeyDriverFactory creates a factory for the given provider config.
func NewStaticAPIKeyDriverFactory(provider APIKeyProviderConfig) *StaticAPIKeyDriverFactory {
	return &StaticAPIKeyDriverFactory{provider: provider}
}

// Type returns the driver type identifier for this provider.
func (f *StaticAPIKeyDriverFactory) Type() string {
	return f.provider.SourceType
}

// ValidateConfig validates source configuration using declarative schema.
// The source only holds connection info (api_url).
func (f *StaticAPIKeyDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(validateAPIKeyURL).
			Describe(fmt.Sprintf("%s API base URL (default: %s)", f.provider.DisplayName, f.provider.DefaultAPIURL)).
			Example(f.provider.DefaultAPIURL),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *StaticAPIKeyDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// InferCredentialType returns the credential type for API key providers.
// All API key providers use the same credential type.
func (f *StaticAPIKeyDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new StaticAPIKeyDriver.
func (f *StaticAPIKeyDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &StaticAPIKeyDriver{
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
func (d *StaticAPIKeyDriver) Type() string {
	return d.provider.SourceType
}

// getAPIURL returns the API base URL from source config.
func (d *StaticAPIKeyDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", d.provider.DefaultAPIURL), "/")
}

// MintCredential returns the API key from spec config.
// The key is static — no TTL, no lease.
func (d *StaticAPIKeyDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no %s API key configured in spec", d.provider.DisplayName)
	}

	rawData := map[string]interface{}{
		"api_key": apiKey,
	}

	// Copy optional metadata from spec config
	for _, field := range d.provider.OptionalMetadata {
		if val := credential.GetString(spec.Config, field, ""); val != "" {
			rawData[field] = val
		}
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// Revoke is a no-op for static API keys.
func (d *StaticAPIKeyDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug(fmt.Sprintf("%s API keys are static, skipping revocation", d.provider.DisplayName),
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Cleanup releases resources.
func (d *StaticAPIKeyDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec's API key is functional by calling
// the provider's verification endpoint.
func (d *StaticAPIKeyDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no %s API key configured in spec", d.provider.DisplayName)
	}

	apiURL := d.getAPIURL() + d.provider.VerifyEndpoint

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       apiKeyMaxRetryAttempts,
		MaxBodySize:       apiKeyMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  d.provider.VerifyMethod,
		URL:     apiURL,
		Headers: d.provider.BuildAuthHeaders(apiKey),
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("%s API key verification failed: %w", d.provider.DisplayName, err)
	}

	return nil
}

// validateAPIKeyURL validates that the api_url is a well-formed HTTPS URL.
// This consolidates the identical per-provider URL validators.
func validateAPIKeyURL(rawURL string) error {
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
