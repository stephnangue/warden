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

// Valid auth_header_type values for API key verification.
const (
	apiKeyAuthBearer       = "bearer"
	apiKeyAuthToken        = "token"
	apiKeyAuthCustomHeader = "custom_header"
)

// Compile-time interface assertions
var _ credential.SourceDriver = (*StaticAPIKeyDriver)(nil)
var _ credential.SpecVerifier = (*StaticAPIKeyDriver)(nil)

// StaticAPIKeyDriver provides API key credentials configured entirely via
// the source config map. Auth credentials (api_key) live in the credential
// spec config and are read at MintCredential time.
type StaticAPIKeyDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// StaticAPIKeyDriverFactory creates StaticAPIKeyDriver instances.
type StaticAPIKeyDriverFactory struct{}

// Type returns the driver type identifier.
func (f *StaticAPIKeyDriverFactory) Type() string {
	return credential.SourceTypeAPIKey
}

// ValidateConfig validates source configuration using declarative schema.
func (f *StaticAPIKeyDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("api_url").
			Custom(func(v string) error {
				return validateAPIKeyURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("API base URL (HTTPS)").
			Example("https://api.openai.com"),

		credential.StringField("verify_endpoint").
			Describe("Path appended to api_url for verification (skip if empty)").
			Example("/v1/models"),

		credential.StringField("verify_method").
			Custom(validateAPIKeyVerifyMethod).
			Describe("HTTP method for verification (default: GET)").
			Example("GET"),

		credential.StringField("auth_header_type").
			Custom(validateAPIKeyAuthHeaderType).
			Describe("How to attach API key for verification: bearer, token, custom_header (default: bearer)").
			Example("bearer"),

		credential.StringField("auth_header_name").
			Describe("Header name when auth_header_type=custom_header").
			Example("x-api-key"),

		credential.StringField("extra_headers").
			Describe("Additional static headers as comma-separated key:value pairs").
			Example("anthropic-version:2023-06-01"),

		credential.StringField("optional_metadata").
			Describe("Comma-separated spec config fields to copy into credential data").
			Example("organization_id,project_id"),

		credential.StringField("display_name").
			Describe("Human-readable label for logs/errors (default: API Key)").
			Example("OpenAI"),

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

	// auth_header_name is required when auth_header_type is custom_header
	if credential.GetString(config, "auth_header_type", "") == apiKeyAuthCustomHeader {
		if credential.GetString(config, "auth_header_name", "") == "" {
			return fmt.Errorf("auth_header_name is required when auth_header_type is custom_header")
		}
	}

	// Validate extra_headers format
	if raw := credential.GetString(config, "extra_headers", ""); raw != "" {
		if _, err := parseExtraHeaders(raw); err != nil {
			return err
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *StaticAPIKeyDriverFactory) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

// InferCredentialType returns the credential type for API key sources.
func (f *StaticAPIKeyDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new StaticAPIKeyDriver.
func (f *StaticAPIKeyDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &StaticAPIKeyDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAPIKey,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeAPIKey),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// Type returns the driver type.
func (d *StaticAPIKeyDriver) Type() string {
	return credential.SourceTypeAPIKey
}

// displayName returns the configured display name or "API Key".
func (d *StaticAPIKeyDriver) displayName() string {
	return credential.GetString(d.credSource.Config, "display_name", "API Key")
}

// getAPIURL returns the API base URL from source config.
func (d *StaticAPIKeyDriver) getAPIURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "api_url", ""), "/")
}

// MintCredential returns the API key from spec config.
// The key is static — no TTL, no lease.
func (d *StaticAPIKeyDriver) MintCredential(_ context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return nil, 0, "", fmt.Errorf("no %s API key configured in spec", d.displayName())
	}

	rawData := map[string]interface{}{
		"api_key": apiKey,
	}

	// Copy optional metadata from spec config
	for _, field := range parseOptionalMetadata(d.credSource.Config) {
		if val := credential.GetString(spec.Config, field, ""); val != "" {
			rawData[field] = val
		}
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// Revoke is a no-op for static API keys.
func (d *StaticAPIKeyDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug(fmt.Sprintf("%s API keys are static, skipping revocation", d.displayName()),
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
// the configured verification endpoint.
func (d *StaticAPIKeyDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	name := d.displayName()

	apiKey := credential.GetString(spec.Config, "api_key", "")
	if apiKey == "" {
		return fmt.Errorf("no %s API key configured in spec", name)
	}

	verifyEndpoint := credential.GetString(d.credSource.Config, "verify_endpoint", "")
	if verifyEndpoint == "" {
		return nil
	}

	apiURL := d.getAPIURL() + verifyEndpoint

	method := credential.GetString(d.credSource.Config, "verify_method", http.MethodGet)
	headers := buildAPIKeyAuthHeaders(d.credSource.Config, apiKey)

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       apiKeyMaxRetryAttempts,
		MaxBodySize:       apiKeyMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  method,
		URL:     apiURL,
		Headers: headers,
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("%s API key verification failed: %w", name, err)
	}

	return nil
}

// buildAPIKeyAuthHeaders builds authentication headers based on source config.
func buildAPIKeyAuthHeaders(config map[string]string, apiKey string) map[string]string {
	headerType := credential.GetString(config, "auth_header_type", apiKeyAuthBearer)
	headers := map[string]string{"Accept": "application/json"}

	switch headerType {
	case apiKeyAuthToken:
		headers["Authorization"] = "Token " + apiKey
	case apiKeyAuthCustomHeader:
		name := credential.GetString(config, "auth_header_name", "")
		if name != "" {
			headers[name] = apiKey
		}
	default: // bearer
		headers["Authorization"] = "Bearer " + apiKey
	}

	// Apply extra static headers
	if raw := credential.GetString(config, "extra_headers", ""); raw != "" {
		if parsed, err := parseExtraHeaders(raw); err == nil {
			for k, v := range parsed {
				headers[k] = v
			}
		}
	}

	return headers
}

// parseExtraHeaders parses comma-separated "key:value" pairs into a map.
func parseExtraHeaders(raw string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, ":")
		if idx < 1 {
			return nil, fmt.Errorf("invalid extra_headers entry %q: expected key:value format", pair)
		}
		key := strings.TrimSpace(pair[:idx])
		val := strings.TrimSpace(pair[idx+1:])
		headers[key] = val
	}
	return headers, nil
}

// parseOptionalMetadata parses comma-separated field names from source config.
func parseOptionalMetadata(config map[string]string) []string {
	raw := credential.GetString(config, "optional_metadata", "")
	if raw == "" {
		return nil
	}
	var fields []string
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			fields = append(fields, f)
		}
	}
	return fields
}

// validateAPIKeyOptionalURL validates that api_url, if non-empty, is a well-formed HTTPS URL.
func validateAPIKeyOptionalURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	return validateAPIKeyURL(rawURL, false)
}

// validateAPIKeyURL validates that the api_url is a well-formed HTTPS URL.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
func validateAPIKeyURL(rawURL string, tlsSkipVerify bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid api_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("api_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("api_url must include a host")
	}
	return nil
}

// validateAPIKeyVerifyMethod validates that verify_method is GET or POST.
func validateAPIKeyVerifyMethod(method string) error {
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

// validateAPIKeyAuthHeaderType validates the auth_header_type enum.
func validateAPIKeyAuthHeaderType(headerType string) error {
	if headerType == "" {
		return nil
	}
	switch headerType {
	case apiKeyAuthBearer, apiKeyAuthToken, apiKeyAuthCustomHeader:
		return nil
	default:
		return fmt.Errorf("auth_header_type must be one of: bearer, token, custom_header; got: %s", headerType)
	}
}
