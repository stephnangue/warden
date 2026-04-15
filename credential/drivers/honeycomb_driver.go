package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// honeycombMaxResponseBodySize limits response body reads to prevent OOM
const honeycombMaxResponseBodySize = 1 << 20 // 1MB

// honeycombMaxRetryAttempts for retryable API operations
const honeycombMaxRetryAttempts = 3

// honeycombDefaultKeyNamePrefix is the default prefix for minted API keys
const honeycombDefaultKeyNamePrefix = "warden-"

// honeycombDefaultKeyType is the default type of API key to mint
const honeycombDefaultKeyType = "ingest"

// honeycombDefaultKeyTTL is the default lease TTL for minted API keys.
// Honeycomb keys don't expire natively, so this controls the Warden lease duration.
const honeycombDefaultKeyTTL = 24 * time.Hour

// honeycombContentType is the JSON:API content type required by Honeycomb V2 API
const honeycombContentType = "application/vnd.api+json"

// Compile-time interface assertions
var _ credential.SourceDriver = (*HoneycombDriver)(nil)
var _ credential.SpecVerifier = (*HoneycombDriver)(nil)

// HoneycombDriver mints credentials from the Honeycomb V2 key management API.
//
// The source config holds a management key (key_id + key_secret) with permissions
// to create and delete API keys. Per-spec config controls the environment,
// key type, naming, and permissions of minted keys.
//
// MintCredential creates a new ingest or configuration API key via POST
// /2/teams/{teamSlug}/api-keys. Revoke deletes the key via DELETE endpoint.
// Key secrets are only returned at creation time, making Warden's capture
// critical.
type HoneycombDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// HoneycombDriverFactory creates HoneycombDriver instances
type HoneycombDriverFactory struct{}

// Type returns the driver type
func (f *HoneycombDriverFactory) Type() string {
	return credential.SourceTypeHoneycomb
}

// ValidateConfig validates Honeycomb source configuration using declarative schema.
func (f *HoneycombDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("honeycomb_url").
			Custom(func(v string) error {
				return validateHoneycombURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Honeycomb API base URL (default: https://api.honeycomb.io)").
			Example("https://api.honeycomb.io"),

		credential.StringField("management_key_id").
			Required().
			Describe("Management key ID (hcxmk_ prefix) for API key management"),

		credential.StringField("management_key_secret").
			Required().
			Describe("Management key secret paired with the key ID"),

		credential.StringField("team_slug").
			Required().
			Describe("Honeycomb team slug used in API paths").
			Example("my-team"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs"),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)"),
	)
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *HoneycombDriverFactory) SensitiveConfigFields() []string {
	return []string{"management_key_id", "management_key_secret", "ca_data"}
}

// InferCredentialType always returns api_key for Honeycomb sources.
func (f *HoneycombDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new HoneycombDriver.
func (f *HoneycombDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeHoneycomb,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeHoneycomb),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// getHoneycombURL returns the Honeycomb API base URL from source config
func (d *HoneycombDriver) getHoneycombURL() string {
	raw := credential.GetString(d.credSource.Config, "honeycomb_url", "https://api.honeycomb.io")
	return strings.TrimRight(raw, "/")
}

// getManagementKeyID returns the management key ID from source config
func (d *HoneycombDriver) getManagementKeyID() string {
	return credential.GetString(d.credSource.Config, "management_key_id", "")
}

// getManagementKeySecret returns the management key secret from source config
func (d *HoneycombDriver) getManagementKeySecret() string {
	return credential.GetString(d.credSource.Config, "management_key_secret", "")
}

// getTeamSlug returns the team slug from source config
func (d *HoneycombDriver) getTeamSlug() string {
	return credential.GetString(d.credSource.Config, "team_slug", "")
}

// MintCredential creates a new Honeycomb API key via the V2 key management API.
//
// Flow:
//  1. Build JSON:API request body with key type, name, environment, and permissions
//  2. POST /2/teams/{teamSlug}/api-keys — create the API key
//  3. Return {"api_key": "<secret>"} with lease TTL from spec config
//
// The leaseID is the Honeycomb key ID (e.g., "hcxik_..."), used for revocation.
// The key secret is only available at creation time.
func (d *HoneycombDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	keyType := credential.GetString(spec.Config, "key_type", honeycombDefaultKeyType)
	namePrefix := credential.GetString(spec.Config, "key_name_prefix", honeycombDefaultKeyNamePrefix)
	environmentID := credential.GetString(spec.Config, "environment_id", "")
	keyTTL := credential.GetDuration(spec.Config, "key_ttl", honeycombDefaultKeyTTL)
	permissionsJSON := credential.GetString(spec.Config, "permissions", "")

	// Validate key_type
	switch keyType {
	case "ingest", "configuration":
	default:
		return nil, 0, "", fmt.Errorf("invalid key_type '%s': must be 'ingest' or 'configuration'", keyType)
	}

	if environmentID == "" {
		return nil, 0, "", fmt.Errorf("environment_id is required in spec config")
	}

	// Build key name
	keyName := fmt.Sprintf("%s%s-%d", namePrefix, spec.Name, time.Now().UnixMilli())

	// Build JSON:API request body
	attributes := map[string]interface{}{
		"key_type": keyType,
		"name":     keyName,
	}

	// Parse and add permissions if specified (configuration keys only)
	if permissionsJSON != "" {
		if keyType != "configuration" {
			return nil, 0, "", fmt.Errorf("permissions can only be set for configuration keys, not %s keys", keyType)
		}
		var permissions map[string]interface{}
		if err := json.Unmarshal([]byte(permissionsJSON), &permissions); err != nil {
			return nil, 0, "", fmt.Errorf("invalid permissions JSON: %w", err)
		}
		attributes["permissions"] = permissions
	}

	reqBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "api-keys",
			"attributes": attributes,
			"relationships": map[string]interface{}{
				"environment": map[string]interface{}{
					"data": map[string]interface{}{
						"type": "environments",
						"id":   environmentID,
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal API key request: %w", err)
	}

	// Create the API key
	teamSlug := d.getTeamSlug()
	path := fmt.Sprintf("/2/teams/%s/api-keys", url.PathEscape(teamSlug))
	respBody, _, err := d.doHoneycombRequest(ctx, http.MethodPost, path, bodyBytes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create API key: %w", err)
	}

	// Parse response — JSON:API format
	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Secret string `json:"secret"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse API key response: %w", err)
	}
	if resp.Data.ID == "" {
		return nil, 0, "", fmt.Errorf("Honeycomb API returned key with empty ID")
	}
	if resp.Data.Attributes.Secret == "" {
		return nil, 0, "", fmt.Errorf("Honeycomb API returned key with empty secret")
	}

	rawData := map[string]interface{}{
		"api_key":  resp.Data.Attributes.Secret,
		"key_type": keyType,
	}

	// leaseID is the Honeycomb key ID for revocation
	leaseID := resp.Data.ID

	if d.logger != nil {
		d.logger.Debug("minted Honeycomb API key",
			logger.String("spec", spec.Name),
			logger.String("key_name", keyName),
			logger.String("key_type", keyType),
			logger.String("key_id", leaseID),
			logger.String("ttl", keyTTL.String()),
		)
	}

	return rawData, keyTTL, leaseID, nil
}

// Revoke deletes the API key identified by leaseID.
// Treats 404 as success since the key may have already been deleted.
func (d *HoneycombDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	teamSlug := d.getTeamSlug()
	path := fmt.Sprintf("/2/teams/%s/api-keys/%s", url.PathEscape(teamSlug), url.PathEscape(leaseID))

	// 204 = deleted, 404 = already gone — both are success
	if _, _, err := d.doHoneycombRequest(ctx, http.MethodDelete, path, nil, 204, 404); err != nil {
		return fmt.Errorf("failed to delete API key %s: %w", leaseID, err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Honeycomb API key",
			logger.String("key_id", leaseID),
		)
	}

	return nil
}

// Type returns the driver type
func (d *HoneycombDriver) Type() string {
	return credential.SourceTypeHoneycomb
}

// Cleanup releases resources
func (d *HoneycombDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates spec configuration and credentials.
// Checks that required spec config fields are present, then lists API keys
// with a page size of 1 to confirm the management key works and the team slug
// is valid.
func (d *HoneycombDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	// Validate required spec config fields early
	environmentID := credential.GetString(spec.Config, "environment_id", "")
	if environmentID == "" {
		return fmt.Errorf("spec config missing required field: environment_id")
	}

	keyType := credential.GetString(spec.Config, "key_type", honeycombDefaultKeyType)
	switch keyType {
	case "ingest", "configuration":
	default:
		return fmt.Errorf("invalid key_type '%s': must be 'ingest' or 'configuration'", keyType)
	}

	// Verify management key and team slug by listing keys
	teamSlug := d.getTeamSlug()
	path := fmt.Sprintf("/2/teams/%s/api-keys?page[size]=1&filter[type]=%s",
		url.PathEscape(teamSlug), url.QueryEscape(keyType))

	if _, _, err := d.doHoneycombRequest(ctx, http.MethodGet, path, nil); err != nil {
		return fmt.Errorf("management key verification failed (GET /2/teams/%s/api-keys): %w", teamSlug, err)
	}
	return nil
}

// --- HTTP helpers ---

// honeycombRetryConfig is the shared retry configuration for all Honeycomb API calls.
var honeycombRetryConfig = HTTPRetryConfig{
	MaxAttempts:       honeycombMaxRetryAttempts,
	MaxBodySize:       honeycombMaxResponseBodySize,
	RetryableStatuses: []int{http.StatusTooManyRequests, 500},
	BaseBackoff:       1 * time.Second,
	JitterPercent:     20,
}

// doHoneycombRequest executes an authenticated HTTP request to the Honeycomb V2 API.
// Optional okStatuses override the default 2xx success check (e.g., pass []int{204, 404}
// to treat 404 as success during revocation).
func (d *HoneycombDriver) doHoneycombRequest(ctx context.Context, method, path string, body []byte, okStatuses ...int) ([]byte, int, error) {
	apiURL := d.getHoneycombURL() + path

	headers := map[string]string{
		"Accept":        honeycombContentType,
		"Authorization": "Bearer " + d.getManagementKeyID() + ":" + d.getManagementKeySecret(),
	}
	if body != nil {
		headers["Content-Type"] = honeycombContentType
	}

	httpReq := HTTPRequest{
		Method:     method,
		URL:        apiURL,
		Body:       body,
		Headers:    headers,
		OKStatuses: okStatuses,
	}

	respBody, status, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, honeycombRetryConfig)
	if err != nil && d.logger != nil {
		d.logger.Warn("Honeycomb API request failed",
			logger.String("method", method),
			logger.String("path", path),
			logger.String("error", err.Error()),
		)
	}
	return respBody, status, err
}

// validateHoneycombURL validates that the honeycomb_url is a well-formed HTTPS URL.
func validateHoneycombURL(rawURL string, tlsSkipVerify bool) error {
	if rawURL == "" {
		return nil // will use default
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid honeycomb_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("honeycomb_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("honeycomb_url must include a host")
	}
	return nil
}
