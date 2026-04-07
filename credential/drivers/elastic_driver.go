package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// DefaultElasticActivationDelay is the default wait period for Elasticsearch
// API key propagation. Elasticsearch propagation is typically near-instant
// within a cluster, so a short 10-second default is used.
// Configurable via activation_delay in source config.
const DefaultElasticActivationDelay = 10 * time.Second

// elasticMaxResponseBodySize limits response body reads to prevent OOM
const elasticMaxResponseBodySize = 1 << 20 // 1MB

// Compile-time interface assertions
var _ credential.SourceDriver = (*ElasticDriver)(nil)
var _ credential.Rotatable = (*ElasticDriver)(nil)
var _ credential.SpecVerifier = (*ElasticDriver)(nil)

// ElasticDriver mints credentials from Elasticsearch clusters.
// It creates API keys via the /_security/api_key endpoint and supports
// rotation of the driver's own source API key.
//
// The driver's source credentials (a pre-encoded API key) are used for:
// - Minting new API keys for credential specs
// - Rotating the source API key via the Security API
type ElasticDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// HTTP client for Elasticsearch API calls
	httpClient *http.Client

	// authMu protects sourceAPIKeyID and credSource.Config writes during rotation.
	authMu sync.Mutex

	// sourceAPIKeyID is the ID portion of the source API key (decoded from base64).
	// Used for cleanup during rotation.
	// Protected by authMu.
	sourceAPIKeyID string
}

// ElasticDriverFactory creates ElasticDriver instances
type ElasticDriverFactory struct{}

// Type returns the driver type
func (f *ElasticDriverFactory) Type() string {
	return credential.SourceTypeElastic
}

// ValidateConfig validates Elasticsearch driver configuration using declarative schema
func (f *ElasticDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("elastic_url").
			Required().
			Custom(func(v string) error {
				if !strings.HasPrefix(v, "https://") {
					return fmt.Errorf("elastic_url must use https scheme, got: %s", v)
				}
				if _, err := url.Parse(v); err != nil {
					return fmt.Errorf("elastic_url is not a valid URL: %w", err)
				}
				return nil
			}).
			Describe("Elasticsearch cluster URL").
			Example("https://my-cluster.es.us-east-1.aws.cloud.es.io"),

		credential.StringField("api_key").
			Required().
			Describe("Pre-encoded Elasticsearch API key (base64 of id:api_key)").
			Example("dXNlcjpwYXNzd29yZA=="),

		credential.StringField("api_key_id").
			Describe("API key ID (optional, extracted from api_key if omitted)").
			Example("VuaCfGcBCdbkQm-e5aOx"),

		credential.StringField("activation_delay").
			Custom(func(v string) error {
				if _, err := time.ParseDuration(v); err != nil {
					return fmt.Errorf("activation_delay must be a valid duration: %w", err)
				}
				return nil
			}).
			Describe("Wait period for API key propagation during rotation (default: 10s)").
			Example("10s"),

		credential.StringField("key_name_prefix").
			Describe("Prefix for generated API key names (default: warden)").
			Example("warden"),
	)
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *ElasticDriverFactory) SensitiveConfigFields() []string {
	return []string{"api_key"}
}

// InferCredentialType returns the credential type for Elasticsearch sources.
func (f *ElasticDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new ElasticDriver
func (f *ElasticDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &ElasticDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeElastic,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeElastic),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Extract API key ID from pre-encoded value if not explicitly provided
	apiKeyID := credential.GetString(config, "api_key_id", "")
	if apiKeyID == "" {
		var err error
		apiKeyID, err = decodeElasticAPIKeyID(credential.GetString(config, "api_key", ""))
		if err != nil {
			return nil, fmt.Errorf("failed to extract API key ID from encoded api_key: %w", err)
		}
	}
	driver.sourceAPIKeyID = apiKeyID

	// Verify source credentials
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := driver.verifyAuthentication(ctx); err != nil {
		return nil, fmt.Errorf("Elasticsearch authentication failed: %w", err)
	}

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential creates a new Elasticsearch API key via POST /_security/api_key.
//
// Spec config fields:
//   - key_name: Override for the generated key name (optional)
//   - role_descriptors: JSON string of role descriptors (optional)
//   - expiration: Key expiration duration, e.g. "30d" (optional)
func (d *ElasticDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	prefix := credential.GetString(d.credSource.Config, "key_name_prefix", "warden")
	keyName := credential.GetString(spec.Config, "key_name", fmt.Sprintf("%s-%s-%d", prefix, spec.Name, time.Now().Unix()))
	expiration := credential.GetString(spec.Config, "expiration", "")

	reqBody := map[string]interface{}{
		"name": keyName,
		"metadata": map[string]interface{}{
			"managed_by": "warden",
			"spec":       spec.Name,
		},
	}

	// Parse optional role_descriptors from spec config
	if rdJSON := credential.GetString(spec.Config, "role_descriptors", ""); rdJSON != "" {
		var roleDescriptors map[string]interface{}
		if err := json.Unmarshal([]byte(rdJSON), &roleDescriptors); err != nil {
			return nil, 0, "", fmt.Errorf("invalid role_descriptors JSON: %w", err)
		}
		reqBody["role_descriptors"] = roleDescriptors
	}

	if expiration != "" {
		reqBody["expiration"] = expiration
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := d.doElasticRequest(ctx, http.MethodPost, "/_security/api_key", body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create Elasticsearch API key: %w", err)
	}

	var createResp struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		APIKey     string `json:"api_key"`
		Encoded    string `json:"encoded"`
		Expiration *int64 `json:"expiration"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Encoded == "" || createResp.ID == "" {
		return nil, 0, "", fmt.Errorf("create API key response missing encoded or id field")
	}

	rawData := map[string]interface{}{
		"api_key": createResp.Encoded,
	}

	// Compute TTL from expiration timestamp
	var ttl time.Duration
	if createResp.Expiration != nil {
		expiryTime := time.UnixMilli(*createResp.Expiration)
		ttl = time.Until(expiryTime)
		if ttl < 0 {
			ttl = 0
		}
	}

	leaseID := "elastic:" + createResp.ID

	if d.logger != nil {
		d.logger.Debug("minted Elasticsearch API key",
			logger.String("spec", spec.Name),
			logger.String("key_name", createResp.Name),
			logger.String("key_id", truncateID(createResp.ID, 8)),
		)
	}

	return rawData, ttl, leaseID, nil
}

// Revoke invalidates an Elasticsearch API key via DELETE /_security/api_key.
func (d *ElasticDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	// Extract key ID from "elastic:<id>" format
	keyID := strings.TrimPrefix(leaseID, "elastic:")
	if keyID == leaseID {
		return fmt.Errorf("invalid lease ID format: %s", leaseID)
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"ids": []string{keyID},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal invalidate request: %w", err)
	}

	_, _, err = d.doElasticRequest(ctx, http.MethodDelete, "/_security/api_key", reqBody)
	if err != nil {
		return fmt.Errorf("failed to invalidate Elasticsearch API key %s: %w", truncateID(keyID, 8), err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Elasticsearch API key",
			logger.String("key_id", truncateID(keyID, 8)),
		)
	}

	return nil
}

// Type returns the driver type
func (d *ElasticDriver) Type() string {
	return credential.SourceTypeElastic
}

// Cleanup releases resources
func (d *ElasticDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the source credentials are functional by calling
// the Elasticsearch authenticate endpoint.
func (d *ElasticDriver) VerifySpec(ctx context.Context, _ *credential.CredSpec) error {
	if err := d.verifyAuthentication(ctx); err != nil {
		return fmt.Errorf("Elasticsearch spec verification failed: %w", err)
	}
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source API Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source API key.
// Rotation requires the source API key to have the manage_api_key or
// manage_own_api_key cluster privilege.
func (d *ElasticDriver) SupportsRotation() bool {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.sourceAPIKeyID != ""
}

// PrepareRotation creates a new API key using the current source credentials.
// Returns activateAfter to allow time for cluster propagation.
func (d *ElasticDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	if d.sourceAPIKeyID == "" {
		return nil, nil, 0, fmt.Errorf("cannot rotate: source API key ID not discovered")
	}

	prefix := credential.GetString(d.credSource.Config, "key_name_prefix", "warden")

	// Create new API key via the Security API
	reqBody, err := json.Marshal(map[string]interface{}{
		"name": fmt.Sprintf("%s-source-rotated-%d", prefix, time.Now().Unix()),
		"metadata": map[string]interface{}{
			"managed_by": "warden",
			"purpose":    "source_rotation",
		},
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := d.doElasticRequest(ctx, http.MethodPost, "/_security/api_key", reqBody)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new source API key: %w", err)
	}

	var createResp struct {
		ID      string `json:"id"`
		Encoded string `json:"encoded"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Encoded == "" || createResp.ID == "" {
		return nil, nil, 0, fmt.Errorf("create API key response missing encoded or id")
	}

	oldAPIKeyID := d.sourceAPIKeyID

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["api_key"] = createResp.Encoded
	newConfig["api_key_id"] = createResp.ID

	cleanupConfig := map[string]string{
		"api_key_id": oldAPIKeyID,
	}

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultElasticActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source API key rotation",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
			logger.String("new_key_id", truncateID(createResp.ID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver.
func (d *ElasticDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Save old state for rollback
	oldConfig := d.credSource.Config
	oldAPIKeyID := d.sourceAPIKeyID

	// Update config
	d.credSource.Config = newConfig
	d.sourceAPIKeyID = credential.GetString(newConfig, "api_key_id", "")

	// Verify new credentials work
	if err := d.verifyAuthentication(ctx); err != nil {
		// Rollback
		d.credSource.Config = oldConfig
		d.sourceAPIKeyID = oldAPIKeyID
		return fmt.Errorf("failed to authenticate with new API key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("committed source API key rotation",
			logger.String("new_key_id", truncateID(d.sourceAPIKeyID, 8)),
		)
	}

	return nil
}

// CleanupRotation invalidates the old API key
func (d *ElasticDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAPIKeyID := cleanupConfig["api_key_id"]
	if oldAPIKeyID == "" {
		return nil
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"ids": []string{oldAPIKeyID},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal invalidate request: %w", err)
	}

	_, _, err = d.doElasticRequest(ctx, http.MethodDelete, "/_security/api_key", reqBody)
	if err != nil {
		return fmt.Errorf("failed to invalidate old API key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old API key",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// verifyAuthentication calls GET /_security/_authenticate to verify the source
// API key is valid.
func (d *ElasticDriver) verifyAuthentication(ctx context.Context) error {
	respBody, _, err := d.doElasticRequest(ctx, http.MethodGet, "/_security/_authenticate", nil)
	if err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}

	var authResp struct {
		Username string `json:"username"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return fmt.Errorf("failed to decode authenticate response: %w", err)
	}

	if authResp.Username == "" {
		return fmt.Errorf("authenticate response missing username")
	}

	return nil
}

// doElasticRequest executes an HTTP request to the Elasticsearch cluster using
// the source API key for authentication.
func (d *ElasticDriver) doElasticRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	elasticURL := credential.GetString(d.credSource.Config, "elastic_url", "")
	apiKey := credential.GetString(d.credSource.Config, "api_key", "")

	headers := map[string]string{
		"Authorization": "ApiKey " + apiKey,
		"Accept":        "application/json",
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	return ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method:  method,
		URL:     elasticURL + path,
		Body:    body,
		Headers: headers,
	}, defaultElasticRetryConfig())
}

// defaultElasticRetryConfig returns the standard retry configuration for Elasticsearch API calls.
func defaultElasticRetryConfig() HTTPRetryConfig {
	return HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       elasticMaxResponseBodySize,
		RetryableStatuses: []int{429, 500}, // 500 = wildcard for all 5xx (see ExecuteWithRetry)
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}

// decodeElasticAPIKeyID extracts the API key ID from a pre-encoded API key.
// The encoded format is base64(id:api_key), so we decode and split on ':'.
func decodeElasticAPIKeyID(encoded string) (string, error) {
	if encoded == "" {
		return "", fmt.Errorf("encoded API key is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe encoding as fallback
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("failed to base64-decode API key: %w", err)
		}
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", fmt.Errorf("decoded API key does not match expected id:api_key format")
	}

	return parts[0], nil
}
