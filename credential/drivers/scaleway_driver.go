package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

const scalewayMaxResponseBodySize = 1 << 20 // 1MB
const scalewayMaxRetryAttempts = 3

// DefaultScalewayIAMPath is the default IAM API path prefix.
// Currently v1alpha1 — update this when Scaleway promotes the API to stable.
const DefaultScalewayIAMPath = "/iam/v1alpha1"

// DefaultScalewayActivationDelay is the default delay before activating rotated
// management keys. While Scaleway IAM is likely immediately consistent, a short
// delay guards against any internal propagation across regions.
const DefaultScalewayActivationDelay = 30 * time.Second

// Compile-time interface assertions
var _ credential.SourceDriver = (*ScalewayDriver)(nil)
var _ credential.SpecVerifier = (*ScalewayDriver)(nil)
var _ credential.Rotatable = (*ScalewayDriver)(nil)

// ScalewayDriver mints credentials from Scaleway IAM.
//
// Two mint methods are supported (configured per-spec via mint_method):
//   - static_keys: Reads access_key + secret_key from spec config (no TTL, no lease)
//   - dynamic_keys: Creates a fresh API key via POST /iam/v1alpha1/api-keys
//     with an optional expires_at. The key is revoked on lease expiry via DELETE.
//
// The source config holds connection info and a management secret key with
// IAM permissions to create/delete API keys.
type ScalewayDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// configMu protects credSource.Config during rotation. MintCredential reads
	// management_secret_key while CommitRotation writes it.
	configMu sync.RWMutex
}

// ScalewayDriverFactory creates ScalewayDriver instances.
type ScalewayDriverFactory struct{}

// Type returns the driver type identifier.
func (f *ScalewayDriverFactory) Type() string {
	return credential.SourceTypeScaleway
}

// ValidateConfig validates Scaleway source configuration.
func (f *ScalewayDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("scaleway_url").
			Custom(func(v string) error {
				if v == "" {
					return nil // uses default
				}
				return validateScalewayURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Scaleway API URL (default: https://api.scaleway.com)").
			Example("https://api.scaleway.com"),

		credential.StringField("management_access_key").
			Custom(func(v string) error {
				if v != "" && !strings.HasPrefix(v, "SCW") {
					return fmt.Errorf("management_access_key must start with SCW, got: %s (did you swap access_key and secret_key?)", v)
				}
				return nil
			}).
			Describe("Access key for management API key (starts with SCW)").
			Example("SCWXXXXXXXXXXXXXXXXX"),

		credential.StringField("management_secret_key").
			Custom(func(v string) error {
				if v != "" && strings.HasPrefix(v, "SCW") {
					return fmt.Errorf("management_secret_key starts with SCW — this looks like an access key (did you swap access_key and secret_key?)")
				}
				return nil
			}).
			Describe("Secret key with IAM permissions to create/delete API keys (UUID format)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("iam_api_path").
			Describe("IAM API path prefix (default: /iam/v1alpha1). Update when Scaleway promotes the API to stable.").
			Example("/iam/v1alpha1"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	)
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *ScalewayDriverFactory) SensitiveConfigFields() []string {
	return []string{"management_secret_key", "ca_data"}
}

// InferCredentialType always returns scaleway_keys for Scaleway sources.
func (f *ScalewayDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeScalewayKeys, nil
}

// Create instantiates a new ScalewayDriver.
func (f *ScalewayDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &ScalewayDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeScaleway,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeScaleway),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// Type returns the driver type.
func (d *ScalewayDriver) Type() string {
	return credential.SourceTypeScaleway
}

// getScalewayURL returns the Scaleway API base URL from source config.
// Thread-safe: scaleway_url is never modified by rotation.
func (d *ScalewayDriver) getScalewayURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "scaleway_url", "https://api.scaleway.com"), "/")
}

// getManagementSecretKeyLocked returns the management secret key from source config.
// Caller must hold configMu (read or write).
func (d *ScalewayDriver) getManagementSecretKeyLocked() string {
	return credential.GetString(d.credSource.Config, "management_secret_key", "")
}

// getIAMAPIPath returns the IAM API path prefix from source config.
// Defaults to DefaultScalewayIAMPath (/iam/v1alpha1).
func (d *ScalewayDriver) getIAMAPIPath() string {
	return credential.GetString(d.credSource.Config, "iam_api_path", DefaultScalewayIAMPath)
}

// iamURL builds a full IAM API URL for the given subpath (e.g., "/api-keys").
func (d *ScalewayDriver) iamURL(subpath string) string {
	return d.getScalewayURL() + d.getIAMAPIPath() + subpath
}

// MintCredential returns Scaleway credentials for the given spec.
func (d *ScalewayDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "static_keys")
	switch mintMethod {
	case "static_keys":
		return d.mintStaticCredential(spec)
	case "dynamic_keys":
		return d.mintDynamicCredential(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method: %s (expected static_keys or dynamic_keys)", mintMethod)
	}
}

// mintStaticCredential reads access_key and secret_key from spec config.
func (d *ScalewayDriver) mintStaticCredential(spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	accessKey := credential.GetString(spec.Config, "access_key", "")
	if accessKey == "" {
		return nil, 0, "", fmt.Errorf("no access_key configured in spec")
	}
	secretKey := credential.GetString(spec.Config, "secret_key", "")
	if secretKey == "" {
		return nil, 0, "", fmt.Errorf("no secret_key configured in spec")
	}

	rawData := map[string]interface{}{
		"access_key": accessKey,
		"secret_key": secretKey,
	}

	return rawData, 0, "", nil // Static — no TTL, no lease
}

// mintDynamicCredential creates a new API key via the Scaleway IAM API.
func (d *ScalewayDriver) mintDynamicCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	d.configMu.RLock()
	managementKey := d.getManagementSecretKeyLocked()
	d.configMu.RUnlock()
	if managementKey == "" {
		return nil, 0, "", fmt.Errorf("management_secret_key is required on source for dynamic_keys mint method")
	}

	applicationID := credential.GetString(spec.Config, "application_id", "")
	if applicationID == "" {
		return nil, 0, "", fmt.Errorf("application_id is required for dynamic_keys mint method")
	}

	ttl := credential.GetDuration(spec.Config, "ttl", 1*time.Hour)
	description := credential.GetString(spec.Config, "description", fmt.Sprintf("warden-%s", spec.Name))
	defaultProjectID := credential.GetString(spec.Config, "default_project_id", "")

	// Build request body
	reqBody := map[string]interface{}{
		"application_id": applicationID,
		"description":    description,
		"expires_at":     time.Now().Add(ttl).UTC().Format(time.RFC3339),
	}
	if defaultProjectID != "" {
		reqBody["default_project_id"] = defaultProjectID
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	apiURL := d.iamURL("/api-keys")

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodPost,
		URL:    apiURL,
		Body:   bodyJSON,
		Headers: map[string]string{
			"X-Auth-Token": managementKey,
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create Scaleway API key: %w", err)
	}

	// Parse response
	var resp struct {
		AccessKey        string `json:"access_key"`
		SecretKey        string `json:"secret_key"`
		ApplicationID    string `json:"application_id"`
		DefaultProjectID string `json:"default_project_id"`
		Description      string `json:"description"`
		ExpiresAt        string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse Scaleway API response: %w", err)
	}

	if resp.AccessKey == "" || resp.SecretKey == "" {
		return nil, 0, "", fmt.Errorf("Scaleway API returned empty access_key or secret_key")
	}

	d.logger.Info("created dynamic Scaleway API key",
		logger.String("access_key", resp.AccessKey),
		logger.String("application_id", resp.ApplicationID),
		logger.String("spec", spec.Name),
		logger.String("expires_at", resp.ExpiresAt),
	)

	rawData := map[string]interface{}{
		"access_key": resp.AccessKey,
		"secret_key": resp.SecretKey,
	}

	// LeaseID is the access_key — used by Revoke to delete the key
	return rawData, ttl, resp.AccessKey, nil
}

// Revoke deletes a dynamically created API key via DELETE /iam/v1alpha1/api-keys/{access_key}.
func (d *ScalewayDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		if d.logger != nil {
			d.logger.Debug("static Scaleway API keys have no lease, skipping revocation")
		}
		return nil
	}

	d.configMu.RLock()
	managementKey := d.getManagementSecretKeyLocked()
	d.configMu.RUnlock()
	if managementKey == "" {
		return fmt.Errorf("management_secret_key is required to revoke Scaleway API keys")
	}

	apiURL := d.iamURL("/api-keys/" + leaseID)

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodDelete,
		URL:    apiURL,
		Headers: map[string]string{
			"X-Auth-Token": managementKey,
			"Accept":       "application/json",
		},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK, http.StatusNotFound},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("failed to revoke Scaleway API key %s: %w", leaseID, err)
	}

	d.logger.Info("revoked dynamic Scaleway API key",
		logger.String("access_key", leaseID),
	)

	return nil
}

// Cleanup releases resources.
func (d *ScalewayDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// --- Rotatable interface (management key rotation) ---

// SupportsRotation returns true if the driver has a management key that can be rotated.
// Rotation requires both management_secret_key and management_access_key.
func (d *ScalewayDriver) SupportsRotation() bool {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.getManagementSecretKeyLocked() != "" &&
		credential.GetString(d.credSource.Config, "management_access_key", "") != ""
}

// PrepareRotation creates a new management API key via the IAM API using the current key.
// Both old and new keys remain valid during the overlap period.
func (d *ScalewayDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.configMu.RLock()
	managementKey := d.getManagementSecretKeyLocked()
	managementAccessKey := credential.GetString(d.credSource.Config, "management_access_key", "")
	configSnapshot := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		configSnapshot[k] = v
	}
	d.configMu.RUnlock()

	if managementKey == "" {
		return nil, nil, 0, fmt.Errorf("management_secret_key is required for rotation")
	}
	if managementAccessKey == "" {
		return nil, nil, 0, fmt.Errorf("management_access_key is required for rotation")
	}

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	// Look up the current key to find its bearer (application_id or user_id)
	getURL := d.iamURL("/api-keys/" + managementAccessKey)
	getReq := HTTPRequest{
		Method:  http.MethodGet,
		URL:     getURL,
		Headers: map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, getReq, retryConfig)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to look up current management key: %w", err)
	}

	var keyInfo struct {
		ApplicationID string `json:"application_id"`
		UserID        string `json:"user_id"`
	}
	if err := json.Unmarshal(respBody, &keyInfo); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse key info: %w", err)
	}

	// Create a new management key for the same bearer
	createBody := map[string]interface{}{
		"description": "warden-management-key-rotated",
	}
	if keyInfo.ApplicationID != "" {
		createBody["application_id"] = keyInfo.ApplicationID
	} else if keyInfo.UserID != "" {
		createBody["user_id"] = keyInfo.UserID
	} else {
		return nil, nil, 0, fmt.Errorf("current management key has no application_id or user_id")
	}

	bodyJSON, err := json.Marshal(createBody)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal create request: %w", err)
	}

	createURL := d.iamURL("/api-keys")
	createReq := HTTPRequest{
		Method:  http.MethodPost,
		URL:     createURL,
		Body:    bodyJSON,
		Headers: map[string]string{"X-Auth-Token": managementKey, "Content-Type": "application/json", "Accept": "application/json"},
	}

	respBody, _, err = ExecuteWithRetry(ctx, d.httpClient, createReq, retryConfig)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new management key: %w", err)
	}

	var newKey struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(respBody, &newKey); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse new key response: %w", err)
	}

	if newKey.AccessKey == "" || newKey.SecretKey == "" {
		return nil, nil, 0, fmt.Errorf("Scaleway API returned empty access_key or secret_key for new management key")
	}

	// Build new config with rotated management credentials
	newConfig := configSnapshot
	newConfig["management_secret_key"] = newKey.SecretKey
	newConfig["management_access_key"] = newKey.AccessKey

	// Build cleanup config to delete the old key
	cleanupConfig := map[string]string{
		"access_key": managementAccessKey,
	}

	d.logger.Info("prepared new management key for rotation",
		logger.String("new_access_key", newKey.AccessKey),
	)

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultScalewayActivationDelay)
	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates the new management key in driver state.
func (d *ScalewayDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	d.credSource.Config = newConfig

	d.logger.Info("committed rotated management key",
		logger.String("new_access_key", credential.GetString(newConfig, "management_access_key", "")),
	)

	return nil
}

// CleanupRotation deletes the old management key via the IAM API.
func (d *ScalewayDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAccessKey := cleanupConfig["access_key"]
	if oldAccessKey == "" {
		return nil
	}

	d.configMu.RLock()
	managementKey := d.getManagementSecretKeyLocked()
	d.configMu.RUnlock()

	if managementKey == "" {
		return fmt.Errorf("management_secret_key is required to clean up old key")
	}

	deleteURL := d.iamURL("/api-keys/" + oldAccessKey)
	retryConfig := HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	deleteReq := HTTPRequest{
		Method:     http.MethodDelete,
		URL:        deleteURL,
		Headers:    map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK, http.StatusNotFound},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, deleteReq, retryConfig)
	if err != nil {
		d.logger.Warn("failed to delete old management key during cleanup",
			logger.Err(err),
			logger.String("access_key", oldAccessKey),
		)
		return fmt.Errorf("failed to delete old management key: %w", err)
	}

	d.logger.Info("deleted old management key",
		logger.String("access_key", oldAccessKey),
	)

	return nil
}

// VerifySpec validates that the spec's credentials are functional.
func (d *ScalewayDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	mintMethod := credential.GetString(spec.Config, "mint_method", "static_keys")

	switch mintMethod {
	case "static_keys":
		return d.verifyStaticKeys(ctx, spec)
	case "dynamic_keys":
		return d.verifyDynamicConfig(spec)
	default:
		return fmt.Errorf("unsupported mint_method: %s", mintMethod)
	}
}

// verifyStaticKeys verifies that the static access_key exists via the IAM API.
func (d *ScalewayDriver) verifyStaticKeys(ctx context.Context, spec *credential.CredSpec) error {
	secretKey := credential.GetString(spec.Config, "secret_key", "")
	if secretKey == "" {
		return fmt.Errorf("no secret_key configured in spec")
	}

	accessKey := credential.GetString(spec.Config, "access_key", "")
	if accessKey == "" {
		return fmt.Errorf("no access_key configured in spec")
	}

	// Verify the key works by calling a lightweight IAM endpoint
	apiURL := d.iamURL("/api-keys/" + accessKey)

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodGet,
		URL:    apiURL,
		Headers: map[string]string{
			"X-Auth-Token": secretKey,
			"Accept":       "application/json",
		},
	}

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("Scaleway API key verification failed: %w", err)
	}

	return nil
}

// verifyDynamicConfig validates that the dynamic_keys config has the required fields.
func (d *ScalewayDriver) verifyDynamicConfig(spec *credential.CredSpec) error {
	d.configMu.RLock()
	hasKey := d.getManagementSecretKeyLocked() != ""
	d.configMu.RUnlock()
	if !hasKey {
		return fmt.Errorf("management_secret_key is required on source for dynamic_keys mint method")
	}
	if credential.GetString(spec.Config, "application_id", "") == "" {
		return fmt.Errorf("application_id is required for dynamic_keys mint method")
	}
	return nil
}

// validateScalewayURL validates that the URL is well-formed HTTPS.
func validateScalewayURL(rawURL string, tlsSkipVerify bool) error {
	if rawURL == "" {
		return nil
	}
	return validateAPIKeyURL(rawURL, tlsSkipVerify)
}
