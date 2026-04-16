package drivers

import (
	"context"
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

// DefaultIBMActivationDelay is the default wait period for IBM Cloud API key propagation.
// IBM Cloud IAM key propagation is typically fast (seconds), but a 2-minute default
// provides a safe buffer for eventual consistency. Configurable via activation_delay.
const DefaultIBMActivationDelay = 2 * time.Minute

// ibmMaxResponseBodySize limits response body reads to prevent OOM
const ibmMaxResponseBodySize = 1 << 20 // 1MB

// defaultIBMIAMEndpoint is the default IBM Cloud IAM endpoint
const defaultIBMIAMEndpoint = "https://iam.cloud.ibm.com"

// Compile-time interface assertions
var _ credential.SourceDriver = (*IBMDriver)(nil)
var _ credential.Rotatable = (*IBMDriver)(nil)
var _ credential.SpecVerifier = (*IBMDriver)(nil)

// IBMDriver mints credentials from IBM Cloud services.
// It exchanges an IBM Cloud API key for IAM bearer tokens.
//
// The driver's source credentials (API key) are used for:
// - Minting IAM bearer tokens via the IAM token endpoint
// - Rotating the source API key via the IAM Identity Services API
type IBMDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Token cache for IAM bearer tokens
	tokenCache *TokenCache

	// HTTP client for IBM Cloud API calls
	httpClient *http.Client

	// authMu protects iamID, apiKeyID, and credSource.Config writes during rotation.
	// These fields are read by SupportsRotation/PrepareRotation and written by
	// CommitRotation/discoverAPIKeyDetails concurrently.
	authMu sync.Mutex

	// iamID is the IAM identity associated with the source API key
	// Discovered at creation time, required for rotation
	// Protected by authMu
	iamID string

	// apiKeyID is the unique ID of the current source API key
	// Used for cleanup during rotation
	// Protected by authMu
	apiKeyID string
}

// IBMDriverFactory creates IBMDriver instances
type IBMDriverFactory struct{}

// Type returns the driver type
func (f *IBMDriverFactory) Type() string {
	return credential.SourceTypeIBM
}

// ValidateConfig validates IBM Cloud driver configuration using declarative schema
func (f *IBMDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("api_key").
			Required().
			Describe("IBM Cloud API key").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("account_id").
			Describe("IBM Cloud account ID (optional, discovered from API key if omitted)").
			Example("abcdef1234567890abcdef1234567890"),

		credential.StringField("iam_endpoint").
			Custom(func(v string) error {
				skipTLS := credential.GetBool(config, "tls_skip_verify", false)
				if !strings.HasPrefix(v, "https://") && !(strings.HasPrefix(v, "http://") && skipTLS) {
					return fmt.Errorf("iam_endpoint must use https scheme, got: %s", v)
				}
				if _, err := url.Parse(v); err != nil {
					return fmt.Errorf("iam_endpoint is not a valid URL: %w", err)
				}
				return nil
			}).
			Describe("IBM Cloud IAM endpoint (optional, defaults to https://iam.cloud.ibm.com)").
			Example("https://iam.cloud.ibm.com"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	)
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *IBMDriverFactory) SensitiveConfigFields() []string {
	return []string{"api_key", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *IBMDriverFactory) InferCredentialType(specConfig map[string]string) (string, error) {
	mintMethod := specConfig["mint_method"]
	switch mintMethod {
	case "iam_token", "":
		return credential.TypeOAuthBearerToken, nil
	case "iam_with_cos":
		return credential.TypeIBMCloudKeys, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// Create instantiates a new IBMDriver
func (f *IBMDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeIBM),
		tokenCache: NewTokenCache(),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := driver.acquireIAMToken(ctx); err != nil {
		return nil, fmt.Errorf("IBM Cloud authentication failed: %w", err)
	}

	// Discover API key details for rotation support
	if err := driver.discoverAPIKeyDetails(ctx); err != nil {
		// Non-fatal: rotation won't be available but minting still works
		if driver.logger != nil {
			driver.logger.Warn("failed to discover API key details, rotation will be disabled",
				logger.Err(err),
			)
		}
	}

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential mints credentials based on the spec's mint_method.
func (d *IBMDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "iam_token")

	switch mintMethod {
	case "iam_token":
		return d.mintIAMToken(ctx, spec)
	case "iam_with_cos":
		return d.mintIAMWithCOS(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for IBM driver; use 'iam_token' or 'iam_with_cos'", mintMethod)
	}
}

// mintIAMToken exchanges the source API key for an IAM bearer token
func (d *IBMDriver) mintIAMToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	token, expiry, err := d.getIAMToken(ctx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to acquire IBM IAM token: %w", err)
	}

	ttl := time.Until(expiry)
	rawData := map[string]interface{}{
		"api_key":      token,
		"access_token": token,
		"token_type":   "Bearer",
	}

	if d.logger != nil {
		d.logger.Debug("minted IBM IAM bearer token",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID — IAM tokens expire naturally and cannot be revoked
	return rawData, ttl, "", nil
}

// mintIAMWithCOS mints an IAM bearer token and combines it with static COS HMAC keys from spec config.
func (d *IBMDriver) mintIAMWithCOS(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	token, expiry, err := d.getIAMToken(ctx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to acquire IBM IAM token: %w", err)
	}

	ttl := time.Until(expiry)
	rawData := map[string]interface{}{
		"access_token": token,
	}

	// Add optional COS HMAC keys from spec config (API-only mode is valid)
	accessKeyID := credential.GetString(spec.Config, "access_key_id", "")
	secretAccessKey := credential.GetString(spec.Config, "secret_access_key", "")
	if accessKeyID != "" && secretAccessKey != "" {
		rawData["access_key_id"] = accessKeyID
		rawData["secret_access_key"] = secretAccessKey
	}

	if d.logger != nil {
		hasCOS := accessKeyID != "" && secretAccessKey != ""
		d.logger.Debug("minted IBM Cloud keys (IAM token + COS HMAC)",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
			logger.Bool("has_cos", hasCOS),
		)
	}

	return rawData, ttl, "", nil
}

// Revoke is a no-op for IBM credentials (IAM tokens expire naturally)
func (d *IBMDriver) Revoke(ctx context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("IBM IAM tokens expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *IBMDriver) Type() string {
	return credential.SourceTypeIBM
}

// Cleanup releases resources
func (d *IBMDriver) Cleanup(ctx context.Context) error {
	return nil
}

// VerifySpec validates that an IBM spec's configuration is functional by performing
// a lightweight IAM token exchange. Called during spec creation/update only.
func (d *IBMDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	mintMethod := credential.GetString(spec.Config, "mint_method", "iam_token")
	if mintMethod != "iam_token" {
		return nil
	}

	// Verify the source API key can mint an IAM token
	_, _, err := d.getIAMToken(ctx)
	if err != nil {
		return fmt.Errorf("IBM spec verification failed: %w", err)
	}
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source API Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source API key.
// Rotation requires the API key's IAM identity to have permission to create/delete API keys.
func (d *IBMDriver) SupportsRotation() bool {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.iamID != ""
}

// PrepareRotation creates a new API key for the same IAM identity.
// Returns activateAfter to allow time for IBM Cloud propagation.
func (d *IBMDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	if d.iamID == "" {
		return nil, nil, 0, fmt.Errorf("cannot rotate: IAM identity not discovered")
	}

	// Get IAM token using current API key
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get IAM token for rotation: %w", err)
	}

	// Create new API key for the same IAM identity
	newAPIKey, newAPIKeyID, err := d.createAPIKey(ctx, iamToken)
	if err != nil {
		return nil, nil, 0, err
	}

	oldAPIKeyID := d.apiKeyID

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["api_key"] = newAPIKey

	cleanupConfig := map[string]string{
		"api_key_id": oldAPIKeyID,
	}

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultIBMActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source API key rotation",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
			logger.String("new_key_id", truncateID(newAPIKeyID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver.
//
// Thread-safety: authMu protects credSource.Config writes and iamID/apiKeyID updates.
// The rotated field (api_key) is only read by acquireIAMToken, which is always called
// either under authMu or during initial creation (single-threaded).
func (d *IBMDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Save old config for rollback on failure
	oldConfig := d.credSource.Config

	// Update config
	d.credSource.Config = newConfig

	// Invalidate all cached tokens from previous generation
	d.tokenCache.InvalidateGeneration()

	// Verify new credentials work
	if _, _, err := d.acquireIAMToken(ctx); err != nil {
		d.credSource.Config = oldConfig
		d.tokenCache.InvalidateGeneration()
		return fmt.Errorf("failed to authenticate with new API key: %w", err)
	}

	// Re-discover API key details with new key
	if err := d.discoverAPIKeyDetailsLocked(ctx); err != nil {
		d.credSource.Config = oldConfig
		d.tokenCache.InvalidateGeneration()
		return fmt.Errorf("failed to discover new API key details: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("committed source API key rotation",
			logger.String("new_key_id", truncateID(d.apiKeyID, 8)),
		)
	}

	return nil
}

// CleanupRotation deletes the old API key
func (d *IBMDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAPIKeyID := cleanupConfig["api_key_id"]
	if oldAPIKeyID == "" {
		return nil
	}

	// Get IAM token using current (new) API key
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IAM token for cleanup: %w", err)
	}

	if err := d.deleteAPIKey(ctx, iamToken, oldAPIKeyID); err != nil {
		return fmt.Errorf("failed to delete old API key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old API key",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Token Acquisition
// ============================================================================

// getIAMToken returns a cached or freshly acquired IAM bearer token.
// Thread-safe via TokenCache.
func (d *IBMDriver) getIAMToken(ctx context.Context) (string, time.Time, error) {
	// Check cache (with 30s refresh buffer)
	if token, expiry, ok := d.tokenCache.Get("iam", 30*time.Second); ok {
		return token, expiry, nil
	}

	// Acquire fresh token
	token, expiry, err := d.acquireIAMToken(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	// Cache it
	d.tokenCache.Set("iam", token, expiry)

	return token, expiry, nil
}

// acquireIAMToken exchanges the source API key for an IAM bearer token.
func (d *IBMDriver) acquireIAMToken(ctx context.Context) (string, time.Time, error) {
	apiKey := credential.GetString(d.credSource.Config, "api_key", "")
	if apiKey == "" {
		return "", time.Time{}, fmt.Errorf("api_key is empty")
	}

	iamEndpoint := d.getIAMEndpoint()

	form := url.Values{
		"grant_type": {"urn:ibm:params:oauth:grant-type:apikey"},
		"apikey":     {apiKey},
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/identity/token",
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("IBM IAM token request failed: %w", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Expiration  int64  `json:"expiration"` // Unix timestamp
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode IAM token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("IAM token response missing access_token")
	}

	// Compute expiry from either expiration (Unix timestamp) or expires_in (seconds)
	var expiry time.Time
	if tokenResp.Expiration > 0 {
		expiry = time.Unix(tokenResp.Expiration, 0)
	} else if tokenResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		expiry = time.Now().Add(1 * time.Hour) // fallback
	}

	return tokenResp.AccessToken, expiry, nil
}

// ============================================================================
// IAM Identity Services API Helpers
// ============================================================================

// discoverAPIKeyDetails fetches the IAM identity and key ID for the source API key.
// Acquires authMu internally.
func (d *IBMDriver) discoverAPIKeyDetails(ctx context.Context) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.discoverAPIKeyDetailsLocked(ctx)
}

// discoverAPIKeyDetailsLocked is the lock-free implementation of discoverAPIKeyDetails.
// Caller must hold authMu.
func (d *IBMDriver) discoverAPIKeyDetailsLocked(ctx context.Context) error {
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IAM token: %w", err)
	}

	iamEndpoint := d.getIAMEndpoint()
	apiKey := credential.GetString(d.credSource.Config, "api_key", "")

	// Use POST with API key in request body (more secure than GET with IAM-Apikey header)
	reqBody, err := json.Marshal(map[string]string{
		"apikey": apiKey,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal API key details request: %w", err)
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/v1/apikeys/details",
		Body:   reqBody,
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return fmt.Errorf("failed to get API key details: %w", err)
	}

	var detailsResp struct {
		ID        string `json:"id"`
		IamID     string `json:"iam_id"`
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(respBody, &detailsResp); err != nil {
		return fmt.Errorf("failed to decode API key details: %w", err)
	}

	if detailsResp.IamID == "" {
		return fmt.Errorf("API key details response missing iam_id")
	}

	d.iamID = detailsResp.IamID
	d.apiKeyID = detailsResp.ID

	// Set account_id from discovery if not already configured
	if credential.GetString(d.credSource.Config, "account_id", "") == "" && detailsResp.AccountID != "" {
		d.credSource.Config["account_id"] = detailsResp.AccountID
	}

	if d.logger != nil {
		d.logger.Trace("discovered IBM API key details",
			logger.String("api_key_id", truncateID(d.apiKeyID, 8)),
			logger.String("iam_id", d.iamID),
		)
	}

	return nil
}

// createAPIKey creates a new API key for the same IAM identity
func (d *IBMDriver) createAPIKey(ctx context.Context, iamToken string) (string, string, error) {
	iamEndpoint := d.getIAMEndpoint()
	accountID := credential.GetString(d.credSource.Config, "account_id", "")

	reqBody, err := json.Marshal(map[string]interface{}{
		"name":        fmt.Sprintf("warden-rotated-%d", time.Now().Unix()),
		"description": "Managed by Warden credential rotation",
		"iam_id":      d.iamID,
		"account_id":  accountID,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/v1/apikeys",
		Body:   reqBody,
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to create new API key: %w", err)
	}

	var createResp struct {
		ID     string `json:"id"`
		Apikey string `json:"apikey"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return "", "", fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Apikey == "" || createResp.ID == "" {
		return "", "", fmt.Errorf("create API key response missing apikey or id")
	}

	return createResp.Apikey, createResp.ID, nil
}

// deleteAPIKey deletes an API key by ID
func (d *IBMDriver) deleteAPIKey(ctx context.Context, iamToken, apiKeyID string) error {
	iamEndpoint := d.getIAMEndpoint()

	_, _, err := ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method: "DELETE",
		URL:    fmt.Sprintf("%s/v1/apikeys/%s", iamEndpoint, url.PathEscape(apiKeyID)),
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
		},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK},
	}, defaultIBMRetryConfig())
	return err
}

// ============================================================================
// Helpers
// ============================================================================

// getIAMEndpoint returns the configured IAM endpoint or the default
func (d *IBMDriver) getIAMEndpoint() string {
	return credential.GetString(d.credSource.Config, "iam_endpoint", defaultIBMIAMEndpoint)
}

// defaultIBMRetryConfig returns the standard retry configuration for IBM Cloud API calls.
func defaultIBMRetryConfig() HTTPRetryConfig {
	return HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       ibmMaxResponseBodySize,
		RetryableStatuses: []int{429, 500}, // 500 = wildcard for all 5xx (see ExecuteWithRetry)
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}
