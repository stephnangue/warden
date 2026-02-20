package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// DefaultGCPActivationDelay is the default wait period for GCP IAM key propagation.
// GCP IAM key propagation is typically faster than AWS/Azure (10-60s measured),
// so a 2-minute default provides a safe buffer. Configurable via activation_delay.
const DefaultGCPActivationDelay = 2 * time.Minute

// gcpMaxResponseBodySize limits response body reads to prevent OOM
const gcpMaxResponseBodySize = 1 << 20 // 1MB

// Compile-time interface assertions
var _ credential.SourceDriver = (*GCPDriver)(nil)
var _ credential.Rotatable = (*GCPDriver)(nil)

// serviceAccountKey represents the parsed structure of a GCP service account JSON key file
type serviceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
	UniverseDomain          string `json:"universe_domain"`
}

// GCPDriver mints credentials from GCP services.
// It exchanges a service account JSON key for OAuth2 access tokens,
// and optionally impersonates other service accounts.
//
// The driver's source credentials (SA key) are used for:
// - Minting access tokens for the source SA
// - Impersonating other service accounts via IAM Credentials API
// - Rotating its own SA key via IAM API
type GCPDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Token cache for the source SA's API access .
	tokenCache *TokenCache

	// HTTP client for GCP API calls
	httpClient *http.Client

	// Flag to track if source credentials have been verified
	sourceVerified bool
}

// Config accessors — single source of truth is credSource.Config.

func (d *GCPDriver) getServiceAccountKey() string {
	return credential.GetString(d.credSource.Config, "service_account_key", "")
}

func (d *GCPDriver) parseServiceAccountKey() (*serviceAccountKey, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return nil, fmt.Errorf("service_account_key is empty")
	}
	var saKey serviceAccountKey
	if err := json.Unmarshal([]byte(saKeyJSON), &saKey); err != nil {
		return nil, fmt.Errorf("invalid service_account_key JSON: %w", err)
	}
	return &saKey, nil
}

// GCPDriverFactory creates GCPDriver instances
type GCPDriverFactory struct{}

// Type returns the driver type
func (f *GCPDriverFactory) Type() string {
	return credential.SourceTypeGCP
}

// ValidateConfig validates GCP driver configuration using declarative schema
func (f *GCPDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("service_account_key").
			Required().
			Custom(func(value string) error {
				// Validate that service_account_key is valid JSON with required fields
				var saKey serviceAccountKey
				if err := json.Unmarshal([]byte(value), &saKey); err != nil {
					return fmt.Errorf("must be valid JSON: %w", err)
				}
				if saKey.ClientEmail == "" {
					return fmt.Errorf("missing 'client_email' field in JSON")
				}
				if saKey.PrivateKey == "" {
					return fmt.Errorf("missing 'private_key' field in JSON")
				}
				return nil
			}).
			Describe("GCP service account key in JSON format").
			Example("{\"type\":\"service_account\",\"project_id\":\"...\",\"private_key\":\"...\"}"),
	)
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *GCPDriverFactory) SensitiveConfigFields() []string {
	return []string{"service_account_key"}
}

// Create instantiates a new GCPDriver
func (f *GCPDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeGCP),
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := driver.acquireToken(ctx, []string{"https://www.googleapis.com/auth/cloud-platform"}); err != nil {
		return nil, fmt.Errorf("GCP authentication failed: %w", err)
	}
	driver.sourceVerified = true

	return driver, nil
}

// MintCredential mints credentials based on the spec's mint_method.
func (d *GCPDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "access_token")

	switch mintMethod {
	case "access_token":
		return d.mintAccessToken(ctx, spec)
	case "impersonated_access_token":
		return d.mintImpersonatedAccessToken(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for GCP driver; use 'access_token' or 'impersonated_access_token'", mintMethod)
	}
}

// mintAccessToken exchanges the source SA key for an OAuth2 access token
func (d *GCPDriver) mintAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	scopesStr := credential.GetString(spec.Config, "scopes", "https://www.googleapis.com/auth/cloud-platform")
	scopes := splitScopes(scopesStr)

	token, expiry, err := d.getSourceToken(ctx, scopes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to acquire GCP access token: %w", err)
	}

	saKey, _ := d.parseServiceAccountKey()
	projectID := ""
	if saKey != nil {
		projectID = saKey.ProjectID
	}

	ttl := time.Until(expiry)
	rawData := map[string]interface{}{
		"access_token": token,
		"project_id":   projectID,
		"scopes":       scopesStr,
		"token_type":   "Bearer",
	}

	if d.logger != nil {
		d.logger.Debug("minted GCP access token",
			logger.String("spec", spec.Name),
			logger.String("scopes", scopesStr),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID - access tokens expire naturally and cannot be revoked
	return rawData, ttl, "", nil
}

// mintImpersonatedAccessToken impersonates another service account via IAM Credentials API
func (d *GCPDriver) mintImpersonatedAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	targetSA := credential.GetString(spec.Config, "target_service_account", "")
	if targetSA == "" {
		return nil, 0, "", fmt.Errorf("target_service_account is required for impersonated_access_token mint method")
	}

	scopesStr := credential.GetString(spec.Config, "scopes", "https://www.googleapis.com/auth/cloud-platform")
	scopes := splitScopes(scopesStr)
	lifetime := credential.GetString(spec.Config, "lifetime", "3600s")

	// Get source token with IAM scope for impersonation
	sourceToken, _, err := d.getSourceToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to get source token for impersonation: %w", err)
	}

	// Call IAM Credentials API to generate an access token for the target SA
	apiURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		url.PathEscape(targetSA))

	reqBody := map[string]interface{}{
		"scope":    scopes,
		"lifetime": lifetime,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal impersonation request: %w", err)
	}

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "POST",
		url:         apiURL,
		body:        bodyBytes,
		contentType: "application/json",
		bearerToken: sourceToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "generateAccessToken",
	}, 1)
	if err != nil {
		return nil, 0, "", err
	}

	var tokenResp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"` // RFC3339
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode impersonation response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, 0, "", fmt.Errorf("impersonation response missing accessToken")
	}

	// Parse expiry time
	var ttl time.Duration
	if tokenResp.ExpireTime != "" {
		if expiry, err := time.Parse(time.RFC3339, tokenResp.ExpireTime); err == nil {
			ttl = time.Until(expiry)
		}
	}
	if ttl <= 0 {
		ttl = 1 * time.Hour // fallback
	}

	saKey, _ := d.parseServiceAccountKey()
	projectID := ""
	if saKey != nil {
		projectID = saKey.ProjectID
	}

	rawData := map[string]interface{}{
		"access_token":           tokenResp.AccessToken,
		"project_id":             projectID,
		"scopes":                 scopesStr,
		"token_type":             "Bearer",
		"target_service_account": targetSA,
	}

	if d.logger != nil {
		d.logger.Debug("minted impersonated GCP access token",
			logger.String("spec", spec.Name),
			logger.String("target_sa", targetSA),
			logger.String("ttl", ttl.String()),
		)
	}

	return rawData, ttl, "", nil
}

// Revoke is a no-op for GCP credentials (they expire naturally)
func (d *GCPDriver) Revoke(ctx context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("GCP credentials expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *GCPDriver) Type() string {
	return credential.SourceTypeGCP
}

// Cleanup releases resources
func (d *GCPDriver) Cleanup(ctx context.Context) error {
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source SA Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source SA key.
// Rotation requires the SA to have iam.serviceAccountKeys.create and
// iam.serviceAccountKeys.delete permissions on itself.
func (d *GCPDriver) SupportsRotation() bool {
	return true
}

// PrepareRotation creates a new SA key for the source service account.
// Returns activateAfter to allow time for GCP IAM propagation.
func (d *GCPDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	saKey, err := d.parseServiceAccountKey()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse current SA key: %w", err)
	}

	oldKeyID := saKey.PrivateKeyID

	// Get IAM token using current credentials
	iamToken, _, err := d.acquireToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get IAM token: %w", err)
	}

	// Create new SA key via IAM API
	newKeyJSON, err := d.createServiceAccountKey(ctx, iamToken, saKey.ClientEmail, saKey.ProjectID)
	if err != nil {
		return nil, nil, 0, err
	}

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["service_account_key"] = newKeyJSON

	cleanupConfig := map[string]string{
		"old_key_id":            oldKeyID,
		"service_account_email": saKey.ClientEmail,
		"project_id":            saKey.ProjectID,
	}

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultGCPActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source SA key rotation",
			logger.String("old_key_id", truncateID(oldKeyID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver
func (d *GCPDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	// Update config (single source of truth for credentials)
	d.credSource.Config = newConfig

	// Invalidate all cached tokens from previous generation
	d.tokenCache.InvalidateGeneration()
	d.sourceVerified = false

	// Verify new credentials work
	_, _, err := d.acquireToken(ctx, []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err != nil {
		return fmt.Errorf("failed to authenticate with new SA key: %w", err)
	}
	d.sourceVerified = true

	if d.logger != nil {
		d.logger.Debug("committed source SA key rotation")
	}

	return nil
}

// CleanupRotation deletes the old SA key
func (d *GCPDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldKeyID := cleanupConfig["old_key_id"]
	if oldKeyID == "" {
		return nil
	}

	saEmail := cleanupConfig["service_account_email"]
	projectID := cleanupConfig["project_id"]

	// Get IAM token
	iamToken, _, err := d.getSourceToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
	if err != nil {
		return fmt.Errorf("failed to get IAM token: %w", err)
	}

	if err := d.deleteServiceAccountKey(ctx, iamToken, projectID, saEmail, oldKeyID); err != nil {
		return fmt.Errorf("failed to delete old SA key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old SA key",
			logger.String("old_key_id", truncateID(oldKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Token Acquisition
// ============================================================================

// getSourceToken returns a cached or freshly acquired token for the given scopes.
// Thread-safe.
func (d *GCPDriver) getSourceToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	scopeKey := strings.Join(scopes, ",")

	// Check cache (with 60s refresh buffer)
	if token, expiry, ok := d.tokenCache.Get(scopeKey, 60*time.Second); ok {
		return token, expiry, nil
	}

	// Acquire fresh token
	token, expiry, err := d.acquireToken(ctx, scopes)
	if err != nil {
		return "", time.Time{}, err
	}

	// Cache it
	d.tokenCache.Set(scopeKey, token, expiry)

	return token, expiry, nil
}

// acquireToken gets a fresh OAuth2 token using the SA key.
func (d *GCPDriver) acquireToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return "", time.Time{}, fmt.Errorf("service_account_key is empty")
	}

	creds, err := google.CredentialsFromJSON(ctx, []byte(saKeyJSON), scopes...)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create GCP credentials: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to acquire GCP token: %w", err)
	}

	return token.AccessToken, token.Expiry, nil
}

// ============================================================================
// IAM API Helpers (raw HTTP, no google-api-go-client dependency)
// ============================================================================

// gcpAPIRequest describes an HTTP request to a GCP API endpoint
type gcpAPIRequest struct {
	method      string
	url         string
	body        []byte
	contentType string
	bearerToken string
	okStatuses  []int
	operation   string
}

// doGCPRequest executes an HTTP request to a GCP API endpoint
func (d *GCPDriver) doGCPRequest(ctx context.Context, apiReq gcpAPIRequest, maxAttempts int) ([]byte, error) {
	// Prepare headers
	headers := make(map[string]string)
	if apiReq.contentType != "" {
		headers["Content-Type"] = apiReq.contentType
	}
	if apiReq.bearerToken != "" {
		headers["Authorization"] = "Bearer " + apiReq.bearerToken
	}

	// Configure retry behavior (no automatic retries by default)
	retryConfig := HTTPRetryConfig{
		MaxAttempts:       maxAttempts,
		MaxBodySize:       gcpMaxResponseBodySize,
		RetryableStatuses: []int{}, // GCP doesn't retry by default
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:     apiReq.method,
		URL:        apiReq.url,
		Body:       apiReq.body,
		Headers:    headers,
		OKStatuses: apiReq.okStatuses,
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", apiReq.operation, err)
	}
	return respBody, nil
}

// createServiceAccountKey creates a new key for the given service account
func (d *GCPDriver) createServiceAccountKey(ctx context.Context, iamToken, saEmail, projectID string) (string, error) {
	apiURL := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys",
		url.PathEscape(projectID), url.PathEscape(saEmail))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	})

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "POST",
		url:         apiURL,
		body:        reqBody,
		contentType: "application/json",
		bearerToken: iamToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "createServiceAccountKey",
	}, 1)
	if err != nil {
		return "", fmt.Errorf("failed to create SA key: %w", err)
	}

	// Response contains the key in base64-encoded privateKeyData
	var keyResp struct {
		PrivateKeyData string `json:"privateKeyData"` // base64-encoded JSON key
	}
	if err := json.Unmarshal(respBody, &keyResp); err != nil {
		return "", fmt.Errorf("failed to decode create key response: %w", err)
	}

	// Decode base64 to get the actual JSON key file content
	import_encoding := keyResp.PrivateKeyData
	if import_encoding == "" {
		return "", fmt.Errorf("create key response missing privateKeyData")
	}

	// The privateKeyData is base64-encoded; decode it
	keyJSON, err := base64Decode(import_encoding)
	if err != nil {
		return "", fmt.Errorf("failed to decode privateKeyData: %w", err)
	}

	// Validate the new key is valid JSON
	var newKey serviceAccountKey
	if err := json.Unmarshal(keyJSON, &newKey); err != nil {
		return "", fmt.Errorf("new SA key is not valid JSON: %w", err)
	}

	return string(keyJSON), nil
}

// deleteServiceAccountKey deletes a specific key from a service account
func (d *GCPDriver) deleteServiceAccountKey(ctx context.Context, iamToken, projectID, saEmail, keyID string) error {
	apiURL := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys/%s",
		url.PathEscape(projectID), url.PathEscape(saEmail), url.PathEscape(keyID))

	_, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "DELETE",
		url:         apiURL,
		bearerToken: iamToken,
		okStatuses:  []int{http.StatusOK, http.StatusNoContent},
		operation:   "deleteServiceAccountKey",
	}, 1)
	return err
}

// ============================================================================
// Helpers
// ============================================================================

// splitScopes splits a comma-separated scopes string into a slice
func splitScopes(scopesStr string) []string {
	scopes := strings.Split(scopesStr, ",")
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}
	return scopes
}

// base64Decode decodes a standard base64-encoded string
func base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
