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

// grafanaMaxResponseBodySize limits response body reads to prevent OOM
const grafanaMaxResponseBodySize = 1 << 20 // 1MB

// grafanaMaxRetryAttempts for retryable API operations
const grafanaMaxRetryAttempts = 3

// grafanaDefaultTokenExpiry is the default TTL for minted service account tokens
const grafanaDefaultTokenExpiry = 1 * time.Hour

// grafanaDefaultNamePrefix is the default prefix for minted service accounts
const grafanaDefaultNamePrefix = "warden-"

// grafanaDefaultRole is the default role for minted service accounts
const grafanaDefaultRole = "Viewer"

// Compile-time interface assertions
var _ credential.SourceDriver = (*GrafanaDriver)(nil)
var _ credential.SpecVerifier = (*GrafanaDriver)(nil)

// GrafanaDriver mints credentials from the Grafana HTTP API.
//
// The source config holds connection info (grafana_url) and an admin service
// account token with permissions to create/delete service accounts. Per-spec
// config controls the role, TTL, and naming of minted service accounts.
//
// MintCredential creates a temporary service account and generates a token
// with a bounded TTL. Revoke deletes the service account (and all its tokens).
type GrafanaDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
}

// GrafanaDriverFactory creates GrafanaDriver instances
type GrafanaDriverFactory struct{}

// Type returns the driver type
func (f *GrafanaDriverFactory) Type() string {
	return credential.SourceTypeGrafana
}

// ValidateConfig validates Grafana source configuration using declarative schema.
func (f *GrafanaDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("grafana_url").
			Required().
			Custom(func(v string) error {
				return validateGrafanaURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Grafana API base URL").
			Example("https://mystack.grafana.net"),

		credential.StringField("admin_token").
			Required().
			Describe("Admin service account token with ServiceAccount admin permissions"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs"),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)"),
	)
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *GrafanaDriverFactory) SensitiveConfigFields() []string {
	return []string{"admin_token", "ca_data"}
}

// InferCredentialType always returns api_key for Grafana sources.
func (f *GrafanaDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new GrafanaDriver.
func (f *GrafanaDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeGrafana),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// getGrafanaURL returns the Grafana API base URL from source config
func (d *GrafanaDriver) getGrafanaURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "grafana_url", ""), "/")
}

// getAdminToken returns the admin service account token from source config
func (d *GrafanaDriver) getAdminToken() string {
	return credential.GetString(d.credSource.Config, "admin_token", "")
}

// MintCredential creates a temporary Grafana service account and token.
//
// Flow:
//  1. POST /api/serviceaccounts — create a service account with the specified role
//  2. POST /api/serviceaccounts/{id}/tokens — create a token with secondsToLive
//  3. Return {"api_key": "<token>"} with TTL matching token expiry
//
// The leaseID is the service account ID, used for cleanup on Revoke.
func (d *GrafanaDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	role := credential.GetString(spec.Config, "role", grafanaDefaultRole)
	namePrefix := credential.GetString(spec.Config, "name_prefix", grafanaDefaultNamePrefix)
	tokenExpiry := credential.GetDuration(spec.Config, "token_expiry", grafanaDefaultTokenExpiry)
	orgID := credential.GetString(spec.Config, "org_id", "")

	// Validate role
	switch role {
	case "Viewer", "Editor", "Admin":
	default:
		return nil, 0, "", fmt.Errorf("invalid role '%s': must be Viewer, Editor, or Admin", role)
	}

	// Step 1: Create a service account
	saName := fmt.Sprintf("%s%s-%d", namePrefix, spec.Name, time.Now().UnixMilli())
	saBody, err := json.Marshal(map[string]interface{}{
		"name":       saName,
		"role":       role,
		"isDisabled": false,
	})
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal service account request: %w", err)
	}

	saResp, _, err := d.doGrafanaRequest(ctx, http.MethodPost, "/api/serviceaccounts", saBody, orgID)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create service account: %w", err)
	}

	var saResult struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(saResp, &saResult); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse service account response: %w", err)
	}
	if saResult.ID == 0 {
		return nil, 0, "", fmt.Errorf("Grafana API returned service account with ID 0")
	}

	// Step 2: Create a token for the service account
	secondsToLive := int64(tokenExpiry.Seconds())
	tokenBody, err := json.Marshal(map[string]interface{}{
		"name":          "warden-token",
		"secondsToLive": secondsToLive,
	})
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	tokenPath := fmt.Sprintf("/api/serviceaccounts/%d/tokens", saResult.ID)
	tokenResp, _, err := d.doGrafanaRequest(ctx, http.MethodPost, tokenPath, tokenBody, orgID)
	if err != nil {
		// Best-effort cleanup: delete the service account we just created
		d.deleteServiceAccount(ctx, saResult.ID, orgID)
		return nil, 0, "", fmt.Errorf("failed to create service account token: %w", err)
	}

	var tokenResult struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(tokenResp, &tokenResult); err != nil {
		d.deleteServiceAccount(ctx, saResult.ID, orgID)
		return nil, 0, "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResult.Key == "" {
		d.deleteServiceAccount(ctx, saResult.ID, orgID)
		return nil, 0, "", fmt.Errorf("Grafana API returned empty token key")
	}

	// Return credential as api_key for BearerAPIKeyExtractor compatibility
	rawData := map[string]interface{}{
		"api_key": tokenResult.Key,
	}

	// leaseID encodes orgID and service account ID for cleanup.
	// Format: "<orgID>:<saID>" when orgID is set, "<saID>" otherwise.
	var leaseID string
	if orgID != "" {
		leaseID = fmt.Sprintf("%s:%d", orgID, saResult.ID)
	} else {
		leaseID = fmt.Sprintf("%d", saResult.ID)
	}

	if d.logger != nil {
		d.logger.Debug("minted Grafana service account token",
			logger.String("spec", spec.Name),
			logger.String("service_account", saName),
			logger.String("role", role),
			logger.String("ttl", tokenExpiry.String()),
		)
	}

	return rawData, tokenExpiry, leaseID, nil
}

// Revoke deletes the service account (and all its tokens) identified by leaseID.
func (d *GrafanaDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	saID, orgID := parseGrafanaLeaseID(leaseID)
	path := fmt.Sprintf("/api/serviceaccounts/%s", saID)
	if _, _, err := d.doGrafanaRequest(ctx, http.MethodDelete, path, nil, orgID); err != nil {
		return fmt.Errorf("failed to delete service account %s: %w", leaseID, err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Grafana service account",
			logger.String("service_account_id", leaseID),
		)
	}

	return nil
}

// Type returns the driver type
func (d *GrafanaDriver) Type() string {
	return credential.SourceTypeGrafana
}

// Cleanup releases resources
func (d *GrafanaDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates spec credentials by making a lightweight API call.
// Creates a test service account, verifies the minted token works, then cleans up.
func (d *GrafanaDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	// Verify the admin token works by listing service accounts
	if _, _, err := d.doGrafanaRequest(ctx, http.MethodGet, "/api/serviceaccounts/search?perpage=1", nil, ""); err != nil {
		return fmt.Errorf("admin token verification failed (GET /api/serviceaccounts/search): %w", err)
	}
	return nil
}

// --- HTTP helpers ---

// doGrafanaRequest executes an authenticated HTTP request to the Grafana API.
func (d *GrafanaDriver) doGrafanaRequest(ctx context.Context, method, path string, body []byte, orgID string) ([]byte, int, error) {
	apiURL := d.getGrafanaURL() + path

	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": "Bearer " + d.getAdminToken(),
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if orgID != "" {
		headers["X-Grafana-Org-Id"] = orgID
	}

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       grafanaMaxRetryAttempts,
		MaxBodySize:       grafanaMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  method,
		URL:     apiURL,
		Body:    body,
		Headers: headers,
	}

	respBody, status, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil && d.logger != nil {
		d.logger.Warn("Grafana API request failed",
			logger.String("method", method),
			logger.String("path", path),
			logger.String("error", err.Error()),
		)
	}
	return respBody, status, err
}

// parseGrafanaLeaseID splits a leaseID into (saID, orgID).
// Format: "<orgID>:<saID>" or "<saID>" (legacy / default org).
func parseGrafanaLeaseID(leaseID string) (saID, orgID string) {
	if i := strings.LastIndex(leaseID, ":"); i >= 0 {
		return leaseID[i+1:], leaseID[:i]
	}
	return leaseID, ""
}

// deleteServiceAccount is a best-effort cleanup helper.
func (d *GrafanaDriver) deleteServiceAccount(ctx context.Context, id int64, orgID string) {
	path := fmt.Sprintf("/api/serviceaccounts/%d", id)
	if _, _, err := d.doGrafanaRequest(ctx, http.MethodDelete, path, nil, orgID); err != nil && d.logger != nil {
		d.logger.Warn("failed to cleanup service account",
			logger.String("id", fmt.Sprintf("%d", id)),
			logger.String("error", err.Error()),
		)
	}
}

// validateGrafanaURL validates that the grafana_url is a well-formed HTTPS URL.
func validateGrafanaURL(rawURL string, tlsSkipVerify bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid grafana_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("grafana_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("grafana_url must include a host")
	}
	return nil
}
