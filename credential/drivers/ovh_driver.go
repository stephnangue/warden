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

const ovhMaxResponseBodySize = 1 << 20 // 1MB
const ovhMaxRetryAttempts = 3

// ovhEndpoint holds the resolved API and OAuth2 token URLs for a region.
type ovhEndpoint struct {
	apiURL   string
	tokenURL string
}

// ovhEndpoints maps endpoint names to their API and token URLs.
var ovhEndpoints = map[string]ovhEndpoint{
	"ovh-eu": {apiURL: "https://eu.api.ovh.com/1.0", tokenURL: "https://www.ovh.com/auth/oauth2/token"},
	"ovh-ca": {apiURL: "https://ca.api.ovh.com/1.0", tokenURL: "https://ca.ovh.com/auth/oauth2/token"},
	"ovh-us": {apiURL: "https://api.us.ovhcloud.com/1.0", tokenURL: "https://us.ovhcloud.com/auth/oauth2/token"},
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*OVHDriver)(nil)
var _ credential.SpecVerifier = (*OVHDriver)(nil)

// OVHDriver mints credentials from OVHcloud APIs.
//
// Two mint methods are supported (configured per-spec via mint_method):
//   - oauth2_token: Mints a bearer token via OAuth2 client_credentials grant (~1h TTL)
//   - dynamic_s3: Creates S3 credentials via the OVH cloud API (static, revocable)
//   - oauth2_token_and_s3: Mints both a bearer token and S3 credentials
//
// The source config holds an OAuth2 service account (client_id + client_secret)
// and optionally default project_id + user_id for S3 credential management.
type OVHDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
	apiURL     string // resolved API base URL
	tokenURL   string // resolved OAuth2 token URL

	// configMu protects credSource.Config reads during potential future rotation.
	configMu sync.RWMutex
}

// OVHDriverFactory creates OVHDriver instances.
type OVHDriverFactory struct{}

// Type returns the driver type identifier.
func (f *OVHDriverFactory) Type() string {
	return credential.SourceTypeOVH
}

// ValidateConfig validates OVH source configuration.
func (f *OVHDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("client_id").
			Required().
			Describe("OAuth2 service account client ID").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("client_secret").
			Required().
			Describe("OAuth2 service account client secret").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("ovh_endpoint").
			OneOf("ovh-eu", "ovh-ca", "ovh-us").
			Describe("OVH regional endpoint (default: ovh-eu)").
			Example("ovh-eu"),

		credential.StringField("project_id").
			Describe("Default Public Cloud project ID for S3 credential management").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("user_id").
			Describe("Default Public Cloud user ID for S3 credential management").
			Example("12345"),

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
func (f *OVHDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "ca_data"}
}

// InferCredentialType always returns ovh_keys for OVH sources.
func (f *OVHDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeOVHKeys, nil
}

// Create instantiates a new OVHDriver.
func (f *OVHDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	endpointName := credential.GetString(config, "ovh_endpoint", "ovh-eu")
	ep, ok := ovhEndpoints[endpointName]
	if !ok {
		return nil, fmt.Errorf("unknown ovh_endpoint: %s (expected ovh-eu, ovh-ca, or ovh-us)", endpointName)
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	driver := &OVHDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOVH,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeOVH),
		httpClient: httpClient,
		apiURL:     ep.apiURL,
		tokenURL:   ep.tokenURL,
	}

	return driver, nil
}

// Type returns the driver type.
func (d *OVHDriver) Type() string {
	return credential.SourceTypeOVH
}

// MintCredential returns OVH credentials for the given spec.
func (d *OVHDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "oauth2_token":
		return d.mintOAuth2Token(ctx)
	case "dynamic_s3":
		return d.mintDynamicS3(ctx, spec)
	case "oauth2_token_and_s3":
		return d.mintOAuth2TokenAndS3(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method: %s (expected oauth2_token, dynamic_s3, or oauth2_token_and_s3)", mintMethod)
	}
}

// getClientCredentials reads client_id and client_secret from source config under RLock.
func (d *OVHDriver) getClientCredentials() (clientID, clientSecret string) {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	clientID = credential.GetString(d.credSource.Config, "client_id", "")
	clientSecret = credential.GetString(d.credSource.Config, "client_secret", "")
	return
}

// resolveProjectAndUser resolves project_id and user_id from spec config, falling back to source config.
func (d *OVHDriver) resolveProjectAndUser(spec *credential.CredSpec) (projectID, userID string, err error) {
	projectID = credential.GetString(spec.Config, "project_id", "")
	if projectID == "" {
		d.configMu.RLock()
		projectID = credential.GetString(d.credSource.Config, "project_id", "")
		d.configMu.RUnlock()
	}
	if projectID == "" {
		return "", "", fmt.Errorf("project_id is required for S3 credential management (set on source or spec)")
	}

	userID = credential.GetString(spec.Config, "user_id", "")
	if userID == "" {
		d.configMu.RLock()
		userID = credential.GetString(d.credSource.Config, "user_id", "")
		d.configMu.RUnlock()
	}
	if userID == "" {
		return "", "", fmt.Errorf("user_id is required for S3 credential management (set on source or spec)")
	}

	return projectID, userID, nil
}

// fetchOAuth2Token performs the OAuth2 client_credentials exchange and returns the access token and TTL.
func (d *OVHDriver) fetchOAuth2Token(ctx context.Context) (accessToken string, ttl time.Duration, err error) {
	clientID, clientSecret := d.getClientCredentials()
	if clientID == "" || clientSecret == "" {
		return "", 0, fmt.Errorf("client_id and client_secret are required on source config")
	}

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       ovhMaxRetryAttempts,
		MaxBodySize:       ovhMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500, 503},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodPost,
		URL:    d.tokenURL,
		Body:   []byte(formData.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return "", 0, fmt.Errorf("OAuth2 token request failed: %w", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to parse OAuth2 token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("OVH OAuth2 response returned empty access_token")
	}

	tokenTTL := time.Duration(tokenResp.ExpiresIn) * time.Second
	if tokenTTL <= 0 {
		tokenTTL = 1 * time.Hour // fallback if expires_in is missing
	}

	return tokenResp.AccessToken, tokenTTL, nil
}

// mintOAuth2Token mints a bearer token via the OAuth2 client_credentials grant.
func (d *OVHDriver) mintOAuth2Token(ctx context.Context) (map[string]interface{}, time.Duration, string, error) {
	token, ttl, err := d.fetchOAuth2Token(ctx)
	if err != nil {
		return nil, 0, "", err
	}

	d.logger.Info("minted OVH OAuth2 bearer token",
		logger.String("ttl", ttl.String()),
	)

	rawData := map[string]interface{}{
		"api_token": token,
	}

	return rawData, ttl, "", nil // No leaseID — token expires naturally
}

// s3CredentialResult holds the result of an S3 credential creation call.
type s3CredentialResult struct {
	accessKey string
	secretKey string
	leaseID   string // projectId/userId/accessKeyId — used for revocation
}

// createS3Credentials creates S3 credentials via the OVH cloud API.
// The token must be a valid OAuth2 bearer token for API auth.
func (d *OVHDriver) createS3Credentials(ctx context.Context, token, projectID, userID string) (*s3CredentialResult, error) {
	apiURL := fmt.Sprintf("%s/cloud/project/%s/user/%s/s3Credentials", d.apiURL, projectID, userID)

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       ovhMaxRetryAttempts,
		MaxBodySize:       ovhMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500, 503},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodPost,
		URL:    apiURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVH S3 credentials: %w", err)
	}

	var s3Resp struct {
		Access string `json:"access"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(respBody, &s3Resp); err != nil {
		return nil, fmt.Errorf("failed to parse S3 credentials response: %w", err)
	}

	if s3Resp.Access == "" || s3Resp.Secret == "" {
		return nil, fmt.Errorf("OVH API returned empty S3 access or secret key")
	}

	return &s3CredentialResult{
		accessKey: s3Resp.Access,
		secretKey: s3Resp.Secret,
		leaseID:   fmt.Sprintf("%s/%s/%s", projectID, userID, s3Resp.Access),
	}, nil
}

// mintDynamicS3 creates S3 credentials via the OVH cloud API.
func (d *OVHDriver) mintDynamicS3(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	token, _, err := d.fetchOAuth2Token(ctx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to get OAuth2 token for S3 credential creation: %w", err)
	}

	projectID, userID, err := d.resolveProjectAndUser(spec)
	if err != nil {
		return nil, 0, "", err
	}

	s3, err := d.createS3Credentials(ctx, token, projectID, userID)
	if err != nil {
		return nil, 0, "", err
	}

	d.logger.Info("created dynamic OVH S3 credentials",
		logger.String("access_key", truncateID(s3.accessKey, 8)),
		logger.String("spec", spec.Name),
	)

	rawData := map[string]interface{}{
		"access_key": s3.accessKey,
		"secret_key": s3.secretKey,
	}

	return rawData, 0, s3.leaseID, nil // Static S3 keys — no TTL, but revocable via leaseID
}

// mintOAuth2TokenAndS3 mints both a bearer token and S3 credentials.
func (d *OVHDriver) mintOAuth2TokenAndS3(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	token, tokenTTL, err := d.fetchOAuth2Token(ctx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to mint OAuth2 token for dual-mode credential: %w", err)
	}

	projectID, userID, err := d.resolveProjectAndUser(spec)
	if err != nil {
		return nil, 0, "", err
	}

	s3, err := d.createS3Credentials(ctx, token, projectID, userID)
	if err != nil {
		return nil, 0, "", err
	}

	d.logger.Info("minted OVH dual-mode credentials (OAuth2 token + S3)",
		logger.String("access_key", truncateID(s3.accessKey, 8)),
		logger.String("token_ttl", tokenTTL.String()),
		logger.String("spec", spec.Name),
	)

	rawData := map[string]interface{}{
		"api_token":  token,
		"access_key": s3.accessKey,
		"secret_key": s3.secretKey,
	}

	// TTL = token TTL (shorter-lived governs refresh; S3 keys are revoked on refresh)
	return rawData, tokenTTL, s3.leaseID, nil
}

// Revoke deletes dynamically created S3 credentials.
// The leaseID format is: projectId/userId/accessKeyId
func (d *OVHDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	parts := strings.SplitN(leaseID, "/", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid OVH lease ID format: %s (expected projectId/userId/accessKeyId)", leaseID)
	}
	projectID, userID, accessKeyID := parts[0], parts[1], parts[2]

	// Mint a fresh token for API auth
	token, _, err := d.fetchOAuth2Token(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OAuth2 token for S3 credential revocation: %w", err)
	}

	apiURL := fmt.Sprintf("%s/cloud/project/%s/user/%s/s3Credentials/%s", d.apiURL, projectID, userID, accessKeyID)

	retryConfig := HTTPRetryConfig{
		MaxAttempts:       ovhMaxRetryAttempts,
		MaxBodySize:       ovhMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500, 503},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method: http.MethodDelete,
		URL:    apiURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
			"Accept":        "application/json",
		},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK, http.StatusNotFound},
	}

	_, _, err = ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return fmt.Errorf("failed to revoke OVH S3 credentials %s: %w", accessKeyID, err)
	}

	d.logger.Info("revoked OVH S3 credentials",
		logger.String("access_key", truncateID(accessKeyID, 8)),
	)

	return nil
}

// Cleanup releases resources.
func (d *OVHDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the spec config is valid for the chosen mint method.
func (d *OVHDriver) VerifySpec(_ context.Context, spec *credential.CredSpec) error {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "oauth2_token":
		// No extra config needed — uses source's client_id/secret
		return nil
	case "dynamic_s3", "oauth2_token_and_s3":
		_, _, err := d.resolveProjectAndUser(spec)
		return err
	default:
		return fmt.Errorf("unsupported mint_method: %s (expected oauth2_token, dynamic_s3, or oauth2_token_and_s3)", mintMethod)
	}
}
