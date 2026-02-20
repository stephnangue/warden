package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)


// gitlabMaxResponseBodySize limits response body reads to prevent OOM
const gitlabMaxResponseBodySize = 1 << 20 // 1MB

// gitlabMaxRetryAttempts for retryable API operations
const gitlabMaxRetryAttempts = 3

// Compile-time interface assertions
var _ credential.SourceDriver = (*GitLabDriver)(nil)
var _ credential.Rotatable = (*GitLabDriver)(nil)

// GitLabDriver mints credentials from GitLab (project and group access tokens).
//
// The driver's source credentials authenticate API calls for token minting/revocation.
// Two auth modes are supported:
//   - PAT mode (auth_method=pat): Uses a Personal Access Token
//   - OAuth2 mode (auth_method=oauth2): Uses OAuth2 client credentials flow
type GitLabDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// OAuth2 token cache (only used in oauth2 mode)
	tokenCache *TokenCache

	// HTTP client for GitLab API calls
	httpClient *http.Client

	// Mutex for protecting config updates during rotation
	configMu sync.Mutex
}

// GitLabDriverFactory creates GitLabDriver instances
type GitLabDriverFactory struct{}

// Type returns the driver type
func (f *GitLabDriverFactory) Type() string {
	return credential.SourceTypeGitLab
}

// ValidateConfig validates GitLab driver configuration using declarative schema
func (f *GitLabDriverFactory) ValidateConfig(config map[string]string) error {
	// Validate gitlab_address with custom URL validation
	if err := credential.ValidateSchema(config,
		credential.StringField("gitlab_address").
			Required().
			Custom(func(value string) error {
				parsed, err := url.Parse(value)
				if err != nil {
					return fmt.Errorf("invalid URL: %w", err)
				}
				if parsed.Scheme != "https" && parsed.Scheme != "http" {
					return fmt.Errorf("must use http:// or https:// scheme, got: %s", parsed.Scheme)
				}
				if parsed.Host == "" {
					return fmt.Errorf("must include a host")
				}
				return nil
			}).
			Describe("GitLab server address").
			Example("https://gitlab.example.com"),
	); err != nil {
		return err
	}

	// Validate auth_method and conditional fields
	authMethod := credential.GetString(config, "auth_method", "pat")
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			OneOf("pat", "oauth2").
			Describe("Authentication method").
			Example("pat"),
	); err != nil {
		return err
	}

	// Validate auth-method-specific fields
	switch authMethod {
	case "pat":
		return credential.ValidateSchema(config,
			credential.StringField("personal_access_token").
				Required().
				Describe("GitLab personal access token").
				Example("glpat-xxxxx"),
		)
	case "oauth2":
		return credential.ValidateSchema(config,
			credential.StringField("application_id").
				Required().
				Describe("GitLab OAuth2 application ID").
				Example("app-id"),

			credential.StringField("application_secret").
				Required().
				Describe("GitLab OAuth2 application secret").
				Example("app-secret"),
		)
	}

	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *GitLabDriverFactory) SensitiveConfigFields() []string {
	return []string{"personal_access_token", "application_secret"}
}

// Create instantiates a new GitLabDriver
func (f *GitLabDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitLab,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeGitLab),
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Verify credentials by calling the API
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := driver.verifyAuth(ctx); err != nil {
		return nil, fmt.Errorf("GitLab authentication failed: %w", err)
	}

	return driver, nil
}

// Config accessors

func (d *GitLabDriver) getGitLabAddress() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "gitlab_address", ""), "/")
}

func (d *GitLabDriver) getAuthMethod() string {
	return credential.GetString(d.credSource.Config, "auth_method", "pat")
}

func (d *GitLabDriver) getPAT() string {
	return credential.GetString(d.credSource.Config, "personal_access_token", "")
}

// verifyAuth validates the source credentials by calling a simple GitLab API endpoint
func (d *GitLabDriver) verifyAuth(ctx context.Context) error {
	_, err := d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		// For OAuth2 mode, try a different endpoint
		if d.getAuthMethod() == "oauth2" {
			_, err = d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/user", nil)
		}
	}
	return err
}

// MintCredential mints credentials based on the spec's mint_method
func (d *GitLabDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "project_access_token":
		return d.mintProjectAccessToken(ctx, spec)
	case "group_access_token":
		return d.mintGroupAccessToken(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for GitLab driver; use 'project_access_token' or 'group_access_token'", mintMethod)
	}
}

// mintProjectAccessToken creates a project access token via the GitLab API
func (d *GitLabDriver) mintProjectAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	projectID := credential.GetString(spec.Config, "project_id", "")
	tokenName := credential.GetString(spec.Config, "token_name", "warden-minted")
	scopes := credential.GetString(spec.Config, "scopes", "api")
	accessLevel := credential.GetInt(spec.Config, "access_level", 30) // 30 = developer

	// Calculate expiry: default 1 day, max 365 days
	ttlStr := credential.GetString(spec.Config, "ttl", "24h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		ttl = 24 * time.Hour
	}
	expiresAt := time.Now().Add(ttl).Format("2006-01-02")

	body := map[string]interface{}{
		"name":         tokenName,
		"scopes":       strings.Split(scopes, ","),
		"access_level": accessLevel,
		"expires_at":   expiresAt,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	path := fmt.Sprintf("/api/v4/projects/%s/access_tokens", url.PathEscape(projectID))
	respBody, err := d.doGitLabRequest(ctx, http.MethodPost, path, bodyBytes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create project access token: %w", err)
	}

	var result struct {
		ID    int    `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Token == "" {
		return nil, 0, "", fmt.Errorf("GitLab API returned empty token")
	}

	tokenIDStr := strconv.Itoa(result.ID)
	leaseID := fmt.Sprintf("project_access_token:%s:%s", projectID, tokenIDStr)

	rawData := map[string]interface{}{
		"access_token": result.Token,
		"token_id":     tokenIDStr,
		"expires_at":   expiresAt,
		"scopes":       scopes,
	}

	if d.logger != nil {
		d.logger.Debug("minted GitLab project access token",
			logger.String("spec", spec.Name),
			logger.String("project_id", projectID),
			logger.String("token_id", tokenIDStr),
		)
	}

	return rawData, ttl, leaseID, nil
}

// mintGroupAccessToken creates a group access token via the GitLab API
func (d *GitLabDriver) mintGroupAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	groupID := credential.GetString(spec.Config, "group_id", "")
	tokenName := credential.GetString(spec.Config, "token_name", "warden-minted")
	scopes := credential.GetString(spec.Config, "scopes", "api")
	accessLevel := credential.GetInt(spec.Config, "access_level", 30)

	ttlStr := credential.GetString(spec.Config, "ttl", "24h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		ttl = 24 * time.Hour
	}
	expiresAt := time.Now().Add(ttl).Format("2006-01-02")

	body := map[string]interface{}{
		"name":         tokenName,
		"scopes":       strings.Split(scopes, ","),
		"access_level": accessLevel,
		"expires_at":   expiresAt,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	path := fmt.Sprintf("/api/v4/groups/%s/access_tokens", url.PathEscape(groupID))
	respBody, err := d.doGitLabRequest(ctx, http.MethodPost, path, bodyBytes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create group access token: %w", err)
	}

	var result struct {
		ID    int    `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Token == "" {
		return nil, 0, "", fmt.Errorf("GitLab API returned empty token")
	}

	tokenIDStr := strconv.Itoa(result.ID)
	leaseID := fmt.Sprintf("group_access_token:%s:%s", groupID, tokenIDStr)

	rawData := map[string]interface{}{
		"access_token": result.Token,
		"token_id":     tokenIDStr,
		"expires_at":   expiresAt,
		"scopes":       scopes,
	}

	if d.logger != nil {
		d.logger.Debug("minted GitLab group access token",
			logger.String("spec", spec.Name),
			logger.String("group_id", groupID),
			logger.String("token_id", tokenIDStr),
		)
	}

	return rawData, ttl, leaseID, nil
}

// Revoke revokes a previously minted access token
func (d *GitLabDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	// Parse leaseID format: "project_access_token:{pid}:{tid}" or "group_access_token:{gid}:{tid}"
	parts := strings.SplitN(leaseID, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid lease ID format: %s", leaseID)
	}

	tokenType := parts[0]
	resourceID := parts[1]
	tokenID := parts[2]

	var path string
	switch tokenType {
	case "project_access_token":
		path = fmt.Sprintf("/api/v4/projects/%s/access_tokens/%s", url.PathEscape(resourceID), url.PathEscape(tokenID))
	case "group_access_token":
		path = fmt.Sprintf("/api/v4/groups/%s/access_tokens/%s", url.PathEscape(resourceID), url.PathEscape(tokenID))
	default:
		return fmt.Errorf("unknown token type in lease ID: %s", tokenType)
	}

	_, err := d.doGitLabRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke %s: %w", tokenType, err)
	}

	if d.logger != nil {
		d.logger.Info("revoked GitLab access token",
			logger.String("token_type", tokenType),
			logger.String("resource_id", resourceID),
			logger.String("token_id", tokenID),
		)
	}

	return nil
}

// Type returns the driver type
func (d *GitLabDriver) Type() string {
	return credential.SourceTypeGitLab
}

// Cleanup releases resources
func (d *GitLabDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// --- Rotatable interface ---

// SupportsRotation returns true if the driver's source credentials can be rotated.
// PAT mode supports rotation via the PAT rotate API.
// OAuth2 mode supports rotation via the application secret rotation API.
func (d *GitLabDriver) SupportsRotation() bool {
	return d.getAuthMethod() == "pat" || d.getAuthMethod() == "oauth2"
}

// PrepareRotation generates new source credentials via GitLab's atomic rotate APIs.
// GitLab's rotate endpoints immediately invalidate the old credentials, so we use
// activateAfter=0 (fast path) to commit the new credentials inline without delay.
func (d *GitLabDriver) PrepareRotation(ctx context.Context) (newConfig, cleanupConfig map[string]string, activateAfter time.Duration, err error) {
	switch d.getAuthMethod() {
	case "pat":
		return d.preparePATRotation(ctx)
	case "oauth2":
		return d.prepareOAuth2Rotation(ctx)
	default:
		return nil, nil, 0, fmt.Errorf("rotation not supported for auth_method '%s'", d.getAuthMethod())
	}
}

// preparePATRotation rotates a Personal Access Token via the GitLab API.
// POST /api/v4/personal_access_tokens/{id}/rotate atomically creates a new token
// and revokes the old one. Returns activateAfter=0 since the new token is
// immediately valid and the old one is already revoked.
func (d *GitLabDriver) preparePATRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	// First, get the current token's ID
	respBody, err := d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get current PAT info: %w", err)
	}

	var tokenInfo struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(respBody, &tokenInfo); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse PAT info: %w", err)
	}

	// Rotate the PAT
	path := fmt.Sprintf("/api/v4/personal_access_tokens/%d/rotate", tokenInfo.ID)
	respBody, err = d.doGitLabRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to rotate PAT: %w", err)
	}

	var rotateResult struct {
		ID    int    `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &rotateResult); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse rotation response: %w", err)
	}

	if rotateResult.Token == "" {
		return nil, nil, 0, fmt.Errorf("GitLab PAT rotation returned empty token")
	}

	// Build new config with the new token
	newConfig := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["personal_access_token"] = rotateResult.Token

	// Eagerly update the driver's config so concurrent MintCredential/Revoke
	// calls immediately use the new token. The old token is already revoked by
	// GitLab's rotate endpoint, so any call using it would fail.
	d.configMu.Lock()
	d.credSource.Config = newConfig
	d.configMu.Unlock()

	cleanupConfig := map[string]string{
		"old_token_id": strconv.Itoa(tokenInfo.ID),
	}

	if d.logger != nil {
		d.logger.Info("prepared PAT rotation",
			logger.Int("old_token_id", tokenInfo.ID),
			logger.Int("new_token_id", rotateResult.ID),
		)
	}

	return newConfig, cleanupConfig, 0, nil
}

// prepareOAuth2Rotation rotates the OAuth2 application secret.
// The rotate_secret endpoint atomically replaces the old secret, so
// activateAfter=0 is returned (fast path, no propagation delay needed).
func (d *GitLabDriver) prepareOAuth2Rotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	applicationID := credential.GetString(d.credSource.Config, "application_id", "")

	// Rotate the application secret via admin API
	path := fmt.Sprintf("/api/v4/applications/%s/rotate_secret", url.PathEscape(applicationID))
	respBody, err := d.doGitLabRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to rotate OAuth2 application secret: %w", err)
	}

	var rotateResult struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(respBody, &rotateResult); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse rotation response: %w", err)
	}

	if rotateResult.Secret == "" {
		return nil, nil, 0, fmt.Errorf("GitLab OAuth2 rotation returned empty secret")
	}

	// Build new config
	newConfig := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["application_secret"] = rotateResult.Secret

	// Eagerly update the driver's config and clear OAuth2 token cache so
	// concurrent calls immediately re-authenticate with the new secret.
	// The old secret is already invalidated by GitLab's rotate endpoint.
	d.configMu.Lock()
	d.credSource.Config = newConfig
	d.configMu.Unlock()
	d.tokenCache.InvalidateGeneration()

	cleanupConfig := map[string]string{
		"application_id": applicationID,
	}

	if d.logger != nil {
		d.logger.Info("prepared OAuth2 application secret rotation",
			logger.String("application_id", applicationID),
		)
	}

	return newConfig, cleanupConfig, 0, nil
}

// CommitRotation activates new credentials in the driver's internal state.
func (d *GitLabDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	// Update the config
	d.credSource.Config = newConfig

	// Invalidate OAuth2 token cache to force re-authentication
	d.tokenCache.InvalidateGeneration()

	// Verify new credentials work
	if err := d.verifyAuth(ctx); err != nil {
		return fmt.Errorf("new credentials verification failed: %w", err)
	}

	if d.logger != nil {
		d.logger.Info("committed rotation, new credentials active")
	}

	return nil
}

// CleanupRotation destroys old credentials.
// For PAT rotation, the old token is already revoked by GitLab's rotate endpoint.
// For OAuth2 rotation, the old secret is already invalidated.
func (d *GitLabDriver) CleanupRotation(_ context.Context, cleanupConfig map[string]string) error {
	// Both PAT and OAuth2 rotation in GitLab invalidate old credentials automatically
	if d.logger != nil {
		d.logger.Debug("cleanup rotation: old credentials already invalidated by GitLab")
	}
	return nil
}

// --- HTTP helpers ---

// doGitLabRequest executes an HTTP request to the GitLab API with authentication.
func (d *GitLabDriver) doGitLabRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	apiURL := d.getGitLabAddress() + path

	// Prepare headers
	headers := make(map[string]string)
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	// Set authentication based on auth method
	switch d.getAuthMethod() {
	case "pat":
		headers["PRIVATE-TOKEN"] = d.getPAT()
	case "oauth2":
		token, err := d.getOAuth2Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to set auth: %w", err)
		}
		headers["Authorization"] = "Bearer " + token
	}

	// Configure retry behavior (only retry on rate limiting)
	retryConfig := HTTPRetryConfig{
		MaxAttempts:       gitlabMaxRetryAttempts,
		MaxBodySize:       gitlabMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests}, // 429 only
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := HTTPRequest{
		Method:  method,
		URL:     apiURL,
		Body:    body,
		Headers: headers,
	}

	respBody, _, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil && d.logger != nil {
		d.logger.Warn("GitLab API request failed", logger.String("error", err.Error()))
	}
	return respBody, err
}

// getOAuth2Token returns a cached or fresh OAuth2 access token
func (d *GitLabDriver) getOAuth2Token(ctx context.Context) (string, error) {
	const cacheKey = "oauth2_token"

	// Check cache (with 30s refresh buffer)
	if token, _, ok := d.tokenCache.Get(cacheKey, 30*time.Second); ok {
		return token, nil
	}

	// Acquire new token via client credentials flow
	applicationID := credential.GetString(d.credSource.Config, "application_id", "")
	applicationSecret := credential.GetString(d.credSource.Config, "application_secret", "")

	tokenURL := d.getGitLabAddress() + "/oauth/token"
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {applicationID},
		"client_secret": {applicationSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create OAuth2 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OAuth2 token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, gitlabMaxResponseBodySize))
	if err != nil {
		return "", fmt.Errorf("failed to read OAuth2 token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth2 token request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse OAuth2 token response: %w", err)
	}

	// Cache the token
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	d.tokenCache.Set(cacheKey, tokenResp.AccessToken, expiresAt)

	return tokenResp.AccessToken, nil
}

