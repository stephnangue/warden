package drivers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// githubMaxResponseBodySize limits response body reads to prevent OOM
const githubMaxResponseBodySize = 1 << 20 // 1MB

// githubMaxRetryAttempts for retryable API operations
const githubMaxRetryAttempts = 3

// Compile-time interface assertions
// Note: GitHubDriver does not implement credential.Rotatable.
// App mode tokens are ephemeral (1h TTL), and GitHub has no API to rotate PATs.
var _ credential.SourceDriver = (*GitHubDriver)(nil)
var _ credential.SpecVerifier = (*GitHubDriver)(nil)

// appTokenCache holds a cached GitHub App installation token for a specific spec
type appTokenCache struct {
	token     string
	expiresAt time.Time
}

// GitHubDriver mints credentials from GitHub.
//
// The source config holds only connection info (github_url). Auth credentials
// (PAT token, App private key, app_id, installation_id) live in the credential
// spec config and are read at MintCredential time. This allows multiple specs
// with different PATs or App installations to share one source.
//
// Two auth modes are supported (configured per-spec via auth_method):
//   - App mode (auth_method=app): Uses a GitHub App private key to mint
//     short-lived installation access tokens (1h TTL)
//   - PAT mode (auth_method=pat): Uses a static Personal Access Token
type GitHubDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// Per-spec App installation token cache (keyed by spec name)
	appTokens  map[string]*appTokenCache
	appTokenMu sync.Mutex
}

// GitHubDriverFactory creates GitHubDriver instances
type GitHubDriverFactory struct{}

// Type returns the driver type
func (f *GitHubDriverFactory) Type() string {
	return credential.SourceTypeGitHub
}

// ValidateConfig validates GitHub source configuration using declarative schema.
// The source only holds connection info (github_url). Auth credentials are
// validated at spec level by GitHubTokenCredType.ValidateConfig.
func (f *GitHubDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("github_url").
			Custom(validateGitHubURL).
			Describe("GitHub API URL (use default for github.com, or specify GitHub Enterprise URL)").
			Example("https://api.github.com"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *GitHubDriverFactory) SensitiveConfigFields() []string {
	return nil
}

// Create instantiates a new GitHubDriver.
// The driver only needs the github_url from source config. Auth credentials
// are provided per-spec at MintCredential time.
func (f *GitHubDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeGitHub),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		appTokens:  make(map[string]*appTokenCache),
	}
	return driver, nil
}

// getGitHubURL returns the GitHub API base URL from source config
func (d *GitHubDriver) getGitHubURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "github_url", "https://api.github.com"), "/")
}

// MintCredential returns a GitHub token for the given spec.
// Auth credentials are read from spec.Config, not from the source.
func (d *GitHubDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	authMethod := credential.GetString(spec.Config, "auth_method", "app")
	switch authMethod {
	case "app":
		return d.mintAppCredential(ctx, spec)
	case "pat":
		return d.mintPATCredential(spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported auth_method '%s'", authMethod)
	}
}

// mintAppCredential mints a GitHub App installation access token using spec config
func (d *GitHubDriver) mintAppCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	d.appTokenMu.Lock()
	defer d.appTokenMu.Unlock()

	// Return cached token if still valid (with 5min buffer)
	if cached, ok := d.appTokens[spec.Name]; ok && time.Now().Add(5*time.Minute).Before(cached.expiresAt) {
		rawData := map[string]interface{}{
			"token":      cached.token,
			"expires_at": cached.expiresAt.Format(time.RFC3339),
		}
		ttl := time.Until(cached.expiresAt)
		return rawData, ttl, "", nil
	}

	// Parse private key from spec config
	keyPEM := credential.GetString(spec.Config, "private_key", "")
	key, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse private key from spec: %w", err)
	}

	appID := credential.GetString(spec.Config, "app_id", "")
	installationID := credential.GetString(spec.Config, "installation_id", "")

	// Mint a fresh installation token
	token, expiresAt, err := d.mintInstallationToken(ctx, key, appID, installationID)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to mint installation token: %w", err)
	}

	// Cache per spec
	d.appTokens[spec.Name] = &appTokenCache{
		token:     token,
		expiresAt: expiresAt,
	}

	ttl := time.Until(expiresAt)
	rawData := map[string]interface{}{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
	}

	if d.logger != nil {
		d.logger.Debug("minted GitHub App installation token",
			logger.String("spec", spec.Name),
			logger.String("installation_id", installationID),
			logger.String("ttl", ttl.String()),
		)
	}

	return rawData, ttl, "", nil
}

// mintPATCredential returns the PAT from spec config as a credential
func (d *GitHubDriver) mintPATCredential(spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	token := credential.GetString(spec.Config, "token", "")
	if token == "" {
		return nil, 0, "", fmt.Errorf("no GitHub PAT configured in spec")
	}

	rawData := map[string]interface{}{
		"token": token,
	}

	// PATs are static - no TTL, no lease
	return rawData, 0, "", nil
}

// mintInstallationToken creates a new installation access token via the GitHub API
func (d *GitHubDriver) mintInstallationToken(ctx context.Context, key *rsa.PrivateKey, appID, installationID string) (string, time.Time, error) {
	// Generate JWT for GitHub App authentication
	jwt, err := generateAppJWT(key, appID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate JWT: %w", err)
	}

	// POST /app/installations/{installation_id}/access_tokens
	path := fmt.Sprintf("/app/installations/%s/access_tokens", url.PathEscape(installationID))

	apiURL := d.getGitHubURL() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("installation token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, githubMaxResponseBodySize))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("GitHub API returned empty token")
	}

	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		// Default to 1 hour if parsing fails
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	return result.Token, expiresAt, nil
}

// Revoke revokes an installation access token
func (d *GitHubDriver) Revoke(ctx context.Context, leaseID string) error {
	// Installation tokens can be revoked, but we don't track lease IDs for them
	// since they are short-lived (1h). This is a no-op.
	if d.logger != nil {
		d.logger.Debug("GitHub tokens expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *GitHubDriver) Type() string {
	return credential.SourceTypeGitHub
}

// Cleanup releases resources
func (d *GitHubDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates spec credentials by making a lightweight API call.
// For App mode, MintCredential already calls the GitHub API (covered by the
// trial mint in ValidateSpec). For PAT mode, we verify with GET /user.
func (d *GitHubDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	authMethod := credential.GetString(spec.Config, "auth_method", "app")
	if authMethod != "pat" {
		// App mode is verified by the trial MintCredential in ValidateSpec
		return nil
	}

	token := credential.GetString(spec.Config, "token", "")
	if token == "" {
		return fmt.Errorf("no GitHub PAT configured in spec")
	}

	if _, err := d.doGitHubRequest(ctx, http.MethodGet, "/user", nil, token); err != nil {
		return fmt.Errorf("GitHub PAT verification failed: %w", err)
	}

	return nil
}

// --- HTTP helpers ---

// doGitHubRequest executes an authenticated HTTP request to the GitHub API.
func (d *GitHubDriver) doGitHubRequest(ctx context.Context, method, path string, body []byte, authToken string) ([]byte, error) {
	apiURL := d.getGitHubURL() + path

	// Prepare headers
	headers := map[string]string{
		"Accept":        "application/vnd.github+json",
		"Authorization": "token " + authToken,
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	// Configure retry behavior (retry on 429 and 5xx)
	retryConfig := HTTPRetryConfig{
		MaxAttempts:       githubMaxRetryAttempts,
		MaxBodySize:       githubMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500}, // 429 and all 5xx
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
		d.logger.Warn("GitHub API request failed", logger.String("error", err.Error()))
	}
	return respBody, err
}

// --- JWT generation ---

// generateAppJWT creates a signed JWT for GitHub App authentication.
// The JWT is used to authenticate as the App and request installation tokens.
// Format: RS256, iss=app_id, iat=now-60, exp=now+600 (10min max per GitHub docs)
func generateAppJWT(key *rsa.PrivateKey, appID string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key not configured")
	}

	now := time.Now()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	payload := map[string]interface{}{
		"iss": appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	// Sign with RS256
	h := rsaSHA256Hash()
	h.Write([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, key, rsaSHA256HashType(), h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// --- Helper functions ---

// parseRSAPrivateKey parses a PEM-encoded RSA private key
func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}

	// Try PKCS1 first, then PKCS8
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return rsaKey, nil
}

// ValidatePEMBlock checks that a PEM string contains a valid PEM block.
// This is a lightweight check for spec-level validation without full RSA parsing.
func ValidatePEMBlock(pemData string) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return fmt.Errorf("no PEM block found in private key")
	}
	return nil
}

// validateGitHubURL validates that the github_url is a well-formed HTTPS URL
func validateGitHubURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid github_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("github_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("github_url must include a host")
	}
	return nil
}

// rsaSHA256Hash returns a new SHA-256 hasher for RS256 JWT signing
func rsaSHA256Hash() hash.Hash {
	return crypto.SHA256.New()
}

// rsaSHA256HashType returns the crypto.Hash for RS256
func rsaSHA256HashType() crypto.Hash {
	return crypto.SHA256
}
