package drivers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/stephnangue/warden/helper/httputil"
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
var _ credential.ChainedSecretMinter = (*GitHubDriver)(nil)

// appTokenCache holds a cached GitHub App installation token
type appTokenCache struct {
	token     string
	expiresAt time.Time
}

// appTokenCacheKey keys a cached installation token by the inputs it was minted
// from, rather than by the spec that asked for it.
//
// The spec name alone was sound only while those inputs were fixed for the life of
// the spec. Two things break that. A chained private key is resolved per mint and
// can differ between callers, so the first caller's token would be served to the
// second without their key ever being exercised — and a key revoked upstream would
// go on working for whoever shares the spec. And the key or installation can change
// under an unchanged spec name, with nothing here to notice: unlike sources, a spec
// update does not rebuild the driver, and this driver has no rotation hook to clear
// a cache from.
//
// Deriving the key from the content instead makes both cases self-correcting — any
// change of input is simply a different entry. The inputs are hashed, so a private
// key never sits in a map key, and length-prefixed so no two input sets can collide
// by concatenating differently.
func appTokenCacheKey(appID, installationID, keyPEM string) string {
	h := sha256.New()
	for _, field := range []string{appID, installationID, keyPEM} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		h.Write(length[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GitHubDriver mints credentials from GitHub.
//
// The source config holds only connection info (github_url). Auth credentials
// (PAT token, App private key, app_id, installation_id) live in the credential
// spec config and are read at MintCredential time. This allows multiple specs
// with different PATs or App installations to share one source.
//
// Two mint methods are supported (configured per-spec via mint_method):
//   - App mode (mint_method=app): Uses a GitHub App private key to mint
//     short-lived installation access tokens (1h TTL)
//   - PAT mode (mint_method=pat): Uses a static Personal Access Token
type GitHubDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// App installation token cache, keyed by appTokenCacheKey over the inputs each
	// token was minted from
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
			Custom(func(v string) error {
				return validateGitHubURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("GitHub API URL (use default for github.com, or specify GitHub Enterprise URL)").
			Example("https://api.github.com"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	)
}

// SensitiveConfigFields returns the list of source config keys that should be masked.
// No secrets are stored on the source — they live in the spec config.
func (f *GitHubDriverFactory) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

// InferCredentialType always returns github_token for GitHub sources.
func (f *GitHubDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeGitHubToken, nil
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
		logger:    log.WithSubsystem(credential.SourceTypeGitHub),
		appTokens: make(map[string]*appTokenCache),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// getGitHubURL returns the GitHub API base URL from source config
func (d *GitHubDriver) getGitHubURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "github_url", "https://api.github.com"), "/")
}

// githubMintMethod resolves the spec's mint_method. It rejects the pre-rename
// auth_method key so a spec persisted before the rename (which skips create-time
// validation on load) fails with a clear migration message rather than a confusing
// downstream error (e.g. a PAT parsed as an App private key).
func githubMintMethod(spec *credential.CredSpec) (string, error) {
	if spec.Config["auth_method"] != "" {
		return "", fmt.Errorf("github: 'auth_method' is no longer supported; use 'mint_method' (app or pat)")
	}
	return credential.GetString(spec.Config, "mint_method", "app"), nil
}

// MintCredential returns a GitHub token for the given spec, minting directly from
// the secret in spec.Config. Chained specs (secret_spec set) mint through
// MintFromSecret instead — the Manager routes them there and never calls this — so
// reaching here with secret_spec set is a misuse and fails closed rather than
// reading a missing inline secret. Non-chained specs are unaffected.
func (d *GitHubDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if spec.Config[credential.ConfigSecretSpec] != "" {
		return nil, nil, 0, "", fmt.Errorf("github: spec uses secret_spec (credential chaining); it must mint from fetched secret material, not directly")
	}
	mintMethod, err := githubMintMethod(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}
	switch mintMethod {
	case "app":
		return d.mintAppCredentialWithKey(ctx, spec, credential.GetString(spec.Config, "private_key", ""), false)
	case "pat":
		return d.mintPATFromToken(credential.GetString(spec.Config, "token", ""))
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s'", mintMethod)
	}
}

// MintFromSecret mints a GitHub token from secret material fetched via credential
// chaining: app mode signs an installation token with the fetched private key; pat
// mode injects the fetched token.
//
// Per-caller authorization is enforced before this runs — the referenced spec was
// minted as the caller, and a caller who may not do that never reaches here. What
// that does not establish is that the fetched key is the one a cached token was
// minted from, which is why the cache in mintAppCredentialWithKey keys on the key
// itself rather than on the spec.
func (d *GitHubDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod, err := githubMintMethod(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}
	switch mintMethod {
	case "app":
		keyPEM := material.Secret()
		// Fall back to the conventional key name ONLY when no field was resolved
		// (single-key auto-detect failed / no secret_field). If a field WAS resolved
		// but is empty, that's a misconfigured secret_field — fail loudly rather than
		// silently substituting a different key.
		if keyPEM == "" && material.Field == "" {
			keyPEM = material.Data["private_key"]
		}
		if keyPEM == "" {
			if material.Field != "" {
				return nil, nil, 0, "", fmt.Errorf("github: secret_field %q is empty or absent in the fetched secret material", material.Field)
			}
			return nil, nil, 0, "", fmt.Errorf("github: no private key in fetched secret material (set secret_field, or store it under 'private_key')")
		}
		return d.mintAppCredentialWithKey(ctx, spec, keyPEM, true)
	case "pat":
		token := material.Secret()
		if token == "" && material.Field == "" {
			token = material.Data["token"]
		}
		if token == "" {
			if material.Field != "" {
				return nil, nil, 0, "", fmt.Errorf("github: secret_field %q is empty or absent in the fetched secret material", material.Field)
			}
			return nil, nil, 0, "", fmt.Errorf("github: no token in fetched secret material (set secret_field, or store it under 'token')")
		}
		return d.mintPATFromToken(token)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s'", mintMethod)
	}
}

// mintAppCredentialWithKey mints a GitHub App installation access token from the
// given private-key PEM. chained says where that PEM came from: spec config for a
// direct mint, or credential chaining — which decides whether a refusal from the
// API is worth marking as retryable.
func (d *GitHubDriver) mintAppCredentialWithKey(ctx context.Context, spec *credential.CredSpec, keyPEM string, chained bool) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	appID := credential.GetString(spec.Config, "app_id", "")
	installationID := credential.GetString(spec.Config, "installation_id", "")
	cacheKey := appTokenCacheKey(appID, installationID, keyPEM)

	d.appTokenMu.Lock()
	defer d.appTokenMu.Unlock()

	// Return cached token if still valid (with 5min buffer)
	if cached, ok := d.appTokens[cacheKey]; ok && time.Now().Add(5*time.Minute).Before(cached.expiresAt) {
		rawData := map[string]interface{}{
			"token":      cached.token,
			"expires_at": cached.expiresAt.Format(time.RFC3339),
		}
		ttl := time.Until(cached.expiresAt)
		return rawData, nil, ttl, "", nil
	}

	key, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Mint a fresh installation token
	token, expiresAt, err := d.mintInstallationToken(ctx, key, appID, installationID, chained)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to mint installation token: %w", err)
	}

	// Entries keyed by content are never read again once any input changes, so
	// sweep what a read would already refuse rather than leaving one behind per
	// rotation. This runs only on a cache miss, off the hit path.
	for k, entry := range d.appTokens {
		if time.Now().After(entry.expiresAt) {
			delete(d.appTokens, k)
		}
	}

	d.appTokens[cacheKey] = &appTokenCache{
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

	return rawData, nil, ttl, "", nil
}

// mintPATFromToken returns the given PAT as a credential (from spec config for a
// direct mint, or fetched via credential chaining).
func (d *GitHubDriver) mintPATFromToken(token string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if token == "" {
		return nil, nil, 0, "", fmt.Errorf("no GitHub PAT configured")
	}

	rawData := map[string]interface{}{
		"token": token,
	}

	// PATs are static - no TTL, no lease
	return rawData, nil, 0, "", nil
}

// mintInstallationToken creates a new installation access token via the GitHub API
func (d *GitHubDriver) mintInstallationToken(ctx context.Context, key *rsa.PrivateKey, appID, installationID string, chained bool) (string, time.Time, error) {
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
		// A key rotated where it is held leaves the chain handing over one the app
		// no longer recognises. Marking that refusal is what lets the minting layer
		// treat its cached copy as stale, evict it and retry once with a fresh
		// fetch; unmarked, every request under that spec fails until the entry ages
		// out on its own. Only the chained path can be retried this way — an inline
		// key has no fresher copy to fetch — so the caller decides by passing
		// chained.
		if chained && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return "", time.Time{}, fmt.Errorf("github: installation token request rejected: %w (status %d: %s)",
				credential.ErrChainedSecretRejected, resp.StatusCode, string(respBody))
		}
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
	mintMethod, err := githubMintMethod(spec)
	if err != nil {
		return err
	}
	if mintMethod != "pat" {
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
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       githubMaxRetryAttempts,
		MaxBodySize:       githubMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500}, // 429 and all 5xx
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method:  method,
		URL:     apiURL,
		Body:    body,
		Headers: headers,
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
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

// validateGitHubURL validates that the github_url is a well-formed HTTPS URL.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
func validateGitHubURL(rawURL string, tlsSkipVerify bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid github_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
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
