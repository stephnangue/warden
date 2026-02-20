package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// DefaultAzureActivationDelay is the default wait period for Azure AD propagation.
// Azure AD may take several seconds to minutes to propagate a new password credential
// across regions. The activation delay replaces polling with a simple scheduled wait.
const DefaultAzureActivationDelay = 5 * time.Minute

// maxResponseBodySize limits response body reads to prevent OOM from large responses
const maxResponseBodySize = 1 << 20 // 1MB

// addPasswordMaxAttempts is the retry count for adding a password credential.
// Higher than remove because add failure causes full rotation failure, while
// remove failure is retried by the rotation manager's cleanup mechanism.
const addPasswordMaxAttempts = 5

// removePasswordMaxAttempts is the retry count for removing a password credential.
// Lower than add because remove is called during cleanup, which has its own retry
// mechanism (3 immediate retries + daily retry for 7 days).
const removePasswordMaxAttempts = 3

// tenantIDPattern matches Azure AD tenant IDs (UUID format)
var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validateTenantID checks that the tenant ID is a valid UUID
func validateTenantID(tenantID string) error {
	if !tenantIDPattern.MatchString(tenantID) {
		return fmt.Errorf("invalid tenant_id '%s': must be a valid UUID", tenantID)
	}
	return nil
}

// truncateID safely truncates a string for logging, appending "..." if truncated
func truncateID(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// readLimitedBody reads a response body with a size limit to prevent OOM
func readLimitedBody(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, maxResponseBodySize))
}

// azureAPIRequest describes an HTTP request to an Azure API endpoint
type azureAPIRequest struct {
	method      string // "GET" or "POST"
	url         string
	body        []byte // nil for GET; []byte so retries can re-send
	contentType string // "" to omit Content-Type header
	bearerToken string // "" to omit Authorization header
	okStatuses  []int  // status codes that mean success
	operation   string // for error messages: "addPassword", "acquireToken", etc.
}

// doAzureRequest executes an HTTP request with optional retry on specific status codes.
// retryStatuses specifies which HTTP status codes should trigger a retry (e.g., 409).
// maxAttempts is the total number of attempts (1 = no retry).
func (d *AzureDriver) doAzureRequest(ctx context.Context, apiReq azureAPIRequest, retryStatuses []int, maxAttempts int) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s... with ~20% jitter
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			jitter := time.Duration(rand.Int63n(int64(backoff / 5)))
			delay := backoff + jitter

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		var bodyReader io.Reader
		if apiReq.body != nil {
			bodyReader = bytes.NewReader(apiReq.body)
		}

		req, err := http.NewRequestWithContext(ctx, apiReq.method, apiReq.url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to create request: %w", apiReq.operation, err)
		}

		if apiReq.contentType != "" {
			req.Header.Set("Content-Type", apiReq.contentType)
		}
		if apiReq.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+apiReq.bearerToken)
		}

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: request failed: %w", apiReq.operation, err)
		}

		respBody, bodyErr := readLimitedBody(resp.Body)
		resp.Body.Close()

		for _, ok := range apiReq.okStatuses {
			if resp.StatusCode == ok {
				if bodyErr != nil {
					return nil, fmt.Errorf("%s: status %d but failed to read response body: %w",
						apiReq.operation, resp.StatusCode, bodyErr)
				}
				return respBody, nil
			}
		}

		bodyStr := string(respBody)
		if bodyErr != nil {
			bodyStr = fmt.Sprintf("[body read error: %v]", bodyErr)
		}
		lastErr = fmt.Errorf("%s failed with status %d: %s", apiReq.operation, resp.StatusCode, bodyStr)

		shouldRetry := false
		for _, rs := range retryStatuses {
			if resp.StatusCode == rs {
				shouldRetry = true
				break
			}
		}
		if !shouldRetry {
			return nil, lastErr
		}

		if d.logger != nil {
			d.logger.Warn(fmt.Sprintf("%s got retryable status %d, retrying", apiReq.operation, resp.StatusCode),
				logger.Int("attempt", attempt+1),
				logger.Int("max_attempts", maxAttempts),
			)
		}
	}
	return nil, lastErr
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*AzureDriver)(nil)
var _ credential.Rotatable = (*AzureDriver)(nil)
var _ credential.SpecRotatable = (*AzureDriver)(nil)

// AzureDriver mints credentials from Azure services.
// It exchanges pre-provisioned service principal credentials (stored in specs)
// for Azure AD bearer tokens.
//
// The driver's source credentials are used for:
// - Validating connectivity to Azure AD
// - Rotating spec credentials via Microsoft Graph API (if Application.ReadWrite.All is granted)
//
// The spec credentials (stored in CredSpec.Config) are used for:
// - Minting bearer tokens for Azure resources
// - Fetching secrets from Azure Key Vault
type AzureDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Token cache for source's API access (keyed by resource URI).
	// credGeneration is bumped on rotation; tokens from old generations are stale.
	tokenCache     map[string]*cachedAzureToken
	credGeneration uint64
	tokenMu        sync.Mutex

	// Object ID cache: appID -> objectID (immutable mapping in Azure AD)
	objectIDCache map[string]string
	objectIDMu    sync.Mutex

	// Cached result for hasGraphPermissions (separate lock from tokenMu
	// to avoid holding tokenMu during the 10s permission-probe HTTP call)
	graphPermsCached bool
	graphPermsResult bool
	graphPermsMu     sync.Mutex

	// HTTP client for Azure API calls
	httpClient *http.Client

	// Flag to track if source credentials have been verified
	sourceVerified bool
}

// Config accessors — single source of truth is credSource.Config.
// These are cheap map lookups, not cached copies.

func (d *AzureDriver) getTenantID() string {
	return credential.GetString(d.credSource.Config, "tenant_id", "")
}

func (d *AzureDriver) getClientID() string {
	return credential.GetString(d.credSource.Config, "client_id", "")
}

func (d *AzureDriver) getClientSecret() string {
	return credential.GetString(d.credSource.Config, "client_secret", "")
}

// cachedAzureToken holds an Azure AD access token with expiry and generation
type cachedAzureToken struct {
	accessToken string
	expiresAt   time.Time
	generation  uint64
}

// AzureDriverFactory creates AzureDriver instances
type AzureDriverFactory struct{}

// Type returns the driver type
func (f *AzureDriverFactory) Type() string {
	return credential.SourceTypeAzure
}

// ValidateConfig validates Azure driver configuration using declarative schema
func (f *AzureDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("tenant_id").
			Required().
			Custom(validateTenantID).
			Describe("Azure AD tenant ID (UUID)").
			Example("00000000-0000-0000-0000-000000000000"),

		credential.StringField("client_id").
			Required().
			Describe("Azure AD application (client) ID").
			Example("11111111-1111-1111-1111-111111111111"),

		credential.StringField("client_secret").
			Required().
			Describe("Azure AD application client secret").
			Example("secret-value"),

		credential.StringField("secret_id").
			Required().
			Describe("Secret ID for the client secret (for rotation tracking)").
			Example("secret-id-uuid"),
	)
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AzureDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret"}
}

// Create instantiates a new AzureDriver
func (f *AzureDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeAzure),
		tokenCache: make(map[string]*cachedAzureToken),
		objectIDCache:  make(map[string]string),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := driver.getSourceToken(ctx, "https://management.azure.com/"); err != nil {
		return nil, fmt.Errorf("Azure authentication failed: %w", err)
	}
	driver.sourceVerified = true

	return driver, nil
}

// MintCredential mints credentials based on the spec's mint_method.
// Credentials are minted using the SP credentials stored in the spec (not the source).
func (d *AzureDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "bearer_token")

	switch mintMethod {
	case "bearer_token":
		return d.mintBearerToken(ctx, spec)
	case "key_vault_secret":
		return d.fetchKeyVaultSecret(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for Azure driver; use 'bearer_token' or 'key_vault_secret'", mintMethod)
	}
}

// mintBearerToken exchanges spec's SP credentials for an Azure AD bearer token
func (d *AzureDriver) mintBearerToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Get SP credentials from spec config (pre-provisioned)
	tenantID := credential.GetString(spec.Config, "tenant_id", d.getTenantID())
	clientID := credential.GetString(spec.Config, "client_id", "")
	clientSecret := credential.GetString(spec.Config, "client_secret", "")
	resourceURI := credential.GetString(spec.Config, "resource_uri", "https://management.azure.com/")

	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("spec config must contain 'client_id' and 'client_secret' for bearer_token mint method")
	}

	// Exchange for bearer token
	token, expiresIn, err := d.acquireToken(ctx, tenantID, clientID, clientSecret, resourceURI)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	ttl := time.Duration(expiresIn) * time.Second

	rawData := map[string]interface{}{
		"access_token": token,
		"resource_uri": resourceURI,
		"tenant_id":    tenantID,
		"client_id":    clientID,
		"token_type":   "Bearer",
	}

	if d.logger != nil {
		d.logger.Debug("minted Azure AD bearer token",
			logger.String("spec", spec.Name),
			logger.String("resource_uri", resourceURI),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID - bearer tokens expire naturally and cannot be revoked
	return rawData, ttl, "", nil
}

// fetchKeyVaultSecret fetches a secret from Azure Key Vault
func (d *AzureDriver) fetchKeyVaultSecret(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Get SP credentials from spec config
	tenantID := credential.GetString(spec.Config, "tenant_id", d.getTenantID())
	clientID := credential.GetString(spec.Config, "client_id", "")
	clientSecret := credential.GetString(spec.Config, "client_secret", "")
	vaultName := credential.GetString(spec.Config, "vault_name", "")
	secretName := credential.GetString(spec.Config, "secret_name", "")
	secretVersion := credential.GetString(spec.Config, "secret_version", "")

	if clientID == "" || clientSecret == "" {
		return nil, 0, "", fmt.Errorf("spec config must contain 'client_id' and 'client_secret' for key_vault_secret mint method")
	}
	if vaultName == "" || secretName == "" {
		return nil, 0, "", fmt.Errorf("spec config must contain 'vault_name' and 'secret_name' for key_vault_secret mint method")
	}

	// Get bearer token for Key Vault
	kvToken, _, err := d.acquireToken(ctx, tenantID, clientID, clientSecret, "https://vault.azure.net/")
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to acquire Key Vault token: %w", err)
	}

	// Build Key Vault URL
	vaultURL := fmt.Sprintf("https://%s.vault.azure.net", vaultName)
	secretPath := fmt.Sprintf("/secrets/%s", secretName)
	if secretVersion != "" {
		secretPath += "/" + secretVersion
	}
	secretPath += "?api-version=7.4"

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "GET",
		url:         vaultURL + secretPath,
		bearerToken: kvToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "fetchKeyVaultSecret",
	}, nil, 1)
	if err != nil {
		return nil, 0, "", err
	}

	var secretResp struct {
		Value string `json:"value"`
		ID    string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode Key Vault response: %w", err)
	}

	// Try to parse as JSON for structured secrets
	rawData := make(map[string]interface{})
	if err := json.Unmarshal([]byte(secretResp.Value), &rawData); err != nil {
		// Not JSON, return as simple value
		rawData["value"] = secretResp.Value
	}

	if d.logger != nil {
		d.logger.Debug("fetched Azure Key Vault secret",
			logger.String("spec", spec.Name),
			logger.String("vault_name", vaultName),
			logger.String("secret_name", secretName),
		)
	}

	// Key Vault secrets are static - no TTL, no lease
	return rawData, 0, "", nil
}

// Revoke is a no-op for Azure credentials (they expire naturally)
func (d *AzureDriver) Revoke(ctx context.Context, leaseID string) error {
	// Azure bearer tokens cannot be revoked - they expire naturally
	if d.logger != nil {
		d.logger.Debug("Azure credentials expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *AzureDriver) Type() string {
	return credential.SourceTypeAzure
}

// Cleanup releases resources
func (d *AzureDriver) Cleanup(ctx context.Context) error {
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source credentials
func (d *AzureDriver) SupportsRotation() bool {
	// Source credentials can be rotated if we have Graph API access
	// This requires the source SP to have Application.ReadWrite.All permission
	return d.hasGraphPermissions()
}

// PrepareRotation creates a new client_secret for the source's SP.
// Returns activateAfter to allow time for Azure AD eventual consistency propagation.
func (d *AzureDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()

	oldSecretID := credential.GetString(d.credSource.Config, "secret_id", "")

	// Get Graph API token
	graphToken, err := d.getGraphTokenLocked(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	// Add new password credential first (single write, avoids 409 conflict).
	// Orphan cleanup happens after success as non-critical housekeeping.
	newSecret, newSecretID, err := d.addPasswordCredential(ctx, graphToken, d.getClientID())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new password credential: %w", err)
	}

	// Best-effort cleanup of orphaned credentials from previously failed rotations.
	// Not time-critical since addPassword already succeeded.
	d.removeOrphanedPasswordCredentials(ctx, graphToken, d.getClientID(), oldSecretID, newSecretID)

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["client_secret"] = newSecret
	newConfig["secret_id"] = newSecretID

	cleanupConfig := map[string]string{
		"old_secret_id": oldSecretID,
	}

	// Return activateAfter to let the rotation manager schedule activation
	// after Azure AD eventual consistency has propagated the new credential.
	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultAzureActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source credential rotation",
			logger.String("new_secret_id", truncateID(newSecretID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver
func (d *AzureDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()

	// Update config (single source of truth for credentials)
	d.credSource.Config = newConfig

	// Bump generation to invalidate all cached tokens; old-generation entries
	// are ignored on lookup without needing to clear the map.
	d.credGeneration++
	d.graphPermsCached = false
	d.sourceVerified = false

	// Verify new credentials work
	_, err := d.getSourceTokenLocked(ctx, "https://management.azure.com/")
	if err != nil {
		return fmt.Errorf("failed to authenticate with new credentials: %w", err)
	}
	d.sourceVerified = true

	// Pre-warm the Graph API token cache so CleanupRotation can reuse it
	// instead of acquiring a fresh token that may hit an unpropagated AD node.
	if _, err := d.getSourceTokenLocked(ctx, "https://graph.microsoft.com/"); err != nil && d.logger != nil {
		d.logger.Trace("Graph token not yet cached during commit, cleanup will retry")
	}

	if d.logger != nil {
		d.logger.Debug("committed source credential rotation")
	}

	return nil
}

// CleanupRotation deletes old client_secret
func (d *AzureDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldSecretID := cleanupConfig["old_secret_id"]
	if oldSecretID == "" {
		return nil
	}

	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Graph API token: %w", err)
	}

	if err := d.removePasswordCredential(ctx, graphToken, d.getClientID(), oldSecretID); err != nil {
		return fmt.Errorf("failed to remove old password credential: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old source credential",
			logger.String("old_secret_id", truncateID(oldSecretID, 8)),
		)
	}

	return nil
}

// ============================================================================
// SpecRotatable Interface Implementation (Spec Rotation)
// ============================================================================

// SupportsSpecRotation returns true if this driver can rotate spec credentials
func (d *AzureDriver) SupportsSpecRotation() bool {
	return d.hasGraphPermissions()
}

// PrepareSpecRotation creates a new client_secret for a spec's workload SP.
// Returns activateAfter to allow time for Azure AD eventual consistency propagation.
func (d *AzureDriver) PrepareSpecRotation(ctx context.Context, spec *credential.CredSpec) (map[string]string, map[string]string, time.Duration, error) {
	workloadAppID := credential.GetString(spec.Config, "client_id", "")
	oldSecretID := credential.GetString(spec.Config, "secret_id", "")

	if workloadAppID == "" {
		return nil, nil, 0, fmt.Errorf("spec config must contain 'client_id'")
	}

	// Get Graph API token using source credentials
	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	// Add new password credential first (single write, avoids 409 conflict).
	// Orphan cleanup happens after success as non-critical housekeeping.
	newSecret, newSecretID, err := d.addPasswordCredential(ctx, graphToken, workloadAppID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new password credential for workload SP: %w", err)
	}

	// Best-effort cleanup of orphaned credentials from previously failed rotations.
	// Not time-critical since addPassword already succeeded.
	d.removeOrphanedPasswordCredentials(ctx, graphToken, workloadAppID, oldSecretID, newSecretID)

	// Build new spec config
	newConfig := make(map[string]string)
	for k, v := range spec.Config {
		newConfig[k] = v
	}
	newConfig["client_secret"] = newSecret
	newConfig["secret_id"] = newSecretID

	cleanupConfig := map[string]string{
		"client_id":     workloadAppID,
		"old_secret_id": oldSecretID,
	}

	// Return activateAfter to let the rotation manager schedule activation
	// after Azure AD eventual consistency has propagated the new credential.
	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultAzureActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared spec credential rotation",
			logger.String("spec", spec.Name),
			logger.String("workload_app_id", truncateID(workloadAppID, 8)),
			logger.String("new_secret_id", truncateID(newSecretID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitSpecRotation activates new credentials for a spec
func (d *AzureDriver) CommitSpecRotation(ctx context.Context, spec *credential.CredSpec, newConfig map[string]string) error {
	// Nothing to do here - the credential manager will use the new spec config
	// and re-mint bearer tokens with the new credentials
	if d.logger != nil {
		d.logger.Debug("committed spec credential rotation",
			logger.String("spec", spec.Name),
		)
	}
	return nil
}

// CleanupSpecRotation deletes old client_secret from workload SP
func (d *AzureDriver) CleanupSpecRotation(ctx context.Context, cleanupConfig map[string]string) error {
	workloadAppID := cleanupConfig["client_id"]
	oldSecretID := cleanupConfig["old_secret_id"]

	if workloadAppID == "" || oldSecretID == "" {
		return nil
	}

	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Graph API token: %w", err)
	}

	if err := d.removePasswordCredential(ctx, graphToken, workloadAppID, oldSecretID); err != nil {
		return fmt.Errorf("failed to remove old password credential: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old spec credential",
			logger.String("workload_app_id", truncateID(workloadAppID, 8)),
			logger.String("old_secret_id", truncateID(oldSecretID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Azure AD Token Acquisition
// ============================================================================

// acquireToken exchanges client credentials for an Azure AD token
func (d *AzureDriver) acquireToken(ctx context.Context, tenantID, clientID, clientSecret, resourceURI string) (string, int, error) {
	if err := validateTenantID(tenantID); err != nil {
		return "", 0, err
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", resourceURI+".default")
	data.Set("grant_type", "client_credentials")

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         tokenURL,
		body:        []byte(data.Encode()),
		contentType: "application/x-www-form-urlencoded",
		okStatuses:  []int{http.StatusOK},
		operation:   "acquireToken",
	}, nil, 1)
	if err != nil {
		return "", 0, err
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// getSourceToken gets a cached token for the source's credentials.
// Holds tokenMu only for cache reads/writes, NOT during the HTTP call,
// so callers are not blocked by slow token acquisition.
func (d *AzureDriver) getSourceToken(ctx context.Context, resourceURI string) (string, error) {
	// Fast path: cache hit
	d.tokenMu.Lock()
	gen := d.credGeneration
	if cached, ok := d.tokenCache[resourceURI]; ok &&
		cached.generation == gen &&
		time.Now().Add(5*time.Minute).Before(cached.expiresAt) {
		token := cached.accessToken
		d.tokenMu.Unlock()
		return token, nil
	}
	d.tokenMu.Unlock()

	// Slow path: acquire token WITHOUT holding lock
	token, expiresIn, err := d.acquireToken(ctx, d.getTenantID(), d.getClientID(), d.getClientSecret(), resourceURI)
	if err != nil {
		return "", err
	}

	// Cache update under lock; discard if rotation happened during HTTP call
	d.tokenMu.Lock()
	if d.credGeneration != gen {
		d.tokenMu.Unlock()
		return d.getSourceToken(ctx, resourceURI)
	}
	if d.tokenCache == nil {
		d.tokenCache = make(map[string]*cachedAzureToken)
	}
	d.tokenCache[resourceURI] = &cachedAzureToken{
		accessToken: token,
		expiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
		generation:  gen,
	}
	d.tokenMu.Unlock()
	return token, nil
}

// getSourceTokenLocked acquires a token while the caller already holds tokenMu.
// Used by PrepareRotation/CommitRotation which need atomicity across config + cache.
func (d *AzureDriver) getSourceTokenLocked(ctx context.Context, resourceURI string) (string, error) {
	gen := d.credGeneration
	if cached, ok := d.tokenCache[resourceURI]; ok &&
		cached.generation == gen &&
		time.Now().Add(5*time.Minute).Before(cached.expiresAt) {
		return cached.accessToken, nil
	}

	token, expiresIn, err := d.acquireToken(ctx, d.getTenantID(), d.getClientID(), d.getClientSecret(), resourceURI)
	if err != nil {
		return "", err
	}

	if d.tokenCache == nil {
		d.tokenCache = make(map[string]*cachedAzureToken)
	}
	d.tokenCache[resourceURI] = &cachedAzureToken{
		accessToken: token,
		expiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
		generation:  gen,
	}
	return token, nil
}

// getGraphToken gets a Graph API token for the source's credentials
func (d *AzureDriver) getGraphToken(ctx context.Context) (string, error) {
	return d.getSourceToken(ctx, "https://graph.microsoft.com/")
}

func (d *AzureDriver) getGraphTokenLocked(ctx context.Context) (string, error) {
	return d.getSourceTokenLocked(ctx, "https://graph.microsoft.com/")
}

// hasGraphPermissions checks if the source has Graph API access (result is cached).
// Uses graphPermsMu (not tokenMu) to avoid blocking token operations during the probe.
func (d *AzureDriver) hasGraphPermissions() bool {
	d.graphPermsMu.Lock()
	defer d.graphPermsMu.Unlock()

	if d.graphPermsCached {
		return d.graphPermsResult
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := d.getSourceToken(ctx, "https://graph.microsoft.com/")
	d.graphPermsCached = true
	d.graphPermsResult = err == nil
	return d.graphPermsResult
}

// ============================================================================
// Microsoft Graph API Operations
// ============================================================================

// graphAppURL resolves an application's object ID and returns its Graph API base URL.
func (d *AzureDriver) graphAppURL(ctx context.Context, graphToken, appID string) (string, error) {
	objectID, err := d.getAppObjectID(ctx, graphToken, appID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s", objectID), nil
}

// addPasswordCredential adds a new password credential to an application.
// Retries on HTTP 409 (Directory_ConcurrencyViolation) with exponential backoff.
func (d *AzureDriver) addPasswordCredential(ctx context.Context, graphToken, appID string) (string, string, error) {
	appURL, err := d.graphAppURL(ctx, graphToken, appID)
	if err != nil {
		return "", "", err
	}

	body := map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": fmt.Sprintf("warden-rotated-%d", time.Now().Unix()),
		},
	}
	bodyJSON, _ := json.Marshal(body)

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         appURL + "/addPassword",
		body:        bodyJSON,
		contentType: "application/json",
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "addPassword",
	}, []int{http.StatusConflict}, addPasswordMaxAttempts)
	if err != nil {
		return "", "", err
	}

	var result struct {
		SecretText string `json:"secretText"`
		KeyID      string `json:"keyId"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("failed to decode addPassword response: %w", err)
	}
	return result.SecretText, result.KeyID, nil
}

// removePasswordCredential removes a password credential from an application.
// Retries on HTTP 409 (Directory_ConcurrencyViolation) with exponential backoff.
// Treats "No password credential found" (HTTP 400) as success for idempotent delete.
func (d *AzureDriver) removePasswordCredential(ctx context.Context, graphToken, appID, keyID string) error {
	appURL, err := d.graphAppURL(ctx, graphToken, appID)
	if err != nil {
		return err
	}

	body := map[string]interface{}{
		"keyId": keyID,
	}
	bodyJSON, _ := json.Marshal(body)

	_, err = d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         appURL + "/removePassword",
		body:        bodyJSON,
		contentType: "application/json",
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK, http.StatusNoContent},
		operation:   "removePassword",
	}, []int{http.StatusConflict}, removePasswordMaxAttempts)
	// Treat "not found" as success (idempotent delete).
	// This happens when orphan cleanup already removed the credential.
	if err != nil && strings.Contains(err.Error(), "No password credential found") {
		return nil
	}
	return err
}

// passwordCredentialInfo holds metadata about an Azure AD password credential
type passwordCredentialInfo struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
}

// listPasswordCredentials lists all password credentials on an application
func (d *AzureDriver) listPasswordCredentials(ctx context.Context, graphToken, appID string) ([]passwordCredentialInfo, error) {
	appURL, err := d.graphAppURL(ctx, graphToken, appID)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("$select", "passwordCredentials")

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "GET",
		url:         appURL + "?" + params.Encode(),
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "listPasswordCredentials",
	}, nil, 1)
	if err != nil {
		return nil, err
	}

	var result struct {
		PasswordCredentials []passwordCredentialInfo `json:"passwordCredentials"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode password credentials response: %w", err)
	}

	return result.PasswordCredentials, nil
}

// removeOrphanedPasswordCredentials lists all password credentials on an application
// and removes any warden-managed credentials not in the keep set.
// Called after addPassword succeeds as best-effort housekeeping.
// Errors are logged but not propagated.
func (d *AzureDriver) removeOrphanedPasswordCredentials(ctx context.Context, graphToken, appID string, keepKeyIDs ...string) {
	creds, err := d.listPasswordCredentials(ctx, graphToken, appID)
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("failed to list password credentials for orphan cleanup", logger.Err(err))
		}
		return
	}

	keepSet := make(map[string]bool, len(keepKeyIDs))
	for _, id := range keepKeyIDs {
		keepSet[id] = true
	}

	// Remove any warden-managed credentials that are not in the keep set
	for _, cred := range creds {
		if keepSet[cred.KeyID] {
			continue
		}
		if !strings.HasPrefix(cred.DisplayName, "warden-rotated-") {
			continue
		}
		if d.logger != nil {
			d.logger.Warn("deleting orphaned password credential from previous failed rotation",
				logger.String("orphaned_secret_id", truncateID(cred.KeyID, 8)),
			)
		}
		if err := d.removePasswordCredential(ctx, graphToken, appID, cred.KeyID); err != nil && d.logger != nil {
			d.logger.Warn("failed to remove orphaned password credential",
				logger.String("orphaned_secret_id", truncateID(cred.KeyID, 8)),
				logger.Err(err),
			)
		}
	}
}

// getAppObjectID gets the object ID of an application from its app ID (client_id).
// Results are cached because the appID -> objectID mapping is immutable in Azure AD.
func (d *AzureDriver) getAppObjectID(ctx context.Context, graphToken, appID string) (string, error) {
	d.objectIDMu.Lock()
	if objectID, ok := d.objectIDCache[appID]; ok {
		d.objectIDMu.Unlock()
		return objectID, nil
	}
	d.objectIDMu.Unlock()

	params := url.Values{}
	params.Set("$filter", fmt.Sprintf("appId eq '%s'", appID))
	params.Set("$select", "id")

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "GET",
		url:         "https://graph.microsoft.com/v1.0/applications?" + params.Encode(),
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "getAppObjectID",
	}, nil, 1)
	if err != nil {
		return "", err
	}

	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to decode application response: %w", err)
	}

	if len(result.Value) == 0 {
		return "", fmt.Errorf("application with appId '%s' not found", appID)
	}

	objectID := result.Value[0].ID
	d.objectIDMu.Lock()
	d.objectIDCache[appID] = objectID
	d.objectIDMu.Unlock()

	return objectID, nil
}
