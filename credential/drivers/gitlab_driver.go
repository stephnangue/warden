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
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// gitlabMaxResponseBodySize limits response body reads to prevent OOM
const gitlabMaxResponseBodySize = 1 << 20 // 1MB

// gitlabMaxRetryAttempts for retryable API operations
const gitlabMaxRetryAttempts = 3

// maxTokenLifetime bounds the expiry date a mint may ask for. The server rejects
// anything beyond its configured maximum token lifetime, which defaults to 365
// days; an administrator can change it, so this is the documented default rather
// than a value we can know. Asking for less than an instance permits costs at most
// a day of lifetime, where asking for more fails the mint outright.
const maxTokenLifetime = 365 * 24 * time.Hour

// Compile-time interface assertions
var _ credential.SourceDriver = (*GitLabDriver)(nil)
var _ credential.Rotatable = (*GitLabDriver)(nil)
var _ credential.ChainedSecretMinter = (*GitLabDriver)(nil)

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

	// Validate TLS fields
	if err := credential.ValidateSchema(config,
		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	); err != nil {
		return err
	}

	// Validate credential-chaining fields
	if err := credential.ValidateSchema(config,
		credential.StringField("secret_spec").
			Describe("Source the personal access token from another cred spec via credential chaining instead of storing it inline (personal_access_token then omitted)").
			Example("gitlab-pat-from-vault"),

		credential.StringField("secret_field").
			Describe("Which field of the referenced secret_spec's credential holds the personal access token (when its payload has multiple keys)").
			Example("pat"),

		credential.StringField("secret_cache_ttl").
			Describe("Cache the chained personal access token source-wide for this duration (e.g. 30m); omit to fetch it on every mint").
			Example("30m"),
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
	chained := credential.GetString(config, credential.ConfigSecretSpec, "") != ""
	switch authMethod {
	case "pat":
		// A chained source is handed its token per-request, so the inline one is not
		// required — and must not be present. Keeping a live token in config while
		// minting from the chain would leave a source that reads as keyless but still
		// stores the very secret chaining exists to remove.
		if chained {
			if credential.GetString(config, "personal_access_token", "") != "" {
				return fmt.Errorf("personal_access_token must be omitted when secret_spec is set; the token is supplied by the referenced spec")
			}
			return nil
		}
		return credential.ValidateSchema(config,
			credential.StringField("personal_access_token").
				Required().
				Describe("GitLab personal access token").
				Example("glpat-xxxxx"),
		)
	case "oauth2":
		// The client-credentials flow caches one bearer token per driver under a fixed
		// key, which is only sound while the application secret is a single
		// source-level constant. A chained secret can resolve per user, so a cached
		// bearer minted for one caller would be served to the next. Until that cache is
		// keyed by the resolved secret, chaining stays PAT-only.
		if chained {
			return fmt.Errorf("credential chaining (secret_spec) is supported only for auth_method=pat, not oauth2")
		}
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
	return []string{"personal_access_token", "application_secret", "ca_data"}
}

// InferCredentialType always returns gitlab_access_token for GitLab sources.
func (f *GitLabDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeGitLabAccessToken, nil
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
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	// A chained source holds no token to verify with: the token belongs to the
	// referenced spec and is minted per-request as the caller, who does not exist
	// yet. Skip the eager check and let the first mint surface a bad address or CA.
	if driver.isChained() {
		return driver, nil
	}

	// Verify credentials by calling the API
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := driver.verifyAuth(ctx, nil); err != nil {
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

// isChained reports whether this source draws its token from another cred spec
// rather than holding one inline.
func (d *GitLabDriver) isChained() bool {
	return credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != ""
}

// verifyAuth validates the source credentials by calling a simple GitLab API endpoint
func (d *GitLabDriver) verifyAuth(ctx context.Context, patOverride *string) error {
	_, _, err := d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/personal_access_tokens/self", nil, patOverride)
	if err != nil {
		// For OAuth2 mode, try a different endpoint
		if d.getAuthMethod() == "oauth2" {
			_, _, err = d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/user", nil, patOverride)
		}
	}
	return err
}

// tokenExpiry resolves a requested lifetime to the expiry date the API accepts and
// the lifetime that date actually grants.
//
// expires_at is an ISO date and the token dies at midnight UTC on it, so the
// granted lifetime lands on a UTC day boundary and is never exactly the requested
// ttl. Two consequences.
//
// The boundary is computed in UTC, not the server's local zone: a server running
// ahead of UTC otherwise names the wrong day.
//
// The boundary is rounded up — the earliest midnight at or after now+ttl — making
// ttl a floor. Rounding down is the tempting alternative, since it never grants
// more than asked, but it can grant almost nothing: a 24h request issued at 23:00
// would truncate to a boundary one hour out. A token that dies long before its
// stated lifetime is a harder failure than one that outlives it by under a day, so
// the floor wins. Callers therefore get a lifetime in [ttl, ttl+24h).
//
// Rounding up is capped at maxTokenLifetime, because it can otherwise push a
// request past the limit the server enforces on expires_at and turn a mint that
// used to succeed into a 400. The cap costs the floor only for a ttl within a day
// of the limit, where the shortfall is under a day out of a year.
//
// The returned duration is what the caller reports as the lease TTL when the
// server does not say otherwise. It is a request, not a fact: an instance
// configured with a shorter limit may hand back a nearer date, which is why
// callers derive the lease from the response's expires_at and fall back to this.
func tokenExpiry(now time.Time, ttl time.Duration) (string, time.Duration) {
	now = now.UTC()

	deadline := now.Add(ttl)
	if limit := now.Add(maxTokenLifetime); deadline.After(limit) {
		deadline = limit
	}

	expiry := time.Date(deadline.Year(), deadline.Month(), deadline.Day(), 0, 0, 0, 0, time.UTC)
	if expiry.Before(deadline) {
		next := expiry.AddDate(0, 0, 1)
		// Only round up while that stays inside the limit. At the very top of the
		// range the truncated date is the best available answer.
		if !next.After(now.Add(maxTokenLifetime)) {
			expiry = next
		}
	}

	return expiry.Format("2006-01-02"), expiry.Sub(now)
}

// grantedExpiry reports what the server actually granted, given the date it
// returned and what we asked for.
//
// The response carries its own expires_at, and it is authoritative: an instance
// whose maximum token lifetime is shorter than the request answers with a nearer
// date. Deriving the lease from the request instead would leave the credential
// cached past the point the token stops working — the one failure the expiry math
// exists to prevent. An absent or unparseable date falls back to the request,
// which is the best available answer and no worse than not looking.
func grantedExpiry(now time.Time, requested string, requestedTTL time.Duration, granted string) (string, time.Duration) {
	if granted == "" || granted == requested {
		return requested, requestedTTL
	}
	parsed, err := time.ParseInLocation("2006-01-02", granted, time.UTC)
	if err != nil {
		return requested, requestedTTL
	}
	return granted, parsed.Sub(now.UTC())
}

// resolveExpiry applies tokenExpiry to a spec's requested ttl.
func (d *GitLabDriver) resolveExpiry(spec *credential.CredSpec) (string, time.Duration) {
	return tokenExpiry(time.Now(), credential.GetDuration(spec.Config, "ttl", 24*time.Hour))
}

// mintLeaseID builds the lease ID for a freshly minted token, or returns "" for a
// chained mint.
//
// Revocation runs when the lease expires, long after the request that created it:
// Revoke receives only a lease ID, with no caller and no way to re-fetch the token
// that would authorise the delete. A chained source has no token of its own, so it
// cannot honour a lease it hands out. It therefore hands out none, and the token
// expires on its own expires_at instead.
//
// That costs nothing, because the reported lease TTL already equals the token's
// real validity (see tokenExpiry): the lease and the token were always going to
// end together, so dropping the lease removes a revoke call that would have found
// the token already dead. What is genuinely given up is early revocation on
// demand, which is not something that happens today.
func mintLeaseID(tokenType, resourceID, tokenID string, patOverride *string) string {
	if patOverride != nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", tokenType, resourceID, tokenID)
}

// mintError wraps a failed mint, marking an authentication rejection on the
// chained path so the minting layer treats a cached token as stale, evicts it and
// retries once with a fresh fetch. Without this a token rotated at its source
// would fail every request until the cache entry aged out on its own.
func mintError(msg string, err error, status int, patOverride *string) error {
	if patOverride != nil && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		return fmt.Errorf("gitlab: %s: %w (%w)", msg, credential.ErrChainedSecretRejected, err)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// MintCredential mints credentials based on the spec's mint_method
func (d *GitLabDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A chained spec must mint through MintFromSecret, which the manager routes it
	// to; arriving here means that routing was bypassed. Fail rather than fall
	// through to an inline token that a chained source does not have.
	if spec.Config[credential.ConfigSecretSpec] != "" || d.isChained() {
		return nil, nil, 0, "", fmt.Errorf("gitlab: source uses secret_spec (credential chaining); it must mint from fetched secret material, not directly")
	}
	return d.mint(ctx, spec, nil)
}

// MintFromSecret mints a token using a personal access token fetched via
// credential chaining, rather than one stored in source config.
func (d *GitLabDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// Config could have drifted to oauth2 after creation, where validation rejects
	// chaining. The fetched material is a personal access token and means nothing to
	// the client-credentials flow, so stop rather than authenticate with it.
	if d.getAuthMethod() != "pat" {
		return nil, nil, 0, "", fmt.Errorf("gitlab: credential chaining requires auth_method=pat, got %q", d.getAuthMethod())
	}

	pat := material.Secret()
	// Fall back to a conventional key ONLY when no field was resolved. A field that
	// resolved to empty is a misconfigured secret_field — say so, rather than
	// silently authenticating with some other value from the payload.
	if pat == "" && material.Field == "" {
		if pat = material.Data["personal_access_token"]; pat == "" {
			pat = material.Data["pat"]
		}
	}
	if pat == "" {
		if material.Field != "" {
			return nil, nil, 0, "", fmt.Errorf("gitlab: secret_field %q is empty or absent in the fetched secret material", material.Field)
		}
		return nil, nil, 0, "", fmt.Errorf("gitlab: no personal access token in fetched secret material (set secret_field, or store it under 'personal_access_token')")
	}

	return d.mint(ctx, spec, &pat)
}

// mint dispatches on the spec's mint_method. patOverride is nil for an inline
// source and set for a chained one.
func (d *GitLabDriver) mint(ctx context.Context, spec *credential.CredSpec, patOverride *string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "project_access_token":
		return d.mintProjectAccessToken(ctx, spec, patOverride)
	case "group_access_token":
		return d.mintGroupAccessToken(ctx, spec, patOverride)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for GitLab driver; use 'project_access_token' or 'group_access_token'", mintMethod)
	}
}

// mintProjectAccessToken creates a project access token via the GitLab API.
//
// patOverride carries the token fetched via credential chaining (nil for an inline
// source). A chained mint is also leaseless: see mintLeaseID.
func (d *GitLabDriver) mintProjectAccessToken(ctx context.Context, spec *credential.CredSpec, patOverride *string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	projectID := credential.GetString(spec.Config, "project_id", "")
	tokenName := credential.GetString(spec.Config, "token_name", "warden-minted")
	scopes := credential.GetString(spec.Config, "scopes", "api")
	accessLevel := credential.GetInt(spec.Config, "access_level", 30) // 30 = developer

	expiresAt, ttl := d.resolveExpiry(spec)

	body := map[string]interface{}{
		"name":         tokenName,
		"scopes":       strings.Split(scopes, ","),
		"access_level": accessLevel,
		"expires_at":   expiresAt,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	path := fmt.Sprintf("/api/v4/projects/%s/access_tokens", url.PathEscape(projectID))
	respBody, status, err := d.doGitLabRequest(ctx, http.MethodPost, path, bodyBytes, patOverride)
	if err != nil {
		return nil, nil, 0, "", mintError("failed to create project access token", err, status, patOverride)
	}

	var result struct {
		ID        int    `json:"id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Token == "" {
		return nil, nil, 0, "", fmt.Errorf("GitLab API returned empty token")
	}

	expiresAt, ttl = grantedExpiry(time.Now(), expiresAt, ttl, result.ExpiresAt)

	tokenIDStr := strconv.Itoa(result.ID)
	leaseID := mintLeaseID("project_access_token", projectID, tokenIDStr, patOverride)

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

	return rawData, nil, ttl, leaseID, nil
}

// mintGroupAccessToken creates a group access token via the GitLab API.
//
// patOverride carries the token fetched via credential chaining (nil for an inline
// source). A chained mint is also leaseless: see mintLeaseID.
func (d *GitLabDriver) mintGroupAccessToken(ctx context.Context, spec *credential.CredSpec, patOverride *string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	groupID := credential.GetString(spec.Config, "group_id", "")
	tokenName := credential.GetString(spec.Config, "token_name", "warden-minted")
	scopes := credential.GetString(spec.Config, "scopes", "api")
	accessLevel := credential.GetInt(spec.Config, "access_level", 30)

	expiresAt, ttl := d.resolveExpiry(spec)

	body := map[string]interface{}{
		"name":         tokenName,
		"scopes":       strings.Split(scopes, ","),
		"access_level": accessLevel,
		"expires_at":   expiresAt,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	path := fmt.Sprintf("/api/v4/groups/%s/access_tokens", url.PathEscape(groupID))
	respBody, status, err := d.doGitLabRequest(ctx, http.MethodPost, path, bodyBytes, patOverride)
	if err != nil {
		return nil, nil, 0, "", mintError("failed to create group access token", err, status, patOverride)
	}

	var result struct {
		ID        int    `json:"id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Token == "" {
		return nil, nil, 0, "", fmt.Errorf("GitLab API returned empty token")
	}

	expiresAt, ttl = grantedExpiry(time.Now(), expiresAt, ttl, result.ExpiresAt)

	tokenIDStr := strconv.Itoa(result.ID)
	leaseID := mintLeaseID("group_access_token", groupID, tokenIDStr, patOverride)

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

	return rawData, nil, ttl, leaseID, nil
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

	_, _, err := d.doGitLabRequest(ctx, http.MethodDelete, path, nil, nil)
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
	// A chained source does not own its token — the referenced spec's owner does,
	// and rotates it there. Rotating here would invalidate someone else's secret and
	// write the replacement into config that is no longer read.
	if d.isChained() {
		return false
	}
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
	respBody, _, err := d.doGitLabRequest(ctx, http.MethodGet, "/api/v4/personal_access_tokens/self", nil, nil)
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
	respBody, _, err = d.doGitLabRequest(ctx, http.MethodPost, path, nil, nil)
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
// The renew-secret endpoint atomically replaces the old secret, so
// activateAfter=0 is returned (fast path, no propagation delay needed).
func (d *GitLabDriver) prepareOAuth2Rotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	applicationID := credential.GetString(d.credSource.Config, "application_id", "")

	// Rotate the application secret via admin API
	path := fmt.Sprintf("/api/v4/applications/%s/renew-secret", url.PathEscape(applicationID))
	respBody, _, err := d.doGitLabRequest(ctx, http.MethodPost, path, nil, nil)
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
	if err := d.verifyAuth(ctx, nil); err != nil {
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
//
// patOverride supplies the token for a single request instead of reading it from
// source config, which is how a chained mint passes the token fetched from its
// referenced spec without touching shared driver state. Nil means "use the inline
// token", the behaviour for every non-chained call site.
//
// The response status is returned alongside the body because the retry helper
// reports failures as an opaque message; a caller that must distinguish an
// authentication rejection from any other error has no other way to see it.
func (d *GitLabDriver) doGitLabRequest(ctx context.Context, method, path string, body []byte, patOverride *string) ([]byte, int, error) {
	apiURL := d.getGitLabAddress() + path

	// Prepare headers
	headers := make(map[string]string)
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	// Set authentication based on auth method
	switch d.getAuthMethod() {
	case "pat":
		if patOverride != nil {
			headers["PRIVATE-TOKEN"] = *patOverride
		} else {
			headers["PRIVATE-TOKEN"] = d.getPAT()
		}
	case "oauth2":
		token, err := d.getOAuth2Token(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to set auth: %w", err)
		}
		headers["Authorization"] = "Bearer " + token
	}

	// Configure retry behavior (only retry on rate limiting)
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       gitlabMaxRetryAttempts,
		MaxBodySize:       gitlabMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests}, // 429 only
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method:  method,
		URL:     apiURL,
		Body:    body,
		Headers: headers,
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil && d.logger != nil {
		d.logger.Warn("GitLab API request failed", logger.String("error", err.Error()))
	}
	return respBody, status, err
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
