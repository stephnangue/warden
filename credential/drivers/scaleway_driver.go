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
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

const scalewayMaxResponseBodySize = 1 << 20 // 1MB
const scalewayMaxRetryAttempts = 3

// scalewayRotationDescriptionPrefix stamps a management key created by rotation.
// The key it replaces is appended, so the stamp names one lineage rather than
// "some Warden rotated this": two sources rotating keys for the same bearer would
// otherwise be indistinguishable, and the orphan sweep below would delete a
// sibling's live key. A key created by rotating from K is never itself stamped
// with K, so the sweep can never reach the key currently in use.
const scalewayRotationDescriptionPrefix = "warden-management-key-rotated-from-"

// scalewayListPageSize bounds one page of the IAM key listing used by the sweep.
const scalewayListPageSize = 100

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
				// The value is deliberately not echoed. When the fields are swapped —
				// the case this check exists to catch — this one holds the secret key,
				// and a validation error travels to API clients and logs where field
				// masking cannot reach it.
				if v != "" && !strings.HasPrefix(v, "SCW") {
					return fmt.Errorf("management_access_key must start with SCW (did you swap access_key and secret_key?)")
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

		credential.DurationField("activation_delay").
			Describe("Overlap before a rotated management key becomes active (default: 30s)").
			Example("30s"),
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

// scalewayRetryConfig retries rate limiting and transient server errors. Safe for
// reads and deletes, which are idempotent.
func scalewayRetryConfig() httputil.HTTPRetryConfig {
	return httputil.HTTPRetryConfig{
		MaxAttempts:       scalewayMaxRetryAttempts,
		MaxBodySize:       scalewayMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}

// scalewayCreateRetryConfig retries rate limiting only.
//
// Creating an API key is not idempotent, and the retry helper treats 500 in the
// list as "every 5xx". A proxy answering 502 after Scaleway already committed the
// key turns one request into two live keys, and only one of them is ever returned
// to us: for a mint the orphan self-expires, but a rotation key carries no expiry
// and would outlive everything. 429 stays because a rate-limited request was
// never processed.
func scalewayCreateRetryConfig() httputil.HTTPRetryConfig {
	cfg := scalewayRetryConfig()
	cfg.RetryableStatuses = []int{http.StatusTooManyRequests}
	return cfg
}

// isScalewayNotFound reports whether a failed delete means the key is already
// gone, as opposed to the request never having reached a key endpoint at all.
//
// Both answer 404. Accepting the status alone — as this driver used to — makes a
// mistyped iam_api_path indistinguishable from a successful cleanup, so a live
// key gets reported as deleted. Scaleway names the resource error in the body;
// a bare routing 404 carries no such marker.
func isScalewayNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), `"type":"not_found"`) ||
		strings.Contains(err.Error(), `"type": "not_found"`)
}

// getScalewayURLLocked returns the Scaleway API base URL from source config.
// Caller must hold configMu (read or write).
func (d *ScalewayDriver) getScalewayURLLocked() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "scaleway_url", "https://api.scaleway.com"), "/")
}

// getManagementSecretKeyLocked returns the management secret key from source config.
// Caller must hold configMu (read or write).
func (d *ScalewayDriver) getManagementSecretKeyLocked() string {
	return credential.GetString(d.credSource.Config, "management_secret_key", "")
}

// getIAMAPIPathLocked returns the IAM API path prefix from source config.
// Defaults to DefaultScalewayIAMPath (/iam/v1alpha1).
// Caller must hold configMu (read or write).
func (d *ScalewayDriver) getIAMAPIPathLocked() string {
	return credential.GetString(d.credSource.Config, "iam_api_path", DefaultScalewayIAMPath)
}

// iamURL builds a full IAM API URL for the given subpath (e.g., "/api-keys").
//
// It takes the read lock even though neither value it reads is rewritten by
// rotation: what rotation replaces is the config map itself, so reading any key
// from it without the lock races the swap. Callers must not already hold
// configMu — read locks are not re-entrant, and a writer queued between two
// acquisitions on one goroutine would deadlock.
func (d *ScalewayDriver) iamURL(subpath string) string {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.getScalewayURLLocked() + d.getIAMAPIPathLocked() + subpath
}

// iamKeyURL builds the URL for one API key, escaping the identifier. The id
// reaches Revoke replayed from a stored lease, so a value carrying "/" or "?"
// would otherwise retarget an authenticated DELETE at another IAM resource.
func (d *ScalewayDriver) iamKeyURL(accessKey string) string {
	return d.iamURL("/api-keys/" + url.PathEscape(accessKey))
}

// MintCredential returns Scaleway credentials for the given spec.
//
// mint_method is not defaulted: the credential type refuses to create a spec
// without an explicit one, so a default here could only ever be reached by a
// config that bypassed validation, and silently minting static keys for it would
// be the wrong answer.
func (d *ScalewayDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "static_keys":
		return d.mintStaticCredential(spec)
	case "dynamic_keys":
		return d.mintDynamicCredential(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method: %s (expected static_keys or dynamic_keys)", mintMethod)
	}
}

// mintStaticCredential reads access_key and secret_key from spec config.
func (d *ScalewayDriver) mintStaticCredential(spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	accessKey := credential.GetString(spec.Config, "access_key", "")
	if accessKey == "" {
		return nil, nil, 0, "", fmt.Errorf("no access_key configured in spec")
	}
	secretKey := credential.GetString(spec.Config, "secret_key", "")
	if secretKey == "" {
		return nil, nil, 0, "", fmt.Errorf("no secret_key configured in spec")
	}

	rawData := map[string]interface{}{
		"access_key": accessKey,
		"secret_key": secretKey,
	}

	return rawData, nil, 0, "", nil // Static — no TTL, no lease
}

// mintDynamicCredential creates a new API key via the Scaleway IAM API.
func (d *ScalewayDriver) mintDynamicCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.configMu.RLock()
	managementKey := d.getManagementSecretKeyLocked()
	d.configMu.RUnlock()
	if managementKey == "" {
		return nil, nil, 0, "", fmt.Errorf("management_secret_key is required on source for dynamic_keys mint method")
	}

	applicationID := credential.GetString(spec.Config, "application_id", "")
	if applicationID == "" {
		return nil, nil, 0, "", fmt.Errorf("application_id is required for dynamic_keys mint method")
	}

	ttl := credential.GetDuration(spec.Config, "ttl", 1*time.Hour)
	if ttl <= 0 {
		return nil, nil, 0, "", fmt.Errorf("ttl must be positive for dynamic_keys mint method, got %s", ttl)
	}
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
		return nil, nil, 0, "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	apiURL := d.iamURL("/api-keys")

	httpReq := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    apiURL,
		Body:   bodyJSON,
		Headers: map[string]string{
			"X-Auth-Token": managementKey,
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, scalewayCreateRetryConfig())
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to create Scaleway API key: %w", err)
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
		return nil, nil, 0, "", fmt.Errorf("failed to parse Scaleway API response: %w", err)
	}

	if resp.AccessKey == "" || resp.SecretKey == "" {
		return nil, nil, 0, "", fmt.Errorf("Scaleway API returned empty access_key or secret_key")
	}

	leaseTTL, err := d.leaseTTLFromExpiry(resp.ExpiresAt, ttl)
	if err != nil {
		return nil, nil, 0, "", err
	}

	d.logger.Info("created dynamic Scaleway API key",
		logger.String("access_key", truncateID(resp.AccessKey, 8)),
		logger.String("spec", spec.Name),
		logger.String("expires_at", resp.ExpiresAt),
		logger.String("lease_ttl", leaseTTL.String()),
	)

	rawData := map[string]interface{}{
		"access_key": resp.AccessKey,
		"secret_key": resp.SecretKey,
	}

	// LeaseID is the access_key — used by Revoke to delete the key
	return rawData, nil, leaseTTL, resp.AccessKey, nil
}

// leaseTTLFromExpiry converts the expires_at Scaleway reports into a lease TTL.
//
// The requested duration alone is the wrong answer. It is measured before the
// round trip, so the lease outlives the key by however long the call took —
// including up to two backoff waits on a retry. It also ignores an expiry the
// organization shortened for its own reasons: a credential-duration policy can
// cap a key well below what was asked, and the credential is cached for its whole
// lease, so an over-long lease means later hits hand out a key that is already
// dead.
//
// The reported expiry is capped at the requested duration, because it is only as
// trustworthy as the agreement between two clocks. A local clock running behind
// Scaleway's would otherwise reintroduce the very over-long lease this exists to
// prevent, bounded by skew rather than by round-trip time.
//
// An unparseable expiry falls back to the requested duration: a usable key should
// not be thrown away over a timestamp format. An expiry already in the past is a
// different matter — there is no usable key to return.
func (d *ScalewayDriver) leaseTTLFromExpiry(expiresAt string, requested time.Duration) (time.Duration, error) {
	if expiresAt == "" {
		d.logger.Warn("Scaleway returned no expires_at; falling back to the requested duration",
			logger.String("requested", requested.String()),
		)
		return requested, nil
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		d.logger.Warn("Scaleway returned an expires_at that is not RFC3339; falling back to the requested duration",
			logger.String("expires_at", expiresAt),
			logger.String("requested", requested.String()),
		)
		return requested, nil
	}

	ttl := time.Until(expiry)
	if ttl <= 0 {
		return 0, fmt.Errorf("Scaleway returned an API key that already expired at %s", expiresAt)
	}
	if ttl > requested {
		return requested, nil
	}
	return ttl, nil
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

	httpReq := httputil.HTTPRequest{
		Method: http.MethodDelete,
		URL:    d.iamKeyURL(leaseID),
		Headers: map[string]string{
			"X-Auth-Token": managementKey,
			"Accept":       "application/json",
		},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK},
	}

	_, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, scalewayRetryConfig())
	if err != nil {
		if isScalewayNotFound(err) {
			d.logger.Info("dynamic Scaleway API key was already gone",
				logger.String("access_key", truncateID(leaseID, 8)),
			)
			return nil
		}
		// A bare 404 is not a revocation. It is almost always a misconfigured
		// iam_api_path, and returning an error would send the expiration manager
		// into backoff and then a daily retry for a request that can never
		// succeed. Say so loudly and let the key expire on its own.
		if status == http.StatusNotFound {
			d.logger.Warn("Scaleway returned 404 with no not_found marker; the key was NOT revoked and will live until it expires — check iam_api_path",
				logger.String("access_key", truncateID(leaseID, 8)),
				logger.String("url", d.iamKeyURL(leaseID)),
			)
			return nil
		}
		return fmt.Errorf("failed to revoke Scaleway API key %s: %w", truncateID(leaseID, 8), err)
	}

	d.logger.Info("revoked dynamic Scaleway API key",
		logger.String("access_key", truncateID(leaseID, 8)),
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

	retryConfig := scalewayRetryConfig()

	// Look up the current key to find its bearer (application_id or user_id)
	getReq := httputil.HTTPRequest{
		Method:  http.MethodGet,
		URL:     d.iamKeyURL(managementAccessKey),
		Headers: map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, getReq, retryConfig)
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

	if keyInfo.ApplicationID == "" && keyInfo.UserID == "" {
		return nil, nil, 0, fmt.Errorf("current management key has no application_id or user_id")
	}

	// Every key this rotation creates is stamped with the key it replaces, so the
	// stamp names one lineage. Sweeping it before creating anything reclaims keys
	// left behind by an earlier attempt at this same rotation — a retried create,
	// or a crash before the staged entry was persisted — which are invisible to
	// Warden and, unlike a minted key, never expire.
	stamp := scalewayRotationDescriptionPrefix + managementAccessKey
	d.sweepOrphanedRotationKeys(ctx, managementKey, keyInfo.ApplicationID, keyInfo.UserID, stamp)

	// Create a new management key for the same bearer
	createBody := map[string]interface{}{
		"description": stamp,
	}
	if keyInfo.ApplicationID != "" {
		createBody["application_id"] = keyInfo.ApplicationID
	} else {
		createBody["user_id"] = keyInfo.UserID
	}

	bodyJSON, err := json.Marshal(createBody)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal create request: %w", err)
	}

	createReq := httputil.HTTPRequest{
		Method:  http.MethodPost,
		URL:     d.iamURL("/api-keys"),
		Body:    bodyJSON,
		Headers: map[string]string{"X-Auth-Token": managementKey, "Content-Type": "application/json", "Accept": "application/json"},
	}

	respBody, _, err = httputil.ExecuteWithRetry(ctx, d.httpClient, createReq, scalewayCreateRetryConfig())
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
		logger.String("new_access_key", truncateID(newKey.AccessKey, 8)),
	)

	// Read from the snapshot taken under the lock above, not from the live map:
	// two network round trips have happened since, and a concurrent CommitRotation
	// may have replaced the map in the meantime.
	activateAfter := credential.GetDuration(configSnapshot, "activation_delay", DefaultScalewayActivationDelay)
	return newConfig, cleanupConfig, activateAfter, nil
}

// sweepOrphanedRotationKeys deletes management keys left behind by an earlier
// attempt at this same rotation.
//
// Scoped by exact description, which encodes the key being replaced. A key
// created by rotating from K is stamped with K, so the key currently in use —
// stamped with *its* predecessor — can never match, and neither can a sibling
// source's key, whose lineage starts somewhere else. That scoping is the whole
// safety argument: a sweep keyed on "some Warden rotated this" would delete
// another source's live credential.
//
// Failures are logged and swallowed. A rotation that works must not be failed
// because tidying up after a previous one did not.
func (d *ScalewayDriver) sweepOrphanedRotationKeys(ctx context.Context, managementKey, applicationID, userID, stamp string) {
	bearer := url.Values{}
	if applicationID != "" {
		bearer.Set("application_id", applicationID)
	} else {
		bearer.Set("user_id", userID)
	}
	bearer.Set("page_size", fmt.Sprintf("%d", scalewayListPageSize))

	for page := 1; ; page++ {
		bearer.Set("page", fmt.Sprintf("%d", page))
		listReq := httputil.HTTPRequest{
			Method:  http.MethodGet,
			URL:     d.iamURL("/api-keys") + "?" + bearer.Encode(),
			Headers: map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
		}

		respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, listReq, scalewayRetryConfig())
		if err != nil {
			d.logger.Warn("could not list API keys to sweep orphaned rotation keys",
				logger.Err(err),
			)
			return
		}

		var list struct {
			APIKeys []struct {
				AccessKey   string `json:"access_key"`
				Description string `json:"description"`
			} `json:"api_keys"`
			TotalCount int `json:"total_count"`
		}
		if err := json.Unmarshal(respBody, &list); err != nil {
			d.logger.Warn("could not parse API key listing while sweeping orphaned rotation keys",
				logger.Err(err),
			)
			return
		}

		for _, key := range list.APIKeys {
			if key.Description != stamp || key.AccessKey == "" {
				continue
			}
			d.logger.Warn("deleting an orphaned management key from a previous rotation attempt",
				logger.String("access_key", truncateID(key.AccessKey, 8)),
			)
			delReq := httputil.HTTPRequest{
				Method:     http.MethodDelete,
				URL:        d.iamKeyURL(key.AccessKey),
				Headers:    map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
				OKStatuses: []int{http.StatusNoContent, http.StatusOK},
			}
			if _, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, delReq, scalewayRetryConfig()); err != nil && !isScalewayNotFound(err) {
				d.logger.Warn("could not delete an orphaned management key",
					logger.Err(err),
					logger.String("access_key", truncateID(key.AccessKey, 8)),
				)
			}
		}

		if len(list.APIKeys) < scalewayListPageSize || page*scalewayListPageSize >= list.TotalCount {
			return
		}
	}
}

// CommitRotation activates the new management key in driver state.
func (d *ScalewayDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	d.credSource.Config = newConfig

	d.logger.Info("committed rotated management key",
		logger.String("new_access_key", truncateID(credential.GetString(newConfig, "management_access_key", ""), 8)),
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

	deleteReq := httputil.HTTPRequest{
		Method:     http.MethodDelete,
		URL:        d.iamKeyURL(oldAccessKey),
		Headers:    map[string]string{"X-Auth-Token": managementKey, "Accept": "application/json"},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK},
	}

	_, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, deleteReq, scalewayRetryConfig())
	if err != nil {
		// Already gone is the outcome this wanted. Anything else — including a bare
		// 404 from a mistyped iam_api_path — is returned rather than swallowed: the
		// old management key carries no expiry, so reporting a failed delete as
		// success would leave a fully privileged credential alive indefinitely.
		if isScalewayNotFound(err) {
			d.logger.Info("old management key was already gone",
				logger.String("access_key", truncateID(oldAccessKey, 8)),
			)
			return nil
		}
		d.logger.Warn("failed to delete old management key during cleanup",
			logger.Err(err),
			logger.String("access_key", truncateID(oldAccessKey, 8)),
		)
		return fmt.Errorf("failed to delete old management key: %w", err)
	}

	d.logger.Info("deleted old management key",
		logger.String("access_key", truncateID(oldAccessKey, 8)),
	)

	return nil
}

// VerifySpec validates that the spec's credentials are functional.
func (d *ScalewayDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")

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
	httpReq := httputil.HTTPRequest{
		Method: http.MethodGet,
		URL:    d.iamKeyURL(accessKey),
		Headers: map[string]string{
			"X-Auth-Token": secretKey,
			"Accept":       "application/json",
		},
	}

	_, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, scalewayRetryConfig())
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
