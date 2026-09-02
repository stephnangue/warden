package drivers

import (
	"context"
	"encoding/base64"
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

// DefaultElasticActivationDelay is the default wait period for Elasticsearch
// API key propagation. Elasticsearch propagation is typically near-instant
// within a cluster, so a short 10-second default is used.
// Configurable via activation_delay in source config.
const DefaultElasticActivationDelay = 10 * time.Second

// elasticMaxResponseBodySize limits response body reads to prevent OOM
const elasticMaxResponseBodySize = 1 << 20 // 1MB

// elasticSweepPageSize bounds the orphan sweep's result set. The sweep runs
// against one cluster principal's rotation keys, where a handful is already a
// symptom; the cap is here so a pathological cluster cannot answer with more
// than elasticMaxResponseBodySize and turn the read itself into the failure.
const elasticSweepPageSize = 100

// Compile-time interface assertions
var _ credential.SourceDriver = (*ElasticDriver)(nil)
var _ credential.Rotatable = (*ElasticDriver)(nil)
var _ credential.SpecVerifier = (*ElasticDriver)(nil)

// ElasticDriver mints credentials from Elasticsearch clusters.
// It creates API keys via the /_security/api_key endpoint and supports
// rotation of the driver's own source API key.
//
// The driver's source credentials (a pre-encoded API key) are used for:
// - Minting new API keys for credential specs
// - Rotating the source API key via the Security API
type ElasticDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// HTTP client for Elasticsearch API calls
	httpClient *http.Client

	// configMu guards every read of credSource.Config as well as the discovered
	// fields below, because rotation replaces the whole config map while requests
	// are in flight on this shared driver.
	//
	// Methods holding it must call the ...With variants, which take the snapshot
	// as an argument: the lock is not reentrant, and both rotation stages issue
	// HTTP requests while holding it.
	configMu sync.RWMutex

	// sourceAPIKeyID is the ID portion of the source API key, and sourceUsername
	// the cluster principal that key authenticates as. The id is what rotation
	// cleans up; the username is what bounds the orphan sweep. Both are
	// discovered at Create and refreshed on commit.
	// Protected by configMu.
	sourceAPIKeyID string
	sourceUsername string
}

// elasticAuth is the credential one request authenticates with, snapshotted out
// of the config so a request in flight is unaffected by a rotation committing
// underneath it.
type elasticAuth struct {
	baseURL string
	encoded string
}

// elasticIdentity is what the cluster says about the key it just authenticated.
type elasticIdentity struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
	APIKey   struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"api_key"`
}

// ElasticDriverFactory creates ElasticDriver instances
type ElasticDriverFactory struct{}

// Type returns the driver type
func (f *ElasticDriverFactory) Type() string {
	return credential.SourceTypeElastic
}

// ValidateConfig validates Elasticsearch driver configuration using declarative schema
func (f *ElasticDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("elastic_url").
			Required().
			Custom(func(v string) error {
				skipTLS := credential.GetBool(config, "tls_skip_verify", false)
				if !strings.HasPrefix(v, "https://") && !(strings.HasPrefix(v, "http://") && skipTLS) {
					return fmt.Errorf("elastic_url must use https scheme, got: %s", v)
				}
				parsed, err := url.Parse(v)
				if err != nil {
					return fmt.Errorf("elastic_url is not a valid URL: %w", err)
				}
				// Past the scheme prefix, Parse accepts almost anything — "https://"
				// alone parses cleanly — so without this the validator passes a value
				// every request will then fail on.
				if parsed.Host == "" {
					return fmt.Errorf("elastic_url must include a host, got: %s", v)
				}
				return nil
			}).
			Describe("Elasticsearch cluster URL").
			Example("https://my-cluster.es.us-east-1.aws.cloud.es.io"),

		credential.StringField("api_key").
			Required().
			Describe("Pre-encoded Elasticsearch API key (base64 of id:api_key)").
			Example("dXNlcjpwYXNzd29yZA=="),

		credential.StringField("api_key_id").
			Describe("API key ID (optional, extracted from api_key if omitted)").
			Example("VuaCfGcBCdbkQm-e5aOx"),

		credential.StringField("activation_delay").
			Custom(func(v string) error {
				if _, err := time.ParseDuration(v); err != nil {
					return fmt.Errorf("activation_delay must be a valid duration: %w", err)
				}
				return nil
			}).
			Describe("Wait period for API key propagation during rotation (default: 10s)").
			Example("10s"),

		credential.StringField("key_name_prefix").
			Describe("Prefix for generated API key names (default: warden)").
			Example("warden"),

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
func (f *ElasticDriverFactory) SensitiveConfigFields() []string {
	return []string{"api_key", "ca_data"}
}

// InferCredentialType returns the credential type for Elasticsearch sources.
func (f *ElasticDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new ElasticDriver
func (f *ElasticDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &ElasticDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeElastic,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeElastic),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	encoded := credential.GetString(config, "api_key", "")

	// Extract API key ID from pre-encoded value if not explicitly provided
	decodedID, decodeErr := decodeElasticAPIKeyID(encoded)
	apiKeyID := credential.GetString(config, "api_key_id", "")
	if apiKeyID == "" {
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to extract API key ID from encoded api_key: %w", decodeErr)
		}
		apiKeyID = decodedID
	} else if decodeErr == nil && apiKeyID != decodedID {
		// An id set by hand wins over the decoded one, and nothing downstream
		// re-derives it — so a typo here is spent on rotation cleanup, which
		// invalidates whatever key that id names. Catch the disagreement while
		// both values are still in hand.
		return nil, fmt.Errorf("api_key_id %q does not match the id encoded in api_key (%q); omit api_key_id to use the encoded one",
			truncateID(apiKeyID, 8), truncateID(decodedID, 8))
	}

	// Verify source credentials
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Snapshotting without the lock is safe here and only here: nothing else can
	// reach this driver until Create returns it.
	identity, err := driver.verifyAuthenticationWith(ctx, driver.authSnapshotLocked())
	if err != nil {
		return nil, fmt.Errorf("Elasticsearch authentication failed: %w", err)
	}

	// The cluster is the authority on which key just authenticated. Checking the
	// configured id against it catches the case the decode cannot: an api_key_id
	// that agrees with a stale api_key, both of them naming a key this source no
	// longer authenticates as.
	if identity.APIKey.ID != "" && apiKeyID != identity.APIKey.ID {
		return nil, fmt.Errorf("configured api_key_id %q is not the key the cluster authenticated (%q)",
			truncateID(apiKeyID, 8), truncateID(identity.APIKey.ID, 8))
	}

	driver.sourceAPIKeyID = apiKeyID
	driver.sourceUsername = identity.Username

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential creates a new Elasticsearch API key via POST /_security/api_key.
//
// Spec config fields:
//   - key_name: Override for the generated key name (optional)
//   - role_descriptors: JSON string of role descriptors (optional)
//   - expiration: Key expiration duration, e.g. "30d" (optional)
func (d *ElasticDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.configMu.RLock()
	auth := d.authSnapshotLocked()
	prefix := credential.GetString(d.credSource.Config, "key_name_prefix", "warden")
	d.configMu.RUnlock()

	keyName := credential.GetString(spec.Config, "key_name", fmt.Sprintf("%s-%s-%d", prefix, spec.Name, time.Now().Unix()))

	reqBody := map[string]interface{}{
		"name": keyName,
		"metadata": map[string]interface{}{
			"managed_by": "warden",
			"spec":       spec.Name,
		},
	}

	// Parse optional role_descriptors from spec config
	if rdJSON := credential.GetString(spec.Config, "role_descriptors", ""); rdJSON != "" {
		var roleDescriptors map[string]interface{}
		if err := json.Unmarshal([]byte(rdJSON), &roleDescriptors); err != nil {
			return nil, nil, 0, "", fmt.Errorf("invalid role_descriptors JSON: %w", err)
		}
		reqBody["role_descriptors"] = roleDescriptors
	}

	// A key created without an expiration never expires, so an empty value is
	// refused rather than passed through as absent. Spec validation rejects it at
	// write time; this holds for a spec that predates that check.
	expiration, present := spec.Config["expiration"]
	if present && expiration == "" {
		return nil, nil, 0, "", fmt.Errorf("spec sets an empty expiration; omit it to take the 1h default, or give a lifetime such as 24h")
	}
	if !present {
		expiration = "1h"
	}
	reqBody["expiration"] = expiration

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := d.doElasticRequestWith(ctx, auth, http.MethodPost, "/_security/api_key", body, defaultElasticRetryConfig())
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to create Elasticsearch API key: %w", err)
	}

	var createResp struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		APIKey     string `json:"api_key"`
		Encoded    string `json:"encoded"`
		Expiration *int64 `json:"expiration"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Encoded == "" || createResp.ID == "" {
		return nil, nil, 0, "", fmt.Errorf("create API key response missing encoded or id field")
	}

	rawData := map[string]interface{}{
		"api_key": createResp.Encoded,
	}

	metadata := map[string]interface{}{
		"key_id":   createResp.ID,
		"key_name": createResp.Name,
	}

	// Compute TTL from expiration timestamp
	var ttl time.Duration
	if createResp.Expiration != nil {
		expiryTime := time.UnixMilli(*createResp.Expiration)
		ttl = time.Until(expiryTime)
		if ttl < 0 {
			ttl = 0
		}
	}

	leaseID := "elastic:" + createResp.ID

	if d.logger != nil {
		d.logger.Debug("minted Elasticsearch API key",
			logger.String("spec", spec.Name),
			logger.String("key_name", createResp.Name),
			logger.String("key_id", truncateID(createResp.ID, 8)),
		)
	}

	return rawData, metadata, ttl, leaseID, nil
}

// Revoke invalidates an Elasticsearch API key via DELETE /_security/api_key.
func (d *ElasticDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	// Extract key ID from "elastic:<id>" format
	keyID := strings.TrimPrefix(leaseID, "elastic:")
	if keyID == leaseID || keyID == "" {
		return fmt.Errorf("invalid lease ID format: %s", leaseID)
	}

	d.configMu.RLock()
	auth := d.authSnapshotLocked()
	d.configMu.RUnlock()

	if err := d.invalidateKeys(ctx, auth, []string{keyID}); err != nil {
		return fmt.Errorf("failed to invalidate Elasticsearch API key %s: %w", truncateID(keyID, 8), err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Elasticsearch API key",
			logger.String("key_id", truncateID(keyID, 8)),
		)
	}

	return nil
}

// Type returns the driver type
func (d *ElasticDriver) Type() string {
	return credential.SourceTypeElastic
}

// Cleanup releases resources
func (d *ElasticDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the source credentials are functional by calling
// the Elasticsearch authenticate endpoint.
func (d *ElasticDriver) VerifySpec(ctx context.Context, _ *credential.CredSpec) error {
	d.configMu.RLock()
	auth := d.authSnapshotLocked()
	d.configMu.RUnlock()

	if _, err := d.verifyAuthenticationWith(ctx, auth); err != nil {
		return fmt.Errorf("Elasticsearch spec verification failed: %w", err)
	}
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source API Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source API key.
// Rotation requires the source API key to have the manage_api_key or
// manage_own_api_key cluster privilege.
func (d *ElasticDriver) SupportsRotation() bool {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.sourceAPIKeyID != ""
}

// PrepareRotation creates a new API key using the current source credentials.
// Returns activateAfter to allow time for cluster propagation.
func (d *ElasticDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	if d.sourceAPIKeyID == "" {
		return nil, nil, 0, fmt.Errorf("cannot rotate: source API key ID not discovered")
	}

	auth := d.authSnapshotLocked()
	prefix := credential.GetString(d.credSource.Config, "key_name_prefix", "warden")
	oldAPIKeyID := d.sourceAPIKeyID

	// Reclaim keys earlier cycles lost before creating another. A rotation that
	// is prepared and then abandoned — the persist fails, the commit fails, the
	// node restarts before activation — leaves a key with this source's full
	// privileges that nothing records and nothing will ever revoke.
	//
	// The sweep runs here, at the top of prepare, because that is the one moment
	// when any staged key that exists is necessarily from an abandoned cycle:
	// prepare is what creates the legitimate one, and it has not run yet.
	d.sweepRotationOrphans(ctx, auth, oldAPIKeyID)

	// Create new API key via the Security API
	reqBody, err := json.Marshal(map[string]interface{}{
		"name": fmt.Sprintf("%s-source-rotated-%d", prefix, time.Now().Unix()),
		"metadata": map[string]interface{}{
			"managed_by": "warden",
			"purpose":    "source_rotation",
			// Lineage, for the operator reading the key list in Kibana: this key
			// exists to replace that one. The sweep does not match on it — a key is
			// orphaned precisely when its cycle was abandoned, so its own stamp is
			// never asked for again.
			"replacing": oldAPIKeyID,
		},
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := d.doElasticRequestWith(ctx, auth, http.MethodPost, "/_security/api_key", reqBody, elasticCreateRetryConfig())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new source API key: %w", err)
	}

	var createResp struct {
		ID      string `json:"id"`
		Encoded string `json:"encoded"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Encoded == "" || createResp.ID == "" {
		return nil, nil, 0, fmt.Errorf("create API key response missing encoded or id")
	}

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["api_key"] = createResp.Encoded
	newConfig["api_key_id"] = createResp.ID

	cleanupConfig := map[string]string{
		"api_key_id": oldAPIKeyID,
	}

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultElasticActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source API key rotation",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
			logger.String("new_key_id", truncateID(createResp.ID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver.
//
// There is no rollback. The manager persists newConfig before calling this
// (see activateSource), so the stored config already names the new key; putting
// the in-memory config back would leave this instance authenticating as a key
// storage no longer records, and the next cycle would then mint a replacement
// for it — a fresh untracked key every failed cycle. Failing forward keeps the
// two in agreement, and a restart rebuilds the driver from what was stored.
func (d *ElasticDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	d.credSource.Config = newConfig
	d.sourceAPIKeyID = credential.GetString(newConfig, "api_key_id", "")

	identity, err := d.verifyAuthenticationWith(ctx, d.authSnapshotLocked())
	if err != nil {
		return fmt.Errorf("failed to authenticate with new API key: %w", err)
	}
	d.sourceUsername = identity.Username

	if d.logger != nil {
		d.logger.Debug("committed source API key rotation",
			logger.String("new_key_id", truncateID(d.sourceAPIKeyID, 8)),
		)
	}

	return nil
}

// CleanupRotation invalidates the old API key
func (d *ElasticDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAPIKeyID := cleanupConfig["api_key_id"]
	if oldAPIKeyID == "" {
		return nil
	}

	d.configMu.RLock()
	auth := d.authSnapshotLocked()
	d.configMu.RUnlock()

	if err := d.invalidateKeys(ctx, auth, []string{oldAPIKeyID}); err != nil {
		return fmt.Errorf("failed to invalidate old API key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old API key",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// warn logs a recoverable problem, if this driver has a logger at all. The
// best-effort paths below — a sweep that could not list, an invalidation the
// cluster had nothing to invalidate — report only this way, and a driver built
// without a logger must not turn that report into a panic.
func (d *ElasticDriver) warn(msg string, fields ...logger.TypedField) {
	if d.logger != nil {
		d.logger.Warn(msg, fields...)
	}
}

// authSnapshotLocked copies out what a request needs to authenticate. Callers
// hold configMu; the returned value is safe to use after releasing it.
//
// The trailing slash comes off here rather than being resolved once at Create,
// so that the config stays the single source of truth for where the cluster is.
// A URL cached at construction is a field that silently disagrees with the
// config every time one is set without the other.
func (d *ElasticDriver) authSnapshotLocked() elasticAuth {
	return elasticAuth{
		baseURL: strings.TrimRight(credential.GetString(d.credSource.Config, "elastic_url", ""), "/"),
		encoded: credential.GetString(d.credSource.Config, "api_key", ""),
	}
}

// verifyAuthenticationWith calls GET /_security/_authenticate and returns what
// the cluster says about the key that authenticated.
func (d *ElasticDriver) verifyAuthenticationWith(ctx context.Context, auth elasticAuth) (elasticIdentity, error) {
	var identity elasticIdentity

	respBody, _, err := d.doElasticRequestWith(ctx, auth, http.MethodGet, "/_security/_authenticate", nil, defaultElasticRetryConfig())
	if err != nil {
		return identity, fmt.Errorf("authentication verification failed: %w", err)
	}

	if err := json.Unmarshal(respBody, &identity); err != nil {
		return identity, fmt.Errorf("failed to decode authenticate response: %w", err)
	}

	if identity.Username == "" {
		return identity, fmt.Errorf("authenticate response missing username")
	}

	// A disabled principal still answers _authenticate. Reading only the username
	// would call such a source healthy at create and at every verification after
	// it, while every mint it is asked for fails.
	if !identity.Enabled {
		return identity, fmt.Errorf("the authenticated principal %q is disabled", identity.Username)
	}

	return identity, nil
}

// sweepRotationOrphans invalidates rotation keys left behind by cycles that
// never completed. Best-effort: a failure here must not stop the rotation that
// is about to run, so it is logged rather than returned.
//
// Two things bound what it will touch. The query is scoped to the cluster
// principal this source authenticates as, so it cannot reach the keys of
// another source — or another deployment — sharing the cluster. And the key in
// use is excluded by id, never by name or by stamp, so a key whose metadata is
// missing or unexpected cannot be mistaken for a sweepable one.
//
// Two sources authenticating as the same principal would still sweep each
// other. That configuration is already fatal without any sweep, since either
// one's cleanup invalidates the key the other holds.
func (d *ElasticDriver) sweepRotationOrphans(ctx context.Context, auth elasticAuth, liveKeyID string) {
	if d.sourceUsername == "" || liveKeyID == "" {
		return
	}

	query, err := json.Marshal(map[string]interface{}{
		"size": elasticSweepPageSize,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{"term": map[string]interface{}{"username": d.sourceUsername}},
					{"term": map[string]interface{}{"invalidated": false}},
					{"term": map[string]interface{}{"metadata.managed_by": "warden"}},
					{"term": map[string]interface{}{"metadata.purpose": "source_rotation"}},
				},
			},
		},
	})
	if err != nil {
		return
	}

	respBody, _, err := d.doElasticRequestWith(ctx, auth, http.MethodPost, "/_security/_query/api_key", query, defaultElasticRetryConfig())
	if err != nil {
		d.warn("could not list rotation keys to reclaim orphans; continuing with the rotation",
			logger.Err(err))
		return
	}

	var queryResp struct {
		APIKeys []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"api_keys"`
	}
	if err := json.Unmarshal(respBody, &queryResp); err != nil {
		d.warn("could not decode the rotation key listing; continuing with the rotation",
			logger.Err(err))
		return
	}

	var orphans []string
	for _, key := range queryResp.APIKeys {
		if key.ID != "" && key.ID != liveKeyID {
			orphans = append(orphans, key.ID)
		}
	}
	if len(orphans) == 0 {
		return
	}

	if err := d.invalidateKeys(ctx, auth, orphans); err != nil {
		d.warn("could not reclaim abandoned rotation keys; they remain live at the cluster",
			logger.Int("count", len(orphans)), logger.Err(err))
		return
	}

	if d.logger != nil {
		d.logger.Info("reclaimed abandoned rotation keys",
			logger.Int("count", len(orphans)))
	}
}

// elasticInvalidateResponse is the body DELETE /_security/api_key answers with.
// The cluster reports per-key outcomes here and still returns 200, so the body
// is the only place a refusal shows up.
type elasticInvalidateResponse struct {
	Invalidated           []string `json:"invalidated_api_keys"`
	PreviouslyInvalidated []string `json:"previously_invalidated_api_keys"`
	ErrorCount            int      `json:"error_count"`
	ErrorDetails          []struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error_details"`
}

// invalidateKeys invalidates the given key ids and reads the outcome out of the
// response body.
//
// A 200 is not success here. The cluster answers per key, so a refusal — a key
// this principal may not manage, most often — arrives as error_count on an
// otherwise ordinary response. Taking the status alone is what let a rotation
// report a completed cleanup while the old source key stayed live.
//
// A key that is already gone is success, in both of the shapes that takes: the
// cluster lists it as previously invalidated, or reports it as not found. That
// tolerance matters more than it looks — cleanup failures are retried daily for
// a week before being abandoned, so treating a key nobody can find as a failure
// buys a week of retries for a request that can never succeed.
func (d *ElasticDriver) invalidateKeys(ctx context.Context, auth elasticAuth, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	reqBody, err := json.Marshal(map[string]interface{}{"ids": ids})
	if err != nil {
		return fmt.Errorf("failed to marshal invalidate request: %w", err)
	}

	respBody, _, err := d.doElasticRequestWith(ctx, auth, http.MethodDelete, "/_security/api_key", reqBody, defaultElasticRetryConfig())
	if err != nil {
		return err
	}

	var resp elasticInvalidateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to decode invalidate response: %w", err)
	}

	var refusals []string
	for _, detail := range resp.ErrorDetails {
		if strings.Contains(detail.Type, "resource_not_found") {
			continue
		}
		refusals = append(refusals, fmt.Sprintf("%s: %s", detail.Type, detail.Reason))
	}
	if len(refusals) > 0 {
		return fmt.Errorf("the cluster refused %d of %d invalidations: %s",
			len(refusals), len(ids), strings.Join(refusals, "; "))
	}

	accounted := make(map[string]struct{}, len(resp.Invalidated)+len(resp.PreviouslyInvalidated))
	for _, id := range resp.Invalidated {
		accounted[id] = struct{}{}
	}
	for _, id := range resp.PreviouslyInvalidated {
		accounted[id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := accounted[id]; !ok {
			// Neither invalidated nor refused: the cluster has no such key. Nothing
			// is left live, so this is not a failure to retry — but it is worth
			// saying, since the likeliest cause is an id that names nothing.
			d.warn("Elasticsearch reported no outcome for an invalidated key; it does not exist at the cluster",
				logger.String("key_id", truncateID(id, 8)))
		}
	}

	return nil
}

// doElasticRequestWith executes an HTTP request against the cluster with an
// explicit credential.
//
// The credential is passed in rather than read from the config here, because
// both rotation stages call this while holding configMu and the lock is not
// reentrant — reading it here would deadlock them. Passing it also means a
// request that started before a rotation finishes with the key it started with.
func (d *ElasticDriver) doElasticRequestWith(ctx context.Context, auth elasticAuth, method, path string, body []byte, retry httputil.HTTPRetryConfig) ([]byte, int, error) {
	headers := map[string]string{
		"Authorization": "ApiKey " + auth.encoded,
		"Accept":        "application/json",
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	return httputil.ExecuteWithRetry(ctx, d.httpClient, httputil.HTTPRequest{
		Method:  method,
		URL:     auth.baseURL + path,
		Body:    body,
		Headers: headers,
	}, retry)
}

// defaultElasticRetryConfig returns the standard retry configuration for Elasticsearch API calls.
func defaultElasticRetryConfig() httputil.HTTPRetryConfig {
	return httputil.HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       elasticMaxResponseBodySize,
		RetryableStatuses: []int{429, 500}, // 500 = wildcard for all 5xx (see httputil.ExecuteWithRetry)
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}

// elasticCreateRetryConfig is used for the rotation's key creation, which is not
// idempotent and must not be retried.
//
// ExecuteWithRetry retries a transport error before it ever consults
// RetryableStatuses, and a connection reset or a timeout reading the response —
// the likeliest way to lose an acknowledgement for a request that arrived — is
// exactly that. Retrying produced up to three live keys of which Warden learned
// one, and a rotation key carries no expiration, so each was permanent.
//
// Failing a rate-limited create is the better trade: the manager retries the
// whole cycle on its own schedule, and a deferred rotation costs less than a key
// nobody can find. The per-spec mint keeps the retries, because the key it
// strands carries an expiration and dies on its own.
func elasticCreateRetryConfig() httputil.HTTPRetryConfig {
	return httputil.HTTPRetryConfig{
		MaxAttempts: 1,
		MaxBodySize: elasticMaxResponseBodySize,
	}
}

// decodeElasticAPIKeyID extracts the API key ID from a pre-encoded API key.
// The encoded format is base64(id:api_key), so we decode and split on ':'.
func decodeElasticAPIKeyID(encoded string) (string, error) {
	if encoded == "" {
		return "", fmt.Errorf("encoded API key is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe encoding as fallback
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("failed to base64-decode API key: %w", err)
		}
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", fmt.Errorf("decoded API key does not match expected id:api_key format")
	}

	return parts[0], nil
}
