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

// DefaultIBMActivationDelay is the default wait period for IBM Cloud API key propagation.
// IBM Cloud IAM key propagation is typically fast (seconds), but a 2-minute default
// provides a safe buffer for eventual consistency. Configurable via activation_delay.
const DefaultIBMActivationDelay = 2 * time.Minute

// ibmMaxResponseBodySize limits response body reads to prevent OOM
const ibmMaxResponseBodySize = 1 << 20 // 1MB

// defaultIBMIAMEndpoint is the default IBM Cloud IAM endpoint
const defaultIBMIAMEndpoint = "https://iam.cloud.ibm.com"

// defaultIBMAccessKeysChainTTL bounds how long a served COS pair stays cached when
// the spec sets no secret_cache_ttl. The pair has no expiry of its own, so this is
// only how long Warden goes before walking the chain again to see whether the
// referenced spec now yields a different one.
const defaultIBMAccessKeysChainTTL = 30 * time.Minute

// Compile-time interface assertions
var _ credential.SourceDriver = (*IBMDriver)(nil)
var _ credential.Rotatable = (*IBMDriver)(nil)
var _ credential.SpecVerifier = (*IBMDriver)(nil)
var _ credential.ChainedSecretMinter = (*IBMDriver)(nil)

// IBMDriver mints credentials from IBM Cloud services.
// It exchanges an IBM Cloud API key for IAM bearer tokens.
//
// The driver's source credentials (API key) are used for:
// - Minting IAM bearer tokens via the IAM token endpoint
// - Rotating the source API key via the IAM Identity Services API
type IBMDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Token cache for IAM bearer tokens
	tokenCache *TokenCache

	// HTTP client for IBM Cloud API calls
	httpClient *http.Client

	// authMu serializes rotation and protects iamID/apiKeyID/discoveredAccountID. It
	// is held across the upstream calls a rotation makes, which can run to minutes
	// under retry.
	authMu sync.Mutex

	// configMu guards credSource.Config, which CommitRotation replaces wholesale.
	// It is deliberately NOT authMu: a mint reads its credentials out of this map, and
	// sharing the rotation lock would park every concurrent mint behind that rotation's
	// HTTP work. Held only across the map access itself, never across an upstream call.
	configMu sync.RWMutex

	// iamID is the IAM identity associated with the source API key
	// Discovered at creation time, required for rotation
	// Protected by authMu
	iamID string

	// apiKeyID is the unique ID of the current source API key
	// Used for cleanup during rotation
	// Protected by authMu
	apiKeyID string

	// discoveredAccountID is the account the source API key belongs to, learned from
	// discovery when the operator did not configure one. It is held here rather than
	// written back into credSource.Config because that map is not the driver's own:
	// the factory is handed the config store's map by reference, and the store serves
	// that same map to readers who take no driver lock. Writing to it raced them.
	// Protected by authMu
	discoveredAccountID string
}

// IBMDriverFactory creates IBMDriver instances
type IBMDriverFactory struct{}

// Type returns the driver type
func (f *IBMDriverFactory) Type() string {
	return credential.SourceTypeIBM
}

// validateIBMChainedConfig rejects source config that contradicts chaining.
//
// A chained source stores no api key: keeping one would leave a source that reads
// as keyless while storing the very secret chaining exists to remove. account_id
// and activation_delay go for a different reason — their only consumer is rotation
// (the account a replacement key is created in, and how long to overlap it), which
// a chained source hands to whoever owns the referenced spec, so leaving them is
// dead config describing a job this source no longer does.
func validateIBMChainedConfig(config map[string]string) error {
	if credential.GetString(config, credential.ConfigSecretSpec, "") == "" {
		return nil
	}
	for _, key := range []string{"api_key", "account_id", "activation_delay"} {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s must be omitted when %s is set; the api key is supplied by the referenced spec, and rotation belongs to whoever owns it",
				key, credential.ConfigSecretSpec)
		}
	}
	return nil
}

// ValidateConfig validates IBM Cloud driver configuration using declarative schema
func (f *IBMDriverFactory) ValidateConfig(config map[string]string) error {
	if err := validateIBMChainedConfig(config); err != nil {
		return err
	}

	return credential.ValidateSchema(config,
		// Not Required(): a source serving only access_keys specs never performs the
		// grant, so demanding a key it will not use would be config kept for nothing,
		// and a chained source is refused one outright. VerifySpec is what actually
		// holds an iam_token spec to a source that can mint for it.
		credential.StringField("api_key").
			Describe("IBM Cloud API key (required for iam_token specs, unless the source sets secret_spec)").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("account_id").
			Describe("IBM Cloud account ID (optional, discovered from API key if omitted)").
			Example("abcdef1234567890abcdef1234567890"),

		credential.StringField(credential.ConfigSecretSpec).
			Describe("Cred spec yielding the IAM api key, instead of storing one here").
			Example("ibm-api-key"),

		credential.StringField(credential.ConfigSecretField).
			Describe("Field of the referenced credential holding the api key (defaults: 'api_key', then 'apikey')").
			Example("api_key"),

		credential.DurationField(credential.ConfigSecretCacheTTL).
			Describe("How long to reuse the fetched api key before re-fetching (default: no caching)").
			Example("30m"),

		// Read by PrepareRotation but never declared until now, so a typo'd duration
		// was silently replaced by the default. The chained validator refuses it by
		// name, which makes it a key that has to be documented.
		credential.DurationField("activation_delay").
			Describe("Overlap before a rotated api key becomes active (default: 2m)").
			Example("2m"),

		credential.StringField("iam_endpoint").
			Custom(func(v string) error {
				skipTLS := credential.GetBool(config, "tls_skip_verify", false)
				if !strings.HasPrefix(v, "https://") && !(strings.HasPrefix(v, "http://") && skipTLS) {
					return fmt.Errorf("iam_endpoint must use https scheme, got: %s", v)
				}
				if _, err := url.Parse(v); err != nil {
					return fmt.Errorf("iam_endpoint is not a valid URL: %w", err)
				}
				return nil
			}).
			Describe("IBM Cloud IAM endpoint (optional, defaults to https://iam.cloud.ibm.com)").
			Example("https://iam.cloud.ibm.com"),

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
func (f *IBMDriverFactory) SensitiveConfigFields() []string {
	return []string{"api_key", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *IBMDriverFactory) InferCredentialType(specConfig map[string]string) (string, error) {
	mintMethod := specConfig["mint_method"]
	switch mintMethod {
	case "iam_token", "":
		return credential.TypeOAuthBearerToken, nil
	case "access_keys":
		return credential.TypeIBMCloudKeys, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// Create instantiates a new IBMDriver
func (f *IBMDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeIBM),
		tokenCache: NewTokenCache(),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	// A source without a stored key has nothing to probe and nothing to discover: a
	// chained source fetches its key per request, as the caller — and there is no
	// caller here — while a source serving only access_keys specs never performs the
	// grant at all. Both checks below exist to catch a bad stored key early; with no
	// stored key they could only refuse config that is absent on purpose. This
	// matters twice over, since Create is both the store's source connection test
	// and the path every lazy driver creation takes.
	if credential.GetString(config, "api_key", "") == "" {
		return driver, nil
	}

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := driver.acquireIAMToken(ctx); err != nil {
		return nil, fmt.Errorf("IBM Cloud authentication failed: %w", err)
	}

	// Discover API key details for rotation support
	if err := driver.discoverAPIKeyDetails(ctx); err != nil {
		// Non-fatal: rotation won't be available but minting still works
		if driver.logger != nil {
			driver.logger.Warn("failed to discover API key details, rotation will be disabled",
				logger.Err(err),
			)
		}
	}

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential mints credentials based on the spec's mint_method.
func (d *IBMDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A chained spec or source mints through MintFromSecret, which the minting layer
	// routes it to. Reaching here means the routing was bypassed, so fail closed
	// rather than falling back to a key this source may not even hold.
	if spec.Config[credential.ConfigSecretSpec] != "" || d.isChained() {
		return nil, nil, 0, "", fmt.Errorf("ibm: %s is set (credential chaining); this spec mints from fetched secret material, not directly",
			credential.ConfigSecretSpec)
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "iam_token")

	switch mintMethod {
	case "iam_token":
		return d.mintIAMToken(ctx, spec)
	case "access_keys":
		// Reached only when the spec named no reference: a chained spec is routed
		// to MintFromSecret instead. Without one there is no pair to serve, and
		// nothing here creates one.
		return nil, nil, 0, "", fmt.Errorf("ibm: an access_keys spec must set %s naming a spec that yields its access_key_id and secret_access_key; the pair is served from that material, never minted here",
			credential.ConfigSecretSpec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for IBM driver; use 'iam_token' or 'access_keys'", mintMethod)
	}
}

// mintIAMToken exchanges the source API key for an IAM bearer token
func (d *IBMDriver) mintIAMToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// The schema no longer demands a key, so this is where its absence is reported.
	// Naming the alternative matters: "api_key is empty" from the exchange helper
	// tells an operator nothing about the reference they could have set instead.
	if d.getAPIKey() == "" {
		return nil, nil, 0, "", fmt.Errorf("api_key is required on source config, or a %s naming a spec that yields it",
			credential.ConfigSecretSpec)
	}

	token, expiry, err := d.getIAMToken(ctx)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire IBM IAM token: %w", err)
	}

	ttl := time.Until(expiry)
	rawData := map[string]interface{}{
		"access_token": token,
	}

	if d.logger != nil {
		d.logger.Debug("minted IBM IAM bearer token",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID — IAM tokens expire naturally and cannot be revoked
	return rawData, nil, ttl, "", nil
}

// MintFromSecret mints from secret material fetched through credential chaining.
// What the material means depends on the mint method, so each arm reads it
// differently: iam_token receives the api key the token grant is made with,
// access_keys receives the COS HMAC pair itself.
func (d *IBMDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	switch mintMethod := credential.GetString(spec.Config, "mint_method", ""); mintMethod {
	case "iam_token", "":
		return d.mintIAMTokenFromSecret(ctx, spec, material)
	case "access_keys":
		return d.mintAccessKeysFromSecret(spec, material)
	default:
		// mint_method is validated at spec create, so reaching here means config
		// drifted. The material's meaning is defined by the method, so with an
		// unknown one there is no safe way to spend it.
		return nil, nil, 0, "", fmt.Errorf("ibm: credential chaining supports mint_method=iam_token or access_keys, got %q", mintMethod)
	}
}

// mintIAMTokenFromSecret performs the apikey grant with an api key fetched through
// the chain, for a source that stores none.
//
// It deliberately does NOT call getIAMToken. That cache files every bearer under
// one fixed key, which is right when a single stored key mints every token — but a
// fetched key is resolved per caller, and the referenced spec may legitimately hand
// different callers different keys, so the shared slot would serve one caller's IAM
// token to another. Per-caller reuse lives where it is safe: the minting layer
// caches the finished credential per session token, and the fetched key per agent
// identity.
func (d *IBMDriver) mintIAMTokenFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	apiKey := material.Secret()

	// Fall back to conventional names ONLY when no field was resolved. A field that
	// resolved to nothing is a misconfigured secret_field — say so, rather than
	// silently authenticating with some other value from the payload.
	if apiKey == "" && material.Field == "" {
		if apiKey = material.Data["api_key"]; apiKey == "" {
			apiKey = material.Data["apikey"]
		}
	}
	if apiKey == "" {
		if material.Field != "" {
			return nil, nil, 0, "", fmt.Errorf("ibm: %s %q is empty or absent in the fetched secret material: %w",
				credential.ConfigSecretField, material.Field, credential.ErrChainedSecretIncomplete)
		}
		return nil, nil, 0, "", fmt.Errorf("ibm: no api key in fetched secret material (set %s, or store it under 'api_key'): %w",
			credential.ConfigSecretField, credential.ErrChainedSecretIncomplete)
	}

	token, expiry, status, err := exchangeIBMAPIKeyForIAMTokenWithStatus(ctx, d.httpClient, apiKey, d.getIAMEndpoint(), d.logger)
	if err != nil {
		// On the chained path an authentication refusal marks the fetched key as
		// possibly stale, so the minting layer evicts a cached copy and retries once
		// with a fresh fetch. IBM answers a bad, deleted or locked api key with 400
		// and a BXNIM error envelope, and the key is the only thing in this request
		// that varies per mint — the grant type is a constant — so a refusal is about
		// the credential or about nothing. Throttling and outages were already
		// retried and arrive with other statuses, unmapped: an IBM outage is not a
		// stale key, and a 404 is a mis-set iam_endpoint.
		switch status {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return nil, nil, 0, "", fmt.Errorf("ibm: IAM token endpoint rejected the chained api key: %w (%w)",
				credential.ErrChainedSecretRejected, err)
		}
		return nil, nil, 0, "", fmt.Errorf("failed to acquire IBM IAM token: %w", err)
	}

	ttl := time.Until(expiry)
	if d.logger != nil {
		d.logger.Debug("minted IBM IAM bearer token from fetched secret material",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID — IAM tokens expire naturally and cannot be revoked
	return map[string]interface{}{"access_token": token}, nil, ttl, "", nil
}

// mintAccessKeysFromSecret serves the COS HMAC pair a referenced spec yields: no
// request is made to IBM, nothing is created, and there is nothing to revoke.
func (d *IBMDriver) mintAccessKeysFromSecret(spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// The spec must name the reference itself. Routed here by a source-level one, the
	// material would be the api key that source authenticates with, not this
	// credential — and an operator's referenced payload may well carry both. Spec
	// create refuses that combination, but a source converted to chaining afterwards
	// is not re-validated against the specs already bound to it, so this is the guard
	// that actually holds.
	if spec.Config[credential.ConfigSecretSpec] == "" {
		return nil, nil, 0, "", fmt.Errorf("ibm: an access_keys spec must set its own %s naming a spec that yields its access_key_id and secret_access_key; this source's chained secret is its IAM api key, not this credential",
			credential.ConfigSecretSpec)
	}

	// Both halves are read by name, from IBM's own spelling for them — the
	// cos_hmac_keys fields of a service credential — so a pair stored from IBM's
	// export is read unrenamed. A payload using other names is projected by the
	// referenced spec's json_key_map, which is where that belongs.
	accessKeyID := material.Data["access_key_id"]
	secretAccessKey := material.Data["secret_access_key"]
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, nil, 0, "", fmt.Errorf("ibm: fetched secret material must hold both 'access_key_id' and 'secret_access_key' for access_keys: %w",
			credential.ErrChainedSecretIncomplete)
	}

	// Advisory TTL, no lease id: nothing was created, so nothing is revocable.
	// Making no request, this path can never be told the pair was rotated, so
	// without a TTL the credential would sit in cache for the caller's whole
	// session. The TTL only forces the chain to be walked again.
	ttl := credential.GetDuration(spec.Config, credential.ConfigSecretCacheTTL, 0)
	if ttl <= 0 {
		ttl = defaultIBMAccessKeysChainTTL
	}

	if d.logger != nil {
		d.logger.Debug("served IBM COS keys from fetched secret material",
			logger.String("spec", spec.Name),
			logger.String("ttl", ttl.String()),
		)
	}

	return map[string]interface{}{
		"access_key_id":     accessKeyID,
		"secret_access_key": secretAccessKey,
	}, nil, ttl, "", nil
}

// Revoke is a no-op for IBM credentials (IAM tokens expire naturally)
func (d *IBMDriver) Revoke(ctx context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("IBM IAM tokens expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *IBMDriver) Type() string {
	return credential.SourceTypeIBM
}

// Cleanup releases resources
func (d *IBMDriver) Cleanup(ctx context.Context) error {
	return nil
}

// VerifySpec validates that an IBM spec's configuration is functional. Called
// during spec creation/update only.
func (d *IBMDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	switch mintMethod := credential.GetString(spec.Config, "mint_method", "iam_token"); mintMethod {
	case "iam_token":
		// The grant runs with the source's api key, which the source schema no longer
		// demands — a source serving only access_keys specs has no use for one. This
		// is where that requirement actually lands, unless the source fetches its key
		// per request, in which case there is nothing to check until one is fetched.
		if d.isChained() {
			return nil
		}
		if d.getAPIKey() == "" {
			return fmt.Errorf("an iam_token spec needs api_key on its source, or a %s naming a spec that yields it",
				credential.ConfigSecretSpec)
		}
		// Verify the source API key can mint an IAM token
		if _, _, err := d.getIAMToken(ctx); err != nil {
			return fmt.Errorf("IBM spec verification failed: %w", err)
		}
		return nil

	case "access_keys":
		// Reached only if the spec named no reference; a chained spec skips
		// verification entirely. Without one there is no pair to serve, and this
		// path makes no request, so there is nothing else to check.
		if spec.Config[credential.ConfigSecretSpec] == "" {
			return fmt.Errorf("an access_keys spec must set %s naming a spec that yields its access_key_id and secret_access_key",
				credential.ConfigSecretSpec)
		}
		return nil

	default:
		return fmt.Errorf("unsupported mint_method: %s (expected iam_token or access_keys)", mintMethod)
	}
}

// ============================================================================
// Rotatable Interface Implementation (Source API Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source API key.
// Rotation requires the API key's IAM identity to have permission to create/delete API keys.
func (d *IBMDriver) SupportsRotation() bool {
	// The key lives at its source of truth, and whoever owns the referenced spec
	// rotates it there. On a chained source iamID is never discovered, so this would
	// be false anyway — stating it keeps the invariant independent of discovery.
	// Taken before authMu: isChained acquires configMu, and the driver's established
	// order is authMu then configMu, never the reverse.
	if d.isChained() {
		return false
	}

	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.iamID != ""
}

// PrepareRotation creates a new API key for the same IAM identity.
// Returns activateAfter to allow time for IBM Cloud propagation.
func (d *IBMDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	// Same ordering note as SupportsRotation: configMu is taken before authMu here,
	// never nested inside it.
	if d.isChained() {
		return nil, nil, 0, fmt.Errorf("rotation does not apply to a chained source (%s is set); the referenced spec's owner rotates the api key",
			credential.ConfigSecretSpec)
	}

	d.authMu.Lock()
	defer d.authMu.Unlock()

	if d.iamID == "" {
		return nil, nil, 0, fmt.Errorf("cannot rotate: IAM identity not discovered")
	}

	// Get IAM token using current API key
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get IAM token for rotation: %w", err)
	}

	// Create new API key for the same IAM identity
	newAPIKey, newAPIKeyID, err := d.createAPIKey(ctx, iamToken)
	if err != nil {
		return nil, nil, 0, err
	}

	oldAPIKeyID := d.apiKeyID

	// Build new config
	newConfig := d.configSnapshot()
	newConfig["api_key"] = newAPIKey

	cleanupConfig := map[string]string{
		"api_key_id": oldAPIKeyID,
	}

	// Rotation does not touch activation_delay, so the snapshot carries the live value.
	activateAfter := credential.GetDuration(newConfig, "activation_delay", DefaultIBMActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source API key rotation",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
			logger.String("new_key_id", truncateID(newAPIKeyID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver.
//
// Thread-safety: authMu is held across the whole swap, so the config write, the
// generation bump and the exchange that verifies the new key are one critical section
// and no mint can observe a half-applied rotation. The lock alone does not stop a token
// minted by the outgoing key from outliving the rotation, though — an exchange already
// in flight holds no lock. That is what the generation retired here is for, which
// iamToken re-checks before it stores.
func (d *IBMDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Save old config for rollback on failure
	oldConfig := d.configSnapshot()

	// Publish the new key and retire every token the old one minted
	d.swapConfig(newConfig)

	// Verify new credentials work
	if _, _, err := d.acquireIAMToken(ctx); err != nil {
		// Roll back, bumping the generation a second time: discovery may already have
		// cached a token minted by the key we are abandoning, and it is filed under the
		// current generation, so restoring the config alone would leave it readable.
		d.swapConfig(oldConfig)
		return fmt.Errorf("failed to authenticate with new API key: %w", err)
	}

	// Re-discover API key details with new key
	if err := d.discoverAPIKeyDetailsLocked(ctx); err != nil {
		d.swapConfig(oldConfig)
		return fmt.Errorf("failed to discover new API key details: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("committed source API key rotation",
			logger.String("new_key_id", truncateID(d.apiKeyID, 8)),
		)
	}

	return nil
}

// CleanupRotation deletes the old API key
func (d *IBMDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAPIKeyID := cleanupConfig["api_key_id"]
	if oldAPIKeyID == "" {
		return nil
	}

	// Get IAM token using current (new) API key
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IAM token for cleanup: %w", err)
	}

	if err := d.deleteAPIKey(ctx, iamToken, oldAPIKeyID); err != nil {
		return fmt.Errorf("failed to delete old API key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old API key",
			logger.String("old_key_id", truncateID(oldAPIKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Token Acquisition
// ============================================================================

// getIAMToken returns a cached or freshly acquired IAM bearer token.
//
// The entry is keyed by a fixed string, so the generation is the only thing
// distinguishing a token minted by the current API key from one minted by a retired
// one. Reading it before the credentials and storing conditionally keeps that
// distinction honest: an exchange that was in flight when CommitRotation landed is
// discarded rather than filed under the new generation, where it would be served until
// its own expiry — IBM does not revoke outstanding IAM tokens when CleanupRotation
// deletes the key that minted them.
//
// The generation must be read BEFORE the credentials, so that a rotation landing in
// between is always visible as a change at store time rather than producing a token
// whose key and generation disagree.
func (d *IBMDriver) getIAMToken(ctx context.Context) (string, time.Time, error) {
	for {
		gen := d.tokenCache.GetGeneration()

		// Check cache (with 30s refresh buffer)
		if token, expiry, ok := d.tokenCache.Get("iam", 30*time.Second); ok {
			return token, expiry, nil
		}

		// Acquire fresh token
		token, expiry, err := d.acquireIAMToken(ctx)
		if err != nil {
			return "", time.Time{}, err
		}

		// Cache it, unless the API key rotated while we were exchanging it
		if d.tokenCache.SetIfGeneration("iam", token, expiry, gen) {
			return token, expiry, nil
		}
	}
}

// acquireIAMToken exchanges the source API key for an IAM bearer token.
func (d *IBMDriver) acquireIAMToken(ctx context.Context) (string, time.Time, error) {
	return exchangeIBMAPIKeyForIAMToken(ctx, d.httpClient, d.getAPIKey(), d.getIAMEndpoint(), d.logger)
}

// Config accessors — single source of truth is credSource.Config, read under configMu
// because CommitRotation replaces the map wholesale.

// getAPIKey reads the source API key.
func (d *IBMDriver) getAPIKey() string {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return credential.GetString(d.credSource.Config, "api_key", "")
}

// accountIDLocked reports the account a rotated key should be created in: the
// operator-configured one, or else the one discovery learned. Caller must hold
// authMu, which guards discoveredAccountID. Taking configMu underneath it follows
// the order the rest of the driver already uses (discoverAPIKeyDetailsLocked reads
// the api key the same way), so the two never nest the other way round.
func (d *IBMDriver) accountIDLocked() string {
	d.configMu.RLock()
	configured := credential.GetString(d.credSource.Config, "account_id", "")
	d.configMu.RUnlock()

	if configured != "" {
		return configured
	}
	return d.discoveredAccountID
}

// configSnapshot copies the source config, so a caller reading several keys sees one
// consistent view rather than racing a rotation between lookups.
func (d *IBMDriver) configSnapshot() map[string]string {
	d.configMu.RLock()
	defer d.configMu.RUnlock()

	snapshot := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		snapshot[k] = v
	}
	return snapshot
}

// isChainedLocked reports whether this source draws its api key from a referenced
// cred spec rather than holding one inline.
// Caller must hold configMu (read or write).
func (d *IBMDriver) isChainedLocked() bool {
	return credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != ""
}

// isChained is isChainedLocked for callers holding no lock. Read locks are not
// re-entrant — a writer queued between two acquisitions on one goroutine
// deadlocks — so anything already inside a configMu block must call the Locked
// form instead.
func (d *IBMDriver) isChained() bool {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.isChainedLocked()
}

// swapConfig publishes a config and retires every token the previous one minted, as one
// step. The generation bump follows the write under the same lock, so a mint that read
// the outgoing credentials also captured the outgoing generation and cannot store under
// the new one.
func (d *IBMDriver) swapConfig(newConfig map[string]string) {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	d.credSource.Config = newConfig
	d.tokenCache.InvalidateGeneration()
}

// ============================================================================
// IAM Identity Services API Helpers
// ============================================================================

// discoverAPIKeyDetails fetches the IAM identity and key ID for the source API key.
// Acquires authMu internally.
func (d *IBMDriver) discoverAPIKeyDetails(ctx context.Context) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.discoverAPIKeyDetailsLocked(ctx)
}

// discoverAPIKeyDetailsLocked is the lock-free implementation of discoverAPIKeyDetails.
// Caller must hold authMu.
func (d *IBMDriver) discoverAPIKeyDetailsLocked(ctx context.Context) error {
	iamToken, _, err := d.getIAMToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IAM token: %w", err)
	}

	iamEndpoint := d.getIAMEndpoint()
	apiKey := d.getAPIKey()

	// Use POST with API key in request body (more secure than GET with IAM-Apikey header)
	reqBody, err := json.Marshal(map[string]string{
		"apikey": apiKey,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal API key details request: %w", err)
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httputil.HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/v1/apikeys/details",
		Body:   reqBody,
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return fmt.Errorf("failed to get API key details: %w", err)
	}

	var detailsResp struct {
		ID        string `json:"id"`
		IamID     string `json:"iam_id"`
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(respBody, &detailsResp); err != nil {
		return fmt.Errorf("failed to decode API key details: %w", err)
	}

	if detailsResp.IamID == "" {
		return fmt.Errorf("API key details response missing iam_id")
	}

	d.iamID = detailsResp.IamID
	d.apiKeyID = detailsResp.ID

	// Record the account discovery reported. An operator-configured account_id still
	// wins at read time, so this is stored unconditionally rather than only when unset.
	d.discoveredAccountID = detailsResp.AccountID

	if d.logger != nil {
		d.logger.Trace("discovered IBM API key details",
			logger.String("api_key_id", truncateID(d.apiKeyID, 8)),
			logger.String("iam_id", d.iamID),
		)
	}

	return nil
}

// createAPIKey creates a new API key for the same IAM identity.
// Caller must hold authMu (PrepareRotation).
func (d *IBMDriver) createAPIKey(ctx context.Context, iamToken string) (string, string, error) {
	iamEndpoint := d.getIAMEndpoint()
	accountID := d.accountIDLocked()

	reqBody, err := json.Marshal(map[string]interface{}{
		"name":        fmt.Sprintf("warden-rotated-%d", time.Now().Unix()),
		"description": "Managed by Warden credential rotation",
		"iam_id":      d.iamID,
		"account_id":  accountID,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal create API key request: %w", err)
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httputil.HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/v1/apikeys",
		Body:   reqBody,
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to create new API key: %w", err)
	}

	var createResp struct {
		ID     string `json:"id"`
		Apikey string `json:"apikey"`
	}
	if err := json.Unmarshal(respBody, &createResp); err != nil {
		return "", "", fmt.Errorf("failed to decode create API key response: %w", err)
	}

	if createResp.Apikey == "" || createResp.ID == "" {
		return "", "", fmt.Errorf("create API key response missing apikey or id")
	}

	return createResp.Apikey, createResp.ID, nil
}

// deleteAPIKey deletes an API key by ID
func (d *IBMDriver) deleteAPIKey(ctx context.Context, iamToken, apiKeyID string) error {
	iamEndpoint := d.getIAMEndpoint()

	_, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httputil.HTTPRequest{
		Method: "DELETE",
		URL:    fmt.Sprintf("%s/v1/apikeys/%s", iamEndpoint, url.PathEscape(apiKeyID)),
		Headers: map[string]string{
			"Authorization": "Bearer " + iamToken,
		},
		OKStatuses: []int{http.StatusNoContent, http.StatusOK},
	}, defaultIBMRetryConfig())
	return err
}

// ============================================================================
// Helpers
// ============================================================================

// getIAMEndpoint returns the configured IAM endpoint or the default.
func (d *IBMDriver) getIAMEndpoint() string {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return credential.GetString(d.credSource.Config, "iam_endpoint", defaultIBMIAMEndpoint)
}

// defaultIBMRetryConfig returns the standard retry configuration for IBM Cloud API calls.
func defaultIBMRetryConfig() httputil.HTTPRetryConfig {
	return httputil.HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       ibmMaxResponseBodySize,
		RetryableStatuses: []int{429, 500}, // 500 = wildcard for all 5xx (see httputil.ExecuteWithRetry)
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}
