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

const ovhMaxResponseBodySize = 1 << 20 // 1MB
const ovhMaxRetryAttempts = 3

// defaultOVHAccessKeysChainTTL bounds how long a served key pair stays cached
// when the spec sets no secret_cache_ttl of its own. The pair itself does not
// expire; this is only how often the chain is walked again to notice that the
// referenced spec now yields a different one.
const defaultOVHAccessKeysChainTTL = 30 * time.Minute

// ovhFallbackTokenTTL bounds a token whose lifetime the endpoint declined to
// state. The lease decides how long the bearer keeps being served from cache, so
// a generous guess hands out a token that expired long ago, while a short one
// costs only another mint.
const ovhFallbackTokenTTL = 5 * time.Minute

// ovhEndpoints maps a regional endpoint name to the OAuth2 token URL it stands
// for. The regional API base URL used to live here too; nothing asks the OVH API
// for anything any more, so the region now selects only where the grant is made.
var ovhEndpoints = map[string]string{
	"ovh-eu": "https://www.ovh.com/auth/oauth2/token",
	"ovh-ca": "https://ca.ovh.com/auth/oauth2/token",
	"ovh-us": "https://us.ovhcloud.com/auth/oauth2/token",
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*OVHDriver)(nil)
var _ credential.SpecVerifier = (*OVHDriver)(nil)
var _ credential.ChainedSecretMinter = (*OVHDriver)(nil)

// OVHDriver mints credentials for OVHcloud APIs.
//
// Two mint methods are supported, configured per-spec via mint_method:
//   - oauth2_token: a bearer token from the OAuth2 client_credentials grant,
//     using the service account in the source config.
//   - access_keys: the object-storage key pair a referenced spec yields. The
//     spec names that reference itself; the pair reaches this driver as fetched
//     secret material and no request is made to OVH at all.
//
// This driver creates nothing upstream and hands out no leases. Object-storage
// keys have no expiry of their own, so a credential that created one would have
// to be deleted again to be safe — and the only moment revocation runs, lease
// expiry, has neither a caller to fetch a secret as nor a stored one to use.
// Serving a pair that already exists sidesteps that entirely: there is nothing
// to revoke because nothing was created.
type OVHDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
	tokenURL   string // resolved OAuth2 token URL

	// configMu protects credSource.Config reads during potential future rotation.
	configMu sync.RWMutex
}

// ovhChainedAuth carries the client credential fetched through credential
// chaining, for a source that stores none of its own.
//
// Both halves travel together. An id kept in config beside a secret fetched from
// the chain would name one service account while presenting another's secret,
// which the token endpoint answers with invalid_client — and which this path
// would then misread as a stale secret and retry, fruitlessly, every time.
type ovhChainedAuth struct {
	clientID     string
	clientSecret string
}

// OVHDriverFactory creates OVHDriver instances.
type OVHDriverFactory struct{}

// Type returns the driver type identifier.
func (f *OVHDriverFactory) Type() string {
	return credential.SourceTypeOVH
}

// ValidateConfig validates OVH source configuration.
func (f *OVHDriverFactory) ValidateConfig(config map[string]string) error {
	if err := validateOVHChainedConfig(config); err != nil {
		return err
	}
	return credential.ValidateSchema(config,
		// Required for oauth2_token specs and refused nowhere else: a source
		// serving only access_keys specs never performs the grant, so demanding a
		// service account it will not use would be config kept for nothing, and a
		// chained source is refused one outright. The spec-level check in
		// VerifySpec is what actually holds an oauth2_token spec to a source that
		// can mint for it.
		credential.StringField("client_id").
			Describe("OAuth2 service account client ID (required for oauth2_token specs)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("client_secret").
			Describe("OAuth2 service account client secret (required for oauth2_token specs)").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("ovh_endpoint").
			OneOf("ovh-eu", "ovh-ca", "ovh-us").
			Describe("OVH regional endpoint (default: ovh-eu)").
			Example("ovh-eu"),

		credential.StringField("token_url").
			Custom(validateOVHEndpointOverride(config)).
			Describe("Override the OAuth2 token URL the endpoint would resolve to. Set it to the token endpoint of whatever issues the service account's tokens.").
			Example("https://ovh-gateway.internal/auth/oauth2/token"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),

		credential.StringField(credential.ConfigSecretSpec).
			Describe("Cred spec yielding the OAuth2 client credential (client_id and client_secret), instead of storing one here").
			Example("ovh-client-cred"),

		credential.StringField(credential.ConfigSecretField).
			Describe("Field of the referenced credential holding the client secret; the client id travels beside it under 'client_id'").
			Example("client_secret"),

		credential.DurationField(credential.ConfigSecretCacheTTL).
			Describe("How long to reuse the fetched client credential before re-fetching (default: no caching)").
			Example("30m"),
	)
}

// validateOVHChainedConfig rejects source config that contradicts chaining.
//
// A chained source holds neither half of the client credential: the secret
// because keeping it would leave a source that reads as keyless while storing
// the very secret chaining removes, and the id because the pair authenticates
// together — see ovhChainedAuth for what a mismatched one costs.
func validateOVHChainedConfig(config map[string]string) error {
	if credential.GetString(config, credential.ConfigSecretSpec, "") == "" {
		return nil
	}
	for _, key := range []string{"client_id", "client_secret"} {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s must be omitted when %s is set; the referenced spec supplies the whole client credential",
				key, credential.ConfigSecretSpec)
		}
	}
	return nil
}

// validateOVHEndpointOverride checks a URL an operator has substituted for the
// regional default. The client secret is posted to token_url, so plaintext is
// only permitted alongside the same tls_skip_verify a caller must already have
// set to mean it — matching how the IBM source gates iam_endpoint.
func validateOVHEndpointOverride(config map[string]string) func(string) error {
	return func(v string) error {
		if v == "" {
			return nil
		}
		skipTLS := credential.GetBool(config, "tls_skip_verify", false)
		if !strings.HasPrefix(v, "https://") && !(strings.HasPrefix(v, "http://") && skipTLS) {
			return fmt.Errorf("must use https scheme, got: %s", v)
		}
		parsed, err := url.Parse(v)
		if err != nil {
			return fmt.Errorf("is not a valid URL: %w", err)
		}
		if parsed.Host == "" {
			return fmt.Errorf("must include a host, got: %s", v)
		}
		return nil
	}
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
	regionTokenURL, ok := ovhEndpoints[endpointName]
	if !ok {
		return nil, fmt.Errorf("unknown ovh_endpoint: %s (expected ovh-eu, ovh-ca, or ovh-us)", endpointName)
	}

	// The regional default can be pointed elsewhere: a deployment whose
	// service-account tokens are issued by something other than ovh.com.
	tokenURL := credential.GetString(config, "token_url", regionTokenURL)

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
		tokenURL:   tokenURL,
	}

	return driver, nil
}

// Type returns the driver type.
func (d *OVHDriver) Type() string {
	return credential.SourceTypeOVH
}

// MintCredential returns OVH credentials for the given spec.
func (d *OVHDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// Both chaining shapes are served from fetched secret material, which arrives
	// through MintFromSecret: an access_keys spec's own reference to its pair, and
	// a source-level reference to the client credential this grant needs. Reaching
	// here with either means the minting layer did not route on it, and there is
	// nothing held here to fall back to.
	if spec.Config[credential.ConfigSecretSpec] != "" || d.isChained() {
		return nil, nil, 0, "", fmt.Errorf("ovh: %s is set (credential chaining); this spec mints from fetched secret material, not directly",
			credential.ConfigSecretSpec)
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "oauth2_token":
		return d.mintOAuth2Token(ctx, nil)
	case "access_keys":
		return nil, nil, 0, "", fmt.Errorf("ovh: an access_keys spec must set %s naming a spec that yields its access_key and secret_key; the pair is served from that material, never minted here",
			credential.ConfigSecretSpec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method: %s (expected oauth2_token or access_keys)", mintMethod)
	}
}

// MintFromSecret mints from secret material fetched through credential chaining.
// What the material means depends on the mint method, so each arm reads it
// differently: oauth2_token receives the client credential the grant is made
// with, access_keys receives the key pair itself.
func (d *OVHDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "oauth2_token":
		return d.mintOAuth2TokenFromSecret(ctx, material)
	case "access_keys":
		return d.mintAccessKeysFromSecret(spec, material)
	default:
		// mint_method is validated at spec create, so reaching here means config
		// drifted. The material's meaning is defined by the method, so with an
		// unknown one there is no safe way to spend it.
		return nil, nil, 0, "", fmt.Errorf("ovh: credential chaining supports mint_method=oauth2_token or access_keys, got %q", mintMethod)
	}
}

// mintOAuth2TokenFromSecret performs the grant with a client credential fetched
// through the chain, for a source that stores none.
func (d *OVHDriver) mintOAuth2TokenFromSecret(ctx context.Context, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	secret := material.Secret()
	// Fall back to conventional names ONLY when no field was resolved. A field
	// that resolved to nothing is a misconfigured secret_field — say so, rather
	// than silently authenticating with some other value from the payload.
	if secret == "" && material.Field == "" {
		if secret = material.Data["client_secret"]; secret == "" {
			secret = material.Data["secret"]
		}
	}
	if secret == "" {
		if material.Field != "" {
			return nil, nil, 0, "", fmt.Errorf("ovh: %s %q is empty or absent in the fetched secret material: %w",
				credential.ConfigSecretField, material.Field, credential.ErrChainedSecretIncomplete)
		}
		return nil, nil, 0, "", fmt.Errorf("ovh: no client secret in fetched secret material (set %s, or store it under 'client_secret'): %w",
			credential.ConfigSecretField, credential.ErrChainedSecretIncomplete)
	}

	// secret_field names the secret, so pointing it at the id is a misconfiguration
	// with a confusing failure: the id would be posted as the secret, the endpoint
	// would answer invalid_client, and that reads on this path as a stale secret —
	// evicting a good cached credential and retrying to no purpose.
	if material.Field == "client_id" {
		return nil, nil, 0, "", fmt.Errorf("ovh: %s must name the client secret, not 'client_id'; the id is read by name alongside it",
			credential.ConfigSecretField)
	}

	// The id travels with its secret. secret_field names the secret alone, so the
	// id is read by convention — and there is nowhere to fall back to, since a
	// chained source is refused an inline one.
	clientID := material.Data["client_id"]
	if clientID == "" {
		return nil, nil, 0, "", fmt.Errorf("ovh: no client id in fetched secret material (store it under 'client_id' alongside the secret): %w",
			credential.ErrChainedSecretIncomplete)
	}

	return d.mintOAuth2Token(ctx, &ovhChainedAuth{clientID: clientID, clientSecret: secret})
}

// mintAccessKeysFromSecret serves the object-storage key pair the referenced spec
// yielded.
//
// It makes no request: the pair already exists, so there is nothing to create and
// nothing to revoke. That is the whole reason this method exists in place of one
// that asks OVH for a fresh pair — see the type comment.
func (d *OVHDriver) mintAccessKeysFromSecret(spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// The spec must name the reference itself. A source-level one would describe
	// whatever that source authenticates with, not this credential.
	//
	// Spec create refuses that combination, but a source converted to chaining
	// afterwards is not re-validated against the specs already bound to it, so this
	// is the guard that actually holds.
	if spec.Config[credential.ConfigSecretSpec] == "" {
		return nil, nil, 0, "", fmt.Errorf("ovh: an access_keys spec must set its own %s naming a spec that yields its access_key and secret_key",
			credential.ConfigSecretSpec)
	}

	// Both halves are read by name. secret_field selects a single secret and a pair
	// is not one, so the spec is refused that field at create and there is nothing
	// here for a resolved field to mean.
	accessKey := material.Data["access_key"]
	secretKey := material.Data["secret_key"]
	if accessKey == "" || secretKey == "" {
		return nil, nil, 0, "", fmt.Errorf("ovh: fetched secret material must hold both 'access_key' and 'secret_key' for access_keys: %w",
			credential.ErrChainedSecretIncomplete)
	}

	// The TTL is advisory. Nothing about this mint can discover that the pair was
	// rotated upstream — it makes no request, so it never sees a rejection — and a
	// zero TTL would pin the credential in cache for the caller's whole session.
	// With no lease id the credential is not revocable, so this only forces the
	// chain to be walked again.
	ttl := credential.GetDuration(spec.Config, credential.ConfigSecretCacheTTL, 0)
	if ttl <= 0 {
		ttl = defaultOVHAccessKeysChainTTL
	}

	d.logger.Info("served OVH access keys from fetched secret material",
		logger.String("access_key", truncateID(accessKey, 8)),
		logger.String("spec", spec.Name),
		logger.String("ttl", ttl.String()),
	)

	rawData := map[string]interface{}{
		"access_key": accessKey,
		"secret_key": secretKey,
	}

	return rawData, nil, ttl, "", nil
}

// getClientCredentials reads client_id and client_secret from source config under RLock.
func (d *OVHDriver) getClientCredentials() (clientID, clientSecret string) {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	clientID = credential.GetString(d.credSource.Config, "client_id", "")
	clientSecret = credential.GetString(d.credSource.Config, "client_secret", "")
	return
}

// isChainedLocked reports whether this source fetches its client credential
// through a reference rather than holding one. The caller must hold configMu.
func (d *OVHDriver) isChainedLocked() bool {
	return credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != ""
}

func (d *OVHDriver) isChained() bool {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.isChainedLocked()
}

// fetchOAuth2Token performs the OAuth2 client_credentials exchange and returns
// the access token and TTL. A chained client credential is passed in; a nil one
// means the source holds its own.
func (d *OVHDriver) fetchOAuth2Token(ctx context.Context, chained *ovhChainedAuth) (accessToken string, ttl time.Duration, err error) {
	var clientID, clientSecret string
	if chained != nil {
		clientID, clientSecret = chained.clientID, chained.clientSecret
	} else {
		clientID, clientSecret = d.getClientCredentials()
	}
	if clientID == "" || clientSecret == "" {
		// The message VerifySpec would give never reaches an operator: spec
		// validation test-mints first and reports whatever that returns. So the
		// alternative is named here, where it is actually read.
		return "", 0, fmt.Errorf("client_id and client_secret are required on source config, or a %s naming a spec that yields them",
			credential.ConfigSecretSpec)
	}

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       ovhMaxRetryAttempts,
		MaxBodySize:       ovhMaxResponseBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500, 503},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    d.tokenURL,
		Body:   []byte(formData.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		// On the chained path an authentication refusal marks the fetched pair as
		// possibly stale, so the minting layer evicts a cached copy and retries once
		// with a fresh fetch. RFC 6749 section 5.2 reports invalid_client as 400 or
		// 401, and the fetched credential is the only thing that varies per mint
		// here — so a refusal is about the credential or about nothing.
		if chained != nil && (status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden) {
			return "", 0, fmt.Errorf("ovh: OAuth2 token endpoint rejected the chained client credential: %w (%w)",
				credential.ErrChainedSecretRejected, err)
		}
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
		// Nothing here knows how long the token is actually good for, and the
		// credential is served from cache for the whole lease. Fall back to a span
		// short enough that a wrong guess is corrected by a re-mint rather than by
		// an agent presenting a dead bearer.
		d.logger.Warn("OAuth2 token response carried no usable expires_in; bounding the lease at the fallback lifetime",
			logger.String("fallback", ovhFallbackTokenTTL.String()),
		)
		tokenTTL = ovhFallbackTokenTTL
	}

	return tokenResp.AccessToken, tokenTTL, nil
}

// mintOAuth2Token mints a bearer token via the OAuth2 client_credentials grant.
func (d *OVHDriver) mintOAuth2Token(ctx context.Context, chained *ovhChainedAuth) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	token, ttl, err := d.fetchOAuth2Token(ctx, chained)
	if err != nil {
		return nil, nil, 0, "", err
	}

	d.logger.Info("minted OVH OAuth2 bearer token",
		logger.String("ttl", ttl.String()),
	)

	rawData := map[string]interface{}{
		"api_token": token,
	}

	return rawData, nil, ttl, "", nil // No leaseID — token expires naturally
}

// Revoke is a no-op: no mint method here issues a lease.
//
// A bearer token expires on its own, and an access_keys pair was never created by
// this driver — it belongs to whoever owns the referenced spec, and deleting it
// would revoke a credential this source only borrowed. So there is never a handle
// to release, and the credential type marks these non-revocable.
func (d *OVHDriver) Revoke(_ context.Context, leaseID string) error {
	if leaseID != "" {
		// Not Debug: a lease this driver did not issue predates the removal of the
		// methods that created object-storage keys. Those keys have no expiry, so
		// this is an orphan someone has to delete by hand — and the lease id names
		// the project, user and key they need.
		d.logger.Warn("cannot revoke a lease from a mint method this driver no longer has; if it names an object-storage key, that key persists until deleted manually",
			logger.String("lease_id", leaseID))
	}
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
		// The grant runs with the source's service account, which the source
		// schema no longer demands — a source serving only access_keys specs has
		// no use for one. This is where that requirement actually lands, unless
		// the source fetches its client credential per request, in which case
		// there is nothing to check until one is fetched.
		if d.isChained() {
			return nil
		}
		clientID, clientSecret := d.getClientCredentials()
		if clientID == "" || clientSecret == "" {
			return fmt.Errorf("an oauth2_token spec needs client_id and client_secret on its source, or a %s naming a spec that yields them",
				credential.ConfigSecretSpec)
		}
		return nil
	case "access_keys":
		// Reached only if the spec named no reference; a chained spec skips
		// verification entirely. Without one there is no pair to serve.
		if spec.Config[credential.ConfigSecretSpec] == "" {
			return fmt.Errorf("an access_keys spec must set %s naming a spec that yields its access_key and secret_key", credential.ConfigSecretSpec)
		}
		return nil
	default:
		return fmt.Errorf("unsupported mint_method: %s (expected oauth2_token or access_keys)", mintMethod)
	}
}
