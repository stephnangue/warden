package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// grafanaMaxResponseBodySize limits response body reads to prevent OOM
const grafanaMaxResponseBodySize = 1 << 20 // 1MB

// grafanaMaxRetryAttempts for retryable API operations
const grafanaMaxRetryAttempts = 3

// grafanaDefaultTokenExpiry is the default TTL for minted service account tokens
const grafanaDefaultTokenExpiry = 1 * time.Hour

// grafanaDefaultNamePrefix is the default prefix for minted token names
const grafanaDefaultNamePrefix = "warden-"

// Sweep bounds. See startSweep and sweepExpiredTokens for why each exists.
const (
	grafanaSweepInterval = 10 * time.Minute
	// A sweep that could not list retries sooner than one that finished. The
	// listing failing is the same event that breaks revocation — a token the
	// server will not accept — so parking the account for the full interval
	// would mute the sweep exactly when it is the only thing still working.
	grafanaSweepRetryInterval = 1 * time.Minute
	grafanaSweepTimeout       = 2 * time.Minute
)

// GrafanaChainedMaxTokenExpiry bounds how long a token minted from a chained
// source may live.
//
// Exported because the config store applies the same rule at spec-write time,
// where an operator can act on it — it is the only layer that can see both the
// spec's lifetime and whether its source is chained.
//
// Such a source cannot revoke: revocation runs at lease expiry, where there is no
// caller to fetch the chained token as. So a minted token stays valid until its
// own expiry however the lease ended — and a lease can end early, well before
// token_expiry, leaving a live credential nothing will take back until the sweep
// sees Grafana report it expired. That window is the exposure, and an operator
// asking for 720h would be asking for a month of it.
const GrafanaChainedMaxTokenExpiry = 24 * time.Hour

// Compile-time interface assertions
var _ credential.SourceDriver = (*GrafanaDriver)(nil)
var _ credential.SpecVerifier = (*GrafanaDriver)(nil)
var _ credential.ChainedSecretMinter = (*GrafanaDriver)(nil)
var _ credential.RotationConfigValidator = (*GrafanaDriverFactory)(nil)

// GrafanaDriver mints tokens on a service account an operator provisioned.
//
// The source holds connection info (grafana_url) and a privileged service-account
// token able to manage tokens on that account. Each spec names the account its
// credentials are issued against — service_account_id, falling back to a
// source-level default — and the shape of the token: its lifetime, and the prefix
// its name carries.
//
// Warden does not create service accounts. The account is provisioned in Grafana
// with whatever role it should have, and a minted token inherits that role, so a
// spec cannot ask for privilege the operator did not already grant. MintCredential
// creates one token on the named account; Revoke deletes that one token, leaving
// the account and every other token on it untouched.
//
// Held inline, the privileged token authenticates every call. Chained
// (secret_spec), it is fetched per mint from a referenced spec as the calling
// agent and kept nowhere — which leaves nothing to revoke with once the request
// is over, since revocation runs at lease expiry where there is no caller to walk
// the chain as. The minted token still expires on its own, and the sweep reclaims
// what it leaves behind.
type GrafanaDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// sweepNext records the earliest each service account may be swept again,
	// keyed by account id. Per account rather than per driver because a sweep
	// only ever looks at one account: a single timestamp would be spent by
	// whichever spec minted first and starve the rest.
	sweepMu   sync.Mutex
	sweepNext map[string]time.Time
}

// GrafanaDriverFactory creates GrafanaDriver instances
type GrafanaDriverFactory struct{}

// Type returns the driver type
func (f *GrafanaDriverFactory) Type() string {
	return credential.SourceTypeGrafana
}

// ValidateConfig validates Grafana source configuration using declarative schema.
func (f *GrafanaDriverFactory) ValidateConfig(config map[string]string) error {
	if err := validateGrafanaChainedConfig(config); err != nil {
		return err
	}
	return credential.ValidateSchema(config,
		credential.StringField("grafana_url").
			Required().
			Custom(func(v string) error {
				return validateGrafanaURL(v, credential.GetBool(config, "tls_skip_verify", false))
			}).
			Describe("Grafana API base URL").
			Example("https://mystack.grafana.net"),

		// Required only when the source holds its own token; a chained source is
		// refused one outright. validateGrafanaChainedConfig enforces both halves of
		// that, since the schema can express neither.
		credential.StringField("admin_token").
			Describe("Service-account token able to manage tokens on the provisioned account; required unless secret_spec is set"),

		credential.StringField("service_account_id").
			Custom(validateGrafanaServiceAccountID).
			Describe("Default provisioned service account that specs mint tokens on; a spec may name its own").
			Example("42"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs"),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)"),

		credential.StringField(credential.ConfigSecretSpec).
			Describe("Cred spec yielding the privileged token, instead of storing one here").
			Example("grafana-admin-token"),

		credential.StringField(credential.ConfigSecretField).
			Describe("Field of the referenced credential holding the privileged token").
			Example("admin_token"),

		credential.DurationField(credential.ConfigSecretCacheTTL).
			Describe("How long to reuse the fetched token before re-fetching (default: no caching)").
			Example("30m"),
	)
}

// validateGrafanaChainedConfig holds a source to exactly one way of getting its
// privileged token.
//
// A chained source keeps none of its own: keeping one would leave a source that
// reads as keyless while storing the very secret chaining removes, and there is
// nothing here that could use it — the fetched token authenticates every call, and
// the paths that run without a caller are disabled rather than falling back to it.
func validateGrafanaChainedConfig(config map[string]string) error {
	if credential.GetString(config, credential.ConfigSecretSpec, "") == "" {
		// The schema cannot express "required unless another key is set", so the
		// non-chained requirement lands here alongside its opposite.
		if credential.GetString(config, "admin_token", "") == "" {
			return fmt.Errorf("admin_token is required unless %s is set", credential.ConfigSecretSpec)
		}
		return nil
	}
	if credential.GetString(config, "admin_token", "") != "" {
		return fmt.Errorf("admin_token must be omitted when %s is set; the referenced spec supplies the privileged token",
			credential.ConfigSecretSpec)
	}
	return nil
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *GrafanaDriverFactory) SensitiveConfigFields() []string {
	return []string{"admin_token", "ca_data"}
}

// ValidateRotationConfig refuses a rotation_period on a grafana source.
//
// The driver holds one long-lived privileged token that it never re-issues: it has
// no Rotatable implementation, and Grafana offers no self-rotation for a
// service-account token. Without this, a rotation_period is accepted at write time
// and then fails every cycle forever, parked and retried by the rotation manager
// and visible only in server logs — see credential.RotationConfigValidator.
func (f *GrafanaDriverFactory) ValidateRotationConfig(_ map[string]string) error {
	return fmt.Errorf("rotation does not apply to a grafana source; its privileged token is issued in Grafana and rotated there, so set rotation_period=0")
}

// InferCredentialType always returns api_key for Grafana sources.
func (f *GrafanaDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAPIKey, nil
}

// Create instantiates a new GrafanaDriver.
func (f *GrafanaDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: config,
		},
		logger:    log.WithSubsystem(credential.SourceTypeGrafana),
		sweepNext: map[string]time.Time{},
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	return driver, nil
}

// getGrafanaURL returns the Grafana API base URL from source config
func (d *GrafanaDriver) getGrafanaURL() string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, "grafana_url", ""), "/")
}

// getAdminToken returns the privileged service account token from source config
func (d *GrafanaDriver) getAdminToken() string {
	return credential.GetString(d.credSource.Config, "admin_token", "")
}

// warn logs a recoverable problem, if this driver has a logger at all. The
// best-effort paths below — a sweep that could not list, a token it could not
// delete — report only this way, and a driver built without a logger must not turn
// that report into a panic.
func (d *GrafanaDriver) warn(msg string, fields ...logger.TypedField) {
	if d.logger != nil {
		d.logger.Warn(msg, fields...)
	}
}

// isChained reports whether this source fetches its privileged token per mint
// rather than holding one.
func (d *GrafanaDriver) isChained() bool {
	return credential.GetString(d.credSource.Config, credential.ConfigSecretSpec, "") != ""
}

// resolveGrafanaServiceAccountID returns the account a spec mints against: its own
// service_account_id, or the source's default.
//
// The spec wins so that one source — one Grafana, one privileged token — can serve
// several accounts, which is how a read-only spec and an editing one coexist: the
// account's role is the credential's privilege, so different privileges mean
// different accounts.
func (d *GrafanaDriver) resolveGrafanaServiceAccountID(spec *credential.CredSpec) (string, error) {
	saID := credential.GetString(spec.Config, "service_account_id", "")
	if saID == "" {
		saID = credential.GetString(d.credSource.Config, "service_account_id", "")
	}
	if saID == "" {
		return "", fmt.Errorf("service_account_id is required: set it on the spec, or on the source as a default; Warden mints tokens on an account you provision in Grafana, it does not create one")
	}
	if err := validateGrafanaServiceAccountID(saID); err != nil {
		return "", err
	}
	return saID, nil
}

// MintCredential creates one token on the spec's provisioned service account.
//
// POST /api/serviceaccounts/{id}/tokens returns the token's id alongside the key
// itself, and that id is what the lease carries: revocation deletes the one token,
// not the account it hangs off.
func (d *GrafanaDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A chained spec mints through MintFromSecret, which the minting layer routes
	// it to. Arriving here means that routing was bypassed, so fail rather than
	// fall through to an inline token this source does not have.
	if d.isChained() || spec.Config[credential.ConfigSecretSpec] != "" {
		return nil, nil, 0, "", fmt.Errorf("grafana: %s is set (credential chaining); this spec mints from fetched secret material, not directly",
			credential.ConfigSecretSpec)
	}
	return d.mintToken(ctx, d.getAdminToken(), spec, false)
}

// MintFromSecret mints from a privileged token fetched through credential
// chaining, for a source that stores none of its own.
func (d *GrafanaDriver) MintFromSecret(ctx context.Context, spec *credential.CredSpec, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	token, err := resolveChainedGrafanaToken(material)
	if err != nil {
		return nil, nil, 0, "", err
	}
	return d.mintToken(ctx, token, spec, true)
}

// resolveChainedGrafanaToken reads the privileged token out of fetched secret
// material.
//
// Grafana has one wire shape for this — an opaque bearer token — so unlike elastic
// there is nothing here to disambiguate; the only question is which key of the
// payload holds it.
func resolveChainedGrafanaToken(material credential.SecretMaterial) (string, error) {
	token := material.Secret()

	// Fall back to conventional names ONLY when no field was resolved. A field that
	// resolved to nothing is a misconfigured secret_field — say so, rather than
	// silently authenticating with some other value from the payload.
	if token == "" && material.Field == "" {
		for _, key := range []string{"admin_token", "api_key", "token"} {
			if token = material.Data[key]; token != "" {
				break
			}
		}
	}
	if token == "" {
		if material.Field != "" {
			return "", fmt.Errorf("grafana: %s %q is empty or absent in the fetched secret material: %w",
				credential.ConfigSecretField, material.Field, credential.ErrChainedSecretIncomplete)
		}
		return "", fmt.Errorf("grafana: no privileged token in fetched secret material (set %s, or store it under 'admin_token', 'api_key' or 'token'): %w",
			credential.ConfigSecretField, credential.ErrChainedSecretIncomplete)
	}
	return token, nil
}

// mintToken creates one token on the spec's account.
//
// chained says where the privileged token it authenticates with came from, which
// decides only how an authentication refusal is reported: a fetched token can be
// stale and worth re-fetching, an inline one cannot.
func (d *GrafanaDriver) mintToken(ctx context.Context, adminToken string, spec *credential.CredSpec, chained bool) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	saID, err := d.resolveGrafanaServiceAccountID(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}

	// The sweep reclaims only names carrying the default prefix, so a spec whose
	// prefix leaves that namespace would mint tokens nothing ever removes. Spec
	// validation refuses it at write time; this holds for a spec that predates
	// the check.
	namePrefix := credential.GetString(spec.Config, "name_prefix", grafanaDefaultNamePrefix)
	if !strings.HasPrefix(namePrefix, grafanaDefaultNamePrefix) {
		return nil, nil, 0, "", fmt.Errorf("name_prefix %q must start with %q, or the tokens it names fall outside what the sweep reclaims",
			namePrefix, grafanaDefaultNamePrefix)
	}

	// Parsed here rather than through credential.GetDuration, which swallows a
	// parse error and hands back the default: "60" would mint an hour while the
	// spec said sixty of something. Spec validation refuses that at write time,
	// but this path is also reached by a spec that predates the check and by one
	// written with verification skipped, which is the whole reason for re-checking.
	tokenExpiry := grafanaDefaultTokenExpiry
	if raw, present := spec.Config["token_expiry"]; present {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("token_expiry %q is not a duration (an integer and a unit, such as 30m or 24h)", raw)
		}
		tokenExpiry = parsed
	}

	// Grafana reads secondsToLive=0 as "no expiration", so anything under a second
	// truncates into a token it will never expire — carrying the account's full
	// role.
	secondsToLive := int64(tokenExpiry.Seconds())
	if secondsToLive < 1 {
		return nil, nil, 0, "", fmt.Errorf("token_expiry %s is under one second, which Grafana would read as a token that never expires; give a lifetime of 1s or more", tokenExpiry)
	}

	// A chained source cannot revoke, so a token it mints stays live until its own
	// expiry — including when the lease ends early, which the sweep cannot help
	// with because it only reclaims tokens Grafana already reports as expired.
	// That window is the whole exposure, so it is bounded here rather than left to
	// whatever an operator typed.
	if chained && tokenExpiry > GrafanaChainedMaxTokenExpiry {
		return nil, nil, 0, "", fmt.Errorf("token_expiry %s exceeds the %s ceiling for a chained source: revocation cannot run without a caller to fetch the token as, so a minted token stays live until it expires",
			tokenExpiry, GrafanaChainedMaxTokenExpiry)
	}

	// Token names are unique per service account, and every spec now mints against
	// an account it may share — so the name carries a random suffix as well as a
	// timestamp. Two mints of the same spec in the same millisecond would otherwise
	// collide, and the loser's error would read as a Grafana fault rather than a
	// name clash.
	tokenName := fmt.Sprintf("%s%s-%d-%s", namePrefix, spec.Name, time.Now().UnixMilli(), helper.GenerateRandomString(8))

	body, err := json.Marshal(map[string]interface{}{
		"name":          tokenName,
		"secondsToLive": secondsToLive,
	})
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	// Not retried: creating a token is not idempotent, and Grafana refuses a
	// duplicate name on the same account. A retry after a lost response would draw
	// that refusal and report a failed mint while the token the first attempt
	// created stands — unknown to Warden, and unrevokable until it expires.
	path := fmt.Sprintf("/api/serviceaccounts/%s/tokens", url.PathEscape(saID))
	respBody, status, err := d.doGrafanaRequestWith(ctx, adminToken, http.MethodPost, path, body, grafanaCreateRetryConfig)
	if err != nil {
		// On the chained path a refusal to authenticate marks the fetched token as
		// stale, so the minting layer evicts what it cached and retries once with a
		// fresh read. An inline source has nothing to evict, and saying so would only
		// send it round a loop that cannot change the outcome.
		if chained && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
			return nil, nil, 0, "", fmt.Errorf("grafana: the server rejected the chained privileged token: %w (%w)",
				credential.ErrChainedSecretRejected, err)
		}
		return nil, nil, 0, "", fmt.Errorf("failed to create token on service account %s: %w", saID, err)
	}

	var result struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if result.Key == "" {
		return nil, nil, 0, "", fmt.Errorf("Grafana API returned empty token key")
	}
	if result.ID <= 0 {
		// Without an id there is nothing to revoke, and the token would live to its
		// own expiry with no lease naming it. Refuse rather than hand out a
		// credential Warden cannot take back.
		return nil, nil, 0, "", fmt.Errorf("Grafana API returned a token with no id; it could never be revoked, so it was not issued")
	}

	// Return credential as api_key for BearerAPIKeyExtractor compatibility
	rawData := map[string]interface{}{
		"api_key": result.Key,
	}

	// The token name is the only thing telling one lease from another in Grafana's
	// own view, where every token on the account acts as the same identity. Record
	// it so the two audit trails can be joined.
	metadata := map[string]interface{}{
		"token_id":           fmt.Sprintf("%d", result.ID),
		"token_name":         tokenName,
		"service_account_id": saID,
	}

	// The lease is the truncated lifetime Grafana was actually asked for, not the
	// configured duration: a fractional second kept here would leave the lease
	// outliving the token it names.
	leaseTTL := time.Duration(secondsToLive) * time.Second
	leaseID := fmt.Sprintf("%s:%d", saID, result.ID)

	if d.logger != nil {
		d.logger.Debug("minted Grafana service account token",
			logger.String("spec", spec.Name),
			logger.String("service_account_id", saID),
			logger.String("token_name", tokenName),
			logger.String("ttl", leaseTTL.String()),
		)
	}

	d.startSweep(adminToken, saID)

	return rawData, metadata, leaseTTL, leaseID, nil
}

// Revoke deletes the one token identified by leaseID, leaving the service account
// and every other token on it untouched.
func (d *GrafanaDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	saID, tokenID, err := parseGrafanaLeaseID(leaseID)
	if err != nil {
		return err
	}

	// A chained source holds no token to authorise the delete, and revocation runs
	// at lease expiry, where there is no caller to walk the chain as. That will
	// never change, so returning an error would only send the expiration manager
	// into backoff and then a daily retry, forever, for a request that cannot
	// succeed. The minted token carries its own expiry — which is why a mint is
	// refused a lifetime Grafana would round to "never" — and a later mint's sweep
	// reclaims it.
	if d.isChained() {
		d.warn("cannot revoke a token minted from a chained privileged token; it expires on its own and is swept on a later mint",
			logger.String("lease", leaseID))
		return nil
	}

	// 200 = deleted, 404 = already gone — both are success. Returning an error for a
	// token that is no longer there would send the expiration manager into backoff
	// and then a daily retry, forever, for a request that can never succeed.
	path := fmt.Sprintf("/api/serviceaccounts/%s/tokens/%s", url.PathEscape(saID), url.PathEscape(tokenID))
	if _, _, err := d.doGrafanaRequest(ctx, d.getAdminToken(), http.MethodDelete, path, nil, 200, 204, 404); err != nil {
		return fmt.Errorf("failed to delete token %s: %w", leaseID, err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Grafana service account token",
			logger.String("lease", leaseID),
		)
	}

	return nil
}

// Type returns the driver type
func (d *GrafanaDriver) Type() string {
	return credential.SourceTypeGrafana
}

// Cleanup releases resources
func (d *GrafanaDriver) Cleanup(_ context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}

// VerifySpec checks that the account the spec mints against exists and that this
// source's token can see it.
//
// A test mint runs immediately before this and already proves a token can be
// created, so what this adds is the one thing that mint cannot distinguish — an
// account id naming nothing — plus the account's role, which is the privilege every
// credential from this spec will carry and is otherwise invisible from Warden's
// side.
func (d *GrafanaDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	saID, err := d.resolveGrafanaServiceAccountID(spec)
	if err != nil {
		return err
	}

	// A chained source holds no token to probe with — it is fetched per mint, as
	// the caller, and there is no caller here. Belt and braces: the store does not
	// call this for a chained spec at all, which is why the account id above is
	// checked by the store rather than relied on here.
	if d.isChained() {
		return nil
	}

	path := fmt.Sprintf("/api/serviceaccounts/%s", url.PathEscape(saID))
	respBody, status, err := d.doGrafanaRequest(ctx, d.getAdminToken(), http.MethodGet, path, nil)
	if err != nil {
		// Reading an account takes a scope that minting a token on it does not, so a
		// deliberately write-scoped privileged token is a legitimate configuration.
		// The mint has already succeeded; failing here would refuse a spec that works.
		if status == http.StatusForbidden {
			return nil
		}
		return fmt.Errorf("service account %s is not reachable (GET /api/serviceaccounts/%s): %w", saID, saID, err)
	}

	var account struct {
		Name       string `json:"name"`
		Role       string `json:"role"`
		IsDisabled bool   `json:"isDisabled"`
	}
	if err := json.Unmarshal(respBody, &account); err != nil {
		// Reachability was the question, and it was answered. The response shape is
		// Grafana's business and varies by version.
		return nil
	}
	if account.IsDisabled {
		return fmt.Errorf("service account %s (%s) is disabled in Grafana; tokens minted on it would not authenticate", saID, account.Name)
	}
	if d.logger != nil {
		d.logger.Debug("verified Grafana service account",
			logger.String("spec", spec.Name),
			logger.String("service_account_id", saID),
			logger.String("role", account.Role),
		)
	}
	return nil
}

// --- HTTP helpers ---

// defaultGrafanaRetryConfig is the shared retry configuration for Grafana API calls.
var defaultGrafanaRetryConfig = httputil.HTTPRetryConfig{
	MaxAttempts:       grafanaMaxRetryAttempts,
	MaxBodySize:       grafanaMaxResponseBodySize,
	RetryableStatuses: []int{http.StatusTooManyRequests, 500},
	BaseBackoff:       1 * time.Second,
	JitterPercent:     20,
}

// grafanaCreateRetryConfig is used for creating a token, which is not idempotent:
// Grafana refuses a duplicate name on the same account, so a retry after a lost
// response cannot succeed and only hides the token the first attempt created.
var grafanaCreateRetryConfig = httputil.HTTPRetryConfig{
	MaxAttempts: 1,
	MaxBodySize: grafanaMaxResponseBodySize,
}

// doGrafanaRequest executes an authenticated HTTP request to the Grafana API with
// the default retry policy. Optional okStatuses override the default 2xx success
// check (e.g. pass 200, 204, 404 to treat an already-deleted token as success).
func (d *GrafanaDriver) doGrafanaRequest(ctx context.Context, adminToken, method, path string, body []byte, okStatuses ...int) ([]byte, int, error) {
	return d.doGrafanaRequestWith(ctx, adminToken, method, path, body, defaultGrafanaRetryConfig, okStatuses...)
}

// doGrafanaRequestWith is doGrafanaRequest with an explicit retry policy.
//
// The privileged token is passed in rather than read from config: a chained
// source holds none, and the one it authenticates with belongs to the request
// that fetched it.
func (d *GrafanaDriver) doGrafanaRequestWith(ctx context.Context, adminToken, method, path string, body []byte, retry httputil.HTTPRetryConfig, okStatuses ...int) ([]byte, int, error) {
	apiURL := d.getGrafanaURL() + path

	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": "Bearer " + adminToken,
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	httpReq := httputil.HTTPRequest{
		Method:     method,
		URL:        apiURL,
		Body:       body,
		Headers:    headers,
		OKStatuses: okStatuses,
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retry)
	if err != nil {
		d.warn("Grafana API request failed",
			logger.String("method", method),
			logger.String("path", path),
			logger.String("error", err.Error()),
		)
	}
	return respBody, status, err
}

// --- Reclaiming expired tokens ---

// startSweep reclaims one account's expired tokens, at most once per interval.
//
// Grafana does not remove a service-account token when it expires: it stays listed
// on the account, inert but accumulating. Revoke normally takes it away first, but
// not always — a revoke that failed for good, a node that died between mint and
// register — so the sweep runs on every mint path rather than only where it is
// load-bearing.
//
// It runs detached, on its own context: a sweep is a list plus a delete per
// reclaimed token, and run inline on the caller's context it would add that to the
// tail of a live request, or be cancelled the moment the mint returns.
func (d *GrafanaDriver) startSweep(adminToken, saID string) {
	// Claimed under the lock rather than with a check-then-set pair: concurrent
	// mints on one account are the normal case, and a gap between them lets every
	// one of them launch a sweep.
	d.sweepMu.Lock()
	// Built lazily: a driver assembled by hand rather than through the factory is
	// a legitimate thing to have, and a nil map here would panic on it.
	if d.sweepNext == nil {
		d.sweepNext = map[string]time.Time{}
	}
	now := time.Now()
	if next, ok := d.sweepNext[saID]; ok && now.Before(next) {
		d.sweepMu.Unlock()
		return
	}
	d.sweepNext[saID] = now.Add(grafanaSweepInterval)
	d.sweepMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), grafanaSweepTimeout)
		defer cancel()
		if !d.sweepExpiredTokens(ctx, adminToken, saID) {
			// Bring the next attempt forward. The interval above exists to stop a
			// busy spec sweeping on every request, not to sit out an outage.
			d.sweepMu.Lock()
			d.sweepNext[saID] = time.Now().Add(grafanaSweepRetryInterval)
			d.sweepMu.Unlock()
		}
	}()
}

// sweepExpiredTokens deletes the expired tokens on an account that Warden minted.
//
// Grafana reports expiry itself, per token, so there is no heuristic here: no stamp
// to parse, no lifetime to re-derive from config that may since have changed. The
// listing covers one account and is a flat array, so there is nothing to paginate.
//
// What it will touch is bounded by name. The account is provisioned by an operator
// and may be shared — with other tooling, or with a token someone issued by hand —
// so only names carrying the Warden prefix are considered. Deleting every expired
// token would be destroying objects this source does not own.
// It reports whether the listing succeeded. A sweep that could not even read the
// account has not done its job, and the caller brings the next attempt forward.
func (d *GrafanaDriver) sweepExpiredTokens(ctx context.Context, adminToken, saID string) bool {
	path := fmt.Sprintf("/api/serviceaccounts/%s/tokens", url.PathEscape(saID))
	respBody, _, err := d.doGrafanaRequest(ctx, adminToken, http.MethodGet, path, nil)
	if err != nil {
		d.warn("could not list service account tokens to reclaim expired ones",
			logger.String("service_account_id", saID),
			logger.String("error", err.Error()))
		return false
	}

	var tokens []struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		HasExpired bool   `json:"hasExpired"`
	}
	if err := json.Unmarshal(respBody, &tokens); err != nil {
		d.warn("could not decode the service account token listing",
			logger.String("service_account_id", saID),
			logger.String("error", err.Error()))
		return false
	}

	var deleted int
	for _, token := range tokens {
		if !token.HasExpired || token.ID <= 0 || !isGrafanaWardenTokenName(token.Name) {
			continue
		}
		delPath := fmt.Sprintf("/api/serviceaccounts/%s/tokens/%d", url.PathEscape(saID), token.ID)
		if _, _, err := d.doGrafanaRequest(ctx, adminToken, http.MethodDelete, delPath, nil, 200, 204, 404); err != nil {
			// Another node sweeping the same account is expected and harmless; a
			// real failure just leaves the token for the next sweep.
			d.warn("could not reclaim an expired token",
				logger.String("service_account_id", saID),
				logger.String("token_id", fmt.Sprintf("%d", token.ID)),
				logger.String("error", err.Error()))
			continue
		}
		deleted++
	}

	if deleted > 0 && d.logger != nil {
		d.logger.Info("reclaimed expired Grafana tokens",
			logger.String("service_account_id", saID),
			logger.Int("count", deleted))
	}
	return true
}

// isGrafanaWardenTokenName reports whether a token name is one this driver writes.
//
// It matches the default prefix rather than any spec's configured one: a sweep
// covers a whole account, which several specs with different prefixes may share,
// and a name that does not announce itself as Warden's is left alone either way.
func isGrafanaWardenTokenName(name string) bool {
	return strings.HasPrefix(name, grafanaDefaultNamePrefix)
}

// parseGrafanaLeaseID splits a leaseID into (saID, tokenID).
//
// Both halves are numeric and both are interpolated into a request path, and they
// reach this function from persisted state rather than from the mint that wrote
// them — so a lease that is not of this shape is refused rather than sent.
func parseGrafanaLeaseID(leaseID string) (saID, tokenID string, err error) {
	saID, tokenID, found := strings.Cut(leaseID, ":")
	if !found {
		return "", "", fmt.Errorf("invalid lease ID %q: expected \"<service account id>:<token id>\"", leaseID)
	}
	if err := validateGrafanaServiceAccountID(saID); err != nil {
		return "", "", fmt.Errorf("invalid lease ID %q: %w", leaseID, err)
	}
	if n, convErr := strconv.ParseInt(tokenID, 10, 64); convErr != nil || n <= 0 {
		return "", "", fmt.Errorf("invalid lease ID %q: token id %q is not a positive number", leaseID, tokenID)
	}
	return saID, tokenID, nil
}

// validateGrafanaServiceAccountID checks an account id is what Grafana issues: a
// positive integer. It is interpolated into a request path, and a value that is not
// a number would be sent there and answered with an opaque 404.
func validateGrafanaServiceAccountID(v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return fmt.Errorf("service_account_id must be a positive integer (the numeric id Grafana gives the account), got: %s", v)
	}
	return nil
}

// validateGrafanaURL validates that the grafana_url is a well-formed HTTPS URL.
func validateGrafanaURL(rawURL string, tlsSkipVerify bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid grafana_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("grafana_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("grafana_url must include a host")
	}
	return nil
}
