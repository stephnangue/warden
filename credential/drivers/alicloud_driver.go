package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// Alicloud management API defaults.
const (
	DefaultAlicloudSTSEndpoint = "https://sts.aliyuncs.com"
	DefaultAlicloudRAMEndpoint = "https://ram.aliyuncs.com"

	alicloudSTSVersion = "2015-04-01"
	alicloudRAMVersion = "2015-05-01"

	alicloudMaxResponseBodySize = 1 << 20 // 1MB
	alicloudMaxRetryAttempts    = 3

	alicloudMinSTSDuration = 900 * time.Second
	alicloudMaxSTSDuration = 3600 * time.Second

	// DefaultAlicloudActivationDelay is the default wait period before activating
	// a rotated management key, accounting for RAM eventual consistency across
	// regions. Matches AWS's 5-minute default.
	DefaultAlicloudActivationDelay = 5 * time.Minute

	// ramParamUserAccessKeyID is the RAM API parameter name for identifying an
	// access key in UpdateAccessKey and DeleteAccessKey calls. Note it is
	// *not* "AccessKeyId" (that's the CreateAccessKey *response* field).
	ramParamUserAccessKeyID = "UserAccessKeyId"
)

// Compile-time interface assertions
var _ credential.SourceDriver = (*AlicloudDriver)(nil)
var _ credential.SpecVerifier = (*AlicloudDriver)(nil)
var _ credential.Rotatable = (*AlicloudDriver)(nil)

// AlicloudDriver mints credentials from Alibaba Cloud STS.
//
// One mint method is supported (configured per-spec via mint_method):
//   - assume_role: Calls STS AssumeRole, returns temporary credentials (900-3600s TTL)
//
// RAM-based dynamic keys (via CreateAccessKey) are intentionally not exposed:
// freshly minted RAM keys are subject to seconds-to-minutes of propagation
// delay across regions, so clients would frequently see spurious
// InvalidAccessKeyId errors on the very first request using the key. Use
// assume_role for dynamic/short-lived access; it sidesteps that propagation
// window because STS tokens are session-based.
//
// The driver does still use the RAM API for management-key rotation (see
// Rotatable) — rotation runs on a slow schedule and uses activation_delay
// to let RAM propagate before switching over.
type AlicloudDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// configMu protects credSource.Config against concurrent reads and writes
	// (for future rotation support).
	configMu sync.RWMutex
}

// AlicloudDriverFactory creates AlicloudDriver instances.
type AlicloudDriverFactory struct{}

// Type returns the driver type identifier.
func (f *AlicloudDriverFactory) Type() string {
	return credential.SourceTypeAlicloud
}

// ValidateConfig validates Alicloud source configuration.
func (f *AlicloudDriverFactory) ValidateConfig(config map[string]string) error {
	return credential.ValidateSchema(config,
		credential.StringField("access_key_id").
			Describe("Management access key ID (usually starts with LTAI)").
			Example("LTAIxxxxxxxxxxxxxxxx"),

		credential.StringField("access_key_secret").
			Describe("Management access key secret").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("sts_endpoint").
			Describe("STS API endpoint (default: https://sts.aliyuncs.com)").
			Example("https://sts.aliyuncs.com"),

		credential.StringField("ram_endpoint").
			Describe("RAM API endpoint (default: https://ram.aliyuncs.com)").
			Example("https://ram.aliyuncs.com"),

		credential.StringField("management_user_name").
			Describe("RAM user that owns the management access key (required for rotation)").
			Example("warden-management"),

		credential.DurationField("activation_delay").
			Describe("Wait between creating a new management key and using it (default: 5m)").
			Example("5m"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example(""),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	)
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *AlicloudDriverFactory) SensitiveConfigFields() []string {
	return []string{"access_key_secret", "ca_data"}
}

// InferCredentialType always returns alicloud_keys for Alicloud sources.
func (f *AlicloudDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeAlicloudKeys, nil
}

// Create instantiates a new AlicloudDriver.
func (f *AlicloudDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &AlicloudDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAlicloud,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeAlicloud),
	}
	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient
	return driver, nil
}

// Type returns the driver type.
func (d *AlicloudDriver) Type() string {
	return credential.SourceTypeAlicloud
}

// Cleanup releases resources held by the driver.
func (d *AlicloudDriver) Cleanup(_ context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}

func (d *AlicloudDriver) mgmtAccessKey() (string, string) {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return credential.GetString(d.credSource.Config, "access_key_id", ""),
		credential.GetString(d.credSource.Config, "access_key_secret", "")
}

func (d *AlicloudDriver) stsEndpoint() string {
	return strings.TrimRight(
		credential.GetString(d.credSource.Config, "sts_endpoint", DefaultAlicloudSTSEndpoint),
		"/",
	)
}

func (d *AlicloudDriver) ramEndpoint() string {
	return strings.TrimRight(
		credential.GetString(d.credSource.Config, "ram_endpoint", DefaultAlicloudRAMEndpoint),
		"/",
	)
}

// MintCredential returns Alicloud credentials for the given spec.
func (d *AlicloudDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "assume_role":
		return d.mintAssumeRole(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported or missing mint_method: %q (only assume_role is supported by the alicloud source)", mintMethod)
	}
}

// mintAssumeRole calls STS AssumeRole to obtain temporary credentials.
func (d *AlicloudDriver) mintAssumeRole(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	mgmtID, mgmtSecret := d.mgmtAccessKey()
	if mgmtID == "" || mgmtSecret == "" {
		return nil, 0, "", fmt.Errorf("source access_key_id and access_key_secret are required for assume_role")
	}

	roleARN := credential.GetString(spec.Config, "role_arn", "")
	if roleARN == "" {
		return nil, 0, "", fmt.Errorf("role_arn is required for assume_role")
	}
	sessionName := credential.GetString(spec.Config, "role_session_name", "warden-session")
	duration := credential.GetDuration(spec.Config, "duration_seconds", time.Hour)
	if duration < alicloudMinSTSDuration {
		duration = alicloudMinSTSDuration
	}
	if duration > alicloudMaxSTSDuration {
		duration = alicloudMaxSTSDuration
	}

	params := url.Values{}
	params.Set("Action", "AssumeRole")
	params.Set("Version", alicloudSTSVersion)
	params.Set("Format", "JSON")
	params.Set("RoleArn", roleARN)
	params.Set("RoleSessionName", sessionName)
	params.Set("DurationSeconds", fmt.Sprintf("%d", int(duration.Seconds())))
	if p := credential.GetString(spec.Config, "policy", ""); p != "" {
		params.Set("Policy", p)
	}

	respBody, err := d.callSignedJSON(ctx, http.MethodPost, d.stsEndpoint(), params, mgmtID, mgmtSecret, "")
	if err != nil {
		return nil, 0, "", fmt.Errorf("STS AssumeRole failed: %w", err)
	}

	var resp struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			AccessKeySecret string `json:"AccessKeySecret"`
			SecurityToken   string `json:"SecurityToken"`
			Expiration      string `json:"Expiration"`
		} `json:"Credentials"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, 0, "", fmt.Errorf("parse STS response: %w", err)
	}
	if resp.Credentials.AccessKeyID == "" || resp.Credentials.AccessKeySecret == "" {
		return nil, 0, "", fmt.Errorf("STS returned empty credentials")
	}

	d.logger.Info("issued STS temporary credentials",
		logger.String("access_key", truncateID(resp.Credentials.AccessKeyID, 8)),
		logger.String("role_arn", roleARN),
		logger.String("expires", resp.Credentials.Expiration),
	)

	return map[string]interface{}{
		"access_key_id":     resp.Credentials.AccessKeyID,
		"access_key_secret": resp.Credentials.AccessKeySecret,
		"security_token":    resp.Credentials.SecurityToken,
	}, duration, "", nil // STS tokens are self-expiring; no leaseID
}

// Revoke is a no-op: the driver's only supported mint method (assume_role)
// returns self-expiring STS tokens with no server-side revocation handle.
// The method is kept to satisfy the SourceDriver interface.
func (d *AlicloudDriver) Revoke(_ context.Context, _ string) error {
	return nil
}

// alicloudVerifyTimeout bounds the pre-flight AssumeRole call in VerifySpec so
// a misconfigured source or unreachable STS endpoint can't hang spec creation.
const alicloudVerifyTimeout = 10 * time.Second

// VerifySpec validates the spec's configuration and performs a live dry-run
// against Alicloud STS to catch broken management keys, bad role_arn values,
// and trust-policy misconfig at config time rather than at first mint.
//
// For assume_role specs it calls AssumeRole with DurationSeconds=900 (the
// minimum) and discards the returned credentials. The signature check inside
// STS validates the management key; a valid signature followed by any RAM
// role resolution error validates the role_arn. A single call covers both.
func (d *AlicloudDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "assume_role":
		roleARN := credential.GetString(spec.Config, "role_arn", "")
		if roleARN == "" {
			return fmt.Errorf("role_arn is required for assume_role")
		}
		mgmtID, mgmtSecret := d.mgmtAccessKey()
		if mgmtID == "" || mgmtSecret == "" {
			return fmt.Errorf("source must have management access_key_id/access_key_secret for assume_role")
		}

		verifyCtx, cancel := context.WithTimeout(ctx, alicloudVerifyTimeout)
		defer cancel()

		params := url.Values{}
		params.Set("Action", "AssumeRole")
		params.Set("Version", alicloudSTSVersion)
		params.Set("Format", "JSON")
		params.Set("RoleArn", roleARN)
		params.Set("RoleSessionName", "warden-verify")
		params.Set("DurationSeconds", fmt.Sprintf("%d", int(alicloudMinSTSDuration.Seconds())))

		if _, err := d.callSignedJSON(verifyCtx, http.MethodPost, d.stsEndpoint(), params, mgmtID, mgmtSecret, ""); err != nil {
			return fmt.Errorf("alicloud pre-flight AssumeRole failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported mint_method: %s (only assume_role is supported)", mintMethod)
	}
}

// alicloudErrorEnvelope is the standard Alicloud RPC error body shape
// (returned on HTTP 200 or HTTP 400 for Throttling, permission errors, etc.).
// Successful RPC responses do not include a top-level Code field.
type alicloudErrorEnvelope struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestId string `json:"RequestId"`
}

// alicloudTransientCodes lists Alicloud error codes that warrant a retry.
// SignatureDoesNotMatch is deliberately excluded: it indicates clock skew or
// a key rotation race and will not self-heal within a few seconds.
var alicloudTransientCodes = map[string]bool{
	"Throttling":         true,
	"Throttling.User":    true,
	"Throttling.Api":     true,
	"InternalError":      true,
	"ServiceUnavailable": true,
}

// parseAlicloudEnvelope returns (env, true) if body looks like an Alicloud
// error envelope (has Code). Credential/access-key success responses never
// include a top-level Code so a match is a reliable error signal.
func parseAlicloudEnvelope(body []byte) (alicloudErrorEnvelope, bool) {
	var env alicloudErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return env, false
	}
	return env, env.Code != ""
}

// alicloudErrorFromEnvelope wraps an Alicloud error envelope into a Go error
// whose message carries Code, Message, and RequestId for operator triage.
func alicloudErrorFromEnvelope(env alicloudErrorEnvelope) error {
	if env.RequestId != "" {
		return fmt.Errorf("%s: %s (RequestId=%s)", env.Code, env.Message, env.RequestId)
	}
	return fmt.Errorf("%s: %s", env.Code, env.Message)
}

// callSignedJSON builds and sends an ACS3-signed request to an Alicloud
// management endpoint with query-string parameters (RPC-style). Returns the
// raw response body on success.
//
// Retries cover both HTTP-level transient failures (429, 5xx) and Alicloud
// error envelopes carrying transient Code values (Throttling*, InternalError,
// ServiceUnavailable) — the latter often arrive on HTTP 200 or HTTP 400 and
// would otherwise surface as hard failures. The retry budget is a single
// shared counter (alicloudMaxRetryAttempts) so callers cannot stack them.
func (d *AlicloudDriver) callSignedJSON(
	ctx context.Context,
	method, endpoint string,
	params url.Values,
	mgmtID, mgmtSecret, securityToken string,
) ([]byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	u.RawQuery = params.Encode()

	var lastErr error
	for attempt := 0; attempt < alicloudMaxRetryAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff + 20% jitter, mirrors ExecuteWithRetry's math.
			backoff := time.Second * time.Duration(1<<uint(attempt-1))
			jitter := time.Duration(rand.Int63n(int64(backoff) / 5))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff + jitter):
			}
		}

		// Re-sign every attempt so x-acs-date and x-acs-signature-nonce
		// advance, staying inside ACS3's 15-minute skew window.
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(nil))
		if err != nil {
			return nil, err
		}
		req.Host = u.Host
		// x-acs-action and x-acs-version are required in the signed headers for V3;
		// mirror the Action and Version query params into them.
		if action := params.Get("Action"); action != "" {
			req.Header.Set("x-acs-action", action)
		}
		if version := params.Get("Version"); version != "" {
			req.Header.Set("x-acs-version", version)
		}
		req.Header.Set("Accept", "application/json")

		if err := signACS3(req, mgmtID, mgmtSecret, securityToken, nil); err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}

		headers := make(map[string]string, len(req.Header))
		for k, vv := range req.Header {
			if len(vv) > 0 {
				headers[k] = vv[0]
			}
		}

		// Single HTTP attempt per iteration — this outer loop owns the retry
		// budget. 400/403/404 are marked OK so Alicloud error envelopes come
		// back as readable bodies (which the helper would otherwise drop) and
		// can be classified by Code: EntityNotExist.* on 404, NoPermission on
		// 403, Throttling/InvalidParameter on 400.
		httpReq := HTTPRequest{
			Method:  method,
			URL:     u.String(),
			Headers: headers,
			OKStatuses: []int{
				http.StatusOK,
				http.StatusBadRequest,
				http.StatusForbidden,
				http.StatusNotFound,
			},
		}
		retry := HTTPRetryConfig{
			MaxAttempts: 1,
			MaxBodySize: alicloudMaxResponseBodySize,
		}

		respBody, status, err := ExecuteWithRetry(ctx, d.httpClient, httpReq, retry)
		if err != nil {
			// Transport error or non-OK HTTP status. Retry on transient HTTP
			// codes (429 and 5xx); surface anything else immediately.
			if status == http.StatusTooManyRequests || (status >= 500 && status < 600) {
				lastErr = err
				continue
			}
			return nil, err
		}

		if env, isErr := parseAlicloudEnvelope(respBody); isErr {
			if alicloudTransientCodes[env.Code] {
				lastErr = alicloudErrorFromEnvelope(env)
				continue
			}
			return nil, alicloudErrorFromEnvelope(env)
		}

		return respBody, nil
	}

	return nil, fmt.Errorf("alicloud request exhausted %d attempts: %w", alicloudMaxRetryAttempts, lastErr)
}

// --- Rotatable interface (management key rotation) ---

// SupportsRotation returns true if the source has enough config to rotate the
// management access key: an existing access_key_id + access_key_secret plus
// management_user_name identifying which RAM user owns the key.
func (d *AlicloudDriver) SupportsRotation() bool {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return credential.GetString(d.credSource.Config, "access_key_id", "") != "" &&
		credential.GetString(d.credSource.Config, "access_key_secret", "") != "" &&
		credential.GetString(d.credSource.Config, "management_user_name", "") != ""
}

// PrepareRotation creates a new RAM access key for the configured management
// user while the existing key remains valid. Before creating, it deletes any
// orphaned keys from previous failed rotations (RAM allows at most 2 keys per
// user). Returns the new config, a cleanup config (with the old access_key_id),
// and the activation delay to let RAM eventual consistency propagate.
func (d *AlicloudDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.configMu.RLock()
	mgmtID := credential.GetString(d.credSource.Config, "access_key_id", "")
	mgmtSecret := credential.GetString(d.credSource.Config, "access_key_secret", "")
	userName := credential.GetString(d.credSource.Config, "management_user_name", "")
	activationDelay := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultAlicloudActivationDelay)
	configSnapshot := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		configSnapshot[k] = v
	}
	d.configMu.RUnlock()

	if mgmtID == "" || mgmtSecret == "" {
		return nil, nil, 0, fmt.Errorf("source access_key_id and access_key_secret are required for rotation")
	}
	if userName == "" {
		return nil, nil, 0, fmt.Errorf("management_user_name is required for rotation")
	}

	// Step 1: clean up orphaned keys from previous failed rotations.
	// RAM users can hold at most 2 access keys; if there are already 2, remove
	// any that aren't our current management key before creating the new one.
	listParams := url.Values{}
	listParams.Set("Action", "ListAccessKeys")
	listParams.Set("Version", alicloudRAMVersion)
	listParams.Set("Format", "JSON")
	listParams.Set("UserName", userName)

	listBody, err := d.callSignedJSON(ctx, http.MethodPost, d.ramEndpoint(), listParams, mgmtID, mgmtSecret, "")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("RAM ListAccessKeys failed: %w", err)
	}
	var listResp struct {
		AccessKeys struct {
			AccessKey []struct {
				AccessKeyID string `json:"AccessKeyId"`
				Status      string `json:"Status"`
			} `json:"AccessKey"`
		} `json:"AccessKeys"`
	}
	if err := json.Unmarshal(listBody, &listResp); err != nil {
		return nil, nil, 0, fmt.Errorf("parse ListAccessKeys response: %w", err)
	}

	for _, k := range listResp.AccessKeys.AccessKey {
		if k.AccessKeyID == mgmtID {
			continue
		}
		d.logger.Warn("deleting orphaned RAM access key from previous failed rotation",
			logger.String("orphaned_key_id", truncateID(k.AccessKeyID, 8)),
			logger.String("ram_user", userName),
		)
		del := url.Values{}
		del.Set("Action", "DeleteAccessKey")
		del.Set("Version", alicloudRAMVersion)
		del.Set("Format", "JSON")
		del.Set("UserName", userName)
		del.Set(ramParamUserAccessKeyID, k.AccessKeyID)
		if _, err := d.callSignedJSON(ctx, http.MethodPost, d.ramEndpoint(), del, mgmtID, mgmtSecret, ""); err != nil {
			return nil, nil, 0, fmt.Errorf("failed to delete orphaned access key %s: %w", truncateID(k.AccessKeyID, 8), err)
		}
	}

	// Step 2: create a new access key for the same user.
	createParams := url.Values{}
	createParams.Set("Action", "CreateAccessKey")
	createParams.Set("Version", alicloudRAMVersion)
	createParams.Set("Format", "JSON")
	createParams.Set("UserName", userName)

	createBody, err := d.callSignedJSON(ctx, http.MethodPost, d.ramEndpoint(), createParams, mgmtID, mgmtSecret, "")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("RAM CreateAccessKey failed: %w", err)
	}
	var createResp struct {
		AccessKey struct {
			AccessKeyID     string `json:"AccessKeyId"`
			AccessKeySecret string `json:"AccessKeySecret"`
		} `json:"AccessKey"`
	}
	if err := json.Unmarshal(createBody, &createResp); err != nil {
		return nil, nil, 0, fmt.Errorf("parse CreateAccessKey response: %w", err)
	}
	if createResp.AccessKey.AccessKeyID == "" || createResp.AccessKey.AccessKeySecret == "" {
		return nil, nil, 0, fmt.Errorf("RAM returned empty access key on rotation")
	}

	// Step 3: build new config and cleanup config.
	newConfig := configSnapshot
	newConfig["access_key_id"] = createResp.AccessKey.AccessKeyID
	newConfig["access_key_secret"] = createResp.AccessKey.AccessKeySecret

	cleanupConfig := map[string]string{
		"access_key_id":        mgmtID,
		"management_user_name": userName,
	}

	d.logger.Info("prepared new management access key for rotation",
		logger.String("new_key_id", truncateID(createResp.AccessKey.AccessKeyID, 8)),
		logger.String("ram_user", userName),
		logger.String("activate_after", activationDelay.String()),
	)

	return newConfig, cleanupConfig, activationDelay, nil
}

// CommitRotation swaps the driver's in-memory source config to the new
// management access key. Called after newConfig has been persisted to storage
// and the activation delay has elapsed.
func (d *AlicloudDriver) CommitRotation(_ context.Context, newConfig map[string]string) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()

	d.credSource.Config = newConfig

	d.logger.Info("committed rotated management access key",
		logger.String("new_key_id", truncateID(credential.GetString(newConfig, "access_key_id", ""), 8)),
	)
	return nil
}

// CleanupRotation retires the old management access key via two RAM calls:
// UpdateAccessKey(Status=Inactive) then DeleteAccessKey. This follows
// Alibaba's documented rotation procedure — the Inactive step makes any
// straggler client still holding the old key fail with a diagnosable
// InactiveAccessKeyId rather than a plain NoSuchEntity, which is what
// compliance audit trails look for. Uses the new (committed) management
// credentials to authenticate both calls. Best-effort: the rotation manager
// retries with backoff if this fails.
func (d *AlicloudDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldKeyID := cleanupConfig["access_key_id"]
	userName := cleanupConfig["management_user_name"]
	if oldKeyID == "" || userName == "" {
		return nil
	}

	mgmtID, mgmtSecret := d.mgmtAccessKey()
	if mgmtID == "" || mgmtSecret == "" {
		return fmt.Errorf("management access keys are required to clean up old key")
	}
	// Guard: do not delete the key we're currently using
	if mgmtID == oldKeyID {
		return fmt.Errorf("refusing to delete the currently active management key %s", truncateID(oldKeyID, 8))
	}

	// Step 1: mark the old key Inactive. Fail loudly — the rotation manager
	// will retry, and a straggler using the old key is better off seeing
	// InactiveAccessKeyId than having the key silently deleted.
	inactivate := url.Values{}
	inactivate.Set("Action", "UpdateAccessKey")
	inactivate.Set("Version", alicloudRAMVersion)
	inactivate.Set("Format", "JSON")
	inactivate.Set("UserName", userName)
	inactivate.Set(ramParamUserAccessKeyID, oldKeyID)
	inactivate.Set("Status", "Inactive")

	if _, err := d.callSignedJSON(ctx, http.MethodPost, d.ramEndpoint(), inactivate, mgmtID, mgmtSecret, ""); err != nil {
		return fmt.Errorf("RAM UpdateAccessKey (Inactive) failed: %w", err)
	}
	d.logger.Info("disabled old management access key",
		logger.String("old_key_id", truncateID(oldKeyID, 8)),
		logger.String("ram_user", userName),
	)

	// Step 2: delete the (now inactive) old key.
	del := url.Values{}
	del.Set("Action", "DeleteAccessKey")
	del.Set("Version", alicloudRAMVersion)
	del.Set("Format", "JSON")
	del.Set("UserName", userName)
	del.Set(ramParamUserAccessKeyID, oldKeyID)

	if _, err := d.callSignedJSON(ctx, http.MethodPost, d.ramEndpoint(), del, mgmtID, mgmtSecret, ""); err != nil {
		return fmt.Errorf("RAM DeleteAccessKey (old management key) failed: %w", err)
	}

	d.logger.Info("deleted old management access key after rotation",
		logger.String("old_key_id", truncateID(oldKeyID, 8)),
		logger.String("ram_user", userName),
	)
	return nil
}
