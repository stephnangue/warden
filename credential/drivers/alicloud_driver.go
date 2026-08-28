package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
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

	// configMu protects credSource.Config against concurrent reads and writes:
	// CommitRotation replaces the whole map while mint and rotation calls are
	// reading it. Every accessor of credSource.Config must hold it.
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

// stsCallConfig returns the STS endpoint and the management key pair from a
// single config snapshot. Endpoint and credentials are read together rather than
// through separate accessors so a rotation committing between two reads cannot
// pair one config's key with another config's address.
func (d *AlicloudDriver) stsCallConfig() (endpoint, keyID, keySecret string) {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.endpointLocked("sts_endpoint", DefaultAlicloudSTSEndpoint),
		credential.GetString(d.credSource.Config, "access_key_id", ""),
		credential.GetString(d.credSource.Config, "access_key_secret", "")
}

// ramCallConfig is stsCallConfig for the RAM management API.
func (d *AlicloudDriver) ramCallConfig() (endpoint, keyID, keySecret string) {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.endpointLocked("ram_endpoint", DefaultAlicloudRAMEndpoint),
		credential.GetString(d.credSource.Config, "access_key_id", ""),
		credential.GetString(d.credSource.Config, "access_key_secret", "")
}

// endpointLocked reads and normalises one endpoint key. Caller must hold configMu.
func (d *AlicloudDriver) endpointLocked(key, fallback string) string {
	return strings.TrimRight(credential.GetString(d.credSource.Config, key, fallback), "/")
}

// MintCredential returns Alicloud credentials for the given spec.
func (d *AlicloudDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "assume_role":
		return d.mintAssumeRole(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported or missing mint_method: %q (only assume_role is supported by the alicloud source)", mintMethod)
	}
}

// mintAssumeRole calls STS AssumeRole to obtain temporary credentials.
func (d *AlicloudDriver) mintAssumeRole(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	stsEndpoint, mgmtID, mgmtSecret := d.stsCallConfig()
	if mgmtID == "" || mgmtSecret == "" {
		return nil, nil, 0, "", fmt.Errorf("source access_key_id and access_key_secret are required for assume_role")
	}

	roleARN := credential.GetString(spec.Config, "role_arn", "")
	if roleARN == "" {
		return nil, nil, 0, "", fmt.Errorf("role_arn is required for assume_role")
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

	respBody, err := d.callSignedJSON(ctx, http.MethodPost, stsEndpoint, params, mgmtID, mgmtSecret, "")
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("STS AssumeRole failed: %w", err)
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
		return nil, nil, 0, "", fmt.Errorf("parse STS response: %w", err)
	}
	if resp.Credentials.AccessKeyID == "" || resp.Credentials.AccessKeySecret == "" {
		return nil, nil, 0, "", fmt.Errorf("STS returned empty credentials")
	}

	leaseTTL, err := d.stsLeaseTTL(resp.Credentials.Expiration, duration)
	if err != nil {
		return nil, nil, 0, "", err
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
	}, nil, leaseTTL, "", nil // STS tokens are self-expiring; no leaseID
}

// stsLeaseTTL converts the Expiration STS reports into a lease TTL.
//
// The requested duration alone is the wrong answer: it is measured before the
// round trip, so the lease outlives the credential by however long the call took,
// and it ignores an expiry STS shortened for its own reasons. The credential is
// cached for its whole lease, so an over-long lease means a cache hit near the
// end hands out a token that dies mid-request. The aws, gcp, ibm, elastic and
// github drivers all derive their TTL from the server's expiry for this reason.
//
// The reported expiry is also capped at the requested duration, because it is
// only as trustworthy as the agreement between two clocks. A local clock running
// behind Alibaba's would otherwise reintroduce the very over-long lease this
// exists to prevent, just bounded by skew rather than by round-trip time. STS
// never issues longer than asked, so a longer expiry means skew, not generosity.
//
// An unparseable Expiration falls back to the requested duration: a usable
// credential should not be thrown away over a timestamp format, and the fallback
// is no worse than the behaviour this replaces. An expiry already in the past is
// a different matter — there is no usable credential to return.
func (d *AlicloudDriver) stsLeaseTTL(expiration string, requested time.Duration) (time.Duration, error) {
	expiry, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		d.logger.Warn("STS returned an Expiration that is not RFC3339; falling back to the requested duration",
			logger.String("expiration", expiration),
			logger.String("requested", requested.String()),
		)
		return requested, nil
	}

	ttl := time.Until(expiry)
	if ttl <= 0 {
		return 0, fmt.Errorf("STS returned credentials that already expired at %s", expiration)
	}
	if ttl > requested {
		return requested, nil
	}
	return ttl, nil
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
		stsEndpoint, mgmtID, mgmtSecret := d.stsCallConfig()
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

		if _, err := d.callSignedJSON(verifyCtx, http.MethodPost, stsEndpoint, params, mgmtID, mgmtSecret, ""); err != nil {
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

// alicloudAPIError carries a parsed error envelope so callers can branch on the
// upstream Code rather than matching substrings of a formatted message. Rotation
// cleanup, for instance, treats an already-deleted key (EntityNotExist.*) as
// success while still failing on anything else.
type alicloudAPIError struct {
	alicloudErrorEnvelope
}

// Error formats Code, Message, and RequestId for operator triage.
func (e *alicloudAPIError) Error() string {
	if e.RequestId != "" {
		return fmt.Sprintf("%s: %s (RequestId=%s)", e.Code, e.Message, e.RequestId)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// alicloudErrorFromEnvelope wraps an Alicloud error envelope into a typed error
// whose message carries Code, Message, and RequestId for operator triage.
func alicloudErrorFromEnvelope(env alicloudErrorEnvelope) error {
	return &alicloudAPIError{alicloudErrorEnvelope: env}
}

// alicloudBodyPreviewLen bounds how much of an unrecognised response body is
// quoted back in an error. Enough to tell an HTML error page from a JSON one and
// read the first line of either, short enough not to flood a log line.
const alicloudBodyPreviewLen = 256

// alicloudBodyPreview renders an unrecognised response body as a single-line
// excerpt for an error message. Whitespace is collapsed because the bodies this
// is reached for are typically multi-line HTML, which would otherwise break the
// error across a dozen log lines.
func alicloudBodyPreview(body []byte) string {
	if len(body) == 0 {
		return "<empty>"
	}
	preview := strings.Join(strings.Fields(string(body)), " ")
	if len(preview) > alicloudBodyPreviewLen {
		preview = preview[:alicloudBodyPreviewLen] + "..."
	}
	return preview
}

// alicloudErrorHasCodePrefix reports whether err carries an Alicloud error
// envelope whose Code equals prefix or begins with prefix + ".". Alicloud groups
// related codes that way (EntityNotExist.User, EntityNotExist.User.AccessKey),
// so matching the family is the useful test; the dotted form keeps
// "EntityNotExist" from also matching a hypothetical "EntityNotExistent".
func alicloudErrorHasCodePrefix(err error, prefix string) bool {
	var apiErr *alicloudAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == prefix || strings.HasPrefix(apiErr.Code, prefix+".")
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
			// Exponential backoff + 20% jitter, mirrors httputil.ExecuteWithRetry's math.
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
		httpReq := httputil.HTTPRequest{
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
		retry := httputil.HTTPRetryConfig{
			MaxAttempts: 1,
			MaxBodySize: alicloudMaxResponseBodySize,
		}

		respBody, status, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retry)
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

		// The 4xx statuses above are marked OK only to get their bodies back for
		// envelope classification, never to accept the outcome. A 4xx whose body
		// is not an envelope — an HTML error page from an intercepting proxy, a
		// load balancer's own JSON — reaches here having failed, so refusing it is
		// the whole point: callers that discard the body (rotation cleanup) would
		// otherwise read it as success and silently leave a live key in place.
		if status != http.StatusOK {
			return nil, fmt.Errorf("alicloud %s returned HTTP %d with an unrecognised body: %s",
				params.Get("Action"), status, alicloudBodyPreview(respBody))
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

// alicloudAccessKey is one entry of a RAM ListAccessKeys response.
type alicloudAccessKey struct {
	AccessKeyID string `json:"AccessKeyId"`
	Status      string `json:"Status"`
}

// alicloudAccessKeyInactive is the RAM status of a disabled access key. A key
// Warden left behind mid-cleanup carries it, because CleanupRotation always
// deactivates before deleting.
const alicloudAccessKeyInactive = "Inactive"

// alicloudCodeEntityNotExist is the RAM error-code family for a subject that is
// not there — EntityNotExist.User, EntityNotExist.User.AccessKey, and so on.
const alicloudCodeEntityNotExist = "EntityNotExist"

// alicloudMaxRAMKeysPerUser is the number of access keys RAM allows one user to
// hold. Rotation needs a free slot to create the new key in, which is the only
// reason it ever removes an existing one.
const alicloudMaxRAMKeysPerUser = 2

// makeRoomForNewKey frees a slot so CreateAccessKey can succeed, and does so
// without destroying a key it cannot attribute to Warden.
//
// It acts only when the user is at the cap, removes at most one key per attempt,
// and deletes only a key that is already Inactive — the state Warden's own
// interrupted cleanup leaves behind, since CleanupRotation deactivates before it
// deletes. An Active key that is not the current one is deactivated instead, and
// the attempt stops with an error; the retry finds it Inactive and reclaims the
// slot. The rotation manager retries a failed prepare on an exponential backoff
// starting around twenty seconds, so that detour costs one short retry, not a
// rotation period.
//
// It exists because rotation must still be able to heal itself. Two paths leave
// an Active key of Warden's own behind — a crash between CreateAccessKey and the
// staged-rotation persist, and a staged activation exhausting its attempts, after
// which the manager resets to idle and prepares afresh — so refusing to touch
// Active keys at all would wedge rotation permanently once either happened.
// Deactivating a genuine third-party key is disruptive but reversible; deleting
// one is not, which is the trade this makes.
func (d *AlicloudDriver) makeRoomForNewKey(
	ctx context.Context,
	ramEndpoint, mgmtID, mgmtSecret, userName string,
	keys []alicloudAccessKey,
) error {
	if len(keys) < alicloudMaxRAMKeysPerUser {
		return nil
	}

	// The current key must be among the user's own. If it is not, the source is
	// pointed at the wrong management_user_name (or the key belongs to another
	// user), and every key listed here belongs to someone else — so touch none of
	// them and say why.
	var candidate *alicloudAccessKey
	currentFound := false
	for i := range keys {
		switch {
		case keys[i].AccessKeyID == mgmtID:
			currentFound = true
		case candidate == nil:
			candidate = &keys[i]
		}
	}
	if !currentFound {
		return fmt.Errorf(
			"RAM user %q holds %d access keys, none of them the configured access_key_id %s: "+
				"refusing to remove a key this source does not own (check management_user_name)",
			userName, len(keys), truncateID(mgmtID, 8))
	}
	if candidate == nil {
		return nil
	}

	if candidate.Status == alicloudAccessKeyInactive {
		d.logger.Warn("deleting inactive orphaned RAM access key from an interrupted rotation",
			logger.String("orphaned_key_id", truncateID(candidate.AccessKeyID, 8)),
			logger.String("ram_user", userName),
		)
		del := url.Values{}
		del.Set("Action", "DeleteAccessKey")
		del.Set("Version", alicloudRAMVersion)
		del.Set("Format", "JSON")
		del.Set("UserName", userName)
		del.Set(ramParamUserAccessKeyID, candidate.AccessKeyID)
		if _, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, del, mgmtID, mgmtSecret, ""); err != nil {
			return fmt.Errorf("failed to delete orphaned access key %s: %w", truncateID(candidate.AccessKeyID, 8), err)
		}
		return nil
	}

	d.logger.Warn("deactivating an active non-current RAM access key to free a rotation slot; "+
		"it will be deleted on the next rotation attempt",
		logger.String("key_id", truncateID(candidate.AccessKeyID, 8)),
		logger.String("ram_user", userName),
	)
	inactivate := url.Values{}
	inactivate.Set("Action", "UpdateAccessKey")
	inactivate.Set("Version", alicloudRAMVersion)
	inactivate.Set("Format", "JSON")
	inactivate.Set("UserName", userName)
	inactivate.Set(ramParamUserAccessKeyID, candidate.AccessKeyID)
	inactivate.Set("Status", alicloudAccessKeyInactive)
	if _, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, inactivate, mgmtID, mgmtSecret, ""); err != nil {
		return fmt.Errorf("failed to deactivate non-current access key %s: %w", truncateID(candidate.AccessKeyID, 8), err)
	}

	return fmt.Errorf(
		"RAM user %q is at the %d-key limit and the non-current key %s was still active; "+
			"it has been deactivated and will be removed on the next rotation attempt. "+
			"If it is not Warden's, reactivate it and give this source a dedicated RAM user",
		userName, alicloudMaxRAMKeysPerUser, truncateID(candidate.AccessKeyID, 8))
}

// PrepareRotation creates a new RAM access key for the configured management
// user while the existing key remains valid. If the user is at RAM's two-key
// limit it first frees a slot (see makeRoomForNewKey). Returns the new config, a
// cleanup config (with the old access_key_id), and the activation delay to let
// RAM eventual consistency propagate.
func (d *AlicloudDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.configMu.RLock()
	mgmtID := credential.GetString(d.credSource.Config, "access_key_id", "")
	mgmtSecret := credential.GetString(d.credSource.Config, "access_key_secret", "")
	userName := credential.GetString(d.credSource.Config, "management_user_name", "")
	activationDelay := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultAlicloudActivationDelay)
	ramEndpoint := d.endpointLocked("ram_endpoint", DefaultAlicloudRAMEndpoint)
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

	// Step 1: list the user's keys, so a slot can be freed if the RAM two-key
	// limit would otherwise make CreateAccessKey fail.
	listParams := url.Values{}
	listParams.Set("Action", "ListAccessKeys")
	listParams.Set("Version", alicloudRAMVersion)
	listParams.Set("Format", "JSON")
	listParams.Set("UserName", userName)

	listBody, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, listParams, mgmtID, mgmtSecret, "")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("RAM ListAccessKeys failed: %w", err)
	}
	var listResp struct {
		AccessKeys struct {
			AccessKey []alicloudAccessKey `json:"AccessKey"`
		} `json:"AccessKeys"`
	}
	if err := json.Unmarshal(listBody, &listResp); err != nil {
		return nil, nil, 0, fmt.Errorf("parse ListAccessKeys response: %w", err)
	}

	if err := d.makeRoomForNewKey(ctx, ramEndpoint, mgmtID, mgmtSecret, userName, listResp.AccessKeys.AccessKey); err != nil {
		return nil, nil, 0, err
	}

	// Step 2: create a new access key for the same user.
	createParams := url.Values{}
	createParams.Set("Action", "CreateAccessKey")
	createParams.Set("Version", alicloudRAMVersion)
	createParams.Set("Format", "JSON")
	createParams.Set("UserName", userName)

	createBody, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, createParams, mgmtID, mgmtSecret, "")
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

	ramEndpoint, mgmtID, mgmtSecret := d.ramCallConfig()
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
	inactivate.Set("Status", alicloudAccessKeyInactive)

	if _, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, inactivate, mgmtID, mgmtSecret, ""); err != nil {
		// A key that is already gone is the outcome this is working towards, so
		// it is success, not failure. Cleanup is retried for days after a failure,
		// and the next rotation's slot-freeing sweep can delete the very key a
		// pending cleanup is still chasing — without this, those retries would
		// fail daily and eventually log an abandonment for a key that no longer
		// exists.
		if alicloudErrorHasCodePrefix(err, alicloudCodeEntityNotExist) {
			d.logger.Info("old management access key was already removed; cleanup is complete",
				logger.String("old_key_id", truncateID(oldKeyID, 8)),
				logger.String("ram_user", userName),
			)
			return nil
		}
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

	if _, err := d.callSignedJSON(ctx, http.MethodPost, ramEndpoint, del, mgmtID, mgmtSecret, ""); err != nil {
		// Same reasoning as the Inactive step: deleted is deleted, whoever did it.
		if !alicloudErrorHasCodePrefix(err, alicloudCodeEntityNotExist) {
			return fmt.Errorf("RAM DeleteAccessKey (old management key) failed: %w", err)
		}
	}

	d.logger.Info("deleted old management access key after rotation",
		logger.String("old_key_id", truncateID(oldKeyID, 8)),
		logger.String("ram_user", userName),
	)
	return nil
}
