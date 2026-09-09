package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// DefaultGCPActivationDelay is the default wait period for GCP IAM key propagation.
// GCP IAM key propagation is typically faster than AWS/Azure (10-60s measured),
// so a 2-minute default provides a safe buffer. Configurable via activation_delay.
const DefaultGCPActivationDelay = 2 * time.Minute

// gcpMaxResponseBodySize limits response body reads to prevent OOM
const gcpMaxResponseBodySize = 1 << 20 // 1MB

// gcpAuthMethodStatic and gcpAuthMethodOIDCFederation select how the source
// authenticates. static (default) exchanges a stored service-account JSON key for
// OAuth2 tokens; oidc_federation holds no key and mints only by exchanging a
// caller-presented identity assertion through Workload Identity Federation.
const (
	gcpAuthMethodStatic         = "static"
	gcpAuthMethodOIDCFederation = "oidc_federation"
)

// Default GCP API hosts. The driver's host fields default to these. The STS and IAM
// Credentials hosts are additionally settable from source config, so a deployment
// behind a private-service-connect endpoint — and the e2e suite, which runs the whole
// federated fetch against a local listener — can redirect them.
const (
	defaultGCPSTSHost            = "https://sts.googleapis.com"
	defaultGCPIAMCredentialsHost = "https://iamcredentials.googleapis.com"
	defaultGCPIAMHost            = "https://iam.googleapis.com"
	defaultGCPSecretManagerHost  = "https://secretmanager.googleapis.com"
)

// gcpMaxSecretPayloadSize is the largest secret Secret Manager stores. It bounds the
// decoded payload, not the response: the payload arrives base64-encoded inside a JSON
// envelope, so the body carrying a legal 64KiB secret is half again as large.
const gcpMaxSecretPayloadSize = 64 * 1024

// gcpFederatedFetchLifetime is how long the impersonated token used for a single
// secret read is asked to live. The read happens immediately and the token is then
// discarded, so this is a floor on clock skew rather than a working lifetime — the
// spec's TTL bounds govern the secret it returns, not this.
const gcpFederatedFetchLifetime = "900s"

// OAuth2 scopes this driver requests. cloud-platform authorizes the token mints and
// the impersonation call; the narrower iam scope authorizes only the key-management
// calls rotation makes against iam.googleapis.com.
const (
	gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	gcpIAMScope           = "https://www.googleapis.com/auth/iam"
)

// gcpSTSTokenFallbackTTL is used when the STS token-exchange response omits the
// optional expires_in, so the lease is never zero/negative. It applies only to that
// response: an impersonated token carries a requested lifetime, and falling back to a
// constant there would hand out a lease outliving the token (see impersonationTTL).
const gcpSTSTokenFallbackTTL = 1 * time.Hour

// gcpMaxImpersonationLifetime is the ceiling generateAccessToken accepts. The API's
// own default maximum is 3600s; 43200s requires the target service account to sit in
// an org policy carrying the credential-lifetime-extension constraint. Validating
// against the higher bound leaves that policy's decision to GCP while still catching
// a lifetime that no configuration could ever satisfy.
const gcpMaxImpersonationLifetime = 43200 * time.Second

// gcpAPIMaxAttempts is how many times a GCP API call is tried before giving up. The
// calls this driver makes are all safe to re-issue, and GCP answers 429 on the
// service-account key quota and 5xx under load — a single attempt turned any of those
// into a failed mint or a half-finished rotation.
const gcpAPIMaxAttempts = 3

// gcpRotationVerifyTimeout bounds the wait for a freshly created service-account key
// to become usable. A new key is not immediately recognised across Google's replicas,
// so the first mints against it can fail with an invalid-signature error that is
// purely propagation delay; treating that as a bad key would delete a good one.
const gcpRotationVerifyTimeout = 60 * time.Second

// Compile-time interface assertions
var _ credential.SourceDriver = (*GCPDriver)(nil)
var _ credential.Rotatable = (*GCPDriver)(nil)
var _ credential.ExchangeMinter = (*GCPDriver)(nil)

// serviceAccountKey represents the parsed structure of a GCP service account JSON key file
type serviceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
	UniverseDomain          string `json:"universe_domain"`
}

// GCPDriver mints credentials from GCP services.
// It exchanges a service account JSON key for OAuth2 access tokens,
// and optionally impersonates other service accounts.
//
// The driver's source credentials (SA key) are used for:
// - Minting access tokens for the source SA
// - Impersonating other service accounts via IAM Credentials API
// - Rotating its own SA key via IAM API
type GCPDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Token cache for the source SA's API access .
	tokenCache *TokenCache

	// HTTP client for GCP API calls
	httpClient *http.Client

	// authMu guards credSource.Config against the rewrite in CommitRotation. It is
	// held only across those field accesses and never across a token mint, so a slow
	// acquisition cannot block a config reader.
	authMu sync.Mutex

	// API hosts, defaulting to the public GCP endpoints. stsHost and
	// iamCredentialsHost are settable from source config; iamHost is not, because the
	// only calls it serves create and delete real service-account keys, which an
	// override cannot redirect anywhere useful. It stays a field so the rotation tests
	// can reach a local listener — before it existed those two calls hardcoded their
	// URL inline and were untestable, which is why they carried no coverage at all.
	stsHost            string
	iamCredentialsHost string
	iamHost            string
	secretManagerHost  string
}

// Config accessors — single source of truth is credSource.Config. Each takes authMu,
// since CommitRotation replaces the whole map underneath them.

func (d *GCPDriver) getServiceAccountKey() string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return credential.GetString(d.credSource.Config, "service_account_key", "")
}

func (d *GCPDriver) getAuthMethod() string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return credential.GetString(d.credSource.Config, "auth_method", gcpAuthMethodStatic)
}

func (d *GCPDriver) getWorkloadIdentityProvider() string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return credential.GetString(d.credSource.Config, "workload_identity_provider", "")
}

// configSnapshot copies the source config under authMu, so a caller reading several
// keys sees one consistent view rather than racing a rotation between lookups.
func (d *GCPDriver) configSnapshot() map[string]string {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	snapshot := make(map[string]string, d.credSource.Config.Len())
	for k, v := range d.credSource.Config.All() {
		snapshot[k] = v
	}
	return snapshot
}

func (d *GCPDriver) parseServiceAccountKey() (*serviceAccountKey, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return nil, fmt.Errorf("service_account_key is empty")
	}
	return parseServiceAccountKeyJSON([]byte(saKeyJSON))
}

// parseServiceAccountKeyJSON decodes a service-account key and checks every field
// this driver goes on to use: the type it dispatches on, the identity it addresses
// the key by when rotating, and the private key that signs the token grant.
//
// "Unmarshals without error" is not a check — `null` and `{}` both satisfy it, and a
// key that passes only that bar reaches storage as the source's credential and breaks
// it. The type is pinned here as well as at the token grant so a credential document
// naming a file or URL to fetch is refused at the boundary it arrives on.
func parseServiceAccountKeyJSON(raw []byte) (*serviceAccountKey, error) {
	var saKey serviceAccountKey
	if err := json.Unmarshal(raw, &saKey); err != nil {
		return nil, fmt.Errorf("must be valid JSON: %w", err)
	}
	if saKey.Type != "service_account" {
		return nil, fmt.Errorf("'type' must be \"service_account\", got %q: other credential types name an external file or URL to read, which this driver never fetches", saKey.Type)
	}
	for _, f := range []struct{ name, value string }{
		{"project_id", saKey.ProjectID},
		{"client_email", saKey.ClientEmail},
		{"private_key", saKey.PrivateKey},
		{"private_key_id", saKey.PrivateKeyID},
	} {
		if f.value == "" {
			return nil, fmt.Errorf("missing '%s' field in JSON", f.name)
		}
	}
	return &saKey, nil
}

// GCPDriverFactory creates GCPDriver instances
type GCPDriverFactory struct{}

// Type returns the driver type
func (f *GCPDriverFactory) Type() string {
	return credential.SourceTypeGCP
}

// ValidateConfig validates GCP driver configuration using declarative schema
func (f *GCPDriverFactory) ValidateConfig(config credential.Config) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			OneOf(gcpAuthMethodStatic, gcpAuthMethodOIDCFederation).
			Describe("How the source authenticates: static (service account key) or oidc_federation (Workload Identity Federation, keyless)").
			Example("static"),

		credential.StringField("service_account_key").
			Custom(func(value string) error {
				_, err := parseServiceAccountKeyJSON([]byte(value))
				return err
			}).
			Describe("GCP service account key in JSON format (required for auth_method=static)").
			Example("{\"type\":\"service_account\",\"project_id\":\"...\",\"private_key\":\"...\"}"),

		credential.StringField("workload_identity_provider").
			Describe("Full WIF provider resource name (required for auth_method=oidc_federation)").
			Example("//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/warden-oidc"),

		credential.StringField("sts_endpoint").
			Custom(validateEndpointURL).
			Describe("Override where the STS token exchange is sent (default: the public GCP endpoint). Only applies to auth_method=oidc_federation").
			Example("https://sts.googleapis.com"),

		credential.StringField("iamcredentials_endpoint").
			Custom(validateEndpointURL).
			Describe("Override where service-account impersonation calls are sent (default: the public GCP endpoint). Does not apply to the IAM key-management calls rotation makes").
			Example("https://iamcredentials.googleapis.com"),

		credential.StringField("secretmanager_endpoint").
			Custom(validateEndpointURL).
			Describe("Override where Secret Manager reads are sent (default: the public GCP endpoint)").
			Example("https://secretmanager.googleapis.com"),

		credential.DurationField("activation_delay").
			Describe("How long to wait after creating a rotated service-account key before activating it, covering IAM propagation").
			Example("2m"),

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

	// Cross-field rules per auth_method.
	switch credential.GetString(config, "auth_method", gcpAuthMethodStatic) {
	case gcpAuthMethodStatic:
		if credential.GetString(config, "service_account_key", "") == "" {
			return fmt.Errorf("service_account_key is required for auth_method=static")
		}
		// workload_identity_provider drives only federation (and later seeds the
		// warden_identity assertion audience); on a static source it would be
		// silently ignored, so reject it rather than mislead.
		if credential.GetString(config, "workload_identity_provider", "") != "" {
			return fmt.Errorf("workload_identity_provider is only valid for auth_method=oidc_federation")
		}
		// Same reasoning for the STS override. Static auth never reaches STS — it
		// exchanges the key's own token_uri — so this would be accepted and never
		// read, leaving a source that looks redirected while talking to Google.
		if credential.GetString(config, "sts_endpoint", "") != "" {
			return fmt.Errorf("sts_endpoint is only valid for auth_method=oidc_federation: static auth exchanges the service account key's own token_uri and never calls STS")
		}
	case gcpAuthMethodOIDCFederation:
		// A federation source holds no static key. Reject leftover static config so a
		// misconfiguration cannot silently mix modes.
		if credential.GetString(config, "service_account_key", "") != "" {
			return fmt.Errorf("service_account_key must not be set for auth_method=oidc_federation")
		}
		provider := credential.GetString(config, "workload_identity_provider", "")
		if provider == "" {
			return fmt.Errorf("workload_identity_provider is required for auth_method=oidc_federation")
		}
		if !strings.HasPrefix(provider, "//iam.googleapis.com/") {
			return fmt.Errorf("workload_identity_provider must start with //iam.googleapis.com/")
		}
	}
	return nil
}

// ValidateRotationConfig refuses a rotation period on a source whose impersonation
// calls are redirected. Rotation acts on the real account through IAM, which
// deliberately has no override, so a source pointed at a stand-in would verify
// against it while trying to rotate keys that only exist somewhere else.
//
// sts_endpoint is absent from this check on purpose: it is valid only under
// oidc_federation, and a federated source is already refused a rotation_period
// before any driver sees it. Naming it here would be a rule that can never fire.
func (f *GCPDriverFactory) ValidateRotationConfig(config credential.Config) error {
	if credential.GetString(config, "iamcredentials_endpoint", "") == "" &&
		credential.GetString(config, "secretmanager_endpoint", "") == "" {
		return nil
	}
	return fmt.Errorf("rotation_period cannot be set on a source that overrides " +
		"iamcredentials_endpoint or secretmanager_endpoint: rotation manages service " +
		"account keys in the real project, which those overrides do not redirect")
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *GCPDriverFactory) SensitiveConfigFields() []string {
	return []string{"service_account_key", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *GCPDriverFactory) InferCredentialType(specConfig credential.Config) (string, error) {
	mintMethod := specConfig.Get("mint_method")
	switch mintMethod {
	case "cloud_sql_iam_token":
		// Named by the db_auth_token schema and validated there, but no mint path
		// implements it. Refusing here turns a spec that writes cleanly and then
		// fails on every request into one that fails at the point the mistake is
		// made. The same refusal lives in the db_auth_token validator, which is the
		// path taken when the operator states `type` instead of leaving it inferred.
		return "", fmt.Errorf("mint_method %q is not implemented for the gcp driver", mintMethod)
	case "secret_read":
		// A stored secret vended under its own key names, with no primary field to
		// select — the shape a chained consumer reads by name.
		return credential.TypeKeyValue, nil
	case "", "access_token", "impersonated_access_token":
		return credential.TypeGCPAccessToken, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// Create instantiates a new GCPDriver
func (f *GCPDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeGCP),
		tokenCache: NewTokenCache(),
		stsHost: strings.TrimRight(
			credential.GetString(config, "sts_endpoint", defaultGCPSTSHost), "/"),
		iamCredentialsHost: strings.TrimRight(
			credential.GetString(config, "iamcredentials_endpoint", defaultGCPIAMCredentialsHost), "/"),
		iamHost: defaultGCPIAMHost,
		secretManagerHost: strings.TrimRight(
			credential.GetString(config, "secretmanager_endpoint", defaultGCPSecretManagerHost), "/"),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	// A federation source holds no service-account key: skip the eager credential
	// probe. All authentication happens per-request from the caller's identity
	// assertion via the exchange path.
	if credential.GetString(config, "auth_method", gcpAuthMethodStatic) == gcpAuthMethodOIDCFederation {
		return driver, nil
	}

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := driver.acquireToken(ctx, []string{gcpCloudPlatformScope}); err != nil {
		return nil, fmt.Errorf("GCP authentication failed: %w", err)
	}

	return driver, nil
}

// MintCredential mints credentials based on the spec's mint_method.
func (d *GCPDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A keyless source mints only through the exchange path, which carries the
	// caller-scoped assertion. Fail closed here to avoid the misleading
	// "service_account_key is empty" error a federation source would otherwise hit.
	if d.getAuthMethod() == gcpAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("gcp: source uses auth_method=oidc_federation; the spec must set subject_token_source (warden_identity or agent_identity)")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "access_token")

	switch mintMethod {
	case "access_token":
		return d.mintAccessToken(ctx, spec)
	case "impersonated_access_token":
		return d.mintImpersonatedAccessToken(ctx, spec)
	case "secret_read":
		return d.mintViaSecretRead(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for GCP driver; use 'access_token', 'impersonated_access_token' or 'secret_read'", mintMethod)
	}
}

// addSourceSAMetadata copies the non-secret attributes of the source service
// account key into meta: the project id and the source SA email under emailKey
// ("subject" for a direct token, the authority "source_service_account" for
// impersonation). Safe with a nil key.
func addSourceSAMetadata(meta map[string]interface{}, saKey *serviceAccountKey, emailKey string) {
	if saKey == nil {
		return
	}
	if saKey.ProjectID != "" {
		meta["project_id"] = saKey.ProjectID
	}
	if saKey.ClientEmail != "" {
		meta[emailKey] = saKey.ClientEmail
	}
}

// gcpAccessTokenMetadata builds clear-loggable identity metadata for a direct
// (source SA) access token; subject is the source SA email.
func gcpAccessTokenMetadata(saKey *serviceAccountKey, scopes string, expiry time.Time) map[string]interface{} {
	meta := map[string]interface{}{
		"scopes":     scopes,
		"expiration": expiry.UTC().Format(time.RFC3339),
	}
	addSourceSAMetadata(meta, saKey, "subject")
	return meta
}

// gcpImpersonatedMetadata builds metadata for an impersonated access token;
// subject is the target SA, with the source SA recorded as the authority.
func gcpImpersonatedMetadata(saKey *serviceAccountKey, targetSA, scopes, lifetime, expireTime string) map[string]interface{} {
	meta := map[string]interface{}{
		"subject":  targetSA,
		"scopes":   scopes,
		"lifetime": lifetime,
	}
	if expireTime != "" {
		meta["expiration"] = expireTime
	}
	addSourceSAMetadata(meta, saKey, "source_service_account")
	return meta
}

// mintAccessToken exchanges the source SA key for an OAuth2 access token.
//
// The credential this vends is the source service account's own token, shared by
// every caller asking for the same scopes. That makes the spec's scopes the only
// thing narrowing it, so they are required rather than defaulted: the former default
// was cloud-platform, which on a rotation-enabled source carries authority over the
// source's own keys — a leaked lease could mint a replacement for Warden's identity
// and outlive any revocation.
func (d *GCPDriver) mintAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	scopesStr := credential.GetString(spec.Config, "scopes", "")
	scopes := splitScopes(scopesStr)
	if len(scopes) == 0 {
		return nil, nil, 0, "", fmt.Errorf("gcp: 'scopes' is required for mint_method=access_token: this vends the source service account's own token, and without explicit scopes it would carry the source's full authority")
	}

	token, expiry, err := d.getSourceToken(ctx, scopes)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire GCP access token: %w", err)
	}

	saKey, err := d.parseServiceAccountKey()
	if err != nil && d.logger != nil {
		// The key just minted a token, so this is near-unreachable; log rather than
		// fail, but do not discard it — the cost is audit metadata losing the subject.
		d.logger.Warn("could not parse source service account key for mint metadata",
			logger.String("spec", spec.Name), logger.String("error", err.Error()))
	}

	// A cached token is handed out with the life it has left, not the life it had.
	// Zero or negative means the grant carried no usable expiry: caching that yields a
	// credential already expired on arrival, which re-mints on every single request.
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return nil, nil, 0, "", fmt.Errorf("gcp: access token carries no usable expiry (expires at %s)", expiry.UTC().Format(time.RFC3339))
	}
	// MinTTL is deliberately not enforced: the token's real validity is fixed by
	// Google and a short remainder cannot be extended, so capping is the only bound
	// available. The same asymmetry is documented on the federated path.
	if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
		ttl = spec.MaxTTL
	}

	rawData := map[string]interface{}{
		"access_token": token,
	}

	if d.logger != nil {
		d.logger.Debug("minted GCP access token",
			logger.String("spec", spec.Name),
			logger.String("scopes", scopesStr),
			logger.String("ttl", ttl.String()),
		)
	}

	metadata := gcpAccessTokenMetadata(saKey, scopesStr, expiry)

	// No leaseID - access tokens expire naturally and cannot be revoked
	return rawData, metadata, ttl, "", nil
}

// mintImpersonatedAccessToken impersonates another service account via IAM Credentials API,
// using the source SA's own token as the impersonation authority.
func (d *GCPDriver) mintImpersonatedAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	targetSA := credential.GetString(spec.Config, "target_service_account", "")
	if targetSA == "" {
		return nil, nil, 0, "", fmt.Errorf("target_service_account is required for impersonated_access_token mint method")
	}

	scopesStr := credential.GetString(spec.Config, "scopes", gcpCloudPlatformScope)
	scopes := splitScopes(scopesStr)
	if len(scopes) == 0 {
		return nil, nil, 0, "", fmt.Errorf("gcp: 'scopes' resolved to nothing for mint_method=impersonated_access_token")
	}
	lifetime := credential.GetString(spec.Config, "lifetime", "3600s")
	// Checked here as well as on the federated path: the impersonated token's life is
	// what the caller asked for, so a value outside the spec's bounds must fail rather
	// than be issued and then capped to something the operator did not choose.
	requested, err := validateGCPLifetime(spec, lifetime)
	if err != nil {
		return nil, nil, 0, "", err
	}

	// The impersonation call authorizes on cloud-platform, the same scope the
	// federated path presents for the identical call.
	sourceToken, _, err := d.getSourceToken(ctx, []string{gcpCloudPlatformScope})
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to get source token for impersonation: %w", err)
	}

	accessToken, expireTime, err := d.generateAccessToken(ctx, sourceToken, targetSA, scopes, lifetime)
	if err != nil {
		return nil, nil, 0, "", err
	}

	ttl := impersonationTTL(expireTime, requested, spec)

	saKey, err := d.parseServiceAccountKey()
	if err != nil && d.logger != nil {
		d.logger.Warn("could not parse source service account key for mint metadata",
			logger.String("spec", spec.Name), logger.String("error", err.Error()))
	}

	rawData := map[string]interface{}{
		"access_token": accessToken,
	}

	if d.logger != nil {
		d.logger.Debug("minted impersonated GCP access token",
			logger.String("spec", spec.Name),
			logger.String("target_sa", targetSA),
			logger.String("ttl", ttl.String()),
		)
	}

	metadata := gcpImpersonatedMetadata(saKey, targetSA, scopesStr, lifetime, expireTime)

	return rawData, metadata, ttl, "", nil
}

// generateAccessToken calls the IAM Credentials API to mint an access token for
// targetSA, using bearerToken as the impersonation authority. bearerToken is the
// source SA's token in the static path and a WIF-federated token in the federation
// path — the call is identical either way. Returns the token and its RFC3339
// expireTime (may be empty).
func (d *GCPDriver) generateAccessToken(ctx context.Context, bearerToken, targetSA string, scopes []string, lifetime string) (string, string, error) {
	apiURL := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		d.iamCredentialsHost, url.PathEscape(targetSA))

	reqBody := map[string]interface{}{
		"scope":    scopes,
		"lifetime": lifetime,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal impersonation request: %w", err)
	}

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "POST",
		url:         apiURL,
		body:        bodyBytes,
		contentType: "application/json",
		bearerToken: bearerToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "generateAccessToken",
	})
	if err != nil {
		return "", "", err
	}

	var tokenResp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"` // RFC3339
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", "", fmt.Errorf("failed to decode impersonation response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", "", fmt.Errorf("impersonation response missing accessToken")
	}
	return tokenResp.AccessToken, tokenResp.ExpireTime, nil
}

// ttlFromExpireTime parses an RFC3339 expireTime into a remaining duration,
// returning fallback when the timestamp is empty, unparseable, or already elapsed.
func ttlFromExpireTime(expireTime string, fallback time.Duration) time.Duration {
	if expireTime != "" {
		if expiry, err := time.Parse(time.RFC3339, expireTime); err == nil {
			if ttl := time.Until(expiry); ttl > 0 {
				return ttl
			}
		}
	}
	return fallback
}

// ============================================================================
// Secret Manager reads (mint_method=secret_read)
// ============================================================================

// resolveSecretVersionPath builds the resource a secret read addresses, resolving any
// {{user.<claim>}} / {{agent.<claim>}} template in the secret name first so one spec
// can serve many callers and each reads only its own secret.
//
// secret_name may be a bare id or an already-qualified resource. A bare id needs the
// project alongside it; a qualified one carries its own, and pairing it with `project`
// is refused where the spec is written rather than silently preferring one of two
// answers. An absent version reads the current one, which is how a spec follows
// rotation of the secret it names.
func resolveSecretVersionPath(spec *credential.CredSpec, userClaims, agentClaims map[string]string) (string, error) {
	name, err := credential.GetStringRequired(spec.Config, "secret_name")
	if err != nil {
		return "", err
	}
	name, err = resolveClaimTemplate(name, userClaims, agentClaims, "secret_name")
	if err != nil {
		return "", err
	}

	// Every segment is escaped, as every other interpolated GCP path in this driver
	// is. Without it a name carrying "#" truncates the request — reading a different
	// version than the spec names while defeating the write-time rule against
	// addressing two — and one carrying "?" turns the read into a different call
	// entirely. The write-time charset checks make those unwritable; escaping here
	// means a config that drifted past them still cannot reshape the request.
	project := credential.GetString(spec.Config, "project", "")
	secretID := name

	if rest, ok := strings.CutPrefix(name, "projects/"); ok {
		// A qualified resource carries its own project; its shape is checked where
		// the spec is written.
		parts := strings.Split(rest, "/secrets/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("'secret_name' must read 'projects/<project>/secrets/<name>' when fully qualified, got: %s", name)
		}
		project, secretID = parts[0], parts[1]
	} else if project == "" {
		return "", fmt.Errorf("'project' is required when 'secret_name' is a bare secret id")
	}

	version := credential.GetString(spec.Config, "secret_version", "")
	if version == "" {
		version = "latest"
	}

	return fmt.Sprintf("projects/%s/secrets/%s/versions/%s",
		url.PathEscape(project), url.PathEscape(secretID), url.PathEscape(version)), nil
}

// fetchSecret reads a Secret Manager payload with the given bearer token and returns
// it as the credential's data. The token may be the source's own (static auth) or one
// obtained for this caller through federation.
//
// The returned TTL is zero and there is no lease: a stored secret does not expire and
// nothing here can revoke it. Its freshness is bounded by the consuming spec's
// secret_cache_ttl, not by a lease this could invent.
func (d *GCPDriver) fetchSecret(ctx context.Context, bearerToken string, spec *credential.CredSpec,
	userClaims, agentClaims map[string]string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {

	versionPath, err := resolveSecretVersionPath(spec, userClaims, agentClaims)
	if err != nil {
		return nil, nil, 0, "", err
	}

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "GET",
		url:         d.secretManagerHost + "/v1/" + versionPath + ":access",
		bearerToken: bearerToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "accessSecretVersion",
	})
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to read secret %q: %w", versionPath, err)
	}

	var accessResp struct {
		Name    string `json:"name"`
		Payload struct {
			Data       string `json:"data"`
			DataCrc32c string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(respBody, &accessResp); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to decode secret response: %w", err)
	}

	decoded, err := base64Decode(accessResp.Payload.Data)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to decode secret payload: %w", err)
	}
	if len(decoded) == 0 {
		return nil, nil, 0, "", fmt.Errorf("secret %q has an empty payload", versionPath)
	}
	if len(decoded) > gcpMaxSecretPayloadSize {
		return nil, nil, 0, "", fmt.Errorf("secret %q payload is %d bytes, beyond the %d Secret Manager stores", versionPath, len(decoded), gcpMaxSecretPayloadSize)
	}
	// The service returns a checksum for exactly this purpose. Verifying it costs a
	// pass over bytes we already hold and turns a truncated payload into an error
	// rather than a credential that is quietly wrong.
	if err := verifySecretCRC32C(decoded, accessResp.Payload.DataCrc32c); err != nil {
		return nil, nil, 0, "", fmt.Errorf("secret %q failed its integrity check: %w", versionPath, err)
	}

	rawData, err := parseSecretPayload(decoded)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("secret %q: %w", versionPath, err)
	}
	rawData = credential.ApplyKeyMap(rawData, credential.GetString(spec.Config, "json_key_map", ""))
	if len(rawData) == 0 {
		return nil, nil, 0, "", fmt.Errorf("secret %q yielded no fields; check 'json_key_map' against the stored payload", versionPath)
	}

	if d.logger != nil {
		d.logger.Debug("read GCP Secret Manager secret",
			logger.String("spec", spec.Name),
			logger.String("secret", versionPath),
		)
	}

	return rawData, nil, 0, "", nil
}

// parseSecretPayload turns raw secret bytes into the credential's fields.
//
// Secret Manager stores arbitrary bytes, so unlike a store that holds documents there
// is no single right shape. A JSON object of scalars is vended under its own key names
// — the multi-field secret a chained consumer reads by name, with numbers and booleans
// rendered as strings because that is the only shape this credential type carries.
// Anything that is not a JSON object at all, a plain API key being the common case, is
// vended whole under "value".
//
// A document containing a nested object or array is refused rather than vended either
// way. Blobbing it under "value" would be actively dangerous: a consuming spec that
// names no secret_field takes the sole key when there is only one, so the entire
// document — every secret stored beside the wanted one — would be sent upstream as the
// credential. Dropping the nested field and keeping the rest would be quietly lossy.
// Neither is worth the convenience of accepting a shape nothing here can represent.
func parseSecretPayload(decoded []byte) (map[string]interface{}, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal(decoded, &fields); err != nil || fields == nil {
		// Not a JSON object: the payload is one opaque secret.
		return map[string]interface{}{"value": string(decoded)}, nil
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("payload is an empty JSON object, carrying no secret")
	}

	out := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		switch typed := v.(type) {
		case string:
			out[k] = typed
		case bool:
			out[k] = strconv.FormatBool(typed)
		case float64:
			// encoding/json decodes every JSON number as a float64. Render integers
			// without a decimal point so a stored port or id reads back as written.
			out[k] = strconv.FormatFloat(typed, 'f', -1, 64)
		case nil:
			return nil, fmt.Errorf("payload field %q is null", k)
		default:
			return nil, fmt.Errorf("payload field %q holds a nested object or array, which a key/value credential cannot carry; store it as its own secret, or as a string", k)
		}
	}
	return out, nil
}

// verifySecretCRC32C checks the payload against the checksum the service reports.
//
// The field is optional, so its absence is not a failure — refusing a secret the
// service chose not to checksum would fail closed on something carrying no evidence of
// corruption. A checksum that is present but unreadable is different: the envelope is
// then demonstrably not what the service sends, which is exactly what this guards
// against, so it fails rather than skipping the check.
func verifySecretCRC32C(payload []byte, want string) error {
	if want == "" {
		return nil
	}
	expected, err := strconv.ParseUint(want, 10, 32)
	if err != nil {
		return fmt.Errorf("reported checksum %q is not a 32-bit value: %w", want, err)
	}
	if got := uint64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))); got != expected {
		return fmt.Errorf("checksum %d does not match the %d reported", got, expected)
	}
	return nil
}

// mintViaSecretRead reads the secret with the source's own credentials.
//
// Neither principal's claims are available here: this path runs when the spec sets no
// subject_token_source, so nothing on the request was verified into claims. Passing
// nil means a templated secret_name fails closed rather than being sent literally —
// which matters, because a store will happily return a secret actually named
// "prod/{{user.sub}}" to whoever can create one.
func (d *GCPDriver) mintViaSecretRead(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// target_service_account is honoured only over federation, where the caller's own
	// assertion authorizes the impersonation. Accepting it here and reading as the
	// source instead would vend a secret under an authority the operator did not name.
	if credential.GetString(spec.Config, "target_service_account", "") != "" {
		return nil, nil, 0, "", fmt.Errorf("gcp: 'target_service_account' applies to mint_method=secret_read only over auth_method=oidc_federation; a static source reads as itself")
	}

	token, _, err := d.getSourceToken(ctx, []string{gcpCloudPlatformScope})
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire GCP access token: %w", err)
	}
	return d.fetchSecret(ctx, token, spec, nil, nil)
}

// ============================================================================
// ExchangeMinter Interface Implementation (Workload Identity Federation)
// ============================================================================

// gcpTokenExchangeGrantType is the RFC 8693 token-exchange grant used against
// GCP STS. GCP STS does not define a package-level constant, so it lives here.
const gcpTokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// gcpFederationScope is the scope requested from STS for the federated token on the
// impersonation path: the token only needs to call generateAccessToken, and the
// real per-credential scopes are applied there. Matches x/oauth2 externalaccount.
const gcpFederationScope = gcpCloudPlatformScope

// MintCredentialWithExchange mints a GCP credential over Workload Identity
// Federation by exchanging the caller's verified identity assertion at GCP STS for
// a federated access token, then optionally impersonating a target service account.
//
// Supported mint methods over federation:
//   - impersonated_access_token: STS federated token → generateAccessToken on the
//     target SA; the impersonated token is the issued credential.
//   - access_token: the STS federated token is itself the issued credential.
func (d *GCPDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if d.getAuthMethod() != gcpAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("gcp: workload identity federation requires auth_method=oidc_federation on the source")
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("gcp: no subject token in exchange inputs")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "access_token")
	switch mintMethod {
	case "impersonated_access_token":
		targetSA := credential.GetString(spec.Config, "target_service_account", "")
		if targetSA == "" {
			return nil, nil, 0, "", fmt.Errorf("gcp: target_service_account is required for impersonated_access_token")
		}
		lifetime := credential.GetString(spec.Config, "lifetime", "3600s")
		requested, err := validateGCPLifetime(spec, lifetime)
		if err != nil {
			return nil, nil, 0, "", err
		}
		scopesStr := credential.GetString(spec.Config, "scopes", gcpFederationScope)
		scopes := splitScopes(scopesStr)
		if len(scopes) == 0 {
			return nil, nil, 0, "", fmt.Errorf("gcp: 'scopes' resolved to nothing for mint_method=impersonated_access_token")
		}

		// Exchange the assertion for a federated token scoped to call the IAM
		// Credentials API, then impersonate the target SA with it.
		fedToken, _, err := d.exchangeWIFToken(ctx, inputs.SubjectToken, inputs.SubjectTokenType, gcpFederationScope)
		if err != nil {
			return nil, nil, 0, "", err
		}
		accessToken, expireTime, err := d.generateAccessToken(ctx, fedToken, targetSA, scopes, lifetime)
		if err != nil {
			return nil, nil, 0, "", err
		}
		ttl := impersonationTTL(expireTime, requested, spec)

		rawData := map[string]interface{}{"access_token": accessToken}
		metadata := map[string]interface{}{
			"subject":  targetSA,
			"scopes":   scopesStr,
			"lifetime": lifetime,
			"provider": d.getWorkloadIdentityProvider(),
		}
		if expireTime != "" {
			metadata["expiration"] = expireTime
		}
		if d.logger != nil {
			d.logger.Debug("minted federated impersonated GCP access token",
				logger.String("spec", spec.Name),
				logger.String("target_sa", targetSA),
				logger.String("ttl", ttl.String()),
			)
		}
		return rawData, metadata, ttl, "", nil

	case "access_token":
		// The federated token itself is the issued credential; honor the spec's scopes.
		scopesStr := credential.GetString(spec.Config, "scopes", gcpFederationScope)
		fedToken, ttl, err := d.exchangeWIFToken(ctx, inputs.SubjectToken, inputs.SubjectTokenType, scopesStr)
		if err != nil {
			return nil, nil, 0, "", err
		}
		// The token's real validity cannot be shortened, but the lease/cache lifetime
		// must not exceed the spec's MaxTTL. MinTTL is deliberately NOT enforced here:
		// unlike the AWS assume-role path (where a duration is requested), the STS
		// token's lifetime is fixed by GCP, so a value below MinTTL cannot be raised —
		// capping to MaxTTL is the only bound we can apply.
		if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
			ttl = spec.MaxTTL
		}
		// The subject is the principal the token was federated for, not the provider
		// it was federated through — the provider is one value for the whole source,
		// so recording it here made every caller look identical in the audit trail.
		// It is still reported separately as `provider`.
		rawData := map[string]interface{}{"access_token": fedToken}
		metadata := map[string]interface{}{
			"scopes":   scopesStr,
			"provider": d.getWorkloadIdentityProvider(),
		}
		if sub := inputs.AgentClaims["sub"]; sub != "" {
			metadata["subject"] = sub
		}
		if d.logger != nil {
			d.logger.Debug("minted federated GCP access token",
				logger.String("spec", spec.Name),
				logger.String("ttl", ttl.String()),
			)
		}
		return rawData, metadata, ttl, "", nil

	case "secret_read":
		// The credential is the stored secret, not the token that reads it, so the
		// token is asked for a short fixed life and discarded straight after. The
		// caller's claims travel with the fetch: a templated secret name resolves
		// from them, scoping the read to the principals on this request.
		fedToken, _, err := d.exchangeWIFToken(ctx, inputs.SubjectToken, inputs.SubjectTokenType, gcpFederationScope)
		if err != nil {
			return nil, nil, 0, "", err
		}

		readToken := fedToken
		if targetSA := credential.GetString(spec.Config, "target_service_account", ""); targetSA != "" {
			readToken, _, err = d.generateAccessToken(ctx, fedToken, targetSA,
				[]string{gcpCloudPlatformScope}, gcpFederatedFetchLifetime)
			if err != nil {
				return nil, nil, 0, "", err
			}
		}

		return d.fetchSecret(ctx, readToken, spec, inputs.UserClaims, inputs.AgentClaims)

	default:
		return nil, nil, 0, "", fmt.Errorf("gcp: mint_method %q is not supported over auth_method=oidc_federation (supported: impersonated_access_token, access_token, secret_read)", mintMethod)
	}
}

// exchangeWIFToken exchanges a subject assertion for a federated GCP access token at
// STS. subjectTokenType defaults to a JWT when empty. scope is the space/comma-list
// of scopes requested for the federated token. Returns the token and its lifetime.
func (d *GCPDriver) exchangeWIFToken(ctx context.Context, subjectToken, subjectTokenType, scope string) (string, time.Duration, error) {
	if subjectTokenType == "" {
		subjectTokenType = credential.TokenTypeJWT
	}
	// STS wants a space-delimited scope list; accept a comma-separated spec value.
	scope = strings.Join(splitScopes(scope), " ")

	form := url.Values{}
	form.Set("grant_type", gcpTokenExchangeGrantType)
	form.Set("audience", d.getWorkloadIdentityProvider())
	form.Set("scope", scope)
	form.Set("requested_token_type", credential.TokenTypeAccessToken)
	form.Set("subject_token_type", subjectTokenType)
	form.Set("subject_token", subjectToken)

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "POST",
		url:         d.stsHost + "/v1/token",
		body:        []byte(form.Encode()),
		contentType: "application/x-www-form-urlencoded",
		okStatuses:  []int{http.StatusOK},
		operation:   "stsTokenExchange",
	})
	if err != nil {
		return "", 0, err
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode STS token-exchange response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("STS token-exchange response missing access_token")
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = gcpSTSTokenFallbackTTL
	}
	return tokenResp.AccessToken, ttl, nil
}

// gcpLifetimePattern matches the only spelling the IAM Credentials API accepts for
// its lifetime field: a decimal number of seconds with an "s" suffix, the protobuf
// Duration JSON encoding. The spec's value is forwarded to that field verbatim, so
// anything Go's duration parser would also accept — "1h", "30m" — has to be refused
// here or it validates locally and is rejected by the API on every mint.
var gcpLifetimePattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?s$`)

// validateGCPLifetime parses a GCP lifetime string (e.g. "1800s") and checks it
// against both the API's ceiling and the spec's TTL bounds, returning the parsed
// duration so callers can bound a lease by what was actually requested.
func validateGCPLifetime(spec *credential.CredSpec, lifetime string) (time.Duration, error) {
	if !gcpLifetimePattern.MatchString(lifetime) {
		return 0, fmt.Errorf("gcp: invalid lifetime %q: must be a number of seconds with an 's' suffix, e.g. \"1800s\"", lifetime)
	}
	dur, err := time.ParseDuration(lifetime)
	if err != nil {
		return 0, fmt.Errorf("gcp: invalid lifetime %q: %w", lifetime, err)
	}
	if dur <= 0 {
		return 0, fmt.Errorf("gcp: lifetime %q must be positive", lifetime)
	}
	if dur > gcpMaxImpersonationLifetime {
		return 0, fmt.Errorf("gcp: lifetime %s exceeds the maximum the IAM Credentials API accepts (%s)", dur, gcpMaxImpersonationLifetime)
	}
	if spec.MinTTL > 0 && dur < spec.MinTTL {
		return 0, fmt.Errorf("gcp: lifetime %s is below the spec minimum %s", dur, spec.MinTTL)
	}
	if spec.MaxTTL > 0 && dur > spec.MaxTTL {
		return 0, fmt.Errorf("gcp: lifetime %s exceeds the spec maximum %s", dur, spec.MaxTTL)
	}
	return dur, nil
}

// impersonationTTL resolves the lease life of an impersonated token. The API's
// expireTime is authoritative when present; when it is absent or unparseable the
// requested lifetime is the honest fallback, because that is what the token was
// asked to live for. A fixed constant here would hand out a lease outliving the
// token — a spec asking for 600s would be served a dead token from cache for the
// remaining 50 minutes of a one-hour lease.
func impersonationTTL(expireTime string, requested time.Duration, spec *credential.CredSpec) time.Duration {
	ttl := ttlFromExpireTime(expireTime, requested)
	if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
		ttl = spec.MaxTTL
	}
	return ttl
}

// gcpAssertionResource reports the canonical downstream resource a GCP federation
// spec targets, for the warden_resource assertion claim. Pure: reads source/spec
// config only, no network or driver state. The provider prefix is human-readable
// sugar on an opaque value — never parse it back.
func gcpAssertionResource(sourceCfg, specCfg credential.Config) (string, bool) {
	// The claim describes what an assertion is presented to, and only a federated
	// source presents one. Without this a static source would derive a resource for a
	// mint the exchange path refuses outright, naming a target nothing ever reaches.
	// gcpAssertionAudience gates on the same condition.
	if credential.GetString(sourceCfg, "auth_method", gcpAuthMethodStatic) != gcpAuthMethodOIDCFederation {
		return "", false
	}

	// Default mirrors the federated mint_method dispatch in MintCredentialWithExchange
	// (empty → access_token) so the named resource matches what the exchange reaches.
	switch credential.GetString(specCfg, "mint_method", "access_token") {
	case "impersonated_access_token":
		if sa := credential.GetString(specCfg, "target_service_account", ""); sa != "" {
			return "gcp-iam:" + sa, true
		}
	case "access_token":
		if p := credential.GetString(sourceCfg, "workload_identity_provider", ""); p != "" {
			return "gcp-wif:" + p, true
		}
	case "secret_read":
		// A templated secret name is carried unresolved, as every templated coordinate
		// is here: this runs before the exchange that produces the claims it would
		// resolve from. A policy conditioning on this claim therefore pins the spec,
		// not the individual secret — per-principal scoping is enforced where the
		// resolved read happens, by the permissions on the identity doing it.
		if n := credential.GetString(specCfg, "secret_name", ""); n != "" {
			return "gcp-secretmanager:" + n, true
		}
	}
	return "", false
}

// Revoke is a no-op for GCP credentials (they expire naturally)
func (d *GCPDriver) Revoke(ctx context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("GCP credentials expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *GCPDriver) Type() string {
	return credential.SourceTypeGCP
}

// Cleanup releases resources. A driver is torn down on every source config change
// and on every rotation, so idle keep-alive connections to the GCP endpoints would
// otherwise accumulate one set per teardown. The token cache needs no clearing — the
// instance is unreachable once this returns.
func (d *GCPDriver) Cleanup(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source SA Key Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source SA key.
// Only a static-key source has a key to rotate; a keyless federation source has
// nothing to rotate. Rotation requires the SA to have iam.serviceAccountKeys.create
// and iam.serviceAccountKeys.delete permissions on itself.
func (d *GCPDriver) SupportsRotation() bool {
	return d.getAuthMethod() == gcpAuthMethodStatic
}

// PrepareRotation creates a new SA key for the source service account, proves it
// works, and returns activateAfter to allow time for GCP IAM propagation.
//
// The verification is not optional. The rotation manager persists the returned config
// before it ever calls CommitRotation, so a key that turns out to be unusable is
// already the source's stored credential by the time anything notices — and the
// created key is never reclaimed, which matters because a service account may hold
// only ten. Left alone, a handful of failed rotations exhausts the quota and no
// future rotation can succeed. So: verify here, and delete what we made if it fails.
func (d *GCPDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	saKey, err := d.parseServiceAccountKey()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse current SA key: %w", err)
	}

	oldKeyID := saKey.PrivateKeyID
	oldKeyJSON := d.getServiceAccountKey()

	// Get IAM token using current credentials
	iamToken, _, err := d.acquireToken(ctx, []string{gcpIAMScope})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get IAM token: %w", err)
	}

	// Create new SA key via IAM API
	newKeyJSON, err := d.createServiceAccountKey(ctx, iamToken, saKey.ClientEmail, saKey.ProjectID)
	if err != nil {
		return nil, nil, 0, err
	}

	if err := d.verifyNewKey(ctx, newKeyJSON); err != nil {
		d.discardUnusableKey(ctx, iamToken, saKey, newKeyJSON)
		return nil, nil, 0, fmt.Errorf("newly created SA key never became usable: %w", err)
	}

	// Build new config
	newConfig := d.configSnapshot()
	newConfig["service_account_key"] = newKeyJSON

	// The old key travels with the cleanup handle so the deletion can authenticate as
	// the key it is deleting. See CleanupRotation for why that matters. This rides the
	// same barrier-encrypted storage the new key already does.
	cleanupConfig := map[string]string{
		"old_key_id":              oldKeyID,
		"service_account_email":   saKey.ClientEmail,
		"project_id":              saKey.ProjectID,
		"old_service_account_key": oldKeyJSON,
	}

	// Rotation does not touch activation_delay, so the snapshot carries the live value.
	activateAfter := credential.GetDuration(credential.NewConfig(newConfig), "activation_delay", DefaultGCPActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source SA key rotation",
			logger.String("old_key_id", truncateID(oldKeyID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// verifyNewKey waits for a freshly created key to mint a token. A new key is not
// recognised across Google's replicas the instant it is created, so the first
// attempts can fail with a signature error that is nothing but propagation delay —
// a single probe would routinely condemn a perfectly good key. Retries with a flat
// one-second gap until the key works or the window closes.
func (d *GCPDriver) verifyNewKey(ctx context.Context, keyJSON string) error {
	deadline := time.Now().Add(gcpRotationVerifyTimeout)

	var lastErr error
	for {
		if _, _, lastErr = d.tokenFromKeyJSON(ctx, keyJSON, []string{gcpCloudPlatformScope}); lastErr == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

// discardUnusableKey deletes a key that was created but never became usable, so a
// failed rotation does not permanently consume one of the ten slots a service
// account has. Best-effort by nature: the rotation has already failed and this only
// decides whether it also leaks. Runs on a detached context so a caller that gave up
// mid-rotation does not cancel the cleanup of what it just created.
func (d *GCPDriver) discardUnusableKey(ctx context.Context, iamToken string, saKey *serviceAccountKey, newKeyJSON string) {
	newKey, err := parseServiceAccountKeyJSON([]byte(newKeyJSON))
	if err != nil || newKey.PrivateKeyID == "" {
		return
	}

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if err := d.deleteServiceAccountKey(cleanupCtx, iamToken, saKey.ProjectID, saKey.ClientEmail, newKey.PrivateKeyID); err != nil && d.logger != nil {
		d.logger.Warn("could not delete the unusable SA key just created; it still counts against the per-account key quota",
			logger.String("key_id", truncateID(newKey.PrivateKeyID, 8)),
			logger.String("error", err.Error()))
	}
}

// CommitRotation activates new credentials in the driver
func (d *GCPDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	// Prove the key works before publishing it, not after. Swapping first and checking
	// second leaves a driver holding a credential it has just discovered is broken,
	// with nothing to roll back to; failing here leaves the working key in place.
	if _, _, err := d.tokenFromKeyJSON(ctx, newConfig["service_account_key"], []string{gcpCloudPlatformScope}); err != nil {
		return fmt.Errorf("failed to authenticate with new SA key: %w", err)
	}

	// Publish the new key and retire every token the old one minted, as one step. The
	// generation bump follows the config write under the same lock, so a mint already
	// in flight against the retired key cannot file its result under the new
	// generation — getSourceToken reads the generation before it reads the key.
	d.authMu.Lock()
	d.credSource.Config = credential.NewConfig(newConfig)
	d.tokenCache.InvalidateGeneration()
	d.authMu.Unlock()

	if d.logger != nil {
		d.logger.Debug("committed source SA key rotation")
	}

	return nil
}

// CleanupRotation deletes the old SA key
func (d *GCPDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldKeyID := cleanupConfig["old_key_id"]
	if oldKeyID == "" {
		return nil
	}

	saEmail := cleanupConfig["service_account_email"]
	projectID := cleanupConfig["project_id"]

	// Authenticate as the key being deleted, when the handle carries it. By this point
	// the new key has only just been published, and it is the one whose public half may
	// not yet be recognised everywhere — the very propagation lag PrepareRotation waits
	// out. The retired key has no such problem: it has existed long enough to be known
	// to every replica, right up until it is removed. An older handle predating this
	// field falls back to the live credential, which is the previous behaviour.
	var iamToken string
	var err error
	if oldKeyJSON := cleanupConfig["old_service_account_key"]; oldKeyJSON != "" {
		iamToken, _, err = d.tokenFromKeyJSON(ctx, oldKeyJSON, []string{gcpIAMScope})
	} else {
		iamToken, _, err = d.getSourceToken(ctx, []string{gcpIAMScope})
	}
	if err != nil {
		return fmt.Errorf("failed to get IAM token: %w", err)
	}

	if err := d.deleteServiceAccountKey(ctx, iamToken, projectID, saEmail, oldKeyID); err != nil {
		return fmt.Errorf("failed to delete old SA key: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old SA key",
			logger.String("old_key_id", truncateID(oldKeyID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Token Acquisition
// ============================================================================

// getSourceToken returns a cached or freshly acquired token for the given scopes.
// Thread-safe.
func (d *GCPDriver) getSourceToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	scopeKey := strings.Join(scopes, ",")

	// Losing the generation race means a rotation landed mid-mint, which is rare and
	// self-clearing. Losing it repeatedly means something is wrong, and this sits on
	// the request path — so bound the retries rather than spin against a rotation loop.
	const maxGenerationRetries = 3

	for attempt := 0; attempt < maxGenerationRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", time.Time{}, err
		}

		// Read the generation before the SA key, so a rotation landing while the mint
		// is in flight is always visible as a change by the time we store.
		gen := d.tokenCache.GetGeneration()

		// Check cache (with 60s refresh buffer)
		if token, expiry, ok := d.tokenCache.Get(scopeKey, 60*time.Second); ok {
			return token, expiry, nil
		}

		// Acquire fresh token
		token, expiry, err := d.acquireToken(ctx, scopes)
		if err != nil {
			return "", time.Time{}, err
		}

		// A refused store means the SA key rotated during the mint, so this token may
		// have come from the retired key. Drop it and mint against the current one.
		if d.tokenCache.SetIfGeneration(scopeKey, token, expiry, gen) {
			return token, expiry, nil
		}
	}

	return "", time.Time{}, fmt.Errorf("gcp: source key rotated repeatedly while minting; giving up after %d attempts", maxGenerationRetries)
}

// acquireToken gets a fresh OAuth2 token using the SA key.
func (d *GCPDriver) acquireToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return "", time.Time{}, fmt.Errorf("service_account_key is empty")
	}
	return d.tokenFromKeyJSON(ctx, saKeyJSON, scopes)
}

// tokenFromKeyJSON mints a token from an explicit key, bypassing both the config and
// the cache. Rotation needs that: it must prove a newly created key works before
// publishing it, and must delete the retired key while still authenticating as it.
//
// The credential type is pinned rather than inferred. The untyped constructor
// dispatches on the JSON's own "type" field, so a key declaring external_account or
// impersonated_service_account would turn this into a fetch of whatever file or URL
// that document names — reading host files and calling arbitrary endpoints as this
// process, from nothing but source config. Only a service-account key is ever valid
// here, so say so.
//
// oauthClientCtx carries the driver's HTTP client: without it the token exchange
// silently runs on http.DefaultClient, ignoring ca_data, tls_skip_verify and the
// client timeout that the operator configured for exactly these calls.
func (d *GCPDriver) tokenFromKeyJSON(ctx context.Context, keyJSON string, scopes []string) (string, time.Time, error) {
	creds, err := google.CredentialsFromJSONWithType(
		d.oauthClientCtx(ctx), []byte(keyJSON), google.ServiceAccount, scopes...)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create GCP credentials: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to acquire GCP token: %w", err)
	}

	return token.AccessToken, token.Expiry, nil
}

// oauthClientCtx returns ctx carrying the driver's HTTP client, which is what
// x/oauth2 looks for when it builds its transport.
func (d *GCPDriver) oauthClientCtx(ctx context.Context) context.Context {
	if d.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, d.httpClient)
}

// ============================================================================
// IAM API Helpers (raw HTTP, no google-api-go-client dependency)
// ============================================================================

// gcpAPIRequest describes an HTTP request to a GCP API endpoint
type gcpAPIRequest struct {
	method      string
	url         string
	body        []byte
	contentType string
	bearerToken string
	okStatuses  []int
	operation   string
}

// doGCPRequest executes an HTTP request to a GCP API endpoint
func (d *GCPDriver) doGCPRequest(ctx context.Context, apiReq gcpAPIRequest) ([]byte, error) {
	// Prepare headers
	headers := make(map[string]string)
	if apiReq.contentType != "" {
		headers["Content-Type"] = apiReq.contentType
	}
	if apiReq.bearerToken != "" {
		headers["Authorization"] = "Bearer " + apiReq.bearerToken
	}

	// GCP answers 429 on quota (service-account key creation is capped per project
	// per minute) and 5xx under load on both STS and IAM Credentials. Every call this
	// driver makes through here is safe to re-issue: the token mints are idempotent in
	// effect, and a re-issued key creation is recovered by the rollback in
	// PrepareRotation. Retrying none of them, as this did, turned one transient answer
	// into a failed mint or a half-finished rotation.
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       gcpAPIMaxAttempts,
		MaxBodySize:       gcpMaxResponseBodySize,
		RetryableStatuses: []int{429, 500, 502, 503, 504},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}

	httpReq := httputil.HTTPRequest{
		Method:     apiReq.method,
		URL:        apiReq.url,
		Body:       apiReq.body,
		Headers:    headers,
		OKStatuses: apiReq.okStatuses,
	}

	respBody, _, err := httputil.ExecuteWithRetry(ctx, d.httpClient, httpReq, retryConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", apiReq.operation, err)
	}
	return respBody, nil
}

// createServiceAccountKey creates a new key for the given service account
func (d *GCPDriver) createServiceAccountKey(ctx context.Context, iamToken, saEmail, projectID string) (string, error) {
	// Empty values here would build a path with a hole in it — /v1/projects//... —
	// which the API answers with a 400 or 404 that says nothing about the real cause.
	if projectID == "" || saEmail == "" {
		return "", fmt.Errorf("cannot create SA key: service account key is missing project_id or client_email")
	}

	apiURL := fmt.Sprintf("%s/v1/projects/%s/serviceAccounts/%s/keys",
		d.iamHost, url.PathEscape(projectID), url.PathEscape(saEmail))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	})

	respBody, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "POST",
		url:         apiURL,
		body:        reqBody,
		contentType: "application/json",
		bearerToken: iamToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "createServiceAccountKey",
	})
	if err != nil {
		return "", fmt.Errorf("failed to create SA key: %w", err)
	}

	// Response contains the key in base64-encoded privateKeyData
	var keyResp struct {
		PrivateKeyData string `json:"privateKeyData"` // base64-encoded JSON key
	}
	if err := json.Unmarshal(respBody, &keyResp); err != nil {
		return "", fmt.Errorf("failed to decode create key response: %w", err)
	}

	if keyResp.PrivateKeyData == "" {
		return "", fmt.Errorf("create key response missing privateKeyData")
	}

	keyJSON, err := base64Decode(keyResp.PrivateKeyData)
	if err != nil {
		return "", fmt.Errorf("failed to decode privateKeyData: %w", err)
	}

	// Checked against every field the driver will use, not merely "is it JSON".
	// Whatever comes back here becomes the source's stored credential, and a
	// truncated or empty document that passed a laxer check would be persisted and
	// leave the source unable to authenticate at all.
	if _, err := parseServiceAccountKeyJSON(keyJSON); err != nil {
		return "", fmt.Errorf("newly created SA key is unusable: %w", err)
	}

	return string(keyJSON), nil
}

// deleteServiceAccountKey deletes a specific key from a service account
func (d *GCPDriver) deleteServiceAccountKey(ctx context.Context, iamToken, projectID, saEmail, keyID string) error {
	if projectID == "" || saEmail == "" || keyID == "" {
		return fmt.Errorf("cannot delete SA key: missing project, service account or key id")
	}

	apiURL := fmt.Sprintf("%s/v1/projects/%s/serviceAccounts/%s/keys/%s",
		d.iamHost, url.PathEscape(projectID), url.PathEscape(saEmail), url.PathEscape(keyID))

	_, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "DELETE",
		url:         apiURL,
		bearerToken: iamToken,
		okStatuses:  []int{http.StatusOK, http.StatusNoContent},
		operation:   "deleteServiceAccountKey",
	})
	return err
}

// ============================================================================
// Helpers
// ============================================================================

// splitScopes splits a scopes string into a slice, accepting either separator an
// operator is likely to reach for: commas, or the spaces Google's own documentation
// uses. Empty elements are dropped rather than passed through — a trailing comma or
// an explicitly empty value would otherwise become a blank scope, which the token
// grant rejects, and which reads as "no scopes set" everywhere it is logged.
func splitScopes(scopesStr string) []string {
	return strings.FieldsFunc(scopesStr, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// base64Decode decodes base64 in any of the four encodings proto3 JSON permits for a
// bytes field. Standard padded encoding is what Google emits today; accepting the
// URL-safe and unpadded forms costs three fallbacks and removes a decode failure that
// would look like a corrupt key.
func base64Decode(encoded string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	var err error
	for _, enc := range encodings {
		var decoded []byte
		if decoded, err = enc.DecodeString(encoded); err == nil {
			return decoded, nil
		}
	}
	return nil, err
}
