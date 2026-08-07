package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// Default GCP API hosts. The driver's stsHost/iamCredentialsHost fields default to
// these; tests override the fields to point token exchange and impersonation at a
// local server.
const (
	defaultGCPSTSHost            = "https://sts.googleapis.com"
	defaultGCPIAMCredentialsHost = "https://iamcredentials.googleapis.com"
)

// gcpFederatedTokenFallbackTTL is used when the STS token-exchange response omits
// the optional expires_in, so the lease is never zero/negative.
const gcpFederatedTokenFallbackTTL = 1 * time.Hour

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

	// Flag to track if source credentials have been verified
	sourceVerified bool

	// API hosts, defaulting to the public GCP endpoints. Overridden in tests to
	// point STS token exchange and SA impersonation at a local server.
	stsHost            string
	iamCredentialsHost string
}

// Config accessors — single source of truth is credSource.Config.

func (d *GCPDriver) getServiceAccountKey() string {
	return credential.GetString(d.credSource.Config, "service_account_key", "")
}

func (d *GCPDriver) getAuthMethod() string {
	return credential.GetString(d.credSource.Config, "auth_method", gcpAuthMethodStatic)
}

func (d *GCPDriver) getWorkloadIdentityProvider() string {
	return credential.GetString(d.credSource.Config, "workload_identity_provider", "")
}

func (d *GCPDriver) parseServiceAccountKey() (*serviceAccountKey, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return nil, fmt.Errorf("service_account_key is empty")
	}
	var saKey serviceAccountKey
	if err := json.Unmarshal([]byte(saKeyJSON), &saKey); err != nil {
		return nil, fmt.Errorf("invalid service_account_key JSON: %w", err)
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
func (f *GCPDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			OneOf(gcpAuthMethodStatic, gcpAuthMethodOIDCFederation).
			Describe("How the source authenticates: static (service account key) or oidc_federation (Workload Identity Federation, keyless)").
			Example("static"),

		credential.StringField("service_account_key").
			Custom(func(value string) error {
				// Validate that service_account_key is valid JSON with required fields
				var saKey serviceAccountKey
				if err := json.Unmarshal([]byte(value), &saKey); err != nil {
					return fmt.Errorf("must be valid JSON: %w", err)
				}
				if saKey.ClientEmail == "" {
					return fmt.Errorf("missing 'client_email' field in JSON")
				}
				if saKey.PrivateKey == "" {
					return fmt.Errorf("missing 'private_key' field in JSON")
				}
				return nil
			}).
			Describe("GCP service account key in JSON format (required for auth_method=static)").
			Example("{\"type\":\"service_account\",\"project_id\":\"...\",\"private_key\":\"...\"}"),

		credential.StringField("workload_identity_provider").
			Describe("Full WIF provider resource name (required for auth_method=oidc_federation)").
			Example("//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/warden-oidc"),

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

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *GCPDriverFactory) SensitiveConfigFields() []string {
	return []string{"service_account_key", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *GCPDriverFactory) InferCredentialType(specConfig map[string]string) (string, error) {
	mintMethod := specConfig["mint_method"]
	switch mintMethod {
	case "cloud_sql_iam_token":
		return credential.TypeDBAuthToken, nil
	case "", "access_token", "impersonated_access_token":
		return credential.TypeGCPAccessToken, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// Create instantiates a new GCPDriver
func (f *GCPDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: config,
		},
		logger:             log.WithSubsystem(credential.SourceTypeGCP),
		tokenCache:         NewTokenCache(),
		stsHost:            defaultGCPSTSHost,
		iamCredentialsHost: defaultGCPIAMCredentialsHost,
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

	if _, _, err := driver.acquireToken(ctx, []string{"https://www.googleapis.com/auth/cloud-platform"}); err != nil {
		return nil, fmt.Errorf("GCP authentication failed: %w", err)
	}
	driver.sourceVerified = true

	return driver, nil
}

// MintCredential mints credentials based on the spec's mint_method.
func (d *GCPDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A keyless source mints only through the exchange path, which carries the
	// caller-scoped assertion. Fail closed here to avoid the misleading
	// "service_account_key is empty" error a federation source would otherwise hit.
	if d.getAuthMethod() == gcpAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("gcp: source uses auth_method=oidc_federation; the spec must set subject_token_source (warden_identity or auth_token)")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "access_token")

	switch mintMethod {
	case "access_token":
		return d.mintAccessToken(ctx, spec)
	case "impersonated_access_token":
		return d.mintImpersonatedAccessToken(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for GCP driver; use 'access_token' or 'impersonated_access_token'", mintMethod)
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

// mintAccessToken exchanges the source SA key for an OAuth2 access token
func (d *GCPDriver) mintAccessToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	scopesStr := credential.GetString(spec.Config, "scopes", "https://www.googleapis.com/auth/cloud-platform")
	scopes := splitScopes(scopesStr)

	token, expiry, err := d.getSourceToken(ctx, scopes)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire GCP access token: %w", err)
	}

	saKey, _ := d.parseServiceAccountKey()

	ttl := time.Until(expiry)
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

	scopesStr := credential.GetString(spec.Config, "scopes", "https://www.googleapis.com/auth/cloud-platform")
	scopes := splitScopes(scopesStr)
	lifetime := credential.GetString(spec.Config, "lifetime", "3600s")

	// Get source token with IAM scope for impersonation
	sourceToken, _, err := d.getSourceToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to get source token for impersonation: %w", err)
	}

	accessToken, expireTime, err := d.generateAccessToken(ctx, sourceToken, targetSA, scopes, lifetime)
	if err != nil {
		return nil, nil, 0, "", err
	}

	ttl := ttlFromExpireTime(expireTime, gcpFederatedTokenFallbackTTL)

	saKey, _ := d.parseServiceAccountKey()

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
	}, 1)
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
// ExchangeMinter Interface Implementation (Workload Identity Federation)
// ============================================================================

// gcpTokenExchangeGrantType is the RFC 8693 token-exchange grant used against
// GCP STS. GCP STS does not define a package-level constant, so it lives here.
const gcpTokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// gcpFederationScope is the scope requested from STS for the federated token on the
// impersonation path: the token only needs to call generateAccessToken, and the
// real per-credential scopes are applied there. Matches x/oauth2 externalaccount.
const gcpFederationScope = "https://www.googleapis.com/auth/cloud-platform"

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
	if inputs.SubjectTokenOrigin != credential.ExchangeOriginVerified {
		return nil, nil, 0, "", fmt.Errorf("gcp: workload identity federation requires a verified subject (subject_token_source=warden_identity or auth_token); a caller-supplied, unverified subject is rejected")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "access_token")
	switch mintMethod {
	case "impersonated_access_token":
		targetSA := credential.GetString(spec.Config, "target_service_account", "")
		if targetSA == "" {
			return nil, nil, 0, "", fmt.Errorf("gcp: target_service_account is required for impersonated_access_token")
		}
		lifetime := credential.GetString(spec.Config, "lifetime", "3600s")
		if err := validateGCPLifetime(spec, lifetime); err != nil {
			return nil, nil, 0, "", err
		}
		scopesStr := credential.GetString(spec.Config, "scopes", gcpFederationScope)
		scopes := splitScopes(scopesStr)

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
		ttl := ttlFromExpireTime(expireTime, gcpFederatedTokenFallbackTTL)

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
		rawData := map[string]interface{}{"access_token": fedToken}
		metadata := map[string]interface{}{
			"subject":  d.getWorkloadIdentityProvider(),
			"scopes":   scopesStr,
			"provider": d.getWorkloadIdentityProvider(),
		}
		if d.logger != nil {
			d.logger.Debug("minted federated GCP access token",
				logger.String("spec", spec.Name),
				logger.String("ttl", ttl.String()),
			)
		}
		return rawData, metadata, ttl, "", nil

	default:
		return nil, nil, 0, "", fmt.Errorf("gcp: mint_method %q is not supported over auth_method=oidc_federation (supported: impersonated_access_token, access_token)", mintMethod)
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
	}, 1)
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
		ttl = gcpFederatedTokenFallbackTTL
	}
	return tokenResp.AccessToken, ttl, nil
}

// validateGCPLifetime parses a GCP lifetime string (e.g. "1800s") and checks it
// against the spec's TTL bounds, mirroring the AWS federated session-TTL guard.
func validateGCPLifetime(spec *credential.CredSpec, lifetime string) error {
	dur, err := time.ParseDuration(lifetime)
	if err != nil {
		return fmt.Errorf("gcp: invalid lifetime %q: %w", lifetime, err)
	}
	if spec.MinTTL > 0 && dur < spec.MinTTL {
		return fmt.Errorf("gcp: lifetime %s is below the spec minimum %s", dur, spec.MinTTL)
	}
	if spec.MaxTTL > 0 && dur > spec.MaxTTL {
		return fmt.Errorf("gcp: lifetime %s exceeds the spec maximum %s", dur, spec.MaxTTL)
	}
	return nil
}

// gcpAssertionResource reports the canonical downstream resource a GCP federation
// spec targets, for the warden_resource assertion claim. Pure: reads source/spec
// config only, no network or driver state. The provider prefix is human-readable
// sugar on an opaque value — never parse it back.
func gcpAssertionResource(sourceCfg, specCfg map[string]string) (string, bool) {
	// Default mirrors the federated mint_method dispatch in MintCredentialWithExchange
	// (empty → access_token) so the named resource matches what the exchange reaches.
	// A static source has no workload_identity_provider, so access_token still yields
	// no resource there.
	switch credential.GetString(specCfg, "mint_method", "access_token") {
	case "impersonated_access_token":
		if sa := credential.GetString(specCfg, "target_service_account", ""); sa != "" {
			return "gcp-iam:" + sa, true
		}
	case "access_token":
		if p := credential.GetString(sourceCfg, "workload_identity_provider", ""); p != "" {
			return "gcp-wif:" + p, true
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

// Cleanup releases resources
func (d *GCPDriver) Cleanup(ctx context.Context) error {
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

// PrepareRotation creates a new SA key for the source service account.
// Returns activateAfter to allow time for GCP IAM propagation.
func (d *GCPDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	saKey, err := d.parseServiceAccountKey()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse current SA key: %w", err)
	}

	oldKeyID := saKey.PrivateKeyID

	// Get IAM token using current credentials
	iamToken, _, err := d.acquireToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get IAM token: %w", err)
	}

	// Create new SA key via IAM API
	newKeyJSON, err := d.createServiceAccountKey(ctx, iamToken, saKey.ClientEmail, saKey.ProjectID)
	if err != nil {
		return nil, nil, 0, err
	}

	// Build new config
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["service_account_key"] = newKeyJSON

	cleanupConfig := map[string]string{
		"old_key_id":            oldKeyID,
		"service_account_email": saKey.ClientEmail,
		"project_id":            saKey.ProjectID,
	}

	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultGCPActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source SA key rotation",
			logger.String("old_key_id", truncateID(oldKeyID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver
func (d *GCPDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	// Update config (single source of truth for credentials)
	d.credSource.Config = newConfig

	// Invalidate all cached tokens from previous generation
	d.tokenCache.InvalidateGeneration()
	d.sourceVerified = false

	// Verify new credentials work
	_, _, err := d.acquireToken(ctx, []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err != nil {
		return fmt.Errorf("failed to authenticate with new SA key: %w", err)
	}
	d.sourceVerified = true

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

	// Get IAM token
	iamToken, _, err := d.getSourceToken(ctx, []string{"https://www.googleapis.com/auth/iam"})
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

	// Check cache (with 60s refresh buffer)
	if token, expiry, ok := d.tokenCache.Get(scopeKey, 60*time.Second); ok {
		return token, expiry, nil
	}

	// Acquire fresh token
	token, expiry, err := d.acquireToken(ctx, scopes)
	if err != nil {
		return "", time.Time{}, err
	}

	// Cache it
	d.tokenCache.Set(scopeKey, token, expiry)

	return token, expiry, nil
}

// acquireToken gets a fresh OAuth2 token using the SA key.
func (d *GCPDriver) acquireToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	saKeyJSON := d.getServiceAccountKey()
	if saKeyJSON == "" {
		return "", time.Time{}, fmt.Errorf("service_account_key is empty")
	}

	creds, err := google.CredentialsFromJSON(ctx, []byte(saKeyJSON), scopes...)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create GCP credentials: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to acquire GCP token: %w", err)
	}

	return token.AccessToken, token.Expiry, nil
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
func (d *GCPDriver) doGCPRequest(ctx context.Context, apiReq gcpAPIRequest, maxAttempts int) ([]byte, error) {
	// Prepare headers
	headers := make(map[string]string)
	if apiReq.contentType != "" {
		headers["Content-Type"] = apiReq.contentType
	}
	if apiReq.bearerToken != "" {
		headers["Authorization"] = "Bearer " + apiReq.bearerToken
	}

	// Configure retry behavior (no automatic retries by default)
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       maxAttempts,
		MaxBodySize:       gcpMaxResponseBodySize,
		RetryableStatuses: []int{}, // GCP doesn't retry by default
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
	apiURL := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys",
		url.PathEscape(projectID), url.PathEscape(saEmail))

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
	}, 1)
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

	// Decode base64 to get the actual JSON key file content
	import_encoding := keyResp.PrivateKeyData
	if import_encoding == "" {
		return "", fmt.Errorf("create key response missing privateKeyData")
	}

	// The privateKeyData is base64-encoded; decode it
	keyJSON, err := base64Decode(import_encoding)
	if err != nil {
		return "", fmt.Errorf("failed to decode privateKeyData: %w", err)
	}

	// Validate the new key is valid JSON
	var newKey serviceAccountKey
	if err := json.Unmarshal(keyJSON, &newKey); err != nil {
		return "", fmt.Errorf("new SA key is not valid JSON: %w", err)
	}

	return string(keyJSON), nil
}

// deleteServiceAccountKey deletes a specific key from a service account
func (d *GCPDriver) deleteServiceAccountKey(ctx context.Context, iamToken, projectID, saEmail, keyID string) error {
	apiURL := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys/%s",
		url.PathEscape(projectID), url.PathEscape(saEmail), url.PathEscape(keyID))

	_, err := d.doGCPRequest(ctx, gcpAPIRequest{
		method:      "DELETE",
		url:         apiURL,
		bearerToken: iamToken,
		okStatuses:  []int{http.StatusOK, http.StatusNoContent},
		operation:   "deleteServiceAccountKey",
	}, 1)
	return err
}

// ============================================================================
// Helpers
// ============================================================================

// splitScopes splits a comma-separated scopes string into a slice
func splitScopes(scopesStr string) []string {
	scopes := strings.Split(scopesStr, ",")
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}
	return scopes
}

// base64Decode decodes a standard base64-encoded string
func base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
