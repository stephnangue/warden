package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// DefaultAzureActivationDelay is the default wait period for Azure AD propagation.
// Azure AD may take several seconds to minutes to propagate a new password credential
// across regions. The activation delay replaces polling with a simple scheduled wait.
const DefaultAzureActivationDelay = 5 * time.Minute

// maxResponseBodySize limits response body reads to prevent OOM from large responses
const maxResponseBodySize = 1 << 20 // 1MB

// addPasswordMaxAttempts is the retry count for adding a password credential.
// Higher than remove because add failure causes full rotation failure, while
// remove failure is retried by the rotation manager's cleanup mechanism.
const addPasswordMaxAttempts = 5

// removePasswordMaxAttempts is the retry count for removing a password credential.
// Lower than add because remove is called during cleanup, which has its own retry
// mechanism (3 immediate retries + daily retry for 7 days).
const removePasswordMaxAttempts = 3

// Source authentication methods. static uses a stored client_secret; oidc_federation
// is keyless — a caller-scoped Warden assertion is presented as a client_assertion
// (Azure AD Workload Identity Federation), so no secret is stored in Warden.
const (
	azureAuthMethodStatic         = "static"
	azureAuthMethodOIDCFederation = "oidc_federation"
)

// defaultAzureLoginHost is the public-cloud Entra ID authority host. The driver's
// loginHost field defaults to this; tests override the field to point token
// acquisition at a local server.
const defaultAzureLoginHost = "https://login.microsoftonline.com"

// defaultAzureGraphHost is the public-cloud Microsoft Graph host. Like loginHost it
// is a struct field rather than config: rotation is the only Graph caller, and a
// config override could only redirect writes to a tenant somewhere else. Tests set
// the field to exercise rotation against a local server.
const defaultAzureGraphHost = "https://graph.microsoft.com"

// Resources the source's own tokens are requested for. graphResource names the API,
// not the host — it stays the public Graph resource even when graphHost points at a
// test server.
const (
	armResource   = "https://management.azure.com/"
	graphResource = "https://graph.microsoft.com/"
)

// Source token cache tuning.
const (
	// azureSourceTokenRefreshBuffer is how long before expiry a cached source token
	// stops being served, so a token handed out is never about to die in flight.
	azureSourceTokenRefreshBuffer = 5 * time.Minute

	// azureSourceTokenAttempts bounds how many times a token acquisition is retried
	// because a rotation retired the credentials it was minted with. Each retry reads
	// the new credentials, so a second attempt succeeds unless rotations land back to
	// back.
	azureSourceTokenAttempts = 3
)

// Graph-permission probe cache lifetimes. A success is stable — it can only change
// when the source's credentials do, which is covered by the generation stamp — so it
// is kept long. A failure is often transient (a network blip, an Entra hiccup), so it
// is kept only long enough to avoid hammering Entra; caching it for the life of the
// driver would switch rotation off until the driver happened to be rebuilt.
const (
	graphPermsPositiveTTL = time.Hour
	graphPermsNegativeTTL = time.Minute
)

// validateTenantID checks that the tenant ID is a valid UUID
func validateTenantID(tenantID string) error {
	return credential.ValidateUUID("tenant_id", tenantID)
}

// truncateID safely truncates a string for logging, appending "..." if truncated
func truncateID(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// readLimitedBody reads a response body with a size limit to prevent OOM
func readLimitedBody(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, maxResponseBodySize))
}

// azureScope turns a resource URI into the ".default" scope the client-credentials
// grant takes. Entra expects the suffix after a slash — "https://management.azure.com/.default",
// "api://<app-id>/.default" — so a resource written without its trailing slash must
// not be glued straight onto ".default". A value that already is a .default scope is
// passed through.
func azureScope(resourceURI string) string {
	if strings.HasSuffix(resourceURI, "/.default") {
		return resourceURI
	}
	return strings.TrimSuffix(resourceURI, "/") + "/.default"
}

// azureAPIRequest describes an HTTP request to an Azure API endpoint
type azureAPIRequest struct {
	method      string // "GET" or "POST"
	url         string
	body        []byte // nil for GET; []byte so retries can re-send
	contentType string // "" to omit Content-Type header
	bearerToken string // "" to omit Authorization header
	okStatuses  []int  // status codes that mean success
	operation   string // for error messages: "addPassword", "acquireToken", etc.
}

// doAzureRequest executes an HTTP request with optional retry on specific status codes.
// retryStatuses specifies which HTTP status codes should trigger a retry (e.g., 409).
// maxAttempts is the total number of attempts (1 = no retry).
func (d *AzureDriver) doAzureRequest(ctx context.Context, apiReq azureAPIRequest, retryStatuses []int, maxAttempts int) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s... with ~20% jitter
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			jitter := time.Duration(rand.Int63n(int64(backoff / 5)))
			timer := time.NewTimer(backoff + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		var bodyReader io.Reader
		if apiReq.body != nil {
			bodyReader = bytes.NewReader(apiReq.body)
		}

		req, err := http.NewRequestWithContext(ctx, apiReq.method, apiReq.url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to create request: %w", apiReq.operation, err)
		}

		if apiReq.contentType != "" {
			req.Header.Set("Content-Type", apiReq.contentType)
		}
		if apiReq.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+apiReq.bearerToken)
		}

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: request failed: %w", apiReq.operation, err)
		}

		respBody, bodyErr := readLimitedBody(resp.Body)
		resp.Body.Close()

		for _, ok := range apiReq.okStatuses {
			if resp.StatusCode == ok {
				if bodyErr != nil {
					return nil, fmt.Errorf("%s: status %d but failed to read response body: %w",
						apiReq.operation, resp.StatusCode, bodyErr)
				}
				return respBody, nil
			}
		}

		bodyStr := string(respBody)
		if bodyErr != nil {
			bodyStr = fmt.Sprintf("[body read error: %v]", bodyErr)
		}
		lastErr = &httputil.StatusError{Status: resp.StatusCode,
			Err: fmt.Errorf("%s failed with status %d: %s", apiReq.operation, resp.StatusCode, bodyStr)}

		shouldRetry := false
		for _, rs := range retryStatuses {
			if resp.StatusCode == rs {
				shouldRetry = true
				break
			}
		}
		if !shouldRetry {
			return nil, lastErr
		}

		if d.logger != nil {
			d.logger.Warn(fmt.Sprintf("%s got retryable status %d, retrying", apiReq.operation, resp.StatusCode),
				logger.Int("attempt", attempt+1),
				logger.Int("max_attempts", maxAttempts),
			)
		}
	}
	return nil, lastErr
}

// Compile-time interface assertions
var _ credential.SourceDriver = (*AzureDriver)(nil)
var _ credential.Rotatable = (*AzureDriver)(nil)
var _ credential.SpecRotatable = (*AzureDriver)(nil)
var _ credential.ExchangeMinter = (*AzureDriver)(nil)
var _ credential.RotationConfigValidator = (*AzureDriverFactory)(nil)

// AzureDriver mints credentials from Azure services.
// It exchanges pre-provisioned service principal credentials (stored in specs)
// for Azure AD bearer tokens.
//
// The driver's source credentials are used for:
//   - Validating connectivity to Azure AD
//   - Rotating source and spec credentials via Microsoft Graph (needs
//     Application.ReadWrite.OwnedBy or Application.ReadWrite.All)
//
// The spec credentials (stored in CredSpec.Config) are used for minting bearer
// tokens for Azure resources.
//
// Locking. No lock is ever held across a network call. configMu guards the source
// config field, which rotation replaces while mints are in flight; the token cache
// carries its own lock; graphPermsMu guards the permission-probe result and is taken
// before the token cache, never after it.
type AzureDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// configMu guards credSource.Config. RWMutex because the readers are on the mint
	// path. sourceConfig takes it, reads one map header and releases, so it never
	// nests with another lock.
	configMu sync.RWMutex

	// tokenCache holds the source's own tokens, keyed by resource URI. Its generation
	// is bumped when rotation installs new credentials, so a token minted by the
	// retired ones is never served. tokenGroup coalesces concurrent misses for the
	// same resource and generation into one request to Entra.
	tokenCache *TokenCache
	tokenGroup singleflight.Group

	// graphPerms caches the Graph-permission probe, stamped with the token-cache
	// generation it was taken under so a rotation invalidates it without touching
	// graphPermsMu. now is the clock the expiry is judged against; nil means
	// time.Now (tests inject a fake).
	graphPermsMu sync.Mutex
	graphPerms   *graphPermsEntry
	now          func() time.Time

	// HTTP client for Azure API calls
	httpClient *http.Client

	// Entra ID authority and Graph hosts; empty means the public-cloud defaults.
	// loginHost comes from the source's login_endpoint; graphHost has no config key
	// and is set only by tests, so rotation can be exercised without Azure.
	loginHost string
	graphHost string

	// keyVaultEndpoint, from the source's key_vault_endpoint, replaces the Key Vault
	// base URL for every read; empty means https://<vault_name>.vault.azure.net.
	// Like loginHost it is fixed when the driver is built — a config change rebuilds
	// the driver — so it is read without a lock.
	keyVaultEndpoint string
}

// graphPermsEntry is one cached Graph-permission probe result.
type graphPermsEntry struct {
	ok         bool
	expiresAt  time.Time
	generation uint64
}

// sourceTokenResult is what a coalesced source-token fetch hands its callers.
// stored reports whether the token was filed under the generation it was requested
// for; a token that was not was minted by credentials a rotation has since retired.
type sourceTokenResult struct {
	token  string
	stored bool
}

// Config accessors — single source of truth is credSource.Config.
// These are cheap map lookups, not cached copies.

// sourceConfig returns the current config map. Rotation swaps in a whole new map
// rather than writing into the live one, so the result is a stable snapshot and
// callers need not hold the lock while reading it.
func (d *AzureDriver) sourceConfig() credential.Config {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.credSource.Config
}

func (d *AzureDriver) getTenantID() string {
	return credential.GetString(d.sourceConfig(), "tenant_id", "")
}

func (d *AzureDriver) getClientID() string {
	return credential.GetString(d.sourceConfig(), "client_id", "")
}

func (d *AzureDriver) getClientSecret() string {
	return credential.GetString(d.sourceConfig(), "client_secret", "")
}

// sourceCreds returns the service principal's tenant, client id and secret from a
// single snapshot.
//
// These three must never be read separately. A rotation landing between two of the
// reads would pair a client id with a secret belonging to a different generation —
// a credential that never existed — and the resulting failure looks like a bad
// stored secret rather than a torn read.
func (d *AzureDriver) sourceCreds() (tenantID, clientID, clientSecret string) {
	return azureCreds(d.sourceConfig())
}

// azureCreds reads the service principal triple from one config snapshot.
func azureCreds(config credential.Config) (tenantID, clientID, clientSecret string) {
	return credential.GetString(config, "tenant_id", ""),
		credential.GetString(config, "client_id", ""),
		credential.GetString(config, "client_secret", "")
}

func (d *AzureDriver) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func (d *AzureDriver) graphBase() string {
	if d.graphHost != "" {
		return d.graphHost
	}
	return defaultAzureGraphHost
}

// AzureDriverFactory creates AzureDriver instances
type AzureDriverFactory struct{}

// Type returns the driver type
func (f *AzureDriverFactory) Type() string {
	return credential.SourceTypeAzure
}

// ValidateConfig validates Azure driver configuration using declarative schema
func (f *AzureDriverFactory) ValidateConfig(config credential.Config) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			OneOf(azureAuthMethodStatic, azureAuthMethodOIDCFederation).
			Describe("How the source authenticates: static (client secret) or oidc_federation (Workload Identity Federation, keyless)").
			Example("static"),

		credential.StringField("tenant_id").
			Custom(validateTenantID).
			Describe("Azure AD tenant ID (UUID; required for auth_method=static)").
			Example("00000000-0000-0000-0000-000000000000"),

		credential.StringField("client_id").
			Custom(func(v string) error { return credential.ValidateUUID("client_id", v) }).
			Describe("Azure AD application (client) ID (UUID; required for auth_method=static)").
			Example("11111111-1111-1111-1111-111111111111"),

		credential.StringField("client_secret").
			Describe("Azure AD application client secret (required for auth_method=static)").
			Example("secret-value"),

		credential.StringField("secret_id").
			Describe("Secret ID for the client secret (for rotation tracking; required for auth_method=static)").
			Example("secret-id-uuid"),

		credential.DurationField("activation_delay").
			Custom(validateNonNegativeDuration).
			Describe("How long a rotated client secret is left to propagate through Entra ID before Warden switches to it (default 5m)").
			Example("5m"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),

		credential.StringField("audience").
			Describe("Audience minted into a warden_identity assertion for this source (oidc_federation only; default api://AzureADTokenExchange)").
			Example("api://AzureADTokenExchange"),

		credential.StringField("login_endpoint").
			Custom(validateEndpointURL).
			Describe("Override the Entra ID authority host every token request goes to (default https://login.microsoftonline.com)").
			Example("https://login.microsoftonline.com"),

		credential.StringField("key_vault_endpoint").
			Custom(validateEndpointURL).
			Describe("Override the Key Vault base URL secret reads go to (default https://<vault_name>.vault.azure.net); applies to every vault this source reads").
			Example("https://acme-prod-kv.vault.azure.net"),
	); err != nil {
		return err
	}

	// Cross-field rules per auth_method.
	switch credential.GetString(config, "auth_method", azureAuthMethodStatic) {
	case azureAuthMethodStatic:
		if credential.GetString(config, "tenant_id", "") == "" ||
			credential.GetString(config, "client_id", "") == "" ||
			credential.GetString(config, "client_secret", "") == "" ||
			credential.GetString(config, "secret_id", "") == "" {
			return fmt.Errorf("tenant_id, client_id, client_secret, and secret_id are required for auth_method=static")
		}
		// audience seeds only the warden_identity federation assertion; on a static
		// source it would be silently ignored, so reject it rather than mislead.
		if credential.GetString(config, "audience", "") != "" {
			return fmt.Errorf("audience is only valid for auth_method=oidc_federation")
		}
	case azureAuthMethodOIDCFederation:
		// A federation source holds no static secret. Reject leftover static config
		// so a misconfiguration cannot silently mix modes.
		if credential.GetString(config, "client_secret", "") != "" || credential.GetString(config, "secret_id", "") != "" {
			return fmt.Errorf("client_secret/secret_id must not be set for auth_method=oidc_federation")
		}
	}
	return nil
}

// validateNonNegativeDuration rejects a negative duration. The type check has
// already run, so a parse failure cannot reach here.
func validateNonNegativeDuration(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	if d < 0 {
		return fmt.Errorf("must not be negative")
	}
	return nil
}

// ValidateRotationConfig refuses a rotation period on a source whose token requests or
// Key Vault reads are redirected. Rotation writes to the real tenant through Graph,
// which neither override redirects: it would rotate a secret in one place while the
// source authenticates somewhere else.
func (f *AzureDriverFactory) ValidateRotationConfig(config credential.Config) error {
	if credential.GetString(config, "login_endpoint", "") == "" &&
		credential.GetString(config, "key_vault_endpoint", "") == "" {
		return nil
	}
	return fmt.Errorf("rotation_period cannot be set on a source that overrides " +
		"login_endpoint or key_vault_endpoint: rotation manages client secrets in the " +
		"real tenant through Microsoft Graph, which those overrides do not redirect")
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AzureDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *AzureDriverFactory) InferCredentialType(specConfig credential.Config) (string, error) {
	mintMethod := specConfig.Get("mint_method")
	switch mintMethod {
	case "", "bearer_token":
		return credential.TypeAzureBearerToken, nil
	case "secret_read":
		// A Key Vault secret is vended under its own key names, the shape a chained
		// consumer reads by name.
		return credential.TypeKeyValue, nil
	case "azure_db_iam_token":
		// Accepted by the db_auth_token schema so the refusal can be specific, but
		// nothing mints it: inferring a type would let a spec be written that fails
		// every mint.
		return "", fmt.Errorf("mint_method 'azure_db_iam_token' is not implemented for the azure driver")
	case "key_vault_secret":
		return "", errKeyVaultSecretRemoved
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// errKeyVaultSecretRemoved refuses the retired Key Vault mint method. It built the
// vault URL from spec config without validating it, so a spec could send a Key Vault
// token to any host.
var errKeyVaultSecretRemoved = errors.New("mint_method 'key_vault_secret' is no longer supported for the azure driver; read Key Vault secrets with type key_value and mint_method secret_read")

// Create instantiates a new AzureDriver
func (f *AzureDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &AzureDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAzure,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeAzure),
		tokenCache: NewTokenCache(),
		// Trailing slashes trimmed so the paths appended to them join cleanly.
		loginHost:        strings.TrimRight(credential.GetString(config, "login_endpoint", ""), "/"),
		keyVaultEndpoint: strings.TrimRight(credential.GetString(config, "key_vault_endpoint", ""), "/"),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	driver.httpClient = httpClient

	// A keyless federation source holds no client_secret to verify — the caller-scoped
	// assertion arrives only at mint time. Skip the eager source-token probe.
	if credential.GetString(config, "auth_method", azureAuthMethodStatic) == azureAuthMethodOIDCFederation {
		return driver, nil
	}

	// Validate source credentials by acquiring a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := driver.getSourceToken(ctx, armResource); err != nil {
		driver.httpClient.CloseIdleConnections()
		return nil, fmt.Errorf("Azure authentication failed: %w", err)
	}

	return driver, nil
}

// MintCredential mints credentials based on the spec's mint_method.
// Credentials are minted using the SP credentials stored in the spec (not the source).
func (d *AzureDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A keyless source mints only through the exchange path, which carries the
	// caller-scoped assertion. Fail closed here to avoid silently minting with
	// no credential material.
	if credential.GetString(d.sourceConfig(), "auth_method", azureAuthMethodStatic) == azureAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("azure: source uses auth_method=oidc_federation; the spec must set subject_token_source (warden_identity or agent_identity)")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "bearer_token")

	switch mintMethod {
	case "bearer_token":
		return d.mintBearerToken(ctx, spec, "")
	case "secret_read":
		return d.mintViaSecretRead(ctx, spec)
	case "key_vault_secret":
		return nil, nil, 0, "", errKeyVaultSecretRemoved
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for Azure driver; use 'bearer_token' or 'secret_read'", mintMethod)
	}
}

// mintViaSecretRead reads a Key Vault secret as the source's own service principal,
// with a cached source token.
//
// A spec naming its own app is refused rather than silently read as the source: that
// identity is honoured only over federation, where the caller's assertion authorizes
// it. Neither principal's claims are available here either — this path runs when the
// spec sets no subject_token_source — so a templated secret_name fails closed rather
// than being sent literally.
func (d *AzureDriver) mintViaSecretRead(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if credential.GetString(spec.Config, "client_id", "") != "" || credential.GetString(spec.Config, "tenant_id", "") != "" {
		return nil, nil, 0, "", fmt.Errorf("azure: 'client_id'/'tenant_id' apply to mint_method=secret_read only over auth_method=oidc_federation; a static source reads as itself")
	}

	token, err := d.getSourceToken(ctx, keyVaultResource)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire Key Vault token: %w", err)
	}
	return d.readKeyVaultSecret(ctx, token, spec, nil, nil)
}

// MintCredentialWithExchange mints a bearer token via Azure AD Workload Identity
// Federation: the subject in inputs is presented to Entra as a client_assertion, so a
// keyless source needs no stored secret. Gated on a federation source and a trusted
// subject, of which there are two shapes: a Warden-minted assertion
// (subject_token_source=warden_identity, the app federates Warden's issuer) or the
// agent's verified inbound JWT forwarded untouched (subject_token_source=agent_identity,
// the app's federated credential must trust the origin IdP directly). There is no
// caller-supplied, unverified subject token.
func (d *AzureDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if credential.GetString(d.sourceConfig(), "auth_method", azureAuthMethodStatic) != azureAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("azure: workload identity federation requires auth_method=oidc_federation on the source")
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("azure: no subject token in exchange inputs")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "bearer_token")
	switch mintMethod {
	case "bearer_token":
		return d.mintBearerToken(ctx, spec, inputs.SubjectToken)
	case "secret_read":
		// The credential is the stored secret, not the token that reads it: the
		// token is used for this one read and discarded. The caller's claims travel
		// with the read, so a templated secret name resolves from them and scopes the
		// read to the principals on this request.
		tenantID := credential.GetString(spec.Config, "tenant_id", "")
		clientID := credential.GetString(spec.Config, "client_id", "")
		if tenantID == "" || clientID == "" {
			return nil, nil, 0, "", fmt.Errorf("spec config must contain 'client_id' and 'tenant_id' for a federated secret_read")
		}
		token, _, err := d.acquireTokenWithAssertion(ctx, tenantID, clientID, inputs.SubjectToken, keyVaultResource)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("failed to acquire Key Vault token: %w", err)
		}
		return d.readKeyVaultSecret(ctx, token, spec, inputs.UserClaims, inputs.AgentClaims)
	default:
		return nil, nil, 0, "", fmt.Errorf("azure: mint_method %q is not supported over auth_method=oidc_federation (supported: bearer_token, secret_read)", mintMethod)
	}
}

// defaultAzureFederationAudience is the standard `aud` an Entra federated identity
// credential expects on a client_assertion presented for workload identity
// federation.
const defaultAzureFederationAudience = "api://AzureADTokenExchange"

// azureAssertionAudience derives the warden_identity assertion audience for an Azure
// federation source: the source's explicit `audience`, else the conventional
// default. Only a keyless (oidc_federation) source federates.
func azureAssertionAudience(sourceCfg credential.Config) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", azureAuthMethodStatic) != azureAuthMethodOIDCFederation {
		return "", false
	}
	return credential.GetString(sourceCfg, "audience", defaultAzureFederationAudience), true
}

// azureAssertionResource reports the canonical downstream resource an Azure
// federation spec targets, for the warden_resource assertion claim. Pure: reads
// spec config only.
//
// For bearer_token the resource is the target API (resource_uri), which is coarser
// than a single item — it names the API, not one thing behind it. Mirrors the
// resource_uri read in mintBearerToken.
//
// For secret_read it is the secret: vault and name. A templated secret name is
// carried unresolved, as every templated coordinate is here: this runs before the
// exchange that produces the claims it would resolve from. A policy conditioning on
// this claim therefore pins the spec, not the individual secret — per-principal
// scoping is enforced where the resolved read happens, by the permissions on the
// identity doing it.
func azureAssertionResource(specCfg credential.Config) (string, bool) {
	switch credential.GetString(specCfg, "mint_method", "bearer_token") {
	case "bearer_token":
		uri := credential.GetString(specCfg, "resource_uri", armResource)
		return "azure:" + uri, true
	case "secret_read":
		vault := credential.GetString(specCfg, "vault_name", "")
		name := credential.GetString(specCfg, "secret_name", "")
		if vault == "" || name == "" {
			return "", false
		}
		return "azure-keyvault:" + vault + "/" + name, true
	default:
		return "", false
	}
}

// mintBearerToken exchanges the spec's SP identity for an Azure AD bearer token.
// When assertion is non-empty the token is acquired via Workload Identity Federation
// (the assertion is presented as a client_assertion, no client_secret needed);
// otherwise the pre-provisioned client_secret from the spec is used.
func (d *AzureDriver) mintBearerToken(ctx context.Context, spec *credential.CredSpec, assertion string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// Get SP identity from spec config (pre-provisioned)
	tenantID := credential.GetString(spec.Config, "tenant_id", d.getTenantID())
	clientID := credential.GetString(spec.Config, "client_id", "")
	resourceURI := credential.GetString(spec.Config, "resource_uri", armResource)

	var token string
	var expiresIn int
	var err error
	if assertion != "" {
		if clientID == "" || tenantID == "" {
			return nil, nil, 0, "", fmt.Errorf("spec config must contain 'client_id' and 'tenant_id' for federated bearer_token mint method")
		}
		token, expiresIn, err = d.acquireTokenWithAssertion(ctx, tenantID, clientID, assertion, resourceURI)
	} else {
		clientSecret := credential.GetString(spec.Config, "client_secret", "")
		if clientID == "" || clientSecret == "" {
			return nil, nil, 0, "", fmt.Errorf("spec config must contain 'client_id' and 'client_secret' for bearer_token mint method")
		}
		token, expiresIn, err = d.acquireToken(ctx, tenantID, clientID, clientSecret, resourceURI)
	}
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	ttl := time.Duration(expiresIn) * time.Second

	rawData := map[string]interface{}{
		"access_token": token,
	}

	metadata := azureBearerTokenMetadata(clientID, tenantID, resourceURI, ttl, time.Now())

	if d.logger != nil {
		d.logger.Debug("minted Azure AD bearer token",
			logger.String("spec", spec.Name),
			logger.String("resource_uri", resourceURI),
			logger.String("ttl", ttl.String()),
		)
	}

	// No leaseID - bearer tokens expire naturally and cannot be revoked
	return rawData, metadata, ttl, "", nil
}

// azureBearerTokenMetadata builds clear-loggable identity metadata for an Azure
// AD bearer token. subject is the service principal's client/app id (the token's
// appid claim); the access token itself stays in rawData.
func azureBearerTokenMetadata(clientID, tenantID, resourceURI string, ttl time.Duration, now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"subject":      clientID,
		"tenant_id":    tenantID,
		"resource_uri": resourceURI,
		"expiration":   now.Add(ttl).UTC().Format(time.RFC3339),
	}
}

// Revoke is a no-op for Azure credentials (they expire naturally)
func (d *AzureDriver) Revoke(ctx context.Context, leaseID string) error {
	// Azure bearer tokens cannot be revoked - they expire naturally
	if d.logger != nil {
		d.logger.Debug("Azure credentials expire naturally, skipping revocation",
			logger.String("lease_id", leaseID),
		)
	}
	return nil
}

// Type returns the driver type
func (d *AzureDriver) Type() string {
	return credential.SourceTypeAzure
}

// Cleanup releases the driver's idle connections. A driver is discarded on every
// source update, rotation and spec-write test mint; without this its pooled
// connections, and the goroutines serving them, outlive it.
func (d *AzureDriver) Cleanup(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source Rotation)
// ============================================================================

// SupportsRotation returns true if this driver can rotate its source credentials
func (d *AzureDriver) SupportsRotation() bool {
	return d.hasGraphPermissions()
}

// PrepareRotation creates a new client_secret for the source's SP.
// Returns activateAfter to allow time for Azure AD eventual consistency propagation.
//
// It holds no lock: every value it derives comes from one config snapshot, and the
// Graph calls — which can back off for tens of seconds on a 409 — must not stall the
// source-token readers.
func (d *AzureDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	// One snapshot for everything this rotation derives from the current config, so
	// the app it adds to, the secret it retires, the map it copies and the delay it
	// returns all describe the same generation.
	current := d.sourceConfig()
	clientID := credential.GetString(current, "client_id", "")
	oldSecretID := credential.GetString(current, "secret_id", "")

	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	newSecret, newSecretID, err := d.addPasswordCredential(ctx, graphToken, clientID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new password credential: %w", err)
	}

	newConfig := make(map[string]string, current.Len())
	for k, v := range current.All() {
		newConfig[k] = v
	}
	newConfig["client_secret"] = newSecret
	newConfig["secret_id"] = newSecretID

	// The app travels with the key id. Cleanup can be retried for days on a driver
	// built from whatever config is current by then; if the source has been pointed
	// at another app meanwhile, removing the key from that app would find nothing and
	// report success while the retired secret lives on in the original one.
	cleanupConfig := map[string]string{
		"client_id":     clientID,
		"old_secret_id": oldSecretID,
	}

	// Return activateAfter to let the rotation manager schedule activation
	// after Azure AD eventual consistency has propagated the new credential.
	activateAfter := credential.GetDuration(current, "activation_delay", DefaultAzureActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared source credential rotation",
			logger.String("new_secret_id", truncateID(newSecretID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates new credentials in the driver.
//
// The order is load-bearing:
//
//  1. Prove the new credentials first, before anything changes. The rotation manager
//     has already persisted the new config by now, so what this protects is the old
//     secret: the error stops the manager before its cleanup deletes it, leaving a
//     working secret on the app while the new one is investigated. (The persisted
//     update also retires this driver instance; the next one is built from the
//     persisted config.)
//  2. Swap the config.
//  3. Bump the token-cache generation, AFTER the swap. A reader takes the generation
//     before it reads the credentials; bumped first, a reader could still pick up the
//     old credentials under the new generation and file their token as current.
//  4. Pre-warm the Graph token, best effort, so CleanupRotation can reuse it.
//
// No lock is held across the network calls.
func (d *AzureDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	next := credential.NewConfig(newConfig)
	tenantID, clientID, clientSecret := azureCreds(next)
	if _, _, err := d.acquireToken(ctx, tenantID, clientID, clientSecret, armResource); err != nil {
		return fmt.Errorf("failed to authenticate with new credentials: %w", err)
	}

	d.configMu.Lock()
	d.credSource.Config = next
	d.configMu.Unlock()

	d.tokenCache.InvalidateGeneration()

	if _, err := d.getGraphToken(ctx); err != nil && d.logger != nil {
		d.logger.Trace("Graph token not yet cached during commit, cleanup will retry")
	}

	if d.logger != nil {
		d.logger.Debug("committed source credential rotation")
	}

	return nil
}

// CleanupRotation deletes old client_secret
func (d *AzureDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldSecretID := cleanupConfig["old_secret_id"]
	if oldSecretID == "" {
		return nil
	}

	// Entries staged before the app was recorded carry no client_id; for those the
	// current config is the best available answer.
	appID := cleanupConfig["client_id"]
	if appID == "" {
		appID = d.getClientID()
	}

	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Graph API token: %w", err)
	}

	if err := d.removePasswordCredential(ctx, graphToken, appID, oldSecretID); err != nil {
		return fmt.Errorf("failed to remove old password credential: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old source credential",
			logger.String("old_secret_id", truncateID(oldSecretID, 8)),
		)
	}

	return nil
}

// ============================================================================
// SpecRotatable Interface Implementation (Spec Rotation)
// ============================================================================

// SupportsSpecRotation returns true if this driver can rotate spec credentials
func (d *AzureDriver) SupportsSpecRotation() bool {
	return d.hasGraphPermissions()
}

// PrepareSpecRotation creates a new client_secret for a spec's workload SP.
// Returns activateAfter to allow time for Azure AD eventual consistency propagation.
func (d *AzureDriver) PrepareSpecRotation(ctx context.Context, spec *credential.CredSpec) (map[string]string, map[string]string, time.Duration, error) {
	workloadAppID := credential.GetString(spec.Config, "client_id", "")
	oldSecretID := credential.GetString(spec.Config, "secret_id", "")

	if workloadAppID == "" {
		return nil, nil, 0, fmt.Errorf("spec config must contain 'client_id'")
	}

	// Get Graph API token using source credentials
	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get Graph API token: %w", err)
	}

	newSecret, newSecretID, err := d.addPasswordCredential(ctx, graphToken, workloadAppID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new password credential for workload SP: %w", err)
	}

	// Build new spec config
	newConfig := make(map[string]string)
	for k, v := range spec.Config.All() {
		newConfig[k] = v
	}
	newConfig["client_secret"] = newSecret
	newConfig["secret_id"] = newSecretID

	cleanupConfig := map[string]string{
		"client_id":     workloadAppID,
		"old_secret_id": oldSecretID,
	}

	// Return activateAfter to let the rotation manager schedule activation
	// after Azure AD eventual consistency has propagated the new credential.
	activateAfter := credential.GetDuration(d.sourceConfig(), "activation_delay", DefaultAzureActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared spec credential rotation",
			logger.String("spec", spec.Name),
			logger.String("workload_app_id", truncateID(workloadAppID, 8)),
			logger.String("new_secret_id", truncateID(newSecretID, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitSpecRotation proves the spec's new secret before the rotation completes.
// The driver holds no per-spec state — the manager re-mints from the new spec config
// — so the proof is the whole job: an error here stops the rotation manager before
// its cleanup deletes the old secret, which is then the only one that still works.
// The token is requested for the spec's own resource, the one its mints will ask for.
func (d *AzureDriver) CommitSpecRotation(ctx context.Context, spec *credential.CredSpec, newConfig map[string]string) error {
	next := credential.NewConfig(newConfig)
	tenantID := credential.GetString(next, "tenant_id", d.getTenantID())
	clientID := credential.GetString(next, "client_id", "")
	clientSecret := credential.GetString(next, "client_secret", "")
	resourceURI := credential.GetString(next, "resource_uri", armResource)

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("rotated spec config must contain 'client_id' and 'client_secret'")
	}
	if _, _, err := d.acquireToken(ctx, tenantID, clientID, clientSecret, resourceURI); err != nil {
		return fmt.Errorf("failed to authenticate with the rotated spec credentials: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("committed spec credential rotation",
			logger.String("spec", spec.Name),
		)
	}
	return nil
}

// CleanupSpecRotation deletes old client_secret from workload SP
func (d *AzureDriver) CleanupSpecRotation(ctx context.Context, cleanupConfig map[string]string) error {
	workloadAppID := cleanupConfig["client_id"]
	oldSecretID := cleanupConfig["old_secret_id"]

	if workloadAppID == "" || oldSecretID == "" {
		return nil
	}

	graphToken, err := d.getGraphToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Graph API token: %w", err)
	}

	if err := d.removePasswordCredential(ctx, graphToken, workloadAppID, oldSecretID); err != nil {
		return fmt.Errorf("failed to remove old password credential: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("cleaned up old spec credential",
			logger.String("workload_app_id", truncateID(workloadAppID, 8)),
			logger.String("old_secret_id", truncateID(oldSecretID, 8)),
		)
	}

	return nil
}

// ============================================================================
// Azure AD Token Acquisition
// ============================================================================

// acquireToken exchanges client credentials for an Azure AD token
func (d *AzureDriver) acquireToken(ctx context.Context, tenantID, clientID, clientSecret, resourceURI string) (string, int, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", azureScope(resourceURI))
	data.Set("grant_type", "client_credentials")
	return d.postTokenRequest(ctx, tenantID, data, "acquireToken")
}

// acquireTokenWithAssertion exchanges a Warden-minted assertion for an Azure AD token
// via the JWT-bearer client-credentials grant (Workload Identity Federation). The
// assertion is presented as a client_assertion instead of a client_secret; the target
// app registration must trust Warden's OIDC issuer via a federated identity credential.
func (d *AzureDriver) acquireTokenWithAssertion(ctx context.Context, tenantID, clientID, assertion, resourceURI string) (string, int, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_assertion_type", clientAssertionType)
	data.Set("client_assertion", assertion)
	data.Set("scope", azureScope(resourceURI))
	data.Set("grant_type", "client_credentials")
	return d.postTokenRequest(ctx, tenantID, data, "acquireTokenWithAssertion")
}

// postTokenRequest POSTs an OAuth2 token request to the Entra ID token endpoint for
// tenantID and returns the access token and its lifetime in seconds. Callers supply the
// grant-specific form fields (client_secret vs client_assertion); the URL construction,
// tenant validation, HTTP call, and response decoding are shared.
func (d *AzureDriver) postTokenRequest(ctx context.Context, tenantID string, data url.Values, operation string) (string, int, error) {
	if err := validateTenantID(tenantID); err != nil {
		return "", 0, err
	}

	host := d.loginHost
	if host == "" {
		host = defaultAzureLoginHost
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", host, tenantID)

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         tokenURL,
		body:        []byte(data.Encode()),
		contentType: "application/x-www-form-urlencoded",
		okStatuses:  []int{http.StatusOK},
		operation:   operation,
	}, nil, 1)
	if err != nil {
		return "", 0, err
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	// A 200 is not proof of a token. An empty one would be vended, or cached as the
	// source's, and fail far from here; a non-positive lifetime would be vended as
	// already expired.
	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("%s: token response carried no access_token", operation)
	}
	if tokenResp.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("%s: token response carried no positive expires_in (got %d)", operation, tokenResp.ExpiresIn)
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// getSourceToken returns a token for the source's own service principal, from the
// cache when it holds a live one.
//
// Concurrent misses for one resource are coalesced into a single request to Entra.
// The request runs detached from any one caller's context (bounded by the HTTP
// client's timeout), so a caller that gives up does not fail the others waiting on
// the same fetch; each caller still returns as soon as its own context ends.
//
// The generation is read before the credentials. A rotation that installs new
// credentials while the request is in flight bumps it, the store is refused, and the
// fetch runs again against the new credentials — bounded, so back-to-back rotations
// cannot loop a caller forever.
func (d *AzureDriver) getSourceToken(ctx context.Context, resourceURI string) (string, error) {
	for attempt := 0; attempt < azureSourceTokenAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if token, _, ok := d.tokenCache.Get(resourceURI, azureSourceTokenRefreshBuffer); ok {
			return token, nil
		}

		gen := d.tokenCache.GetGeneration()
		ch := d.tokenGroup.DoChan(fmt.Sprintf("%d|%s", gen, resourceURI), func() (interface{}, error) {
			tenantID, clientID, clientSecret := d.sourceCreds()
			token, expiresIn, err := d.acquireToken(context.WithoutCancel(ctx), tenantID, clientID, clientSecret, resourceURI)
			if err != nil {
				return nil, err
			}
			expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)
			stored := d.tokenCache.SetIfGeneration(resourceURI, token, expiresAt, gen)
			return sourceTokenResult{token: token, stored: stored}, nil
		})

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-ch:
			if res.Err != nil {
				return "", res.Err
			}
			if r := res.Val.(sourceTokenResult); r.stored {
				return r.token, nil
			}
			// Minted by credentials a rotation retired mid-flight; fetch again.
		}
	}
	return "", fmt.Errorf("azure: source credentials were rotated %d times while acquiring a token for %s",
		azureSourceTokenAttempts, resourceURI)
}

// getGraphToken gets a Graph API token for the source's credentials
func (d *AzureDriver) getGraphToken(ctx context.Context) (string, error) {
	return d.getSourceToken(ctx, graphResource)
}

// hasGraphPermissions reports whether the source can obtain a Microsoft Graph token,
// the precondition for rotating anything. It does not prove the source holds
// Application.ReadWrite.*: a token is issued without it, and a missing permission
// surfaces as Graph's own 403 when rotation runs.
//
// The result is cached (see graphPermsPositiveTTL) and stamped with the token-cache
// generation, so a rotation invalidates it without taking graphPermsMu. Lock order is
// graphPermsMu, then the token cache, never the reverse.
func (d *AzureDriver) hasGraphPermissions() bool {
	// A keyless federation source has no client_secret, so the source-token probe
	// below would be a doomed round-trip. It also has nothing to rotate.
	if credential.GetString(d.sourceConfig(), "auth_method", azureAuthMethodStatic) == azureAuthMethodOIDCFederation {
		return false
	}

	d.graphPermsMu.Lock()
	defer d.graphPermsMu.Unlock()

	gen := d.tokenCache.GetGeneration()
	now := d.clock()
	if e := d.graphPerms; e != nil && e.generation == gen && now.Before(e.expiresAt) {
		return e.ok
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := d.getSourceToken(ctx, graphResource)
	ttl := graphPermsPositiveTTL
	if err != nil {
		ttl = graphPermsNegativeTTL
	}
	d.graphPerms = &graphPermsEntry{ok: err == nil, expiresAt: now.Add(ttl), generation: gen}
	return err == nil
}

// ============================================================================
// Microsoft Graph API Operations
// ============================================================================

// graphAppURL returns the Graph URL of an application, addressed by its appId. Graph
// v1.0 accepts the applications(appId='...') form directly, so no object-id lookup
// is needed. The appId is spliced into the path, so it is held to a UUID first.
func (d *AzureDriver) graphAppURL(appID string) (string, error) {
	if err := credential.ValidateUUID("client_id", appID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v1.0/applications(appId='%s')", d.graphBase(), appID), nil
}

// addPasswordCredential adds a new password credential to an application.
// Retries on HTTP 409 (Directory_ConcurrencyViolation) with exponential backoff.
//
// A response missing the secret or its key id is refused: persisted, it would become
// the credential every later mint and rotation depends on. A key Graph did create is
// removed again rather than left behind.
func (d *AzureDriver) addPasswordCredential(ctx context.Context, graphToken, appID string) (string, string, error) {
	appURL, err := d.graphAppURL(appID)
	if err != nil {
		return "", "", err
	}

	body := map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": fmt.Sprintf("warden-rotated-%d", time.Now().Unix()),
		},
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode addPassword request: %w", err)
	}

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         appURL + "/addPassword",
		body:        bodyJSON,
		contentType: "application/json",
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "addPassword",
	}, []int{http.StatusConflict}, addPasswordMaxAttempts)
	if err != nil {
		return "", "", err
	}

	var result struct {
		SecretText string `json:"secretText"`
		KeyID      string `json:"keyId"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("failed to decode addPassword response: %w", err)
	}
	if result.SecretText == "" || result.KeyID == "" {
		if result.KeyID != "" {
			d.discardPasswordCredential(ctx, graphToken, appID, result.KeyID)
		}
		return "", "", fmt.Errorf("addPassword response is missing secretText or keyId")
	}
	return result.SecretText, result.KeyID, nil
}

// discardPasswordCredential removes a password credential Warden just created and
// cannot use, so a failed rotation does not leave it on the app. Best effort: the
// rotation has already failed, and this only decides whether it also leaks. Runs on a
// detached context so a caller that gave up does not cancel the cleanup.
func (d *AzureDriver) discardPasswordCredential(ctx context.Context, graphToken, appID, keyID string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if err := d.removePasswordCredential(cleanupCtx, graphToken, appID, keyID); err != nil && d.logger != nil {
		d.logger.Warn("could not remove the unusable password credential just created",
			logger.String("secret_id", truncateID(keyID, 8)),
			logger.Err(err),
		)
	}
}

// removePasswordCredential removes a password credential from an application.
// Retries on HTTP 409 (Directory_ConcurrencyViolation) with exponential backoff.
//
// Removal is idempotent: a key that is already gone counts as removed. Graph documents
// only the success response, not what a missing keyId returns, so the error text is not
// trusted to say so. On a client error the app's credential list is consulted instead,
// and only a keyId absent from it is treated as removed.
func (d *AzureDriver) removePasswordCredential(ctx context.Context, graphToken, appID, keyID string) error {
	appURL, err := d.graphAppURL(appID)
	if err != nil {
		return err
	}

	bodyJSON, err := json.Marshal(map[string]interface{}{"keyId": keyID})
	if err != nil {
		return fmt.Errorf("failed to encode removePassword request: %w", err)
	}

	_, err = d.doAzureRequest(ctx, azureAPIRequest{
		method:      "POST",
		url:         appURL + "/removePassword",
		body:        bodyJSON,
		contentType: "application/json",
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK, http.StatusNoContent},
		operation:   "removePassword",
	}, []int{http.StatusConflict}, removePasswordMaxAttempts)
	if err == nil {
		return nil
	}

	var statusErr *httputil.StatusError
	if errors.As(err, &statusErr) && statusErr.Status >= 400 && statusErr.Status < 500 {
		creds, listErr := d.listPasswordCredentials(ctx, graphToken, appID)
		if listErr == nil && !hasPasswordCredential(creds, keyID) {
			return nil
		}
	}
	return err
}

// passwordCredentialInfo holds metadata about an Azure AD password credential
type passwordCredentialInfo struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
}

// hasPasswordCredential reports whether keyID is among creds.
func hasPasswordCredential(creds []passwordCredentialInfo, keyID string) bool {
	for _, c := range creds {
		if strings.EqualFold(c.KeyID, keyID) {
			return true
		}
	}
	return false
}

// listPasswordCredentials lists all password credentials on an application
func (d *AzureDriver) listPasswordCredentials(ctx context.Context, graphToken, appID string) ([]passwordCredentialInfo, error) {
	appURL, err := d.graphAppURL(appID)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("$select", "passwordCredentials")

	respBody, err := d.doAzureRequest(ctx, azureAPIRequest{
		method:      "GET",
		url:         appURL + "?" + params.Encode(),
		bearerToken: graphToken,
		okStatuses:  []int{http.StatusOK},
		operation:   "listPasswordCredentials",
	}, nil, 1)
	if err != nil {
		return nil, err
	}

	var result struct {
		PasswordCredentials []passwordCredentialInfo `json:"passwordCredentials"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode password credentials response: %w", err)
	}

	return result.PasswordCredentials, nil
}
