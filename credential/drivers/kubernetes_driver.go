package drivers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// k8sMaxResponseBodySize limits response body reads to prevent OOM
const k8sMaxResponseBodySize = 1 << 20 // 1MB

// kubernetesAuthMethodStatic and kubernetesAuthMethodOIDCFederation select how the
// source authenticates to the API server. static holds a long-lived bearer token
// with permission to create tokens for the target service accounts (rotatable);
// oidc_federation holds no secret and presents the caller's identity assertion as
// the bearer token on every request. An empty auth_method means static, so records
// written before federation existed keep working.
//
// Federation needs no token-exchange hop: an API server configured to trust
// Warden's issuer accepts the assertion as an ordinary bearer token and authorizes
// the claims it maps to a user and groups.
const (
	kubernetesAuthMethodStatic         = "static"
	kubernetesAuthMethodOIDCFederation = "oidc_federation"
)

// defaultK8sTLSPort is the port a TLS handshake probe dials when kubernetes_url
// names none.
const defaultK8sTLSPort = "443"

// Compile-time interface assertions
var _ credential.SourceDriver = (*KubernetesDriver)(nil)
var _ credential.SpecVerifier = (*KubernetesDriver)(nil)
var _ credential.Rotatable = (*KubernetesDriver)(nil)
var _ credential.ExchangeMinter = (*KubernetesDriver)(nil)

// KubernetesDriver mints ServiceAccount tokens via the Kubernetes TokenRequest API.
// It uses raw HTTP calls to POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token
// to create short-lived, audience-scoped bearer tokens.
//
// When source_service_account and source_namespace are configured, the driver
// supports rotation by minting a new token for its own service account via
// the same TokenRequest API.
type KubernetesDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client

	// authMu protects credSource.Config writes during rotation.
	authMu sync.Mutex
}

// KubernetesDriverFactory creates KubernetesDriver instances
type KubernetesDriverFactory struct{}

// Type returns the driver type
func (f *KubernetesDriverFactory) Type() string {
	return credential.SourceTypeKubernetes
}

// ValidateConfig validates Kubernetes driver configuration using declarative schema
func (f *KubernetesDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("kubernetes_url").
			Required().
			Custom(func(v string) error {
				parsed, err := url.Parse(v)
				if err != nil {
					return fmt.Errorf("kubernetes_url is not a valid URL: %w", err)
				}
				skipTLS := credential.GetBool(config, "tls_skip_verify", false)
				if parsed.Scheme != "https" && !skipTLS {
					return fmt.Errorf("kubernetes_url must use https scheme, got: %s", parsed.Scheme)
				}
				if parsed.Host == "" {
					return fmt.Errorf("kubernetes_url must include a host")
				}
				return nil
			}).
			Describe("Kubernetes API server URL").
			Example("https://my-cluster.example.com:6443"),

		credential.StringField("auth_method").
			OneOf(kubernetesAuthMethodStatic, kubernetesAuthMethodOIDCFederation).
			Describe("How the source authenticates: 'static' (stored bearer token) or 'oidc_federation' (keyless, presents the caller's identity assertion)").
			Example(kubernetesAuthMethodStatic),

		credential.StringField("token").
			Describe("Bearer token for authenticating to the Kubernetes API server (required for auth_method=static)").
			Example("eyJhbGciOiJSUzI1NiIs..."),

		credential.StringField("audience").
			Describe("Assertion audience; must match an entry in the cluster authenticator's audiences (auth_method=oidc_federation)").
			Example("https://kubernetes.example.com"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for the cluster").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (for dev/test clusters)").
			Example("false"),

		credential.StringField("source_service_account").
			Describe("Name of the source service account (required for rotation)").
			Example("warden-token-creator"),

		credential.StringField("source_namespace").
			Describe("Namespace of the source service account (required for rotation)").
			Example("warden"),

		credential.DurationField("source_token_ttl").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				d, err := time.ParseDuration(v)
				if err != nil {
					return fmt.Errorf("invalid source_token_ttl: %w", err)
				}
				if d < 10*time.Minute {
					return fmt.Errorf("source_token_ttl must be at least 10m, got: %s", d)
				}
				if d > 48*time.Hour {
					return fmt.Errorf("source_token_ttl must not exceed 48h, got: %s", d)
				}
				return nil
			}).
			Describe("TTL for rotated source tokens (default: 24h, min: 10m, max: 48h)").
			Example("24h"),
	); err != nil {
		return err
	}

	// Cross-field rules per auth_method. Each mode rejects the other's fields, so a
	// half-converted source fails at write rather than behaving as the mode the
	// operator did not intend.
	//
	// Present-but-empty is validated as static, not skipped. GetString returns a
	// stored "" rather than the default, and the schema pass above skips empty
	// values too — so a switch that only matched the two named modes would let a
	// source through carrying neither a token nor a federation config, and it is
	// static that such a source then behaves as.
	switch credential.GetString(config, "auth_method", kubernetesAuthMethodStatic) {
	case "", kubernetesAuthMethodStatic:
		if credential.GetString(config, "token", "") == "" {
			return fmt.Errorf("token is required for auth_method=%s", kubernetesAuthMethodStatic)
		}
		if credential.GetString(config, "audience", "") != "" {
			return fmt.Errorf("audience is only valid for auth_method=%s", kubernetesAuthMethodOIDCFederation)
		}
	case kubernetesAuthMethodOIDCFederation:
		// A federation source holds no token of its own, so it has nothing to rotate
		// and no service account to rotate as.
		for _, k := range []string{"token", "source_service_account", "source_namespace", "source_token_ttl"} {
			if config[k] != "" {
				return fmt.Errorf("field '%s' must not be set for auth_method=%s", k, kubernetesAuthMethodOIDCFederation)
			}
		}
	}
	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *KubernetesDriverFactory) SensitiveConfigFields() []string {
	return []string{"token", "ca_data"}
}

// InferCredentialType returns the credential type for Kubernetes sources.
func (f *KubernetesDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeKubernetesToken, nil
}

// Create instantiates a new KubernetesDriver
func (f *KubernetesDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	driver := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeKubernetes,
			Config: config,
		},
		logger: log.WithSubsystem(credential.SourceTypeKubernetes),
	}

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	driver.httpClient = httpClient

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A federation source holds no credential, so the eager probe cannot check
	// authority — but the transport config is still worth checking, and a
	// handshake does that without one. kubernetes_url and ca_data are typed by
	// the operator and are the two things most likely to be wrong; catching them
	// here beats surfacing them at the first mint.
	if credential.GetString(config, "auth_method", kubernetesAuthMethodStatic) == kubernetesAuthMethodOIDCFederation {
		if err := driver.probeTLS(ctx); err != nil {
			return nil, err
		}
		return driver, nil
	}

	// Verify source credentials by checking API server connectivity
	if err := driver.verifyConnection(ctx); err != nil {
		return nil, fmt.Errorf("Kubernetes API server connection failed: %w", err)
	}

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential creates a new ServiceAccount token via the Kubernetes TokenRequest
// API, authenticating with the source's stored bearer token.
//
// Spec config fields:
//   - service_account: Target service account name (required)
//   - namespace: Target namespace (required)
//   - audiences: Comma-separated token audiences (optional)
//   - ttl: Token TTL duration, e.g. "1h" (optional, default: 1h)
func (d *KubernetesDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if d.getAuthMethod() == kubernetesAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("kubernetes: a source with auth_method=%s mints only from a caller assertion: set subject_token_source on the spec", kubernetesAuthMethodOIDCFederation)
	}
	k8sURL, token := d.configSnapshot()
	return d.mintServiceAccountToken(ctx, k8sURL, token, spec)
}

// MintCredentialWithExchange mints a ServiceAccount token over workload identity
// federation: the caller's identity assertion is the bearer token on the
// TokenRequest call, so the source stores no credential of its own and the API
// server sees, and audits, the identity behind each request rather than one shared
// service account.
//
// Unlike the STS-backed drivers there is no exchange hop to make. An API server
// configured to trust the assertion's issuer accepts it directly, so the assertion
// is handed to the same mint path a stored token would take.
//
// The minted token outliving the assertion is expected and harmless: its lifetime
// is fixed by the API server when it is issued and does not depend on the assertion
// that asked for it.
func (d *KubernetesDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if d.getAuthMethod() != kubernetesAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("kubernetes: workload identity federation requires auth_method=%s on the source", kubernetesAuthMethodOIDCFederation)
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("kubernetes: no subject token in exchange inputs")
	}
	k8sURL, _ := d.configSnapshot()
	return d.mintServiceAccountToken(ctx, k8sURL, inputs.SubjectToken, spec)
}

// mintServiceAccountToken calls the TokenRequest API for the spec's service account
// with the given bearer token, which is the source's stored token under static auth
// and the caller's assertion under federation. Everything below this point is
// identical in both modes.
//
// The URL is passed in rather than read here so that the static path pairs a token
// with the URL from the same config snapshot: reading them separately would let a
// rotation land between the two and mint with one config's token against another's
// address.
func (d *KubernetesDriver) mintServiceAccountToken(ctx context.Context, k8sURL, bearer string, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	sa := credential.GetString(spec.Config, "service_account", "")
	namespace := credential.GetString(spec.Config, "namespace", "")
	audiencesStr := credential.GetString(spec.Config, "audiences", "")
	ttl := credential.GetDuration(spec.Config, "ttl", 1*time.Hour)

	if sa == "" {
		return nil, nil, 0, "", fmt.Errorf("service_account is required in spec config")
	}
	if namespace == "" {
		return nil, nil, 0, "", fmt.Errorf("namespace is required in spec config")
	}

	// Build audiences list
	var audiences []string
	if audiencesStr != "" {
		for _, a := range strings.Split(audiencesStr, ",") {
			if trimmed := strings.TrimSpace(a); trimmed != "" {
				audiences = append(audiences, trimmed)
			}
		}
	}

	// Convert TTL to seconds
	expirationSeconds := int64(ttl.Seconds())

	body, err := buildTokenRequestBody(expirationSeconds, audiences)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to marshal TokenRequest: %w", err)
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token",
		url.PathEscape(namespace), url.PathEscape(sa))

	respBody, statusCode, err := d.doK8sRequestWith(ctx, k8sURL, bearer, http.MethodPost, path, body)
	if err != nil {
		return nil, nil, 0, "", d.mapError(err, statusCode, sa, namespace)
	}

	// Parse TokenRequest response
	var tokenResp struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to decode TokenRequest response: %w", err)
	}

	if tokenResp.Status.Token == "" {
		return nil, nil, 0, "", fmt.Errorf("TokenRequest response missing token")
	}

	// Compute TTL from expiration timestamp
	var computedTTL time.Duration
	if tokenResp.Status.ExpirationTimestamp != "" {
		expiryTime, err := time.Parse(time.RFC3339, tokenResp.Status.ExpirationTimestamp)
		if err == nil {
			computedTTL = time.Until(expiryTime)
			if computedTTL < 0 {
				if d.logger != nil {
					d.logger.Warn("minted token expiration is in the past (possible clock skew)",
						logger.String("expiration", tokenResp.Status.ExpirationTimestamp),
					)
				}
				computedTTL = 0
			}
		} else if d.logger != nil {
			d.logger.Warn("failed to parse token expirationTimestamp, falling back to requested TTL",
				logger.String("raw_timestamp", tokenResp.Status.ExpirationTimestamp),
			)
		}
	} else if d.logger != nil {
		d.logger.Warn("token response missing expirationTimestamp, falling back to requested TTL")
	}
	if computedTTL == 0 {
		computedTTL = ttl
	}

	rawData := map[string]interface{}{
		"token":           tokenResp.Status.Token,
		"namespace":       namespace,
		"service_account": sa,
		"audiences":       audiencesStr,
	}

	metadata := kubernetesTokenMetadata(sa, namespace, audiencesStr, tokenResp.Status.ExpirationTimestamp)

	if d.logger != nil {
		d.logger.Debug("minted Kubernetes ServiceAccount token",
			logger.String("spec", spec.Name),
			logger.String("service_account", sa),
			logger.String("namespace", namespace),
		)
	}

	return rawData, metadata, computedTTL, "", nil
}

// kubernetesTokenMetadata builds clear-loggable identity metadata for a minted
// ServiceAccount token. subject is the canonical Kubernetes SA identity, matching
// what apiserver RBAC and audit logs use. The token itself stays in rawData.
func kubernetesTokenMetadata(sa, namespace, audiences, expiration string) map[string]interface{} {
	meta := map[string]interface{}{
		"subject":         fmt.Sprintf("system:serviceaccount:%s:%s", namespace, sa),
		"service_account": sa,
		"namespace":       namespace,
	}
	if audiences != "" {
		meta["audiences"] = audiences
	}
	if expiration != "" {
		meta["expiration"] = expiration
	}
	return meta
}

// Revoke is a no-op for Kubernetes ServiceAccount tokens.
// Tokens expire naturally and cannot be revoked via the API.
func (d *KubernetesDriver) Revoke(_ context.Context, leaseID string) error {
	if d.logger != nil {
		d.logger.Debug("revoke is a no-op for Kubernetes tokens (they expire naturally)")
	}
	return nil
}

// Type returns the driver type
func (d *KubernetesDriver) Type() string {
	return credential.SourceTypeKubernetes
}

// Cleanup releases resources
func (d *KubernetesDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	return nil
}

// VerifySpec validates that the target service account exists.
//
// A federation source has no ambient credential to look it up with — assertions
// are per caller, per request — so verification is skipped and a missing service
// account surfaces at the first mint instead.
func (d *KubernetesDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
	if d.getAuthMethod() == kubernetesAuthMethodOIDCFederation {
		return nil
	}

	sa := credential.GetString(spec.Config, "service_account", "")
	namespace := credential.GetString(spec.Config, "namespace", "")

	if sa == "" || namespace == "" {
		return fmt.Errorf("service_account and namespace are required")
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s",
		url.PathEscape(namespace), url.PathEscape(sa))

	_, statusCode, err := d.doK8sRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		if statusCode == http.StatusNotFound {
			return fmt.Errorf("service account %q not found in namespace %q", sa, namespace)
		}
		return fmt.Errorf("failed to verify service account: %w", err)
	}

	return nil
}

// ============================================================================
// Rotatable Interface Implementation (Source Token Rotation)
// ============================================================================

// SupportsRotation returns true if the driver can rotate its source token.
// Rotation requires source_service_account and source_namespace to be configured
// so the driver knows which SA to mint a new token for.
//
// A federation source holds no token, so there is nothing to rotate. ValidateConfig
// already keeps the rotation fields off such a source, which would make the check
// below false anyway; stating it here keeps the invariant independent of that.
func (d *KubernetesDriver) SupportsRotation() bool {
	if d.getAuthMethod() == kubernetesAuthMethodOIDCFederation {
		return false
	}

	d.authMu.Lock()
	defer d.authMu.Unlock()
	sa := credential.GetString(d.credSource.Config, "source_service_account", "")
	ns := credential.GetString(d.credSource.Config, "source_namespace", "")
	return sa != "" && ns != ""
}

// PrepareRotation mints a new token for the source service account using the
// current (still valid) source token. Kubernetes has immediate consistency,
// so activateAfter is 0.
func (d *KubernetesDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	if d.getAuthMethod() == kubernetesAuthMethodOIDCFederation {
		return nil, nil, 0, fmt.Errorf("kubernetes: a source with auth_method=%s holds no token to rotate", kubernetesAuthMethodOIDCFederation)
	}

	// Snapshot config under lock, then release before making HTTP calls.
	d.authMu.Lock()
	sa := credential.GetString(d.credSource.Config, "source_service_account", "")
	ns := credential.GetString(d.credSource.Config, "source_namespace", "")
	if sa == "" || ns == "" {
		d.authMu.Unlock()
		return nil, nil, 0, fmt.Errorf("cannot rotate: source_service_account and source_namespace are required")
	}

	ttl := credential.GetDuration(d.credSource.Config, "source_token_ttl", 24*time.Hour)
	k8sURL := credential.GetString(d.credSource.Config, "kubernetes_url", "")
	token := credential.GetString(d.credSource.Config, "token", "")

	// Copy config for building newConfig later
	configCopy := make(map[string]string, len(d.credSource.Config))
	for k, v := range d.credSource.Config {
		configCopy[k] = v
	}
	d.authMu.Unlock()

	expirationSeconds := int64(ttl.Seconds())

	body, err := buildTokenRequestBody(expirationSeconds, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal TokenRequest: %w", err)
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token",
		url.PathEscape(ns), url.PathEscape(sa))

	respBody, _, err := d.doK8sRequestWith(ctx, k8sURL, token, http.MethodPost, path, body)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new source token: %w", err)
	}

	var tokenResp struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to decode TokenRequest response: %w", err)
	}

	if tokenResp.Status.Token == "" {
		return nil, nil, 0, fmt.Errorf("TokenRequest response missing token")
	}

	// Build new config with the fresh token
	configCopy["token"] = tokenResp.Status.Token

	// No cleanup needed — old tokens expire naturally
	cleanupConfig := map[string]string{}

	if d.logger != nil {
		d.logger.Debug("prepared source token rotation",
			logger.String("service_account", sa),
			logger.String("namespace", ns),
		)
	}

	// Kubernetes has immediate consistency — activate right away
	return configCopy, cleanupConfig, 0, nil
}

// CommitRotation activates the new source token.
func (d *KubernetesDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	// Snapshot new config values for verification without holding the lock during HTTP calls.
	newK8sURL := credential.GetString(newConfig, "kubernetes_url", "")
	newToken := credential.GetString(newConfig, "token", "")

	// Verify new token works before committing
	if err := d.verifyConnectionWith(ctx, newK8sURL, newToken); err != nil {
		return fmt.Errorf("failed to authenticate with new source token: %w", err)
	}

	// Swap config under lock
	d.authMu.Lock()
	oldConfig := d.credSource.Config
	d.credSource.Config = newConfig

	// Rebuild HTTP client if TLS config changed
	oldCA := credential.GetString(oldConfig, "ca_data", "")
	oldSkip := credential.GetString(oldConfig, "tls_skip_verify", "")
	newCA := credential.GetString(newConfig, "ca_data", "")
	newSkip := credential.GetString(newConfig, "tls_skip_verify", "")
	tlsChanged := oldCA != newCA || oldSkip != newSkip
	d.authMu.Unlock()

	if tlsChanged {
		httpClient, err := BuildHTTPClient(newConfig, 30*time.Second)
		if err != nil {
			// Rollback config on TLS rebuild failure
			d.authMu.Lock()
			d.credSource.Config = oldConfig
			d.authMu.Unlock()
			return fmt.Errorf("failed to rebuild HTTP client after rotation: %w", err)
		}
		d.httpClient = httpClient
	}

	if d.logger != nil {
		d.logger.Debug("committed source token rotation")
	}

	return nil
}

// CleanupRotation is a no-op for Kubernetes. Old tokens expire naturally
// and cannot be revoked via the API.
func (d *KubernetesDriver) CleanupRotation(_ context.Context, _ map[string]string) error {
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// buildTokenRequestBody constructs the JSON body for the Kubernetes TokenRequest API.
func buildTokenRequestBody(expirationSeconds int64, audiences []string) ([]byte, error) {
	tokenReqSpec := map[string]interface{}{
		"expirationSeconds": expirationSeconds,
	}
	if len(audiences) > 0 {
		tokenReqSpec["audiences"] = audiences
	}

	reqBody := map[string]interface{}{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       tokenReqSpec,
	}

	return json.Marshal(reqBody)
}

// getAuthMethod returns the source's configured auth_method, normalising both an
// absent key and a stored empty string to static — the former so a record written
// before federation existed keeps its old behaviour, the latter because GetString
// hands back a stored "" rather than the default. It reads under authMu because
// CommitRotation swaps the whole config map under that lock.
func (d *KubernetesDriver) getAuthMethod() string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if method := credential.GetString(d.credSource.Config, "auth_method", kubernetesAuthMethodStatic); method != "" {
		return method
	}
	return kubernetesAuthMethodStatic
}

// probeTLS completes a TLS handshake against the API server and closes the
// connection, sending no HTTP request. It is the credential-free half of
// verifyConnection: it proves the host resolves and answers, and that its
// certificate verifies against ca_data, which is all a source with no token of
// its own can check.
//
// It runs only against an https URL. ValidateConfig permits a plain-HTTP
// kubernetes_url when tls_skip_verify is set, and a handshake with a plain HTTP
// listener fails whatever InsecureSkipVerify says — so probing one would reject
// every dev cluster.
//
// Known limitation: it dials the host directly and so ignores HTTPS_PROXY, which
// the client's own transport would honour. A deployment reaching the API server
// only through a proxy therefore fails source creation here even though its mints
// would succeed.
func (d *KubernetesDriver) probeTLS(ctx context.Context) error {
	k8sURL, _ := d.configSnapshot()

	parsed, err := url.Parse(k8sURL)
	if err != nil {
		return fmt.Errorf("kubernetes_url is not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil
	}

	port := parsed.Port()
	if port == "" {
		port = defaultK8sTLSPort
	}

	// The client carries the CA pool and skip-verify flag built from config. Its
	// Transport is nil when neither is set (BuildHTTPClient returns a bare client
	// then), which leaves a nil config and the system roots — the right default.
	var tlsConfig *tls.Config
	if transport, ok := d.httpClient.Transport.(*http.Transport); ok && transport != nil {
		tlsConfig = transport.TLSClientConfig
	}

	dialer := &tls.Dialer{Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return fmt.Errorf("cannot establish a TLS connection to the Kubernetes API server at %s: %w (check kubernetes_url and ca_data)", parsed.Host, err)
	}
	return conn.Close()
}

// verifyConnection checks API server connectivity using the /version endpoint,
// which requires no RBAC permissions.
func (d *KubernetesDriver) verifyConnection(ctx context.Context) error {
	k8sURL, token := d.configSnapshot()
	return d.verifyConnectionWith(ctx, k8sURL, token)
}

// verifyConnectionWith checks API server connectivity using explicit URL and token.
// Used by rotation methods that need to verify before committing config.
func (d *KubernetesDriver) verifyConnectionWith(ctx context.Context, k8sURL, token string) error {
	_, statusCode, err := d.doK8sRequestWith(ctx, k8sURL, token, http.MethodGet, "/version", nil)
	if err != nil {
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return fmt.Errorf("authentication failed (HTTP %d): verify the source token is valid", statusCode)
		}
		return fmt.Errorf("API server unreachable: %w", err)
	}
	return nil
}

// configSnapshot returns the current kubernetes_url and token under the auth lock.
func (d *KubernetesDriver) configSnapshot() (k8sURL, token string) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return credential.GetString(d.credSource.Config, "kubernetes_url", ""),
		credential.GetString(d.credSource.Config, "token", "")
}

// doK8sRequest executes an HTTP request to the Kubernetes API server.
func (d *KubernetesDriver) doK8sRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	k8sURL, token := d.configSnapshot()
	return d.doK8sRequestWith(ctx, k8sURL, token, method, path, body)
}

// doK8sRequestWith executes an HTTP request using the provided URL and token.
// Used by rotation methods that already hold authMu and have their own config snapshot.
func (d *KubernetesDriver) doK8sRequestWith(ctx context.Context, k8sURL, token, method, path string, body []byte) ([]byte, int, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}

	return httputil.ExecuteWithRetry(ctx, d.httpClient, httputil.HTTPRequest{
		Method:  method,
		URL:     k8sURL + path,
		Body:    body,
		Headers: headers,
	}, defaultK8sRetryConfig())
}

// defaultK8sRetryConfig returns the standard retry configuration for Kubernetes API calls.
func defaultK8sRetryConfig() httputil.HTTPRetryConfig {
	return httputil.HTTPRetryConfig{
		MaxAttempts:       3,
		MaxBodySize:       k8sMaxResponseBodySize,
		RetryableStatuses: []int{429, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
}

// mapError converts HTTP status codes to actionable error messages.
func (d *KubernetesDriver) mapError(err error, statusCode int, sa, namespace string) error {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		// Under federation the assertion carries the identity, so a refusal is as
		// likely to be a trust or audience mismatch as a missing grant. Naming all
		// three saves an operator from auditing RBAC for what is a config problem.
		if d.getAuthMethod() == kubernetesAuthMethodOIDCFederation {
			return fmt.Errorf("kubernetes API server rejected the identity assertion (HTTP %d) when creating a token for service account %q in namespace %q: "+
				"check that the cluster trusts Warden's issuer, that the source's audience matches the authenticator's audiences, "+
				"and that the mapped user or groups may create serviceaccounts/token there: %w", statusCode, sa, namespace, err)
		}
		return fmt.Errorf("insufficient permissions to create token for service account %q in namespace %q: %w", sa, namespace, err)
	case http.StatusNotFound:
		return fmt.Errorf("service account %q not found in namespace %q: %w", sa, namespace, err)
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("invalid token request parameters: %w", err)
	case http.StatusTooManyRequests:
		return fmt.Errorf("rate limited by Kubernetes API server: %w", err)
	default:
		return fmt.Errorf("failed to create Kubernetes token: %w", err)
	}
}
