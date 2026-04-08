package drivers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// k8sMaxResponseBodySize limits response body reads to prevent OOM
const k8sMaxResponseBodySize = 1 << 20 // 1MB

// Compile-time interface assertions
var _ credential.SourceDriver = (*KubernetesDriver)(nil)
var _ credential.SpecVerifier = (*KubernetesDriver)(nil)
var _ credential.Rotatable = (*KubernetesDriver)(nil)

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
	return credential.ValidateSchema(config,
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

		credential.StringField("token").
			Required().
			Describe("Bearer token for authenticating to the Kubernetes API server").
			Example("eyJhbGciOiJSUzI1NiIs..."),

		credential.StringField("ca_data").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				pemBytes, err := base64.StdEncoding.DecodeString(v)
				if err != nil {
					return fmt.Errorf("ca_data is not valid base64: %w", err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pemBytes) {
					return fmt.Errorf("ca_data contains no valid PEM certificates")
				}
				return nil
			}).
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
	)
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

	httpClient, err := driver.buildHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	driver.httpClient = httpClient

	// Verify source credentials by checking API server connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := driver.verifyConnection(ctx); err != nil {
		return nil, fmt.Errorf("Kubernetes API server connection failed: %w", err)
	}

	return driver, nil
}

// ============================================================================
// SourceDriver Interface Implementation
// ============================================================================

// MintCredential creates a new ServiceAccount token via the Kubernetes TokenRequest API.
//
// Spec config fields:
//   - service_account: Target service account name (required)
//   - namespace: Target namespace (required)
//   - audiences: Comma-separated token audiences (optional)
//   - ttl: Token TTL duration, e.g. "1h" (optional, default: 1h)
func (d *KubernetesDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	sa := credential.GetString(spec.Config, "service_account", "")
	namespace := credential.GetString(spec.Config, "namespace", "")
	audiencesStr := credential.GetString(spec.Config, "audiences", "")
	ttl := credential.GetDuration(spec.Config, "ttl", 1*time.Hour)

	if sa == "" {
		return nil, 0, "", fmt.Errorf("service_account is required in spec config")
	}
	if namespace == "" {
		return nil, 0, "", fmt.Errorf("namespace is required in spec config")
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
		return nil, 0, "", fmt.Errorf("failed to marshal TokenRequest: %w", err)
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token",
		url.PathEscape(namespace), url.PathEscape(sa))

	respBody, statusCode, err := d.doK8sRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, 0, "", d.mapError(err, statusCode, sa, namespace)
	}

	// Parse TokenRequest response
	var tokenResp struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode TokenRequest response: %w", err)
	}

	if tokenResp.Status.Token == "" {
		return nil, 0, "", fmt.Errorf("TokenRequest response missing token")
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

	if d.logger != nil {
		d.logger.Debug("minted Kubernetes ServiceAccount token",
			logger.String("spec", spec.Name),
			logger.String("service_account", sa),
			logger.String("namespace", namespace),
		)
	}

	return rawData, computedTTL, "", nil
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
func (d *KubernetesDriver) VerifySpec(ctx context.Context, spec *credential.CredSpec) error {
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
func (d *KubernetesDriver) SupportsRotation() bool {
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
		httpClient, err := d.buildHTTPClient(newConfig)
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

// buildHTTPClient creates an HTTP client with custom TLS configuration.
func (d *KubernetesDriver) buildHTTPClient(config map[string]string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if credential.GetBool(config, "tls_skip_verify", false) {
		tlsConfig.InsecureSkipVerify = true
	}

	if caData := credential.GetString(config, "ca_data", ""); caData != "" {
		pemBytes, err := base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, fmt.Errorf("ca_data is not valid base64: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca_data contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
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

	return ExecuteWithRetry(ctx, d.httpClient, HTTPRequest{
		Method:  method,
		URL:     k8sURL + path,
		Body:    body,
		Headers: headers,
	}, defaultK8sRetryConfig())
}

// defaultK8sRetryConfig returns the standard retry configuration for Kubernetes API calls.
func defaultK8sRetryConfig() HTTPRetryConfig {
	return HTTPRetryConfig{
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
