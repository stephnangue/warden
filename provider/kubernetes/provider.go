package kubernetes

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultKubernetesTimeout is the default request timeout for Kubernetes API calls
const DefaultKubernetesTimeout = 30 * time.Second

// extractToken extracts the Warden session token from incoming HTTP requests.
// It checks X-Warden-Token first, then falls back to Authorization: Bearer.
func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

// validateKubernetesURL validates that the kubernetes_url is a well-formed HTTPS URL.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
func validateKubernetesURL(addr string, tlsSkipVerify bool) error {
	if addr == "" {
		return fmt.Errorf("kubernetes_url is required")
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid kubernetes_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("kubernetes_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("kubernetes_url must include a host")
	}
	return nil
}

// Spec defines the Kubernetes provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:            "kubernetes",
	DefaultURL:      "", // Cluster-specific, must be configured
	URLConfigKey:    "kubernetes_url",
	DefaultTimeout:  DefaultKubernetesTimeout,
	ParseStreamBody: true,
	UserAgent:       "warden-kubernetes-proxy",
	HelpText:        kubernetesBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(
		credential.TypeKubernetesToken, "token", "Authorization", "Bearer ",
	),
	ExtractToken: extractToken,
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["kubernetes_url"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("kubernetes_url is required")
		}
		skipVerify := false
		if v, ok := conf["tls_skip_verify"].(bool); ok {
			skipVerify = v
		}
		return validateKubernetesURL(addr, skipVerify)
	},
}

// Factory creates a new Kubernetes provider backend.
var Factory = httpproxy.NewFactory(Spec)

const kubernetesBackendHelp = `
The Kubernetes provider enables proxying requests to a Kubernetes API server
with automatic credential management and bearer token injection.

Warden performs implicit authentication on every request and obtains a
Kubernetes ServiceAccount token from the credential manager, injecting it
into the proxied request's Authorization header using the Bearer scheme.
This allows Warden to broker Kubernetes API access without exposing
long-lived tokens to clients.

The gateway path format is:
  /kubernetes/gateway/{api-path}

Examples:
  /kubernetes/gateway/api/v1/namespaces
  /kubernetes/gateway/api/v1/namespaces/default/pods
  /kubernetes/gateway/apis/apps/v1/namespaces/default/deployments
  /kubernetes/gateway/api/v1/namespaces/default/services
  /kubernetes/gateway/healthz

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /kubernetes/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Kubernetes
API request fields for fine-grained access control.

Credential source type:
- kubernetes: Kubernetes driver with ServiceAccount token creation via
  the TokenRequest API (short-lived, audience-scoped tokens)

Configuration:
- kubernetes_url: Kubernetes API server URL (required, e.g., "https://my-cluster.example.com:6443")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
- tls_skip_verify: Skip TLS certificate verification (for dev/test clusters)
- ca_data: Base64-encoded PEM CA certificate for clusters with custom CAs
`
