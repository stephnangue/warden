package splunk

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultSplunkTimeout is the default request timeout for Splunk API calls
const DefaultSplunkTimeout = 30 * time.Second

// extractToken extracts the Warden session token from incoming HTTP requests.
// It checks X-Warden-Token first, then Authorization: Splunk (since Splunk
// clients natively use this format for session tokens), then falls back to
// Authorization: Bearer (JWT tokens).
func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Splunk " {
		return authHeader[7:]
	}
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

// validateSplunkURL validates that the splunk_url is a well-formed HTTPS URL.
func validateSplunkURL(addr string) error {
	if addr == "" {
		return fmt.Errorf("splunk_url is required")
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid splunk_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("splunk_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("splunk_url must include a host")
	}
	return nil
}

// Spec defines the Splunk provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "splunk",
	DefaultURL:         "", // Instance-specific, must be configured
	URLConfigKey:       "splunk_url",
	DefaultTimeout:     DefaultSplunkTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-splunk-proxy",
	HelpText:           splunkBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	ExtractToken:       extractToken,
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["splunk_url"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("splunk_url is required")
		}
		return validateSplunkURL(addr)
	},
}

// Factory creates a new Splunk provider backend.
var Factory = httpproxy.NewFactory(Spec)

const splunkBackendHelp = `
The Splunk provider enables proxying requests to the Splunk REST API with
automatic credential management and bearer token injection.

Warden performs implicit authentication on every request and obtains a
Splunk bearer token from the credential manager, injecting it into the
proxied request's Authorization header. This allows Warden to broker
Splunk access without exposing tokens to clients.

The gateway path format is:
  /splunk/gateway/{api-path}

Examples:
  /splunk/gateway/services/search/jobs
  /splunk/gateway/services/saved/searches
  /splunk/gateway/services/server/info
  /splunk/gateway/services/data/indexes
  /splunk/gateway/services/authorization/tokens
  /splunk/gateway/servicesNS/{owner}/{app}/{endpoint}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /splunk/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Splunk
request fields for fine-grained access control.

Two credential source types are supported:
- apikey: Static Splunk bearer token (stored in spec config as api_key)
- hvault: Vault/OpenBao KV v2 secret containing api_key; use
  mint_method=static_apikey on the spec

Configuration:
- splunk_url: Splunk management API base URL (required, must use HTTPS,
  e.g., "https://splunk.example.com:8089")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The splunk_url must point to the Splunk management port (default 8089).
For Splunk Cloud, use the search head URL provided by Splunk, for example:
  https://<stack-name>.splunkcloud.com:8089
`
