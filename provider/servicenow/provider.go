package servicenow

import (
	"fmt"
	"net/url"
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultServiceNowTimeout is the default request timeout for ServiceNow API calls.
// ServiceNow APIs can be slow for large table queries, so a 60s default is used.
const DefaultServiceNowTimeout = 60 * time.Second

// validateServiceNowURL validates that the servicenow_url is a well-formed HTTPS URL.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
func validateServiceNowURL(addr string, tlsSkipVerify bool) error {
	if addr == "" {
		return fmt.Errorf("servicenow_url is required")
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid servicenow_url: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && tlsSkipVerify) {
		return fmt.Errorf("servicenow_url must use https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("servicenow_url must include a host")
	}
	return nil
}

// Spec defines the ServiceNow provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "servicenow",
	DefaultURL:         "", // Instance-specific, must be configured
	URLConfigKey:       "servicenow_url",
	DefaultTimeout:     DefaultServiceNowTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-servicenow-proxy",
	HelpText:           servicenowBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["servicenow_url"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("servicenow_url is required")
		}
		skipVerify := false
		if v, ok := conf["tls_skip_verify"].(bool); ok {
			skipVerify = v
		}
		return validateServiceNowURL(addr, skipVerify)
	},
}

// Factory creates a new ServiceNow provider backend.
var Factory = httpproxy.NewFactory(Spec)

const servicenowBackendHelp = `
The ServiceNow provider enables proxying requests to a ServiceNow instance
REST API with automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
ServiceNow OAuth2 bearer token or API token from the credential manager,
injecting it into the proxied request's Authorization header. This allows
Warden to broker ServiceNow access without exposing tokens to clients.

The gateway path format is:
  /servicenow/gateway/{api-path}

The {api-path} is appended to the configured servicenow_url and forwarded
over HTTPS.

Examples:
  /servicenow/gateway/api/now/table/incident
  /servicenow/gateway/api/now/table/sys_user
  /servicenow/gateway/api/now/table/change_request
  /servicenow/gateway/api/now/cmdb/instance/cmdb_ci_server
  /servicenow/gateway/api/now/import/u_custom_table
  /servicenow/gateway/api/now/attachment
  /servicenow/gateway/api/now/stats/incident

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /servicenow/role/{role}/gateway/{api-path}

Two credential source types are supported:
- apikey: Static bearer token (stored in spec config as api_key)
- oauth2: OAuth2 client credentials flow (client_id/client_secret/token_url
  on source, scope on spec; token_url is typically
  https://{instance}.service-now.com/oauth_token.do; default scope
  is "useraccount")

Configuration:
- servicenow_url: ServiceNow instance URL (required, e.g., "https://mycompany.service-now.com")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 60s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
