package pagerduty

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultPagerDutyURL is the default PagerDuty API base URL
const DefaultPagerDutyURL = "https://api.pagerduty.com"

// DefaultPagerDutyTimeout is the default request timeout for PagerDuty API calls
const DefaultPagerDutyTimeout = 30 * time.Second

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// Spec defines the PagerDuty provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "pagerduty",
	DefaultURL:         DefaultPagerDutyURL,
	URLConfigKey:       "pagerduty_url",
	DefaultTimeout:     DefaultPagerDutyTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-pagerduty-proxy",
	HelpText:           pagerdutyBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	Transport:          sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
}

// Factory creates a new PagerDuty provider backend.
var Factory = httpproxy.NewFactory(Spec)

const pagerdutyBackendHelp = `
The PagerDuty provider enables proxying requests to the PagerDuty REST API v2
with automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
PagerDuty API token or OAuth2 bearer token from the credential manager,
injecting it into the proxied request's Authorization header. This allows
Warden to broker PagerDuty access without exposing tokens to clients.

The gateway path format is:
  /pagerduty/gateway/{api-path}

Examples:
  /pagerduty/gateway/incidents
  /pagerduty/gateway/services
  /pagerduty/gateway/users/me
  /pagerduty/gateway/schedules
  /pagerduty/gateway/escalation_policies

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /pagerduty/role/{role}/gateway/{api-path}

Two credential source types are supported:
- apikey: Static API token (stored in spec config as api_key)
- oauth2: OAuth2 client credentials flow (client_id/client_secret/token_url
  on source, scope on spec; tokens are minted dynamically)

Configuration:
- pagerduty_url: PagerDuty API base URL (default: https://api.pagerduty.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
