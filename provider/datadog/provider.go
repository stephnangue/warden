package datadog

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultDatadogURL is the default Datadog API base URL (US1 site)
const DefaultDatadogURL = "https://api.datadoghq.com"

// DefaultDatadogTimeout is the default request timeout for Datadog API calls
const DefaultDatadogTimeout = 30 * time.Second

// Spec defines the Datadog provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:            "datadog",
	DefaultURL:      DefaultDatadogURL,
	URLConfigKey:    "datadog_url",
	DefaultTimeout:  DefaultDatadogTimeout,
	ParseStreamBody: true,
	UserAgent:       "warden-datadog-proxy",
	HelpText:        datadogBackendHelp,
	ExtractCredentials: httpproxy.MultiFieldAPIKeyExtractor(
		map[string]string{"api_key": "DD-API-KEY"},
		map[string]string{"application_key": "DD-APPLICATION-KEY"},
	),
}

// Factory creates a new Datadog provider backend.
var Factory = httpproxy.NewFactory(Spec)

const datadogBackendHelp = `
The Datadog provider enables proxying requests to the Datadog REST API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains a
Datadog API key (and optionally an Application key) from the credential
manager, injecting them into the proxied request's DD-API-KEY and
DD-APPLICATION-KEY headers. This allows Warden to broker Datadog access
without exposing keys to clients.

The gateway path format is:
  /datadog/gateway/{api-path}

Examples:
  /datadog/gateway/api/v1/query
  /datadog/gateway/api/v2/metrics
  /datadog/gateway/api/v1/monitor
  /datadog/gateway/api/v2/logs/events/search
  /datadog/gateway/api/v1/dashboard

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /datadog/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Datadog
request fields for fine-grained access control.

Two credential source types are supported:
- apikey: Static API key (stored in spec config as api_key) with an optional
  application_key for endpoints that require it
- hvault: Vault/OpenBao KV v2 secret containing api_key (and optionally
  application_key); use mint_method=static_apikey on the spec

Configuration:
- datadog_url: Datadog API base URL (default: https://api.datadoghq.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The datadog_url must match your Datadog site:
  US1:     https://api.datadoghq.com (default)
  US3:     https://api.us3.datadoghq.com
  US5:     https://api.us5.datadoghq.com
  EU1:     https://api.datadoghq.eu
  AP1:     https://api.ap1.datadoghq.com
  AP2:     https://api.ap2.datadoghq.com
  US1-FED: https://api.ddog-gov.com
`
