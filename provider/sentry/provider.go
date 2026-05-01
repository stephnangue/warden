package sentry

import (
	"time"

	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultSentryURL is the default Sentry API base URL
const DefaultSentryURL = "https://sentry.io/api/0"

// DefaultSentryTimeout is the default request timeout for Sentry API calls
const DefaultSentryTimeout = 30 * time.Second

// Spec defines the Sentry provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "sentry",
	DefaultURL:         DefaultSentryURL,
	URLConfigKey:       "sentry_url",
	DefaultTimeout:     DefaultSentryTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-sentry-proxy",
	HelpText:           sentryBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
}

// Factory creates a new Sentry provider backend.
var Factory = httpproxy.NewFactory(Spec)

const sentryBackendHelp = `
The Sentry provider enables proxying requests to the Sentry REST API
with automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
Sentry Internal Integration token from the credential manager, injecting
it into the proxied request's Authorization header. This allows Warden
to broker Sentry access without exposing tokens to clients.

The gateway path format is:
  /sentry/gateway/{api-path}

Examples:
  /sentry/gateway/organizations/
  /sentry/gateway/organizations/{org}/projects/
  /sentry/gateway/projects/{org}/{project}/issues/
  /sentry/gateway/projects/{org}/{project}/events/
  /sentry/gateway/organizations/{org}/members/

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /sentry/role/{role}/gateway/{api-path}

Credential source type:
- apikey: Static Internal Integration token (created in Sentry UI under
  Settings > Developer Settings > Internal Integrations)

Configuration:
- sentry_url: Sentry API base URL (default: https://sentry.io/api/0)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
