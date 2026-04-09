package cloudflare

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultCloudflareURL is the default Cloudflare API base URL
const DefaultCloudflareURL = "https://api.cloudflare.com/client/v4"

// DefaultCloudflareTimeout is the default request timeout for Cloudflare API calls
const DefaultCloudflareTimeout = 30 * time.Second

// Spec defines the Cloudflare provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "cloudflare",
	DefaultURL:         DefaultCloudflareURL,
	URLConfigKey:       "cloudflare_url",
	DefaultTimeout:     DefaultCloudflareTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-cloudflare-proxy",
	HelpText:           cloudflareBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
}

// Factory creates a new Cloudflare provider backend.
var Factory = httpproxy.NewFactory(Spec)

const cloudflareBackendHelp = `
The Cloudflare provider enables proxying requests to the Cloudflare API v4
with automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
Cloudflare API token from the credential manager, injecting it into the
proxied request's Authorization header. This allows Warden to broker
Cloudflare access without exposing tokens to clients.

The gateway path format is:
  /cloudflare/gateway/{api-path}

Examples:
  /cloudflare/gateway/zones
  /cloudflare/gateway/zones/{zone_id}/dns_records
  /cloudflare/gateway/user/tokens/verify
  /cloudflare/gateway/accounts/{account_id}/workers/scripts

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /cloudflare/role/{role}/gateway/{api-path}

The supported credential source type is:
- apikey: Static API token (stored in spec config as api_key)

Configuration:
- cloudflare_url: Cloudflare API base URL (default: https://api.cloudflare.com/client/v4)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
