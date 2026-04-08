package ovh

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultOVHURL is the default OVH API base URL (Europe region)
const DefaultOVHURL = "https://eu.api.ovh.com/1.0"

// DefaultOVHTimeout is the default request timeout for OVH API calls
const DefaultOVHTimeout = 30 * time.Second

// Spec defines the OVH provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "ovh",
	DefaultURL:         DefaultOVHURL,
	URLConfigKey:       "ovh_url",
	DefaultTimeout:     DefaultOVHTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-ovh-proxy",
	HelpText:           ovhBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
}

// Factory creates a new OVH provider backend.
var Factory = httpproxy.NewFactory(Spec)

const ovhBackendHelp = `
The OVH provider enables proxying requests to the OVHcloud REST API
with automatic credential management and OAuth2 bearer token injection.

Warden performs implicit authentication on every request and obtains an
OAuth2 bearer token from the credential manager, injecting it into the
proxied request's Authorization header. This allows Warden to broker
OVH access without exposing tokens to clients.

The gateway path format is:
  /ovh/gateway/{api-path}

Examples:
  /ovh/gateway/me
  /ovh/gateway/cloud/project
  /ovh/gateway/domain
  /ovh/gateway/ip

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /ovh/role/{role}/gateway/{api-path}

Two credential source types are supported:
- oauth2: OAuth2 client credentials flow (client_id/client_secret/token_url
  on source, scope on spec; tokens are minted dynamically)
- vault: HashiCorp Vault / OpenBao dynamic secret engine

Regional API endpoints and their matching OAuth2 token URLs:
- EU:  ovh_url=https://eu.api.ovh.com/1.0   token_url=https://www.ovh.com/auth/oauth2/token
- CA:  ovh_url=https://ca.api.ovh.com/1.0   token_url=https://ca.ovh.com/auth/oauth2/token
- US:  ovh_url=https://api.us.ovhcloud.com/1.0  token_url=https://us.ovhcloud.com/auth/oauth2/token

Configuration:
- ovh_url: OVH API base URL (default: https://eu.api.ovh.com/1.0)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
