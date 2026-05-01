package tfe

import (
	"time"

	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultTFEURL is the default HCP Terraform API base URL
const DefaultTFEURL = "https://app.terraform.io"

// DefaultTFETimeout is the default request timeout for TFE API calls
const DefaultTFETimeout = 30 * time.Second

// Spec defines the TFE provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "tfe",
	DefaultURL:         DefaultTFEURL,
	URLConfigKey:       "tfe_url",
	DefaultTimeout:     DefaultTFETimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-tfe-proxy",
	HelpText:           tfeBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	DefaultHeaders:     map[string]string{"Content-Type": "application/vnd.api+json"},
	DefaultAccept:      "application/vnd.api+json",
}

// Factory creates a new TFE provider backend.
var Factory = httpproxy.NewFactory(Spec)

const tfeBackendHelp = `
The TFE provider enables proxying requests to the Terraform Enterprise (TFE)
and HCP Terraform API with automatic credential management and bearer token
injection.

Warden performs implicit authentication on every request and obtains a
TFE API token from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker TFE access
without exposing API tokens to clients.

The gateway path format is:
  /tfe/gateway/{api-path}

Examples:
  /tfe/gateway/api/v2/organizations
  /tfe/gateway/api/v2/workspaces
  /tfe/gateway/api/v2/runs
  /tfe/gateway/api/v2/projects
  /tfe/gateway/api/v2/state-versions

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /tfe/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate TFE request
fields for fine-grained access control — for example, restricting which
organizations or workspaces a role can manage.

All TFE API endpoints use the JSON:API specification. The Content-Type
header is automatically set to "application/vnd.api+json" on all proxied
requests.

TFE enforces a rate limit of 30 requests per second per authenticated
user. Exceeding this limit returns HTTP 429.

Five token types are supported (all injected as Bearer tokens):
- User tokens: Full access scoped to the user's permissions
- Team tokens: Access scoped to the team's assigned workspaces
- Organization tokens: Organization-level settings (cannot execute runs)
- Audit Trail tokens: Read-only access to organization audit data
- Agent tokens: Agent pool communication (not for direct API use)

Two credential source types are supported:
- apikey: Static TFE API token (stored in spec config as api_key)
- hvault: Vault/OpenBao KV v2 secret containing api_key;
  use mint_method=static_apikey on the spec

Configuration:
- tfe_url: TFE API base URL (default: https://app.terraform.io)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

For Terraform Enterprise (self-hosted), set tfe_url to your instance URL:
  https://tfe.example.com
`
