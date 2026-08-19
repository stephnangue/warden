package newrelic

import (
	"net/http"
	"time"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultNewRelicURL is the default New Relic API base URL (US datacenter)
const DefaultNewRelicURL = "https://api.newrelic.com"

// DefaultNewRelicTimeout is the default request timeout for New Relic API calls
const DefaultNewRelicTimeout = 30 * time.Second

// extractTokens resolves the two principals on a New Relic gateway request.
//
// Agent channels, in the provider's existing order: the native Api-Key header
// first, then X-Warden-Token — Api-Key must keep winning so New Relic clients
// authenticate naturally. On a protected-resource mount an agent presented out
// of band — X-Warden-Agent-Token or a trusted client certificate — frees
// Authorization to carry the user.
//
// Extraction matrix. "-" means nothing extracted; an empty agent under a
// client certificate means the certificate authenticates the agent
// downstream. Off the user leg there is never a user.
//
//	request carries                     agent(off)  agent(on)  user(on)
//	Authorization: Bearer u             u           u          -
//	X-Warden-Token: w + Bearer u        w           w          -
//	X-Warden-Agent-Token: a + Bearer u  u           a          u
//	client cert + Bearer u              u           -          u
//	client cert only                    -           -          -
//	Api-Key: n + Bearer u               n           n          u
//	Api-Key: n + Bearer u + cert        n           n          u
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	return logical.ExtractTokensWithChannels(r, userLeg, "Api-Key", "X-Warden-Token")
}

// Spec defines the New Relic provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "newrelic",
	DefaultURL:         DefaultNewRelicURL,
	URLConfigKey:       "newrelic_url",
	DefaultTimeout:     DefaultNewRelicTimeout,
	ExtractToken:       extractTokens,
	ParseStreamBody:    true,
	UserAgent:          "warden-newrelic-proxy",
	HelpText:           newrelicBackendHelp,
	ExtractCredentials: httpproxy.HeaderAPIKeyExtractor("Api-Key"),
}

// Factory creates a new New Relic provider backend.
var Factory = httpproxy.NewFactory(Spec)

const newrelicBackendHelp = `
The New Relic provider enables proxying requests to the New Relic REST API and
NerdGraph (GraphQL) API with automatic credential management and API key
injection.

Warden performs implicit authentication on every request and obtains a
New Relic User API key from the credential manager, injecting it into the
proxied request's Api-Key header. This allows Warden to broker New Relic
access without exposing keys to clients.

The gateway path format is:
  /newrelic/gateway/{api-path}

Examples:
  /newrelic/gateway/graphql
  /newrelic/gateway/v2/applications.json
  /newrelic/gateway/v2/alerts_policies.json

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /newrelic/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate New Relic
request fields (including NerdGraph queries) for fine-grained access control.

Two credential source types are supported:
- apikey: Static User API key (stored in spec config as api_key)
- hvault: Vault/OpenBao KV v2 secret containing api_key;
  use mint_method=static_apikey on the spec

Configuration:
- newrelic_url: New Relic API base URL (default: https://api.newrelic.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The newrelic_url must match your New Relic datacenter region:
  US: https://api.newrelic.com (default)
  EU: https://api.eu.newrelic.com
`
