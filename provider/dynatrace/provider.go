package dynatrace

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultDynatraceTimeout is the default request timeout for Dynatrace API calls.
const DefaultDynatraceTimeout = 30 * time.Second

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// dynatraceCredentialExtractor extracts credentials and returns the appropriate
// Authorization header. Dynatrace Environment API uses "Api-Token" prefix for
// static API tokens, while Platform API uses "Bearer" prefix for OAuth2 tokens.
func dynatraceCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	switch req.Credential.Type {
	case credential.TypeAPIKey:
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		return map[string]string{
			"Authorization": "Api-Token " + apiKey,
		}, nil
	case credential.TypeOAuthBearerToken:
		token := req.Credential.Data["api_key"]
		if token == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		return map[string]string{
			"Authorization": "Bearer " + token,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
}

// Spec defines the Dynatrace provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "dynatrace",
	DefaultURL:         "https://{environment-id}.live.dynatrace.com",
	URLConfigKey:       "dynatrace_url",
	DefaultTimeout:     DefaultDynatraceTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-dynatrace-proxy",
	HelpText:           dynatraceBackendHelp,
	ExtractCredentials: dynatraceCredentialExtractor,
	Transport:          sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
}

// Factory creates a new Dynatrace provider backend.
var Factory = httpproxy.NewFactory(Spec)

const dynatraceBackendHelp = `
The Dynatrace provider enables proxying requests to the Dynatrace REST API with
automatic credential management and authentication header injection.

Warden performs implicit authentication on every request and obtains credentials
from the credential manager, injecting them into the proxied request's
Authorization header. For static API tokens, the header uses the "Api-Token"
prefix required by Dynatrace Environment API. For OAuth2 bearer tokens, the
standard "Bearer" prefix is used for Dynatrace Platform API.

The gateway path format is:
  /dynatrace/gateway/{api-path}

Examples:
  /dynatrace/gateway/api/v2/entities
  /dynatrace/gateway/api/v2/metrics/query
  /dynatrace/gateway/api/v2/logs/search
  /dynatrace/gateway/api/v2/tokens
  /dynatrace/gateway/api/v2/settings/objects
  /dynatrace/gateway/api/v2/problems

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /dynatrace/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Dynatrace
request fields for fine-grained access control.

Two credential source types are supported:
- apikey: Static API token (stored in spec config as api_key); uses the
  Dynatrace "Api-Token" authorization scheme
- oauth2: OAuth2 client credentials flow via Dynatrace SSO
  (token_url=https://sso.dynatrace.com/sso/oauth2/token); uses the
  "Bearer" authorization scheme. Set token_param.resource to the account
  URN (urn:dtaccount:{account-uuid}) when required by the Platform API.
- hvault: Vault/OpenBao KV v2 secret containing api_key; use
  mint_method=static_apikey on the spec

Configuration:
- dynatrace_url: Dynatrace API base URL (required — must include your
  environment ID, e.g., https://abc12345.live.dynatrace.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The dynatrace_url depends on your deployment:
  SaaS:      https://{environment-id}.live.dynatrace.com
  Platform:  https://{environment-id}.apps.dynatrace.com
  Managed:   https://{your-domain}/e/{environment-id}
`
