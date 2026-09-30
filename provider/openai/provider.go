package openai

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// openaiCredentialExtractor injects the credential as an Authorization bearer.
//
// An API key (api_key) carries the organization and project it should bill to, and
// sends them as OpenAI-Organization / OpenAI-Project when set. A federated token
// (oauth_bearer_token) sends the bearer alone: it is issued for one service
// account, which already belongs to one project in one organization, so a header
// naming another would assert the binding twice and let the two disagree. Both
// headers are stripped from the client's request either way.
func openaiCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}

	switch req.Credential.Type {
	case credential.TypeAPIKey:
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		headers := map[string]string{
			"Authorization": "Bearer " + apiKey,
		}
		if orgID := req.Credential.Data["organization_id"]; orgID != "" {
			headers["OpenAI-Organization"] = orgID
		}
		if projectID := req.Credential.Data["project_id"]; projectID != "" {
			headers["OpenAI-Project"] = projectID
		}
		return headers, nil

	case credential.TypeOAuthBearerToken:
		// api_key is this type's primary field too. A source that returns the
		// token as access_token is normalised onto api_key when the credential
		// is parsed, so there is only ever the one name to read here.
		token := req.Credential.Data["api_key"]
		if token == "" {
			return nil, fmt.Errorf("credential missing bearer token (api_key, or access_token as the source returned it)")
		}
		return map[string]string{"Authorization": "Bearer " + token}, nil

	default:
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
}

// DefaultOpenAIURL is the default OpenAI API base URL
const DefaultOpenAIURL = "https://api.openai.com"

// DefaultOpenAITimeout is the default request timeout for AI inference
const DefaultOpenAITimeout = 120 * time.Second

// Spec defines the OpenAI provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:                 "openai",
	DefaultURL:           DefaultOpenAIURL,
	URLConfigKey:         "openai_url",
	DefaultTimeout:       DefaultOpenAITimeout,
	ParseStreamBody:      true,
	UserAgent:            "warden-openai-proxy",
	HelpText:             openaiBackendHelp,
	ExtractCredentials:   openaiCredentialExtractor,
	ExtraHeadersToRemove: []string{"OpenAI-Organization", "OpenAI-Project"},
}

// Factory creates a new OpenAI provider backend.
var Factory = httpproxy.NewFactory(Spec)

const openaiBackendHelp = `
The OpenAI provider enables proxying requests to the OpenAI API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains an
OpenAI API key from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker OpenAI access
without exposing API keys to clients.

For keyless access, bind the role to a spec on an openai credential source:
Warden then exchanges a Warden-signed identity assertion for a short-lived
OpenAI access token through workload identity federation, and injects that
token instead. No OpenAI key is stored. A federated token is bound to its
service account's organization and project, so no OpenAI-Organization or
OpenAI-Project header is sent with it.

The gateway path format is:
  /openai/gateway/{api-path}

Examples:
  /openai/gateway/v1/chat/completions
  /openai/gateway/v1/responses
  /openai/gateway/v1/embeddings
  /openai/gateway/v1/models

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /openai/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Configuration:
- openai_url: OpenAI API base URL (default: https://api.openai.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
