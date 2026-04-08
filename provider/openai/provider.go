package openai

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/httpproxy"
)

// openaiCredentialExtractor extracts api_key (as Bearer), organization_id, and project_id.
func openaiCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != credential.TypeAPIKey {
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
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
