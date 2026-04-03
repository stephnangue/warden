package mistral

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultMistralURL is the default Mistral API base URL
const DefaultMistralURL = "https://api.mistral.ai"

// DefaultMistralTimeout is the default request timeout for AI inference
const DefaultMistralTimeout = 120 * time.Second

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// Spec defines the Mistral provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "mistral",
	DefaultURL:         DefaultMistralURL,
	URLConfigKey:       "mistral_url",
	DefaultTimeout:     DefaultMistralTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-mistral-proxy",
	HelpText:           mistralBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	Transport:          sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
}

// Factory creates a new Mistral provider backend.
var Factory = httpproxy.NewFactory(Spec)

const mistralBackendHelp = `
The Mistral provider enables proxying requests to the Mistral AI API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains a
Mistral API key from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker Mistral AI
access without exposing API keys to clients.

The gateway path format is:
  /mistral/gateway/{api-path}

Examples:
  /mistral/gateway/v1/chat/completions
  /mistral/gateway/v1/embeddings
  /mistral/gateway/v1/models

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /mistral/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Configuration:
- mistral_url: Mistral API base URL (default: https://api.mistral.ai)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
