package cohere

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultCohereURL is the default Cohere API base URL
const DefaultCohereURL = "https://api.cohere.com"

// DefaultCohereTimeout is the default request timeout for AI inference
const DefaultCohereTimeout = 120 * time.Second

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// Spec defines the Cohere provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "cohere",
	DefaultURL:         DefaultCohereURL,
	URLConfigKey:       "cohere_url",
	DefaultTimeout:     DefaultCohereTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-cohere-proxy",
	HelpText:           cohereBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	Transport:          sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
}

// Factory creates a new Cohere provider backend.
var Factory = httpproxy.NewFactory(Spec)

const cohereBackendHelp = `
The Cohere provider enables proxying requests to the Cohere API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains a
Cohere API key from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker Cohere AI
access without exposing API keys to clients.

The gateway path format is:
  /cohere/gateway/{api-path}

Examples:
  /cohere/gateway/v2/chat
  /cohere/gateway/v2/embed
  /cohere/gateway/v1/rerank
  /cohere/gateway/v1/models
  /cohere/gateway/v1/tokenize
  /cohere/gateway/v1/detokenize

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /cohere/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Configuration:
- cohere_url: Cohere API base URL (default: https://api.cohere.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
