package anthropic

import (
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultAnthropicURL is the default Anthropic API base URL
const DefaultAnthropicURL = "https://api.anthropic.com"

// DefaultAnthropicTimeout is the default request timeout for AI inference
const DefaultAnthropicTimeout = 120 * time.Second

// extractToken extracts Warden token from X-Warden-Token, x-api-key, or Authorization: Bearer headers.
// Anthropic clients typically send credentials via x-api-key, so we accept that as a Warden token source.
func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	if token := r.Header.Get("x-api-key"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	return ""
}

// Spec defines the Anthropic provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:                 "anthropic",
	DefaultURL:           DefaultAnthropicURL,
	URLConfigKey:         "anthropic_url",
	DefaultTimeout:       DefaultAnthropicTimeout,
	ParseStreamBody:      true,
	UserAgent:            "warden-anthropic-proxy",
	HelpText:             anthropicBackendHelp,
	ExtractCredentials:   httpproxy.HeaderAPIKeyExtractor("x-api-key"),
	ExtractToken:         extractToken,
	ExtraHeadersToRemove: []string{"x-api-key", "anthropic-version"},
	DefaultHeaders:       map[string]string{"anthropic-version": "2023-06-01"},
}

// Factory creates a new Anthropic provider backend.
var Factory = httpproxy.NewFactory(Spec)

const anthropicBackendHelp = `
The Anthropic provider enables proxying requests to the Anthropic API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains an
Anthropic API key from the credential manager, injecting it into the proxied
request's x-api-key header. This allows Warden to broker Anthropic access
without exposing API keys to clients.

The gateway path format is:
  /anthropic/gateway/{api-path}

Examples:
  /anthropic/gateway/v1/messages
  /anthropic/gateway/v1/models

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /anthropic/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Configuration:
- anthropic_url: Anthropic API base URL (default: https://api.anthropic.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
