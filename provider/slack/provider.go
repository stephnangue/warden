package slack

import (
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultSlackURL is the default Slack API base URL
const DefaultSlackURL = "https://slack.com/api"

// DefaultSlackTimeout is the default request timeout for Slack API calls
const DefaultSlackTimeout = 30 * time.Second

// Spec defines the Slack provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "slack",
	DefaultURL:         DefaultSlackURL,
	URLConfigKey:       "slack_url",
	DefaultTimeout:     DefaultSlackTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-slack-proxy",
	HelpText:           slackBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
}

// Factory creates a new Slack provider backend.
var Factory = httpproxy.NewFactory(Spec)

const slackBackendHelp = `
The Slack provider enables proxying requests to the Slack Web API with
automatic credential management and bot token injection.

Warden performs implicit authentication on every request and obtains a
Slack bot token from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker Slack access
without exposing bot tokens to clients.

The gateway path format is:
  /slack/gateway/{slack-method}

Examples:
  /slack/gateway/chat.postMessage
  /slack/gateway/conversations.list
  /slack/gateway/conversations.history
  /slack/gateway/auth.test
  /slack/gateway/users.info

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /slack/role/{role}/gateway/{slack-method}

Request body parsing is enabled, allowing policies to evaluate Slack request
fields such as channel, text, user, and as_user. This enables fine-grained
access control — for example, restricting which channels a role can post to.

Configuration:
- slack_url: Slack API base URL (default: https://slack.com/api)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
