package mcp_github

import (
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultMCPGitHubURL is the default URL for GitHub's hosted MCP server.
const DefaultMCPGitHubURL = "https://api.githubcopilot.com/mcp"

// DefaultMCPGitHubTimeout caps a single MCP session. MCP responses can stream
// over SSE for many tool calls, so the default sits well above the per-request
// shapes that govern REST providers; operators raise this for longer sessions.
const DefaultMCPGitHubTimeout = 10 * time.Minute

// Spec defines the mcp_github provider configuration for the httpproxy framework.
//
// The provider transparently proxies traffic to GitHub's hosted MCP server,
// injecting a GitHub token as Authorization: Bearer <pat>. Bodies and Accept
// negotiation pass through unchanged so Streamable HTTP (JSON or SSE) works
// without any MCP-specific framework support.
var Spec = &httpproxy.ProviderSpec{
	Name:            "mcp_github",
	DefaultURL:      DefaultMCPGitHubURL,
	URLConfigKey:    "mcp_github_url",
	DefaultTimeout:  DefaultMCPGitHubTimeout,
	ParseStreamBody: false,
	UserAgent:       "warden-mcp-github-proxy",
	HelpText:        mcpGitHubBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(
		credential.TypeGitHubToken, "token", "Authorization", "Bearer ",
	),
	// DefaultAccept intentionally unset. The httpproxy framework injects a
	// default Accept only when the client sends none; MCP clients always
	// negotiate ("application/json, text/event-stream"). Forcing a default
	// here would break one-shot JSON clients.
}

// Factory creates a new mcp_github provider backend.
var Factory = httpproxy.NewFactory(Spec)

const mcpGitHubBackendHelp = `
The mcp_github provider proxies requests to GitHub's hosted MCP server
with automatic credential management. Warden performs implicit
authentication on every request, mints a GitHub token from the
credential manager, and injects it as Authorization: Bearer <token>.
Clients never hold a PAT.

The gateway path format is:
  /mcp_github/gateway/{mcp-path}

The MCP server exposes a single endpoint; an empty suffix routes to the
canonical server URL. Examples:

  POST /mcp_github/gateway/    → POST https://api.githubcopilot.com/mcp/
  GET  /mcp_github/gateway/    → GET  https://api.githubcopilot.com/mcp/

JSON-RPC bodies, the Accept header, and the Mcp-Session-Id header pass
through unchanged. Streamable HTTP responses (JSON or SSE) are streamed
without buffering.

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /mcp_github/role/{role}/gateway/

Header-routed alternative: clients that prefer a base URL without the
/v1/mcp_github/gateway/ prefix can send the mount path as
X-Warden-Provider (and the namespace as X-Warden-Namespace) and let
Warden synthesise the canonical gateway path. The X-Warden-Provider
value is the mount path from 'warden provider list', not the literal
provider type — see the skill markdown for the exact command.

The same TypeGitHubToken credspec used for the github REST provider works
here unchanged — binding one to a role grants both REST and MCP reach.

Configuration:
- mcp_github_url: MCP server base URL (default: https://api.githubcopilot.com/mcp)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Session timeout (default: 10m). Raise for long agent sessions
    that keep an SSE stream open across many tool calls.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
`
