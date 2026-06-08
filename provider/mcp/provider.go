package mcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultMCPTimeout caps a single MCP session. MCP responses can stream over
// SSE for many tool calls, so the default sits well above the per-request
// shapes that govern REST providers; operators raise this for longer sessions.
// The value matches mcp_aws (the other MCP provider) so operators learn one
// timeout knob across every MCP mount.
const DefaultMCPTimeout = 10 * time.Minute

// Spec defines the generic mcp provider configuration for the httpproxy
// framework.
//
// This is the catch-all MCP provider: it fronts any MCP server that
// authenticates with a bearer token, injecting the minted credential as
// Authorization: Bearer <token>. Bodies and Accept negotiation pass through
// unchanged so Streamable HTTP (JSON or SSE) works without any MCP-specific
// framework support.
//
// It accepts every bearer-shaped credential a role may bind: oauth_bearer_token
// (OAuth2, including the authorization-code flow — the shape most remote MCP
// servers require), api_key (a static, long-lived personal or service token),
// github_token (a GitHub App token or PAT), and gcp_access_token (a short-lived
// Google Cloud access token). Per-upstream setup recipes live under
// provider/mcp/docs/. Only mcp_aws keeps a dedicated provider, because it signs
// requests with SigV4 rather than injecting a bearer.
//
// There is no canonical generic MCP endpoint, so there is no default URL; the
// operator must set mcp_url. A single mount fronts exactly one product; agents
// pick the right mount by its operator-set description, never by inspecting the
// URL. Per-upstream recipes live under provider/mcp/docs/.
var Spec = &httpproxy.ProviderSpec{
	Name:               "mcp",
	DefaultURL:         "", // operator-required; no canonical generic MCP endpoint
	URLConfigKey:       "mcp_url",
	DefaultTimeout:     DefaultMCPTimeout,
	ParseStreamBody:    false,
	UserAgent:          "warden-mcp-proxy",
	HelpText:           mcpBackendHelp,
	ExtractCredentials: extractBearerToken,
	// DefaultAccept intentionally unset. The httpproxy framework injects a
	// default Accept only when the client sends none; MCP clients always
	// negotiate ("application/json, text/event-stream"). Forcing a default
	// here would break one-shot JSON clients.

	ShouldEnforceMCPPolicy: shouldEnforceMCPPolicy,
}

// extractBearerToken injects the minted credential as Authorization: Bearer.
// It accepts every bearer-shaped credential a role may bind, reading the token
// from whichever field that credential type stores it in:
//   - oauth_bearer_token (OAuth2 authorization-code / client-credentials) → "api_key"
//   - api_key (static, long-lived personal/service token)                → "api_key"
//   - github_token (GitHub App installation token or PAT)                → "token"
//   - gcp_access_token (short-lived Google Cloud access token)           → "access_token"
//   - azure_bearer_token (Entra ID access token; audience must match the
//     target MCP server's app registration)                              → "access_token"
//
// All are injected verbatim as a Bearer token. Upstreams that expect a token in
// a non-Authorization header (e.g. x-api-key) or a signed request (AWS SigV4,
// served by mcp_aws) are out of scope for this provider.
func extractBearerToken(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	var token string
	switch req.Credential.Type {
	case credential.TypeOAuthBearerToken, credential.TypeAPIKey:
		token = req.Credential.Data["api_key"]
	case credential.TypeGCPAccessToken, credential.TypeAzureBearerToken:
		token = req.Credential.Data["access_token"]
	case credential.TypeGitHubToken:
		token = req.Credential.Data["token"]
	default:
		return nil, fmt.Errorf("unsupported credential type for mcp: %s", req.Credential.Type)
	}
	if token == "" {
		return nil, fmt.Errorf("credential missing token")
	}
	return map[string]string{"Authorization": "Bearer " + token}, nil
}

// shouldEnforceMCPPolicy opts the generic mcp provider into CBP
// body-authoritative mcp { } enforcement for the subset of traffic where it is
// meaningful: JSON-RPC POSTs. GET (SSE reconnect) and DELETE (session close),
// and any non-JSON Content-Type, decline and pass through under
// token-scope-only enforcement.
func shouldEnforceMCPPolicy(req *logical.Request) bool {
	if req == nil || req.HTTPRequest == nil {
		return false
	}
	r := req.HTTPRequest
	if r.Method != http.MethodPost {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	// Trim a charset / boundary parameter (e.g. "application/json; charset=utf-8")
	// before comparing to the bare media type.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json"
}

// Factory creates a new generic mcp provider backend.
var Factory = httpproxy.NewFactory(Spec)

const mcpBackendHelp = `
The mcp provider proxies requests to a bearer-authenticated MCP server with
automatic credential management. Warden performs implicit authentication on
every request, mints a bearer token from the credential manager, and injects
it as Authorization: Bearer <token>. Clients never hold the token.

This is the generic MCP provider. It fronts any MCP server that accepts a bearer
token in the Authorization header, and accepts every bearer-shaped credential a
role may bind: oauth_bearer_token (OAuth2, including the authorization-code flow
— the shape most remote MCP servers require), api_key (a static, long-lived
personal or service token), github_token (a GitHub App token or PAT), and
gcp_access_token (a short-lived Google Cloud access token). Per-upstream setup
recipes live under provider/mcp/docs/. Only mcp_aws keeps a dedicated provider,
because it signs requests with SigV4 rather than injecting a bearer.

There is no canonical generic MCP endpoint, so this provider has no default
upstream URL — mcp_url must be configured before the mount can serve traffic.
A single mount fronts one product; consumers select the right mount by its
operator-set description, not by reading the URL.

The gateway path format is:
  /mcp/gateway/{mcp-path}

The MCP server exposes a single endpoint; an empty suffix routes to the
canonical server URL. JSON-RPC bodies, the Accept header, and the
Mcp-Session-Id header pass through unchanged. Streamable HTTP responses
(JSON or SSE) are streamed without buffering.

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /mcp/role/{role}/gateway/

Header-routed alternative: clients that prefer a base URL without the
/v1/mcp/gateway/ prefix can send the mount path as X-Warden-Provider
(and the namespace as X-Warden-Namespace) and let Warden synthesise the
canonical gateway path. The X-Warden-Provider value is the mount path from
'warden provider list', not the literal provider type — see the skill
markdown for the exact command.

An oauth2 authorization_code credspec (oauth_bearer_token) lets a role act as a
consenting user — the shape most remote MCP servers require (Slack's MCP server,
for example, is OAuth-only). A static api_key credspec is also accepted, as are
the github_token and gcp_access_token credspecs that back the github and gcp REST
providers — binding one of those to a role grants both REST and MCP reach. Note
that an upstream's REST credential is not always accepted by the same upstream's
MCP server (Slack's MCP server, for instance, rejects the REST bot token), so
check the upstream's MCP auth before assuming a credspec can be reused.

Policy:
Two layers of authorization apply to MCP traffic. The minted bearer token is
the security boundary — its scopes bound what the agent can actually do at the
upstream regardless of what Warden lets through. On top of that, Warden's CBP
policies support an mcp { } block for governance-style restrictions enforced at
the gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource
URIs, prompt names, and selected tool arguments. Enforcement is
body-authoritative — Warden strict-parses the JSON-RPC request body and matches
against the parsed body, never against client-supplied request headers. The
parser rejects malformed bodies, duplicate keys at any depth, empty batches, and
oversized payloads; on any structural failure the request denies with a specific
rule_type (malformed_jsonrpc, duplicate_key, oversized_body, batch_empty,
missing_body, malformed_params). Denied requests return HTTP 403 with an RFC
6750 WWW-Authenticate header and a small JSON body the agent SDK surfaces as a
structured tool-call failure.

Body parsing runs only for POST requests carrying Content-Type
application/json. Other request shapes do not produce a parsed body descriptor:
when a policy in scope binds an mcp { } block to a path that also receives
non-POST or non-JSON traffic, those requests deny with rule_type missing_body.
Operators scope mcp { } blocks to paths they expect to carry JSON-RPC POSTs.

Policies without an mcp { } block in scope skip the strict parser entirely
— no body buffering or parsing is performed on those paths.

Configuration:
- mcp_url: MCP server base URL (required; no default)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Session timeout (default: 10m). Raise for long agent sessions
    that keep an SSE stream open across many tool calls.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
- tls_skip_verify: Skip TLS verification (development only)
- ca_data: Base64-encoded PEM CA certificate for custom/self-signed CAs
`
