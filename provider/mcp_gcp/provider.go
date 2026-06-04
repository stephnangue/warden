package mcp_gcp

import (
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultMCPGCPTimeout caps a single MCP session. MCP responses can stream
// over SSE for many tool calls, so the default sits well above the per-request
// shapes that govern REST providers; operators raise this for longer sessions.
const DefaultMCPGCPTimeout = 10 * time.Minute

// Spec defines the mcp_gcp provider configuration for the httpproxy framework.
//
// The provider transparently proxies traffic to a Google Cloud MCP server,
// injecting a short-lived GCP access token as Authorization: Bearer <token>.
// Bodies and Accept negotiation pass through unchanged so Streamable HTTP
// (JSON or SSE) works without any MCP-specific framework support.
//
// Unlike GitHub's hosted MCP server, Google Cloud has no single canonical MCP
// endpoint — operators run MCP servers on Cloud Run, Vertex AI, the genai
// toolbox, and elsewhere. There is therefore no default URL; the operator must
// set mcp_gcp_url. A single mount fronts exactly one product; agents pick the
// right mount by its operator-set description, never by inspecting the URL.
var Spec = &httpproxy.ProviderSpec{
	Name:            "mcp_gcp",
	DefaultURL:      "", // operator-required; no canonical GCP MCP endpoint
	URLConfigKey:    "mcp_gcp_url",
	DefaultTimeout:  DefaultMCPGCPTimeout,
	ParseStreamBody: false,
	UserAgent:       "warden-mcp-gcp-proxy",
	HelpText:        mcpGCPBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(
		credential.TypeGCPAccessToken, "access_token", "Authorization", "Bearer ",
	),
	// DefaultAccept intentionally unset. The httpproxy framework injects a
	// default Accept only when the client sends none; MCP clients always
	// negotiate ("application/json, text/event-stream"). Forcing a default
	// here would break one-shot JSON clients.
	ShouldEnforceMCPPolicy: shouldEnforceMCPPolicy,
}

// shouldEnforceMCPPolicy opts mcp_gcp into CBP body-authoritative
// mcp { } enforcement for the subset of traffic where it is meaningful:
// JSON-RPC POSTs. GET (SSE reconnect) and DELETE (session close), and
// any non-JSON Content-Type, decline and pass through under
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

// Factory creates a new mcp_gcp provider backend.
var Factory = httpproxy.NewFactory(Spec)

const mcpGCPBackendHelp = `
The mcp_gcp provider proxies requests to a Google Cloud MCP server with
automatic credential management. Warden performs implicit authentication
on every request, mints a short-lived GCP access token from the
credential manager, and injects it as Authorization: Bearer <token>.
Clients never hold a service account key or token.

Google Cloud has no single canonical hosted MCP server. Operators run MCP
servers on Cloud Run, Vertex AI, the genai toolbox, and elsewhere, so this
provider has no default upstream URL — mcp_gcp_url must be configured before
the mount can serve traffic. A single mount fronts one product; consumers
select the right mount by its operator-set description, not by reading the URL.

The gateway path format is:
  /mcp_gcp/gateway/{mcp-path}

The MCP server exposes a single endpoint; an empty suffix routes to the
canonical server URL. JSON-RPC bodies, the Accept header, and the
Mcp-Session-Id header pass through unchanged. Streamable HTTP responses
(JSON or SSE) are streamed without buffering.

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /mcp_gcp/role/{role}/gateway/

Header-routed alternative: clients that prefer a base URL without the
/v1/mcp_gcp/gateway/ prefix can send the mount path as X-Warden-Provider
(and the namespace as X-Warden-Namespace) and let Warden synthesise the
canonical gateway path. The X-Warden-Provider value is the mount path from
'warden provider list', not the literal provider type — see the skill
markdown for the exact command.

The same gcp_access_token credspec used for the gcp REST provider works here
unchanged — binding one to a role grants both REST and MCP reach.

Policy:
Two layers of authorization apply to MCP traffic. The minted GCP access
token is the security boundary — its scopes and the service account's IAM
bindings bound what the agent can actually do at Google Cloud regardless of
what Warden lets through. On top of that, Warden's CBP policies support an
mcp { } block for governance-style restrictions enforced at the gateway:
allow- and deny-lists for JSON-RPC methods, tool names, resource URIs,
prompt names, and selected tool arguments. Enforcement is body-authoritative
— Warden strict-parses the JSON-RPC request body and matches against the
parsed body, never against client-supplied request headers. The parser
rejects malformed bodies, duplicate keys at any depth, empty batches, and
oversized payloads; on any structural failure the request denies with a
specific rule_type (malformed_jsonrpc, duplicate_key, oversized_body,
batch_empty, missing_body, malformed_params). Denied requests return HTTP
403 with an RFC 6750 WWW-Authenticate header and a small JSON body the agent
SDK surfaces as a structured tool-call failure.

Body parsing runs only for POST requests carrying Content-Type
application/json. Other request shapes do not produce a parsed body
descriptor: when a policy in scope binds an mcp { } block to a path that
also receives non-POST or non-JSON traffic, those requests deny with
rule_type missing_body. Operators scope mcp { } blocks to paths they expect
to carry JSON-RPC POSTs.

Policies without an mcp { } block in scope skip the strict parser entirely
— no body buffering or parsing is performed on those paths.

Configuration:
- mcp_gcp_url: MCP server base URL (required; no default)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Session timeout (default: 10m). Raise for long agent sessions
    that keep an SSE stream open across many tool calls.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
- tls_skip_verify: Skip TLS verification (development only)
- ca_data: Base64-encoded PEM CA certificate for custom/self-signed CAs
`
