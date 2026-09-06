package mcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultMCPTimeout caps a single call other than subscriptions/listen —
// a tool call, a listing, a resource read. Open-ended streaming is no longer
// its job: listen_timeout took that over, so this is a unary ceiling and
// nothing more, and it dropped from ten minutes to sixty seconds when it
// stopped having to cover a subscription.
//
// A ceiling is not a delay, but a long one multiplies how long a stalled
// call holds its goroutine and both connections, and the transport caps
// neither the number of upstream connections nor a peer that sends headers
// and then dribbles. A tool that genuinely runs for minutes is meant to
// report progress and be polled, not to hold a request open; mounts that
// front one anyway raise timeout explicitly. The value matches mcp_aws so
// operators learn one timeout knob across every MCP mount.
const DefaultMCPTimeout = 60 * time.Second

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

	// A subscriptions/listen stream is open-ended by design and answers to
	// listen_timeout; every other call keeps the unary ceiling above.
	SelectTimeout: httpproxy.SelectListenTimeout,
	ExtraConfigFields: map[string]*framework.FieldSchema{
		httpproxy.ListenTimeoutKey: httpproxy.ListenTimeoutField(),
	},
	OnConfigRead: func(state map[string]any) map[string]any {
		return map[string]any{
			httpproxy.ListenTimeoutKey: httpproxy.ReadListenTimeout(state).String(),
		}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		if err := httpproxy.WriteListenTimeout(d, state); err != nil {
			return nil, err
		}
		return state, nil
	},
	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		httpproxy.InitializeListenTimeout(config, state)
		return state
	},
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

// shouldEnforceMCPPolicy opts the generic mcp provider into
// body-authoritative MCP policy enforcement for the subset of traffic where it
// is meaningful: JSON-RPC POSTs. GET (SSE reconnect) and DELETE (session close),
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

Mcp-Session-Id is legacy-era and is forwarded for the upstreams that still
use it; a server speaking 2026-07-28 holds no session and ignores it. The
transport headers that revision introduced — MCP-Protocol-Version, Mcp-Method
and Mcp-Name — are validated against the parsed body when a client sends
them, and required of a client that announces the revision.

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
upstream regardless of what Warden lets through. On top of that, Warden supports
MCP policies for governance-style restrictions enforced at the gateway: a
document of its own, written to sys/policies/mcp/<name> and attached to the
token alongside the capability policy that grants the path, whose stanzas group
allow- and deny-lists by what they govern — methods, tools, resources, prompts —
plus a CEL condition over the call arguments. An MCP policy only ever narrows:
the request must already be allowed by a capability policy. Enforcement is
body-authoritative — Warden strict-parses the JSON-RPC request body and matches
against the parsed body, never against client-supplied request headers. The
parser rejects malformed bodies, duplicate keys at any depth, empty batches, and
oversized payloads; on any structural failure the request denies with a specific
rule_type (malformed_jsonrpc, duplicate_key, oversized_body, batch_empty,
missing_body, malformed_params, batch_unsupported, header_mismatch). Denied
requests return HTTP 403 with an RFC 6750 WWW-Authenticate header and a small
JSON body the agent SDK surfaces as a structured tool-call failure.

Two refusals are protocol faults rather than authorization decisions and are
answered differently. A request whose transport headers contradict its body
gets HTTP 400 and a JSON-RPC -32020 with the request id echoed, so a client
that speaks both eras corrects its headers instead of reading a 403 as "not
permitted" and downgrading to initialize. A batch from a client announcing
2026-07-28 is refused as batch_unsupported — batching left the spec in
2025-06-18 — while a legacy client's batch is still accepted and every element
policy-checked.

The methods a contract governs span both eras. server/discover joins
initialize, ping and notifications/* as exempt from the method allow-list:
a modern client sends it as the first request of every connection, and it
discloses protocol versions, coarse capabilities and serverInfo, never tool or
resource names. Naming it in denied_methods still blocks it. Subscribing to a
resource's updates answers to the resources family exactly as reading it does,
whether the caller subscribes with the modern subscriptions/listen or the
legacy resources/subscribe — the content never arrives either way, but the
resource's existence and the timing of every change would.

Body parsing runs only for POST requests carrying Content-Type
application/json. Other request shapes do not produce a parsed body descriptor:
when an MCP policy stanza covers a path that also receives non-POST or non-JSON
traffic, those requests deny with rule_type missing_body. Operators scope MCP
stanzas to paths they expect to carry JSON-RPC POSTs.

Paths with no MCP stanza in scope skip the strict parser entirely — no body
buffering or parsing is performed on them.

Deadlines:
Two knobs, chosen by what the request is rather than by how it responds.
subscriptions/listen — and the legacy SSE GET it replaced — take
listen_timeout, because a subscription is open-ended by design. Everything
else takes timeout.

The boundary surprises people, so state it plainly: a long-running tool call
that streams progress notifications is still capped by timeout, not by
listen_timeout. Raising listen_timeout will not save it. That is the intended
split — a unary call should be bounded more tightly than an open-ended
subscription — and the alternative is worse: raising timeout far enough to
hold a stream open would hand every hung call on the mount the same ceiling,
each one holding a goroutine and two connections for the duration.

A severed stream is survivable. The spec treats an abrupt drop as a reconnect
trigger, and a modern server holds no cross-connection subscription state, so
the client reconnects with a fresh subscription. Notifications that would have
arrived in the gap are lost.

Configuration:
- mcp_url: MCP server base URL (required; no default)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Deadline for a single call — a tool call, a listing, a resource
    read (default: 60s). Raise it for a mount fronting a genuinely slow tool;
    it is also how long a hung call on this mount keeps its goroutine and its
    two connections alive.
- listen_timeout: Deadline for a subscriptions/listen stream (default: 10m).
    Raise it for long-lived subscriptions. It governs that method only: a
    long-running tool call streaming progress is still capped by timeout.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
- tls_skip_verify: Skip TLS verification (development only)
- ca_data: Base64-encoded PEM CA certificate for custom/self-signed CAs
`
