---
name: mcp_gcp
description: "Talk to a Google Cloud MCP server through Warden — without holding a service account key or token. Use any MCP client (Claude Code, Cursor, ...) by pointing it at Warden; tools and JSON/SSE responses pass through unchanged."
category: provider-guide
provider: mcp_gcp
requires: [foundation, discovery]
upstream: A Google Cloud MCP server (operator-configured; e.g. Cloud Run, Vertex AI, genai toolbox)
---

# Google Cloud MCP through Warden

## What it does

Warden proxies traffic to a Google Cloud MCP server. The MCP client calls
a Warden URL; Warden authenticates the caller (JWT/cert), mints a
short-lived GCP access token bound to the chosen role, injects it as
`Authorization: Bearer <token>`, and streams the response (JSON or SSE)
back unchanged. The agent **never holds a service account key or token**.

The same `gcp_access_token` credspec that backs the `gcp` REST provider
also backs this mount — a single role binding grants both REST and MCP
reach.

## Pick the right mount

Google Cloud has **no single hosted MCP endpoint**. A `mcp_gcp` mount may
front a Cloud Run-hosted MCP server, a Vertex AI surface, the genai
toolbox, or any other MCP server an operator stood up — each at its own
`mcp_gcp_url`. **Identify the mount you want by its operator-set
description from `warden provider list`, never by reading `mcp_gcp_url`
or guessing from the provider type.** The URL tells you nothing about
which product or scope set the mount fronts; the description does.

## Configure the MCP client

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/mcp_gcp/`,
  `/v1/team-data/mcp_gcp/`). Warden has already baked the namespace
  and mount path in.
- `<role>` is the role you picked from `warden role list` to perform
  this task — it goes in the URL path.

```
MCP server URL : $WARDEN_ADDR<mount-url>role/<role>/gateway/
Auth header    : Authorization: Bearer $WARDEN_TOKEN
```

For MCP client configuration files, the entry looks like (Claude Code
/ Cursor / Continue / Cline / Goose all accept this shape):

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR<mount-url>role/<role>/gateway/",
  "headers": {
    "Authorization": "Bearer $WARDEN_TOKEN"
  }
}
```

Substitute `$WARDEN_ADDR`, `<mount-url>`, `<role>`, and `$WARDEN_TOKEN`
before saving — most MCP clients do not expand environment variables
inside config files.

## Examples

(All examples below assume `mount_url = /v1/mcp_gcp/` and role
`mcp-reader`; substitute yours from `warden provider list`.)

List the tools the server exposes:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  $WARDEN_ADDR/v1/mcp_gcp/role/mcp-reader/gateway/
```

Call a tool (the operator must grant a role whose token has the IAM
reach for the tool — see Quirks below):
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_datasets","arguments":{"projectId":"my-project"}}}' \
  $WARDEN_ADDR/v1/mcp_gcp/role/mcp-reader/gateway/
```

The trailing slash on `gateway/` matters — Warden composes the upstream
URL as the mount's configured upstream URL plus the gateway suffix.

## Header-routed alternative

If you prefer an MCP server URL that is just `$WARDEN_ADDR/` (some MCP
clients dislike long paths, or you want to mux several MCP providers
under one base URL), pass the mount path as `X-Warden-Provider` and the
namespace as `X-Warden-Namespace`:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="<your-mount-description>") | .path' | head -1)

curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "X-Warden-Provider: $path" \
  -H "X-Warden-Namespace: $WARDEN_NAMESPACE" \
  -H "X-Warden-Role: mcp-reader" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  $WARDEN_ADDR/
```

For an MCP client config:

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR/",
  "headers": {
    "Authorization": "Bearer $WARDEN_TOKEN",
    "X-Warden-Provider": "<path-from-warden-provider-list>",
    "X-Warden-Namespace": "<namespace>",
    "X-Warden-Role": "<role>"
  }
}
```

Select the mount by `description` rather than `type` — when more than one
`mcp_gcp` mount exists, the type and `path` alone don't tell you which
upstream product or scope set the mount fronts.

## Quirks

- **The injected header is `Authorization: Bearer <token>`.** The token
  is a short-lived GCP OAuth2 access token Warden mints per request from
  the bound credspec. The same `gcp_access_token` credspec backs both the
  `gcp` REST provider and this mount.
- **It's an access token, not an ID token.** The bearer is an OAuth2
  *access token* — it authenticates to Google Cloud APIs and to MCP
  servers that validate access tokens at the application layer. It is
  **not** an OIDC *ID token*. An MCP server behind IAM-authenticated
  Cloud Run ingress (which requires an ID token scoped to the service
  URL) won't accept it; that deployment shape isn't supported by the
  `gcp` source today. A `401`/`403` from the platform ingress (as opposed
  to the MCP server itself) is the tell.
- **IAM bindings and token scopes determine which tools resolve.** The
  upstream MCP server enforces Google Cloud IAM on the minted token. A
  `403` or `permission denied` from a `tools/call` usually means the
  bound service account (or impersonated principal) lacks a required IAM
  role, or the token's `scopes` don't cover the API. Ask the operator to
  widen the binding rather than switching Warden roles unless one exists.
- **Warden policy can gate tools too — body-authoritative.** Operators
  may bind a policy with an `mcp { }` block that restricts JSON-RPC
  methods, tool names, resource URIs, prompt names, and `tools/call`
  arguments. Warden strict-parses the JSON-RPC request body and matches
  against the parsed body — no client-side opt-in or header mirroring is
  required. A deny shows up as HTTP 403 with an RFC 6750
  `WWW-Authenticate: Bearer error="insufficient_permissions",
  error_description="..."` header and a small JSON body of the same
  shape; the description names the offending method/tool/parameter. This
  is independent of IAM errors — read the `error_description` to tell the
  two apart. The parser also fails closed on structural problems
  (malformed JSON-RPC, duplicate keys, oversized body, etc.) with a
  specific `rule_type` in the audit log. See the README's "Create a
  Policy" section for the full rule_type table.
- **Streamable HTTP / SSE flows through transparently.** Send
  `Accept: application/json, text/event-stream` and the server's choice
  of framing comes back unchanged. The `Mcp-Session-Id` response header
  round-trips automatically; subsequent client requests carrying it reach
  the same upstream session.
- **Session timeout is mount-wide.** The mount's `timeout` config caps an
  entire SSE session (default 10 minutes). For longer agent sessions, ask
  the operator to raise it.
- **Tokens are short-lived (~1h).** Warden re-mints per request and
  refreshes before expiry, so long sessions don't require client action.
- **Not in scope**: OAuth flows (Dynamic Client Registration, PRM
  discovery, `.well-known/oauth-protected-resource`), stdio transport,
  and legacy split-endpoint HTTP+SSE. Use the bearer-token path.
