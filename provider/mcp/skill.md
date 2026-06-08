---
name: mcp
description: "Talk to any bearer-authenticated MCP server through Warden — without holding the OAuth token or API key. Point any MCP client (Claude Code, Cursor, ...) at Warden; tools and JSON/SSE responses pass through unchanged."
category: provider-guide
provider: mcp
requires: [foundation, discovery]
upstream: Any bearer-authenticated MCP server (operator-configured; e.g. Cloudflare, Slack, Linear, Sentry, Notion)
---

# Generic MCP through Warden

## What it does

Warden proxies traffic to a bearer-authenticated MCP server. The MCP client
calls a Warden URL; Warden authenticates the caller (JWT/cert), mints a bearer
token bound to the chosen role, injects it as `Authorization: Bearer <token>`,
and streams the response (JSON or SSE) back unchanged. The agent **never holds
the OAuth token or API key**.

## Pick the right mount

The `mcp` type is generic, so a single mount fronts exactly **one** MCP server —
Cloudflare, Slack, Linear, or whatever an operator stood up — each at its own
`mcp_url`. **Identify the mount you want by its operator-set description from
`warden provider list`, never by reading `mcp_url` or guessing from the provider
type.** The URL tells you nothing about which product the mount fronts; the
description does. When several `mcp` mounts exist, the type alone can't tell
them apart.

## Configure the MCP client

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/mcp/`, `/v1/team-tools/cloudflare-mcp/`).
  Warden has already baked the namespace and mount path in.
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

```
MCP server URL : $WARDEN_ADDR<mount-url>role/<role>/gateway/
Auth header    : Authorization: Bearer $WARDEN_TOKEN
```

For MCP client configuration files, the entry looks like (Claude Code / Cursor
/ Continue / Cline / Goose all accept this shape):

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR<mount-url>role/<role>/gateway/",
  "headers": {
    "Authorization": "Bearer $WARDEN_TOKEN"
  }
}
```

Substitute `$WARDEN_ADDR`, `<mount-url>`, `<role>`, and `$WARDEN_TOKEN` before
saving — most MCP clients do not expand environment variables inside config
files.

## Examples

(All examples below assume `mount_url = /v1/mcp/` and role `mcp-user`;
substitute yours from `warden provider list`.)

List the tools the server exposes:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  $WARDEN_ADDR/v1/mcp/role/mcp-user/gateway/
```

Call a tool (the bound token's scopes bound what actually succeeds — see
Quirks):
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"<tool>","arguments":{}}}' \
  $WARDEN_ADDR/v1/mcp/role/mcp-user/gateway/
```

The trailing slash on `gateway/` matters — Warden composes the upstream URL as
the mount's configured upstream URL plus the gateway suffix.

## Header-routed alternative

If you prefer an MCP server URL that is just `$WARDEN_ADDR/` (some MCP clients
dislike long paths, or you want to mux several MCP providers under one base
URL), pass the mount path as `X-Warden-Provider` and the namespace as
`X-Warden-Namespace`:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="<your-mount-description>") | .path' | head -1)

curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "X-Warden-Provider: $path" \
  -H "X-Warden-Namespace: $WARDEN_NAMESPACE" \
  -H "X-Warden-Role: mcp-user" \
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

Select the mount by `description` rather than `type` — when more than one `mcp`
mount exists, the type and `path` alone don't tell you which upstream product
the mount fronts.

## Quirks

- **The injected header is `Authorization: Bearer <token>`.** Warden mints the
  token per request from the bound credspec. It accepts both an
  `oauth_bearer_token` (OAuth2) and a static `api_key`. Servers that expect a
  static key in a non-`Authorization` header (e.g. `x-api-key`) are **not**
  supported by this provider — they need a dedicated provider.
- **The bound token's scopes determine which tools resolve.** The upstream
  enforces its own authorization on the minted token. A `403` or
  `permission denied` from a `tools/call` usually means the bound credential
  lacks the required scope/grant. Ask the operator to widen it rather than
  switching Warden roles unless one with broader reach exists.
- **OAuth vs static key is an operator choice you don't see.** Whether the mount
  is backed by a browser-consented OAuth grant (refreshed automatically) or a
  static API key is configured by the operator; from the client side both look
  like `Authorization: Bearer $WARDEN_TOKEN` to Warden. The per-upstream notes
  under the provider's `docs/` folder (e.g. `slack.md`) call out which shape a
  given upstream uses.
- **Warden policy can gate tools too — body-authoritative.** Operators may bind
  a policy with an `mcp { }` block that restricts JSON-RPC methods, tool names,
  resource URIs, prompt names, and `tools/call` arguments. Warden strict-parses
  the JSON-RPC request body and matches against the parsed body — no client-side
  opt-in or header mirroring is required. A deny shows up as HTTP 403 with an
  RFC 6750 `WWW-Authenticate: Bearer error="insufficient_permissions",
  error_description="..."` header and a small JSON body of the same shape; the
  description names the offending method/tool/parameter. This is independent of
  upstream scope errors — read the `error_description` to tell the two apart.
  The parser also fails closed on structural problems (malformed JSON-RPC,
  duplicate keys, oversized body, etc.) with a specific `rule_type` in the audit
  log. See the README's "Create a Policy" section for the full rule_type table.
- **Streamable HTTP / SSE flows through transparently.** Send
  `Accept: application/json, text/event-stream` and the server's choice of
  framing comes back unchanged. The `Mcp-Session-Id` response header round-trips
  automatically; subsequent client requests carrying it reach the same upstream
  session.
- **Session timeout is mount-wide.** The mount's `timeout` config caps an entire
  SSE session (default 10 minutes). For longer agent sessions, ask the operator
  to raise it.
- **Not in scope**: OAuth flows initiated by the *client* (Dynamic Client
  Registration, PRM discovery, `.well-known/oauth-protected-resource`), stdio
  transport, and legacy split-endpoint HTTP+SSE. Warden brokers the bearer token
  for you; use the bearer-token path above.
