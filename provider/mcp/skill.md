---
name: mcp
description: "Talk to any bearer-authenticated MCP server through Warden — without holding the OAuth token or API key. Your MCP client points at Warden under a role fixed at attach time (one attached server per role). Tools and JSON/SSE pass through unchanged."
category: provider-guide
provider: mcp
requires: []
upstream: Any bearer-authenticated MCP server (operator-configured; e.g. Cloudflare, Slack, Linear, Sentry, Notion)
---

# Generic MCP through Warden

## What it does

Warden proxies traffic to a bearer-authenticated MCP server. Your MCP client
calls Warden **under a role**; Warden authenticates the caller (JWT/cert), mints
a bearer token bound to that role, injects it as `Authorization: Bearer <token>`,
and streams the response (JSON or SSE) back unchanged. You **never hold the OAuth
token or API key**.

## Your role — one attached server per role

Everything depends on **which role** the call runs under — the role's policy
decides which tools you can list and call, and which upstream credential Warden
mints.

Your role is the `role/<role>/gateway/` segment of the URL this MCP server was
attached at. It is **fixed for this server** and you cannot change it at
runtime: an MCP client sends a fixed set of headers, and the role cannot be
passed in a tool call. This attached server *is* that role.

To act under a **different** role, call the MCP server the operator attached for
*that* role. The operator attaches **one server per role** — each at its own
`…/role/<role>/gateway/` URL, named or described so you can match it to a role
from the `list_roles` discovery tool. Pick the attached server whose role fits
the task.

## Attaching the client

The MCP server is attached to your client by the operator or your runtime (for
Claude Code, `claude mcp add`; Cursor/Continue/Cline/Goose take the same
HTTP-server shape), with your identity as a header — one attachment per role:

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR/v1/<namespace>/<mount>/role/<role>/gateway/",
  "headers": { "Authorization": "Bearer <jwt>" }
}
```

The trailing slash on `gateway/` matters — Warden composes the upstream URL as
the mount's configured upstream URL plus the gateway suffix. A `401` means the
JWT expired (typical TTL 5–60 min) — refresh it in the client config.

## Using it

- **`tools/list` is policy-filtered.** It returns only the tools this server's
  role allows — fewer tools than the raw upstream offers is the policy, not a
  bug. If the tool you need isn't listed, this role cannot call it; call the
  attached server for a role whose `list_roles` description fits the task.
- **Call tools normally.** Warden injects the upstream credential per request.

## Quirks

- **The bound token's scopes determine which tools resolve.** The upstream
  enforces its own authorization on the minted token. A `403` /
  `permission denied` from a `tools/call` usually means the bound credential
  lacks the scope/grant — ask the operator to widen it rather than switching
  roles, unless one with broader reach exists.
- **Warden policy can gate tools too — body-authoritative.** An operator may bind
  a policy with an `mcp { }` block restricting JSON-RPC methods, tool names,
  resource URIs, prompt names, and `tools/call` arguments; Warden strict-parses
  the request body and matches against it. A deny is HTTP 403 with an RFC 6750
  `WWW-Authenticate: Bearer error="insufficient_permissions",
  error_description="..."` header naming the offending method/tool/parameter.
  Read the `error_description` to tell a Warden policy deny from an upstream
  scope error. Structural problems (malformed JSON-RPC, duplicate keys, oversized
  body) also fail closed.
- **Streamable HTTP / SSE flows through transparently.** The server's framing
  comes back unchanged, and the `Mcp-Session-Id` response header round-trips
  automatically so follow-up requests reach the same upstream session.
- **Session timeout is mount-wide.** The mount's `timeout` config caps an entire
  SSE session (default 10 minutes). For longer sessions, ask the operator to
  raise it.
- **Static-key upstreams that expect a non-`Authorization` header** (e.g.
  `x-api-key`) are not served by this provider — they need a dedicated one.
- **Not in scope:** client-initiated OAuth (Dynamic Client Registration, PRM
  discovery), stdio transport, and legacy split-endpoint HTTP+SSE. Warden brokers
  the bearer token for you.
