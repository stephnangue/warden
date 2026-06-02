---
name: mcp_github
description: "Talk to GitHub's hosted MCP server through Warden — without holding a GitHub PAT. Use any MCP client (Claude Code, Cursor, ...) by pointing it at Warden; tools and JSON/SSE responses pass through unchanged."
category: provider-guide
provider: mcp_github
requires: [foundation, discovery]
upstream: GitHub's hosted MCP server (api.githubcopilot.com/mcp)
---

# GitHub MCP through Warden

## What it does

Warden proxies traffic to GitHub's hosted MCP server. The MCP client
calls a Warden URL; Warden authenticates the caller (JWT/cert), looks
up the GitHub PAT bound to the chosen role, injects it as
`Authorization: Bearer <pat>`, and streams the response (JSON or SSE)
back unchanged. The agent **never holds a PAT**.

The same PAT that backs the `github` REST provider also backs this
mount — a single role binding grants both REST and MCP reach.

## Configure the MCP client

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/mcp_github/`,
  `/v1/team-data/mcp_github/`). Warden has already baked the namespace
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

(All examples below assume `mount_url = /v1/mcp_github/` and role
`mcp-reader`; substitute yours from `warden provider list`.)

List the tools the server exposes:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  $WARDEN_ADDR/v1/mcp_github/role/mcp-reader/gateway/
```

Call a tool (the operator must grant a role with a PAT scoped for the
tool — see Quirks below):
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"myorg","repo":"myrepo"}}}' \
  $WARDEN_ADDR/v1/mcp_github/role/mcp-reader/gateway/
```

The trailing slash on `gateway/` matters — GitHub's MCP server lives at
exactly one path, and Warden composes the upstream URL as the mount's
upstream-URL config + the gateway suffix.

## Header-routed alternative

If you prefer an MCP server URL that is just `$WARDEN_ADDR/` (some MCP
clients dislike long paths, or you want to mux several MCP providers
under one base URL), pass the mount path as `X-Warden-Provider` and the
namespace as `X-Warden-Namespace`:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_github") | .path' | head -1)

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

When more than one `mcp_github` mount exists, replace `head -1` with a
`select(.description=="...")` matching the mount you want — `path`
alone doesn't tell you which PAT or scope set the mount fronts.

## Quirks

- **The injected header is `Authorization: Bearer <pat>`** — the same
  Bearer prefix the GitHub MCP docs document. This is the opposite of
  the `github` REST provider, which uses `Authorization: token <pat>`.
  The same `TypeGitHubToken` credspec works for both; only the wire
  format differs.
- **PAT scopes determine which tools resolve.** GitHub's MCP server
  enforces upstream scopes per tool. A `403` or `tool not available`
  response usually means the bound PAT lacks a required scope (e.g.
  `repo`, `issues`, `pull_requests`). Operators provision PATs with
  scopes covering the intended toolset; agents that hit scope errors
  should ask the operator to widen the binding, not request a different
  Warden role unless one exists.
- **Warden policy can gate tools too — body-authoritative.** Operators
  may bind a policy with an `mcp { }` block that restricts JSON-RPC
  methods, tool names, resource URIs, prompt names, and `tools/call`
  arguments. Warden strict-parses the JSON-RPC request body and
  matches against the parsed body — no client-side opt-in or header
  mirroring is required. A deny shows up as HTTP 403 with an RFC 6750
  `WWW-Authenticate: Bearer error="insufficient_permissions",
  error_description="..."` header and a small JSON body of the same
  shape; the description names the offending method/tool/parameter.
  This is independent of PAT scope errors — read the `error_description`
  to tell the two apart. The parser also fails closed on structural
  problems (malformed JSON-RPC, duplicate keys, oversized body, etc.)
  with a specific `rule_type` in the audit log. See the README's
  "Create a Policy" section for the full rule_type table.
- **Streamable HTTP / SSE flows through transparently.** Send
  `Accept: application/json, text/event-stream` and the server's
  choice of framing comes back unchanged. The `Mcp-Session-Id`
  response header round-trips automatically; subsequent client
  requests carrying it reach the same upstream session.
- **Session timeout is mount-wide.** The mount's `timeout` config
  caps an entire SSE session (default 10 minutes). For longer agent
  sessions, ask the operator to raise it.
- **Rate limits propagate from GitHub**. Warden does not retry; back
  off when you see GitHub-side rate limit responses.
- **Not in scope**: OAuth flows (Dynamic Client Registration, PRM
  discovery, `.well-known/oauth-protected-resource`), stdio transport,
  and legacy split-endpoint HTTP+SSE. Use the PAT path.
