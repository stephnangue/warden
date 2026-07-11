---
name: mcp_aws
description: "Talk to AWS-hosted MCP through Warden — without holding IAM keys. Your MCP client points at Warden under a role fixed at attach time (one attached server per role). Fronts both AWS's hosted MCP Server (aws-mcp.{region}.api.aws) and customer-owned MCP servers on Bedrock AgentCore."
category: provider-guide
provider: mcp_aws
requires: []
upstream: AWS-hosted MCP servers — the GA AWS MCP Server (aws-mcp.{region}.api.aws/mcp) and Bedrock AgentCore Runtime/Gateway endpoints
---

# AWS MCP through Warden

## What it does

Warden proxies MCP traffic to an AWS-hosted MCP endpoint, signing each outgoing
request with AWS SigV4 using IAM credentials minted by the `aws` source driver.
Your MCP client calls Warden **under a role**; Warden authenticates the caller
(JWT/cert), looks up the IAM role bound to that Warden role, mints short-lived
STS credentials, signs the upstream request with SigV4, and streams the response
(JSON or SSE) back unchanged. You **never hold IAM credentials** — no
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` on the host, no
`~/.aws/credentials` to leak.

## Your role — one attached server per role

Which **role** the call runs under decides which IAM role is assumed (and which
Warden policy applies). Your role is the `role/<role>/gateway` segment of the URL
this server was attached at — **fixed for this server**, and not changeable at
runtime (an MCP client sends fixed headers, and the role can't be passed in a
tool call). To act under a *different* role, call the MCP server the operator
attached for that role: the operator attaches **one server per role**, named or
described to match a `list_roles` entry.

## Attaching the client

The server is attached by the operator or your runtime (Claude Code
`claude mcp add`; Cursor/Continue/Cline/Goose take the same HTTP-server shape),
with your identity as a header — one attachment per role:

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR/v1/<namespace>/<mount>/role/<role>/gateway",
  "headers": { "Authorization": "Bearer <jwt>" }
}
```

**No trailing slash** on `gateway` — the opposite of GitHub's hosted MCP server.
AWS's hosted MCP Server lives at exactly `/mcp` and rejects `/mcp/` with a
JSON-RPC `-32600 Invalid request path`; Bedrock AgentCore follows the same
convention. A `401` means the JWT expired (typical TTL 5–60 min) — refresh it.

## Using it

- **`tools/list` is policy-filtered** to the active role's grant. For AWS's
  hosted MCP Server, every AWS API call goes through a single `call_aws` tool
  whose arguments select service, operation, and region:

  ```json
  {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_aws",
   "arguments":{"service_name":"s3","operation_name":"list_buckets",
   "region_name":"us-east-1","parameters":{}}}}
  ```

  `region_name` selects the target AWS region and is **independent** of the
  mount's signing region — a mount fronting `aws-mcp.us-east-1.api.aws/mcp` can
  still reach `eu-west-1` S3, as long as the bound IAM role's permissions cover
  it. For a Bedrock AgentCore server, the tools are whatever the customer's
  server exposes — discover them via `tools/list`.

## Quirks

- **The injected auth is AWS SigV4, not Bearer.** mcp_aws builds an
  `Authorization: AWS4-HMAC-SHA256 …` header per request (plus `X-Amz-Date`,
  `X-Amz-Content-Sha256`, and `X-Amz-Security-Token` for STS creds). Signing
  service/region derive from the upstream host — you don't need either.
- **IAM permissions determine which calls succeed.** The bound IAM role's policy
  is the security boundary. A `403` / `AccessDeniedException` from the upstream
  means the role lacks the permission for the target service/action/resource —
  ask the operator to widen it, don't switch Warden roles unless a broader one
  exists.
- **Warden policy can gate tools too — body-authoritative.** An operator may bind
  an `mcp { }` block restricting JSON-RPC methods, tool names, and `tools/call`
  arguments (including `service_name` / `operation_name` / `region_name`). A deny
  is HTTP 403 with an RFC 6750 `WWW-Authenticate: Bearer
  error="insufficient_permissions", error_description="..."` header naming the
  offender — **independent** of IAM `AccessDenied` (a native AWS error streamed
  back). Read the `error_description` to tell them apart. Structural problems
  (malformed JSON-RPC, duplicate keys, oversized body) also fail closed.
- **Streamable HTTP / SSE flows through transparently.** The `Mcp-Session-Id`
  response header round-trips so follow-up requests reach the same session.
- **Session timeout is mount-wide** (default 10 minutes); ask the operator to
  raise it for longer sessions.
- **STS credentials are short-lived.** A signed request is valid 15 minutes from
  `X-Amz-Date`; tool calls beyond that fail with a SigV4 expiration error rather
  than refreshing — restart the session for very long operations.
- **Rate limits propagate from AWS.** Warden does not retry; back off on
  `ThrottlingException` / `RequestLimitExceeded`. CloudTrail captures every call.
- **Not in scope:** client-initiated OAuth (DCR, PRM discovery), stdio transport,
  and anything requiring AWS's `mcp-proxy-for-aws` on the client — Warden
  replaces that proxy; the client speaks plain Streamable HTTP MCP to Warden.
