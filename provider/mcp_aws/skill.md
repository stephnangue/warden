---
name: mcp_aws
description: "Talk to AWS-hosted MCP through Warden — without holding IAM keys. Use any MCP client (Claude Code, Cursor, ...) by pointing it at Warden; tools and JSON/SSE responses pass through unchanged. Fronts both AWS's hosted MCP Server (aws-mcp.{region}.api.aws) and customer-owned MCP servers on Bedrock AgentCore."
category: provider-guide
provider: mcp_aws
requires: [foundation, discovery]
upstream: AWS-hosted MCP servers — the GA AWS MCP Server (aws-mcp.{region}.api.aws/mcp) and Bedrock AgentCore Runtime/Gateway endpoints
---

# AWS MCP through Warden

## What it does

Warden proxies MCP traffic to an AWS-hosted MCP endpoint, signing each
outgoing request with AWS SigV4 using IAM credentials minted by the
`aws` source driver. The MCP client calls a Warden URL; Warden
authenticates the caller (JWT/cert), looks up the IAM role bound to the
chosen Warden role, mints short-lived STS credentials, signs the
upstream request with SigV4, and streams the response (JSON or SSE)
back unchanged. The agent **never holds IAM credentials** — no
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` on the agent host, no
`~/.aws/credentials`, no profile to leak.

## Pick the right mount

A single `mcp_aws` mount fronts exactly one upstream — either AWS's
hosted MCP Server product, or a customer-owned MCP server on Bedrock
AgentCore Runtime / Gateway. When more than one `mcp_aws` mount exists,
**match by the operator-set mount description**, not by inspecting the
upstream URL. The description reflects what the operator intends the
mount to be used for (which IAM role, which region, which AgentCore
server); the URL is a backend detail that may change without semantic
meaning.

```bash
warden provider list -o json | jq -r '.[] | select(.type=="mcp_aws") | "\(.path)\t\(.description)"'
```

Pick the mount whose description matches your task. If none of the
descriptions cover what you need, ask the operator to mount one — do
not pick the first mcp_aws mount by URL pattern alone.

## Configure the MCP client

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/mcp_aws/`,
  `/v1/team-data/mcp_aws/`). Warden has already baked the namespace
  and mount path in.
- `<role>` is the role you picked from `warden role list` to perform
  this task — it goes in the URL path.

```
MCP server URL : $WARDEN_ADDR<mount-url>role/<role>/gateway
Auth header    : Authorization: Bearer $WARDEN_TOKEN
```

Note **no trailing slash** on `gateway` — this is the opposite of
GitHub's hosted MCP server. AWS's hosted MCP Server lives at exactly `/mcp` and
rejects requests to `/mcp/` with a JSON-RPC `-32600 Invalid request
path` error. Bedrock AgentCore endpoints follow the same convention.

For MCP client configuration files, the entry looks like (Claude Code
/ Cursor / Continue / Cline / Goose all accept this shape):

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR<mount-url>role/<role>/gateway",
  "headers": {
    "Authorization": "Bearer $WARDEN_TOKEN"
  }
}
```

Substitute `$WARDEN_ADDR`, `<mount-url>`, `<role>`, and `$WARDEN_TOKEN`
before saving — most MCP clients do not expand environment variables
inside config files.

## Examples

(All examples below assume `mount_url = /v1/mcp_aws/` and role
`s3-reader`; substitute yours from `warden provider list`.)

List the tools the server exposes:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  $WARDEN_ADDR/v1/mcp_aws/role/s3-reader/gateway
```

Call a tool (the operator must grant a role whose IAM permissions cover
the requested AWS operation — see Quirks below). For AWS's hosted MCP
Server, every AWS API call goes through a single `call_aws` tool whose
arguments select the service, operation, and target region:

```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_aws","arguments":{"service_name":"s3","operation_name":"list_buckets","region_name":"us-east-1","parameters":{}}}}' \
  $WARDEN_ADDR/v1/mcp_aws/role/s3-reader/gateway
```

The `region_name` inside the tool arguments selects which AWS region's
API to call — this is **independent** of the mount's signing region.
A mount fronting `aws-mcp.us-east-1.api.aws/mcp` can still reach
`eu-west-1` S3, `ap-southeast-2` DynamoDB, etc., as long as the bound
IAM role's permissions cover those operations.

For a Bedrock AgentCore-hosted MCP server, the available tools depend
on what the customer's server exposes — discover them via `tools/list`
and call them with their published argument shapes.

The **absence** of a trailing slash on `gateway` matters — Warden
composes the upstream URL as the mount's configured base + whatever
follows `gateway` in the request. AWS's hosted MCP Server requires
`/mcp` exactly; `/mcp/` returns JSON-RPC `-32600 Invalid request path`.
(This is the opposite convention from GitHub's hosted MCP server, which
requires the trailing slash on `/mcp/`.)

## Header-routed alternative

If you prefer an MCP server URL that is just `$WARDEN_ADDR/` (some MCP
clients dislike long paths, or you want to mux several MCP providers
under one base URL), pass the mount path as `X-Warden-Provider` and the
namespace as `X-Warden-Namespace`:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_aws" and .description=="<the description you want>") | .path' | head -1)

curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "X-Warden-Provider: $path" \
  -H "X-Warden-Namespace: $WARDEN_NAMESPACE" \
  -H "X-Warden-Role: s3-reader" \
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

When more than one `mcp_aws` mount exists, the `jq` filter above keys
on `.description` — the same rule as "Pick the right mount" above.

## Quirks

- **The injected auth is AWS SigV4, not Bearer.** Unlike the generic `mcp`
  provider, which injects `Authorization: Bearer <token>`, mcp_aws builds an
  `Authorization: AWS4-HMAC-SHA256 Credential=…/{date}/{region}/{service}/aws4_request,SignedHeaders=…,Signature=…`
  header per request along with `X-Amz-Date`, `X-Amz-Content-Sha256`,
  and (for STS-minted credentials) `X-Amz-Security-Token`. The signing
  service and region are derived from the upstream URL host — agents
  don't need to know either.
- **IAM permissions determine which calls succeed.** The bound IAM
  role's policy is the security boundary. A `403` or
  `AccessDeniedException` from the upstream means the role lacks the
  required permission for the target service / action / resource.
  Operators provision IAM roles whose permissions cover the intended
  toolset; agents hitting `AccessDenied` should ask the operator to
  widen the role's policy, not try a different Warden role unless one
  exists.
- **Warden policy can gate tools too — body-authoritative.** Operators
  may bind a policy with an `mcp { }` block that restricts JSON-RPC
  methods, tool names, resource URIs, prompt names, and `tools/call`
  arguments (including the `service_name` / `operation_name` /
  `region_name` keys the AWS MCP Server's `call_aws` tool reads).
  Warden strict-parses the JSON-RPC request body and matches against
  the parsed body — no client-side opt-in or header mirroring required.
  A deny shows up as HTTP 403 with an RFC 6750
  `WWW-Authenticate: Bearer error="insufficient_permissions", error_description="..."`
  header and a small JSON body of the same shape; the description
  names the offending method/tool/parameter. This is **independent**
  of IAM `AccessDenied` errors, which surface as native AWS error
  responses streamed back from the upstream — read the
  `error_description` to tell the two apart. The strict parser also
  fails closed on structural problems (malformed JSON-RPC, duplicate
  keys, oversized body, etc.) with a specific `rule_type` in the audit
  log. See the README's "Create a Policy" section for the full
  rule_type table.
- **Streamable HTTP / SSE flows through transparently.** Send
  `Accept: application/json, text/event-stream` and the server's
  choice of framing comes back unchanged. The `Mcp-Session-Id`
  response header round-trips automatically; subsequent client
  requests carrying it reach the same upstream session.
- **Session timeout is mount-wide.** The mount's `timeout` config
  caps an entire SSE session (default 10 minutes). For longer agent
  sessions, ask the operator to raise it.
- **The mount's region is the *signing* region, not a restriction on
  AWS region of API calls.** AWS's MCP Server can call any region's
  APIs; the agent picks the target region via `region_name` inside
  the tool arguments. A second mount is only needed when the operator
  specifically wants the MCP server itself in another region — for
  latency, data sovereignty, or failover.
- **AgentCore-hosted MCP servers expose different tool shapes.** When
  the upstream is `*.bedrock-agentcore.{region}.amazonaws.com`, the
  available tools and their argument schemas come from whatever the
  customer-owned server exposes — discover via `tools/list`. The
  `call_aws` example above is specific to AWS's hosted MCP Server
  product.
- **STS credentials are short-lived.** The bound IAM role's STS
  session duration caps how long any individual MCP request can take
  end-to-end on the signing side. The signed request is valid for 15
  minutes from `X-Amz-Date`; long-running tool calls beyond that
  window will fail with a SigV4 expiration error rather than a token
  refresh. Restart the MCP session for very long operations.
- **Rate limits propagate from AWS.** Warden does not retry; back off
  when you see `ThrottlingException` / `RequestLimitExceeded` from
  AWS. CloudTrail captures every call for audit.
- **Not in scope**: OAuth flows (Dynamic Client Registration, PRM
  discovery), stdio transport, and any path that requires running
  AWS's `mcp-proxy-for-aws` on the client side. Warden replaces that
  proxy; the client just speaks plain Streamable HTTP MCP to Warden.
