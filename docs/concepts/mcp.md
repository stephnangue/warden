# Model Context Protocol (MCP)

The **Model Context Protocol** is the JSON-RPC protocol an AI agent uses to talk
to an *MCP server* — to list and call its **tools**, read its **resources**, and
fetch its **prompts**. Warden fronts MCP servers the same way it fronts any other
upstream: the agent points its MCP client at a Warden mount as if it were the
server, and Warden authenticates the caller, **authorizes the individual
JSON-RPC call**, injects the upstream [credential](credentials.md), and proxies
the request — streaming the response back untouched.

What makes MCP special in Warden is the middle step. For most [providers](providers.md)
authorization is path-and-method; for MCP, Warden parses the JSON-RPC **body** and
decides per call which tool, resource, or prompt — with which arguments — the
agent may invoke. That is how you govern what an agent can actually *do* through a
server, not just whether it can reach it.

## The MCP Providers

Two providers front MCP servers; both proxy MCP over streamable HTTP (single JSON
responses and SSE both flow through, and the `Mcp-Session-Id` header round-trips):

- **`mcp`** — a generic MCP server reached over HTTP. Configured with the
  upstream `mcp_url`, it injects a **bearer token** (from the brokered credential)
  as `Authorization: Bearer …`.
- **`mcp_aws`** — AWS-hosted MCP servers (the AWS MCP endpoint and Bedrock
  AgentCore). Instead of a bearer header it **SigV4-signs** the request with the
  brokered AWS credentials.

Both are mounted and routed like any provider — see [Providers](providers.md) for
gateway paths and routing. One convention trips people up: the `mcp` skill's
client URL ends in a **trailing slash** (`…/gateway/`) while `mcp_aws` omits it
(`…/gateway`), because the AWS endpoint rejects a trailing slash. Warden routes
either shape; the convention exists to match what each upstream expects.

## Body-Authoritative Authorization

A policy path that fronts an MCP mount can carry an `mcp { }` block. When it does,
Warden **strict-parses** the JSON-RPC request body and evaluates each call against
the rules before the request reaches the upstream. The block's full field grammar
lives in [Policies → Authorizing Gateway Requests](policies.md#authorizing-gateway-requests);
this section explains the *semantics*.

Enforcement applies only to actual JSON-RPC calls — **`POST` with a JSON body**.
SSE reconnects (`GET`) and session teardown (`DELETE`) carry no call to authorize
and pass through under the path's capability check alone.

### Name-bearing methods

Three methods carry a name that the policy can gate; others are gated by method
only:

| Method | Gated name | From |
|--------|-----------|------|
| `tools/call` | the tool | `params.name` |
| `resources/read` | the resource | `params.uri` |
| `prompts/get` | the prompt | `params.name` |

### Evaluation order

Each call passes through gates in order; the first failure denies it:

1. **Method** — `denied_methods` then `allowed_methods`.
2. **Name** (for the three name-bearing methods) — `denied_tools`/`resources`/`prompts`
   then the matching `allowed_*` list.
3. **Parameters** (`tools/call` only) — `denied_params` then `allowed_params`,
   per argument key.

Within a gate, a `denied_*` match always rejects; an `allowed_*` list, if present,
means the value must match it. Patterns are matched with a **trailing `*`** wildcard
(`delete_*`, or a bare `*` for "anything"), case-insensitively. For parameters, an
`allowed_params` entry is conditional — *"if this argument is present, it must
match"* — and non-scalar argument values (objects, arrays, null) are treated as
absent, so they neither satisfy nor violate a string pattern.

### Batches and malformed bodies

- A JSON-RPC **batch** is all-or-nothing: if any call in the batch is denied, the
  whole batch is denied.
- The body is parsed **strictly**. A malformed JSON-RPC envelope, a duplicate key,
  an empty batch, or a body over the size cap is denied outright — recorded with a
  structural reason (`malformed_jsonrpc`, `duplicate_key`, `oversized_body`, …)
  distinct from a policy denial, so operators can tell bad input from a refused
  call.
- When more than one `mcp { }` block applies, they combine with **OR** (any block
  that allows, allows); on denial the **strongest reason** is surfaced — a
  structural failure outranks a policy refusal.

### What the agent sees on a denial

A denied call gets **HTTP 403** with a `WWW-Authenticate: Bearer …` header and a
short `error_description` naming the offending method, tool, or parameter
(e.g. *"Tool 'delete_database' not allowed."*). The message is deliberately
generic — it never reveals the shape of the policy or echoes raw body bytes — but
it tells the agent enough to correct course rather than guess at an opaque 403.

## Auditing MCP Decisions

Every consulted `mcp { }` block records its outcome to the [audit log](audit.md):
the `decision` (allow/deny), the `rule_type` that fired (`denied_tools`,
`allowed_params`, `duplicate_key`, …), the `method` and `name`, and the parameter
key/value when a param gate decided it. The decision is recorded on **both** allow
and deny, so the audit trail shows not just what was blocked but every tool call
that was permitted — a complete record of an agent's activity through the server.

## Using an MCP Mount

An agent points its MCP client at the mount's gateway URL and presents its
identity — a bearer credential (the JWT in `IDENTITY_TOKEN`, shown below) or an
mTLS client certificate on the TLS connection — which Warden resolves through
[transparent authentication](authentication.md#transparent-authentication):

```json
{
  "type": "http",
  "url": "$WARDEN_ADDR/v1/mcp/role/<role>/gateway/",
  "headers": { "Authorization": "Bearer $IDENTITY_TOKEN" }
}
```

The agent need not hold or attach that credential itself — a **sidecar** can
channel its identity to Warden (here a bearer JWT, so a tool like
[Robin](https://github.com/stephnangue/robin)), leaving the agent to speak plain
MCP to its local sidecar. See
[Channelling Identity with a Sidecar](authentication.md#channelling-identity-with-a-sidecar).

From there the agent uses MCP normally — `tools/list`, `tools/call`, and the rest
— while Warden injects the real upstream credential and applies the policy. As
with every mount, the agent finds the right one by its description, not its type
(see [Discovery and Skills](discovery-and-skills.md)); each provider also ships a
skill that documents its quirks.

## See Also

- [Policies](policies.md) — the full `mcp { }` rule grammar.
- [Providers](providers.md) — how MCP mounts are enabled and routed.
- [Credentials](credentials.md) — the bearer token or AWS credential injected.
- [Audit](audit.md) — where each MCP decision is recorded.
- [Discovery and Skills](discovery-and-skills.md) — how an agent finds an MCP mount.
