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
3. **Condition** (CEL) — the block's per-call `condition`, if present, runs last
   and gates on argument values (`call.args`).

Within a name/method gate, a `denied_*` match always rejects; an `allowed_*`
list, if present, means the value must match it. Patterns are matched with a
**trailing `*`** wildcard (`delete_*`, or a bare `*` for "anything"),
case-insensitively. Argument-value constraints are expressed in the per-call
`condition` (below), not as structured lists.

### Per-call CEL conditions

An `mcp { }` block can carry a **`condition`** — a [CEL](https://cel.dev)
expression evaluated **once per call**, after the structured gates above. The
call is allowed only if its structured gates *and* its condition pass. It is the
expressive escape hatch for value logic the lists can't express — per-tool
budgets, currency sets, cross-argument rules:

```hcl
mcp {
  allowed_methods = ["tools/call"]
  allowed_tools   = ["create_payment", "refund"]
  condition       = <<-CEL
    (call.tool == "create_payment" ? call.args.amount <= 1500 :
     call.tool == "refund"         ? call.args.amount <=  200 : true)
    && call.args.currency in ["USD", "EUR"]
  CEL
}
```

The condition reads a per-call namespace on top of the request/token namespaces
documented in [Policies → Fine-grained access](policies.md#fine-grained-access)
(worked examples in the [CEL Condition Cookbook](cel-conditions.md)):

- `call.method` — the JSON-RPC method (`tools/call`, …)
- `call.tool` — the name-bearing field (tool/resource/prompt name)
- `call.args.<key>` — `tools/call` arguments, typed from the body
- `call.batch_index` — the call's position in a batch

The same **fail-closed** rules apply: a `false` result *or* an error (reading an
absent argument, a type mismatch) denies. Because the condition is **set-wide**
— evaluated for *every* method the block governs — a condition that reads
`call.args` will deny an argument-less method like `tools/list` the same block
allows. Scope it with `call.method` when a block governs more than `tools/call`:

```hcl
condition = "call.method != 'tools/call' || call.args.amount <= 1500"
```

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
`allowed_methods`, `duplicate_key`, `condition`, `condition_error`, …), the
`method` and `name`. When a `condition` decided the call, a `condition` object
records the expression and (on a fail-closed error) a sanitized error category.
The decision is recorded
on **both** allow and deny, so the audit trail shows not just what was blocked
but every tool call that was permitted — a complete record of an agent's activity
through the server.

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
