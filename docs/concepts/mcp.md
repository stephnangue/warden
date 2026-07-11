# Model Context Protocol (MCP)

The **Model Context Protocol** is the JSON-RPC protocol an AI agent uses to talk
to an *MCP server* — to list and call its **tools**, read its **resources**, and
fetch its **prompts**. Warden fronts MCP servers the same way it fronts any other
upstream: the agent points its MCP client at a Warden mount as if it were the
server, and Warden authenticates the caller, **authorizes the individual
JSON-RPC call**, injects the upstream [credential](credentials.md), and proxies
the request — streaming the response back untouched, except that a **list**
method's response is pruned to the items the caller is allowed to use (below).

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

Authorization is **deny-by-default**: an `mcp { }` block grants nothing until you
allow-list it. Each call passes through gates in order; the first failure denies it:

1. **Method** — `denied_methods` rejects first; then the method must appear in
   `allowed_methods`. An empty or absent `allowed_methods` matches nothing and so
   **denies every method**. *Exception:* the session-lifecycle methods
   `initialize`, `ping`, and `notifications/*` are exempt from the allow-list —
   they carry no tool/resource/data access and must work for the handshake — but
   `denied_methods` can still block them explicitly.
2. **Name** (for the three name-bearing methods) — `denied_tools`/`resources`/`prompts`
   rejects first; then the name must appear in the matching `allowed_*` list. An
   empty or absent list **denies every name**.
3. **Condition** (CEL) — the block's per-call `condition`, if present, runs last
   and gates on argument values (`call.args`).

Within a name/method gate a `denied_*` match always rejects, and the value must
then match the corresponding `allowed_*` list — which is **mandatory** under
deny-by-default. Patterns are matched with a **trailing `*`** wildcard
(`delete_*`, or a bare `*` for "anything"), case-insensitively. To open a mount
fully, allow-list `["*"]`:

```hcl
# fully open (the explicit form of "no restriction")
mcp {
  allowed_methods   = ["*"]
  allowed_tools     = ["*"]
  allowed_resources = ["*"]
  allowed_prompts   = ["*"]
}

# read-only: list and call get_*/list_* only; delete_* is never callable
mcp {
  allowed_methods = ["tools/list", "tools/call"]
  allowed_tools   = ["get_*", "list_*"]
}
```

Argument-value constraints are expressed in the per-call `condition` (below), not
as structured lists.

### Filtering list responses

The gates above decide whether a *call* is allowed. Warden also applies them to
what an agent can *discover*: when a `tools/list`, `resources/list`, or
`prompts/list` request is allowed, Warden prunes the response so it lists only
the items the caller could actually use — an item survives iff a `tools/call`
(resp. `resources/read`, `prompts/get`) for it would pass the gates. Under
deny-by-default this means a mount with no `allowed_tools` returns an **empty**
tools list, and one scoped to `get_*` lists only those. Discovery matches
enforcement: what the agent sees is what it can call.

Per-call CEL `condition`s are *not* evaluated during filtering — a list carries
no arguments — so a condition-gated tool still appears in the list and its
arguments are checked when it is actually called. A batched JSON-RPC request
that contains a list method is denied (`batch_list_unfilterable`): a batched
list response can't be pruned per element, so Warden fails closed rather than
return an unfiltered list.

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

## Warden as an MCP Server (Discovery Interface)

Everything above is about Warden **fronting** an upstream MCP server. Warden also
answers MCP for **its own** capabilities, so an agent can discover what it is
allowed to do *before* it picks a role and touches a gateway. This discovery
interface lives at a dedicated, always-on endpoint — `/v1/sys/mcp` — and needs no
role: it authorizes on the identity the agent presents (a bearer JWT or an mTLS
client certificate), exactly like the rest of Warden's introspection. A caller in
a sub-namespace selects it with the usual `X-Warden-Namespace` header.

It exposes two tools:

- **`list_roles`** — the roles the caller's identity can assume, each with its
  operator-written **description**. This is the agent's menu (see
  [Roles → Discovery](roles.md#discovery-what-roles-can-i-assume)). By convention
  the operator embeds the **skill name** in the description — e.g.
  *"search & read any repo (skill: github)"* — and, for a **non-MCP** provider,
  the role's **gateway URL** as well — e.g.
  *"read app secrets (skill: vault, url: /v1/vault/role/read-secret/gateway/)"*.
  The agent reads these verbatim.
- **`get_skill`** — given a **skill name** (the one just read out of a role
  description), returns that **skill**: the markdown recipe that teaches the agent
  how to drive the provider.

The loop, then, is: connect to `/v1/sys/mcp` → `list_roles` to see the menu → read
the chosen role's skill name (and, for a non-MCP provider, its gateway URL) from
the description → `get_skill` to learn how to drive it → do the work. The role a
request runs as is the `role/<role>/` segment of its gateway URL. For an MCP
provider that gateway is already attached to the agent's MCP client — one
attachment per role, so the agent picks the attached server whose role fits; a
non-MCP provider is called over HTTP at the role's gateway URL from the
description, and another role means another URL. The discovery interface only
*tells* the agent what it can do — the work still flows through the gateways
described above.

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
- [Roles](roles.md) — the discovery loop `list_roles`/`get_skill` mirrors, one role per step.
