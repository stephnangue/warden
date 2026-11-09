---
title: "Model Context Protocol (MCP)"
---

The **Model Context Protocol** is the JSON-RPC protocol an AI agent uses to talk
to an *MCP server* — to list and call its **tools**, read its **resources**, and
fetch its **prompts**. Warden fronts MCP servers the same way it fronts any other
upstream: the agent points its MCP client at a Warden mount as if it were the
server, and Warden authenticates the caller, **authorizes the individual
JSON-RPC call**, injects the upstream [credential](/concepts/credentials/), and proxies
the request — streaming the response back untouched, except that a **list**
method's response is pruned to the items the caller is allowed to use (below).

What makes MCP special in Warden is the middle step. For most [providers](/concepts/providers/)
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

Both are mounted and routed like any provider — see [Providers](/concepts/providers/) for
gateway paths and routing. One convention trips people up: the `mcp` skill's
client URL ends in a **trailing slash** (`…/gateway/`) while `mcp_aws` omits it
(`…/gateway`), because the AWS endpoint rejects a trailing slash. Warden routes
either shape; the convention exists to match what each upstream expects.

## Body-Authoritative Authorization

MCP traffic is governed by its own **policy type**, stored at
`sys/policies/mcp/<name>` and written with `-type mcp`. Where a
[capability policy](/identity/policies/) governs paths and operations, an MCP
policy governs *calls*: Warden **strict-parses** the JSON-RPC request body and
evaluates each call against the rules before the request reaches the upstream.

```bash
warden policy write -type mcp github-tools - <<'EOF'
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["get_*", "list_*"]
    denied  = ["delete_*"]
  }
}
EOF
```

The two types compose as an **intersection**: a request must be granted by a
capability policy **and** permitted by every MCP policy in scope. An MCP policy is
purely restrictive — it can never grant access a capability policy withholds.

An MCP policy comes into scope exactly the way a capability policy does: by being
named in the [role](/identity/roles/)'s `policies`. Policy names are unique across
both types, so one list carries both:

```bash
warden role create mcp-user -json '{
  "description": "read GitHub through the MCP server",
  "policies": ["github-paths", "github-tools"],
  "provider_path": "mcp/"
}'
```

A [group](/identity/groups/) then grants the role to the callers who may use it.

Forgetting the MCP policy is the common first mistake — the role still grants the
path, but every call is denied with `no_mcp_policy`. MCP traffic on a path with no
MCP policy in scope is always denied: a mount meant to stay open needs an explicit
wildcard policy.

Enforcement applies only to actual JSON-RPC calls — **`POST` with a JSON body**.
SSE reconnects (`GET`) and session teardown (`DELETE`) carry no call to authorize
and pass through under the capability policy alone.

### Name-bearing methods

Six methods carry a name that the policy can gate; others are gated by method only:

| Method | Gated name | From | Family |
|--------|-----------|------|--------|
| `tools/call` | the tool | `params.name` | `tools` |
| `resources/read` | the resource | `params.uri` | `resources` |
| `resources/subscribe` | the resource | `params.uri` | `resources` |
| `resources/directory/read` | the directory | `params.uri` | `resources` |
| `skills/get` | the skill's `SKILL.md` | `params.uri` | `resources` |
| `prompts/get` | the prompt | `params.name` | `prompts` |

`subscriptions/listen` is gated too: each URI it subscribes to is checked against the
`resources` lists, so a caller denied `resources/read` on a URI cannot reach the same
data through update-timing signals instead.

#### Skills

The MCP Skills extension builds skills on resources: a skill is addressed by the
URI of its `SKILL.md`, and `resources/directory/read` lists the files under a
directory URI. So `skills/get` and `resources/directory/read` answer to the
`resources` block, exactly as `resources/read` does, deny-by-default included. A
contract with `methods { allowed = ["*"] }` and no `resources` block refuses both;
grant the resources to open them:

```hcl
path "mcp/gateway/*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["skill://*"] }
}
```

To let a caller fetch one skill and browse its files, grant its folder and its
root:

```hcl
path "mcp/gateway/*" {
  methods {
    allowed = ["skills/list", "skills/get", "resources/read", "resources/directory/read"]
  }
  resources {
    allowed = ["skill://pdf-processing", "skill://pdf-processing/*"]
  }
}
```

The extension writes a skill's root directory with no trailing slash
(`skill://pdf-processing`), and a trailing `*` is a prefix match, so
`skill://pdf-processing/*` does not cover the root: browsing it needs the literal.
`skill://pdf-processing*` would also match `skill://pdf-processing-evil/…`.

Grant a skill by its folder rather than its `SKILL.md` alone. A `skills/get`
allowed by an exact `skill://<name>/SKILL.md` grant still returns the skill's full
file list, with each file's URI, digest and size, because the extension requires
that list complete.

### Evaluation order

Authorization is **deny-by-default**, at two levels. A path with no MCP policy in
scope denies every call (`no_mcp_policy`); within a policy, each family block
grants nothing until it allow-lists something. Each call passes through gates in
order, and the first failure denies it:

1. **Method** — `methods { denied }` rejects first; then the method must appear in
   `methods { allowed }`. An empty or absent `allowed` matches nothing and so
   **denies every method**. *Exception:* the session-lifecycle methods
   `initialize`, `ping`, `notifications/*`, and `server/discover` are exempt from
   the allow-list — they carry no tool/resource/data access and must work for the
   handshake and discovery — but a `denied` entry can still block them explicitly.
2. **Name** (for the six name-bearing methods) — the matching
   `tools` / `resources` / `prompts` block's `denied` rejects first; then the name
   must appear in its `allowed`. An empty or absent list **denies every name**.
3. **Condition** (CEL) — the stanza's per-call `condition`, if present, runs last
   and gates on argument values (`call.args`).

Within a gate a `denied` match always rejects, and the value must then match the
corresponding `allowed` list — which is **mandatory** under deny-by-default.
Patterns are matched with a **trailing `*`** wildcard (`delete_*`, or a bare `*`
for "anything"), case-insensitively. To open a mount fully, allow-list `["*"]`:

```hcl
# fully open (the explicit form of "no restriction")
path "mcp/gateway/*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["*"] }
  prompts   { allowed = ["*"] }
}

# read-only: list and call get_*/list_* only; delete_* is never callable
path "mcp/gateway/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools   { allowed = ["get_*", "list_*"] }
}
```

Argument-value constraints are expressed in the per-call `condition` (below), not
as structured lists.

### Filtering list responses

The gates above decide whether a *call* is allowed. Warden also applies them to
what an agent can *discover*: when a list request is allowed, Warden prunes the
response so it lists only the items the caller could actually use:

| List method | An item survives iff this would pass |
|---|---|
| `tools/list` | `tools/call` for the tool |
| `resources/list` | `resources/read` of the resource |
| `prompts/list` | `prompts/get` for the prompt |
| `skills/list` | `skills/get` for the skill's `SKILL.md` URI |
| `resources/directory/read` | `resources/read` of the child |

Under deny-by-default this means a mount whose `tools` block allows nothing
returns an **empty** tools list, and one scoped to `get_*` lists only those. A
contract that allows `resources/directory/read` but not `resources/read` lists an
empty directory, as `tools/list` without `tools/call` lists no tools. A
`skills/list` entry is kept or dropped whole: a kept skill's file list is never
trimmed, since a client checks it against the skill. Discovery matches
enforcement: what the agent sees is what it can call.

Per-call CEL `condition`s are *not* evaluated during filtering — a list carries
no arguments — so a condition-gated tool still appears in the list and its
arguments are checked when it is actually called. A batched JSON-RPC request
that contains any of these list methods is denied (`batch_list_unfilterable`): a
batched list response can't be pruned per element, so Warden fails closed rather
than return an unfiltered list.

Two known limits: `resources/templates/list`, and `completion/complete` on a
`skill://` template, are gated by method only, and can reveal skill paths.

### Per-call CEL conditions

A `path` stanza in an MCP policy can carry a **`condition`** — a
[CEL](https://cel.dev) expression evaluated **once per call**, after the
structured gates above. The call is allowed only if its structured gates *and*
its condition pass. It is the expressive escape hatch for value logic the lists
can't express — per-tool budgets, currency sets, cross-argument rules:

```hcl
path "mcp/payments/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["create_payment", "refund"] }
  condition = <<-CEL
    (call.tool == 'create_payment' ? call.args.amount <= 1500 :
     call.tool == 'refund'         ? call.args.amount <=  200 : true)
    && call.args.currency in ['USD', 'EUR']
  CEL
}
```

The condition reads a per-call namespace on top of the `request`, `agent` and `user`
namespaces documented in the
[CEL Condition Cookbook](/identity/cel-conditions/#quick-reference):

- `call.method` — the JSON-RPC method (`tools/call`, …)
- `call.tool` — the name-bearing field: the tool or prompt name, or the URI for
  `resources/read`, `resources/subscribe`, `resources/directory/read` and
  `skills/get`
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
- When more than one MCP policy applies, their stanzas combine with **OR** (any
  that allows, allows); on denial the **strongest reason** is surfaced — a
  structural failure outranks a policy refusal. Note this ORs *within* the MCP
  layer; the MCP layer as a whole still intersects with the capability policy.

### What the agent sees on a denial

A denied call gets **HTTP 403** with a `WWW-Authenticate: Bearer …` header, and a
body that is a **JSON-RPC error** for the call it refuses:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32090,
    "message": "Warden: Tool 'delete_database' not allowed.",
    "data": {
      "error": "insufficient_permissions",
      "error_description": "Tool 'delete_database' not allowed.",
      "request_id": "…"
    }
  }
}
```

The error echoes the call's `id`, so the MCP client fails that one call and keeps
its session: the next call goes through. `-32090` is Warden's own code for a
refusal, by policy or for want of a valid identity, and retrying the same call
fails the same way. A batch or a notification has no single `id` to echo, so its
refusal carries `"id": null`.

The description names the offending method, tool, or parameter. It is
deliberately generic — it never reveals the shape of the policy or echoes raw body
bytes — but it tells the agent enough to correct course rather than guess at an
opaque 403.

Policy applies to **every `POST`** to an MCP mount, whatever its `Content-Type`:
the body goes to the strict JSON-RPC parser regardless of label, so relabelling a
`tools/call` as `text/plain`, or sending it with no `Content-Type`, does not
slip it past the rules. `GET` and `DELETE`, which carry no JSON-RPC method, are
left to the capability policy.

## Denial reasons

Every decision records a `rule_type` in the [audit log](/concepts/audit/). Policy
`rule_type`s name which gate fired; structural ones name a strict-parse failure,
distinct from a policy refusal so operators can tell bad input from a governed
denial:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read`, `resources/subscribe`, `resources/directory/read` or `skills/get` with a `params.uri` matching a deny pattern, or not in the allow list — also applied per URI when `subscriptions/listen` subscribes |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `no_mcp_policy` | MCP traffic reached a path with **no MCP policy in scope** |
| `header_mismatch` | MCP transport headers contradict, or fail to describe, the body Warden parsed — for example an `Mcp-Name` that disagrees with the name or URI in the body, on any name-bearing method. `Mcp-Name` is required only on `tools/call`, `resources/read` and `prompts/get`, but one that is sent is always checked. Structural rather than a policy decision — no contract was consulted, and none can permit it |
| `missing_method_header` | A legacy sentinel for a transport that declared no method. Effectively unreachable on the body-authoritative path, where `header_mismatch` covers transport contradictions |
| `batch_unsupported` | A batch arrived from a client negotiating a modern protocol revision, where batching left the spec |
| `batch_list_unfilterable` | A batch contains a list method (`tools/list`, `resources/list`, `prompts/list`, `skills/list`, `resources/directory/read`); a batched list response cannot be pruned per element, so Warden fails closed rather than return an unfiltered list |
| `missing_body` | A `POST` body is absent or fails to parse on a path with MCP enforcement. Every `POST` is evaluated, whatever its `Content-Type`; body-less verbs (`GET` SSE stream, `DELETE` session terminate) skip MCP evaluation entirely |
| `malformed_jsonrpc` | Body is not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, …) |
| `duplicate_key` | Duplicate object key anywhere in the body — Warden rejects the ambiguity a last-wins parser would hide |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `batch_too_large` | A batch to Warden's own discovery server carries more than 50 messages |
| `malformed_params` | A name-bearing method (`tools/call`, `resources/read`, `resources/subscribe`, `resources/directory/read`, `skills/get`, `prompts/get`) has a missing or wrong-shape `params.name` / `params.uri`, or `subscriptions/listen` has malformed subscription params |

## Auditing MCP Decisions

Every consulted MCP policy stanza records its outcome to the [audit log](/concepts/audit/):
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
interface lives at `/v1/sys/mcp` in every namespace and takes no role: it
authorizes on the identity the agent presents (a bearer JWT, an mTLS client
certificate, or a person's ticket). A caller in a sub-namespace selects it with
the `X-Warden-Namespace` header or by path (`/v1/<namespace>/sys/mcp`).

It is served through the request path like any other path, and every call is
audited. The namespace's built-in policies authorize it: `default-cbp` grants the
path, and `default-mcp` is its MCP contract, under the same gates as above.
Lifecycle methods, `tools/list`, `resources/templates/list`, `logging/setLevel`
and `subscriptions/listen` need no credential; every other call answers `401`
without one. Unlike a gateway, it filters lists inside a batch call by call, and
refuses a batch of more than 50 messages. See
[Discovery and Skills](/concepts/discovery-and-skills/#every-call-is-authorized-and-audited).

It exposes two tools:

- **`list_roles`** — the roles [groups](/identity/groups/) grant the caller's
  identity. This is the agent's menu (see [Roles](/identity/roles/)). Each
  role comes with its operator-written **description**, the **provider** type it
  is used with, its **skill** as a `skill://<name>/SKILL.md` URI, and the **url**
  to call it at, relative to the Warden address. Warden derives the last three
  from the role's `provider_path` and `skill` fields.
- **`read_skill`** — given a role's `skill` URI, returns that **skill**: the
  markdown recipe that teaches the agent how to drive the provider.

The same skills are served through the MCP Skills extension (`skills/list`,
`skills/get`, and `resources/read` on `skill://` URIs), and an identity can read
only the skills its roles lead to. See
[Discovery and Skills](/concepts/discovery-and-skills/#skill-reads-are-identity-bound).

The loop, then, is: connect to `/v1/sys/mcp` → `list_roles` to see the menu → pick
the role whose description fits → `read_skill` on its `skill` URI to learn how to
drive it → do the work. The role a request runs as is the `role/<role>/` segment
of its gateway URL. For an MCP provider that gateway is already attached to the
agent's MCP client — one attachment per role, so the agent picks the attached
server whose role fits; a non-MCP provider is called over HTTP at the role's
`url`, and another role means another URL. The discovery interface only *tells*
the agent what it can do — the work still flows through the gateways described
above.

## Using an MCP Mount

An agent points its MCP client at the mount's gateway URL and presents its
identity — a bearer credential (the JWT in `IDENTITY_TOKEN`, shown below) or an
mTLS client certificate on the TLS connection — which Warden resolves through
[transparent authentication](/identity/authentication/):

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
[Channelling Identity with a Sidecar](/identity/authentication/).

From there the agent uses MCP normally — `tools/list`, `tools/call`, and the rest
— while Warden injects the real upstream credential and applies the policy. As
with every mount, the agent finds the right one by its description, not its type
(see [Discovery and Skills](/concepts/discovery-and-skills/)); each provider also ships a
skill that documents its quirks.

## See Also

- [Policies](/identity/policies/) — capability policies, and how they intersect with MCP policies.
- [Providers](/concepts/providers/) — how MCP mounts are enabled and routed.
- [Credentials](/concepts/credentials/) — the bearer token or AWS credential injected.
- [Audit](/concepts/audit/) — where each MCP decision is recorded.
- [Discovery and Skills](/concepts/discovery-and-skills/) — how an agent finds an MCP mount.
- [Roles](/identity/roles/) — the discovery loop `list_roles`/`read_skill` mirrors, one role per step.
