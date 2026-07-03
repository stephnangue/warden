# CEL Condition Cookbook

A CBP policy grants access in two layers. The **structural** layer — `capabilities`
and the MCP method/tool allow-lists — decides *which rule applies* and *what it
permits* without seeing a concrete request. The **condition** layer refines that
grant with a [Google CEL](https://cel.dev) expression evaluated against the actual
request: values, network and time context, and the caller's verified identity.

A `condition` can appear in two places:

- **Path level** — inside a `path { }` block, evaluated once per request against
  `request.*`, `token.*`, and `now`.
- **Per call** — inside an `mcp { }` block, evaluated once per MCP tool call with
  the additional `call.*` namespace (see [MCP](mcp.md)).

The rule passes only if its structural gates pass **and** its condition evaluates
to `true`. Evaluation is **fail-closed**: `false`, a type mismatch, or reading an
absent key all deny.

This page is a cookbook. For the full semantics — the activation contract, cost
bounds, the two-environment rule, how inputs are recorded in the audit log — see
[Policies → Fine-grained access](policies.md#fine-grained-access).

## Quick reference

The expression reads from a fixed set of namespaces:

| Namespace | Fields |
| --- | --- |
| `request` | `path`, `operation`, `client_ip`, `mount_point`, `mount_type`, `mount_class`, `mount_accessor`, `transparent`, `namespace`, `data.<key>` |
| `token` | `principal`, `role`, `type`, `namespace`, `policies` (list), `metadata.<key>`, `actors` (list of `{subject, verified}`), `ttl_seconds`, `expires_at` |
| `now` | the request timestamp |
| `call` | `method`, `tool`, `args.<key>`, `batch_index` — **`mcp { }` only** |

Values you will reference often:

- `request.operation` — one of `read`, `create`, `update`, `delete`, `list`,
  `scan`, `patch`. (For an MCP gateway POST it is always `update`; gate on
  `call.tool` instead.)
- `token.type` — the authenticating method: `spiffe_role`, `cert_role`,
  `jwt_role`, or `kubernetes_role`.
- `request.mount_class` — `provider`, `auth`, `audit`, `system`, or `ns_system`.
- `token.namespace` / `request.namespace` — a namespace path, `""` for root or
  `"team-a/"` / `"team-a/team-b/"` (trailing slash) for children. `token.namespace`
  is where the token was **minted**; `request.namespace` is the namespace the
  request **targets**.

Functions available: the CEL standard library (`has()`, `size()`, `in`,
`startsWith()`/`endsWith()`/`contains()`, `all()`/`exists()`, the `? :` ternary),
optional access `x.?field.orValue(default)`, timezone-aware
`now.getHours(tz)` / `now.getDayOfWeek(tz)` (0 = Sunday) / `now.getMinutes(tz)`,
and Warden's `cidrContains(cidr, ip)`.

> **Three rules that bite.** *Fail-closed* — any error or `false` denies, so a
> missing key denies unless you guard it. *Runtime typing* — `request.data.amount`
> is compared as the type it arrived as; the string `"1000"` does **not** satisfy
> `> 1000`, it denies. *Absent-is-OK* — when a missing field should pass, use
> `has(...)` or `x.?field.orValue(default)` rather than a bare reference.

---

## Body value guards

### 1. Cap a numeric field

Bound a value in the request body — e.g. an LLM token budget:

```hcl
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "update"]
  condition    = "request.data.max_tokens <= 4096"
}
```

### 2. Pin to an allowlist

Restrict a field to an approved set:

```hcl
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "update"]
  condition    = "request.data.model in ['claude-sonnet-4-5', 'claude-opus-4-1']"
}
```

### 3. Require a field to be present

Force callers to supply a value (absent → deny):

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "has(request.data.justification)"
}
```

### 4. Optional field with a safe default

Cap a field *if present*, but allow the request when it is omitted:

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "request.data.?ttl_seconds.orValue(0) <= 3600"
}
```

### 5. Closed key set

Reject any request that carries a body field outside an allowed set:

```hcl
path "slack/role/+/gateway/chat.postMessage" {
  capabilities = ["create"]
  condition    = "request.data.all(k, k in ['channel', 'text', 'thread_ts'])"
}
```

---

## Network and time

### 6. Source-IP allowlist

Only accept requests originating inside a CIDR block:

```hcl
path "admin/*" {
  capabilities = ["update"]
  condition    = "cidrContains('10.0.0.0/8', request.client_ip)"
}
```

> `request.client_ip` is only as trustworthy as your proxy chain — it derives from
> `X-Real-IP` / `X-Forwarded-For`, which a client can forge if those headers are
> not stripped at the edge.

### 7. Business hours only

Gate on the wall-clock hour in a named timezone:

```hcl
path "aws/role/+/*" {
  capabilities = ["update", "delete"]
  condition    = "now.getHours('America/New_York') >= 9 && now.getHours('America/New_York') < 17"
}
```

### 8. Weekdays only

`getDayOfWeek` returns `0` for Sunday through `6` for Saturday:

```hcl
path "aws/role/+/*" {
  capabilities = ["update", "delete"]
  condition    = "now.getDayOfWeek('UTC') in [1, 2, 3, 4, 5]"
}
```

---

## Operation shaping

The `capabilities` list already selects the rule; a condition can narrow *which*
operations proceed based on request context.

### 9. Read-only on a wildcard path

```hcl
path "secret/data/*" {
  capabilities = ["read", "list", "create", "update", "delete"]
  condition    = "request.operation in ['read', 'list']"
}
```

### 10. Reads open, writes gated by metadata

```hcl
path "kv/*" {
  capabilities = ["read", "update", "delete"]
  condition    = "request.operation == 'read' || token.metadata.role == 'writer'"
}
```

---

## Identity and authentication method

### 11. Require a specific auth method

Only accept callers that authenticated with SPIFFE (workload identity):

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "token.type == 'spiffe_role'"
}
```

> To require *any* hardware-backed method (certificate or SPIFFE, but not JWT or
> Kubernetes): `token.type in ['cert_role', 'spiffe_role']`.

### 12. Pin to a specific role

Gate on *which role was assumed*, distinct from which method authenticated it:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "token.role == 'payments-writer'"
}
```

### 13. Principal or trust-domain prefix

Match the verified principal — e.g. a SPIFFE trust domain:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "token.principal.startsWith('spiffe://prod.example.org/')"
}
```

### 14. Reject implicit (transparent) tokens

`request.transparent` is `true` when the identity was established implicitly via a
forwarded JWT rather than an explicit login. Require an explicitly authenticated
token here:

```hcl
path "admin/*" {
  capabilities = ["update", "delete"]
  condition    = "!request.transparent"
}
```

### 15. Ephemeral tokens only

Refuse long-lived tokens on a sensitive path — only accept ones expiring soon:

```hcl
path "prod/break-glass/*" {
  capabilities = ["update"]
  condition    = "token.ttl_seconds <= 3600"
}
```

### 16. Require an attached policy

`token.policies` is the list of policies bound to the token; require a specific one:

```hcl
path "prod/break-glass/*" {
  capabilities = ["update"]
  condition    = "'break-glass' in token.policies"
}
```

---

## Delegation

### 17. Require a verified delegate

`token.actors` is the on-behalf-of chain (see [Delegation](delegation.md)). Require
at least one actor, and that **every** actor in the chain was cryptographically
attested:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "size(token.actors) > 0 && token.actors.all(a, a.verified)"
}
```

The `size(...) > 0` guard matters: `all()` over an empty list is vacuously `true`,
so without it a request with no delegation chain would pass.

---

## Namespace confinement

`token.namespace` is where the token was minted; `request.namespace` is the
namespace the request targets. A token minted in a parent namespace can, by
default, act in its child namespaces — these conditions constrain that.

### 18. Same-namespace only

Deny a parent-namespace token acting in any child namespace:

```hcl
path "secret/data/*" {
  capabilities = ["read", "update", "delete"]
  condition    = "token.namespace == request.namespace"
}
```

### 19. Parent token read-only in child namespaces

Allow a parent-minted token to read across children, but write only in its own
namespace:

```hcl
path "secret/data/*" {
  capabilities = ["read", "list", "update", "delete"]
  condition    = "request.operation in ['read', 'list'] || token.namespace == request.namespace"
}
```

---

## MCP per-call and composite

### 20. A full payments stanza

The most complex case combines every layer: structural tool gates, per-tool
budgets over `call.args`, and request/identity/time context — all fail-closed.

```hcl
path "mcp/payments/*" {
  capabilities = ["update"]                    # structural: which rule applies
  mcp {
    allowed_methods = ["tools/call"]           # structural, enumerable
    allowed_tools   = ["create_payment", "refund"]
    condition       = <<-CEL
      cidrContains("10.0.0.0/8", request.client_ip)
      && now.getDayOfWeek("America/New_York") in [1, 2, 3, 4, 5]   // Mon–Fri
      && now.getHours("America/New_York") >= 9
      && now.getHours("America/New_York") <  17
      && token.metadata.env == "prod"
      && size(token.actors) > 0 && token.actors.all(a, a.verified)
      && (call.tool == "create_payment" ? call.args.amount <= 2500 :
          call.tool == "refund"         ? call.args.amount <=  500 : false)
      && call.args.currency in ["USD", "EUR", "GBP"]
    CEL
  }
}
```

---

## Gotchas

- **An `mcp { }` condition runs for every method the block governs.** If a block
  covers more than `tools/call`, an expression reading `call.args` will fail closed
  on the other methods. Scope it: `call.method != 'tools/call' || call.args.amount <= 1500`.
- **`request.operation` is `update` for MCP gateway POSTs.** Operation-conditional
  logic there is moot; branch on `call.tool` instead.
- **Path-level conditions cannot see `call.*`.** Referencing `call.args` in a
  `path`-level condition is a compile-time error, not a silent deny — the two
  layers use separate CEL environments by design.
- **Not every reference is audited.** The values a condition reads are recorded
  under `auth.policy_results.condition.inputs` (see [Audit](audit.md)), but
  `now.*` and bracket/optional access (`request.data["k"]`, `call.args.?x`) are not
  captured there — dotted field access (`request.data.model`) is.

## See also

- [Policies → Fine-grained access](policies.md#fine-grained-access) — the full
  condition semantics and cost bounds.
- [MCP → Per-call CEL conditions](mcp.md) — the `call.*` namespace and batch
  behavior.
- [Audit](audit.md) — how a condition's inputs are recorded and salted.
