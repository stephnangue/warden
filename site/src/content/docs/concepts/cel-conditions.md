---
title: "CEL Condition Cookbook"
description: "Recipes for Warden's CEL conditions — gating on the agent, binding an agent to the user it acts for, shaping requests, and constraining MCP tool calls."
---

Authorization in Warden has a **structural** layer and a **condition** layer. The
structural layer — `capabilities` on a capability policy, the method and tool families on
an [MCP policy](/concepts/mcp/) — decides *which rule applies* and *what it permits*
without seeing a concrete request. The condition layer refines that grant with a
[Google CEL](https://cel.dev) expression evaluated against the actual request: its values,
its network and time context, and the verified identities behind it.

A `condition` can appear in two places, and they use **separate CEL environments**:

- **In a capability policy's `path { }` block** — evaluated once per request against
  `request.*`, `agent.*`, `user.*`, and `now`.
- **In an MCP policy's `path { }` block** — evaluated once per MCP call, with the
  additional `call.*` namespace.

A rule passes only if its structural gates pass **and** its condition evaluates to `true`.
Evaluation is **fail-closed**: `false`, a type mismatch, or reading an absent key all deny.

This page is the cookbook. For the full semantics — the activation contract, cost bounds,
how inputs reach the audit log — see
[Policies → Fine-grained access](/concepts/policies/#fine-grained-access).

## Quick reference

An expression reads from a fixed set of namespaces. This table is the canonical one; other
pages link here rather than repeating it.

| Namespace | Fields |
| --- | --- |
| `request` | `path`, `operation`, `client_ip`, `mount_point`, `mount_type`, `mount_class`, `mount_accessor`, `transparent`, `namespace`, `data.<key>` |
| `agent` | `principal`, `role`, `namespace`, `policies` (list), `metadata.<key>`, `actors` (list of `{subject}`), `token_type`, `token_ttl_seconds`, `token_expires_at` |
| `user` | `present`, `principal`, `role`, `namespace`, `metadata.<key>`, `actors`, `token_type`, `token_ttl_seconds`, `token_expires_at`. There is no `user.policies` ([why](#13-what-user-does-not-give-you)) |
| `now` | the request timestamp |
| `call` | `method`, `tool`, `args.<key>`, `batch_index` — **MCP policies only** |

`agent` is the request's authenticating principal and the **sole authorizer**. `user` is
the optional second principal the agent acts for; it is identity-only and never authorizes.

Values you will reference often:

- `request.operation` — one of `read`, `create`, `update`, `delete`, `list`, `scan`,
  `patch`. (For an MCP gateway POST it is always `update`; gate on `call.tool` instead.)
- `agent.token_type` — how the principal authenticated: `spiffe_role`, `cert_role`,
  `jwt_role`, or `kubernetes_role`. It describes the *credential*, not the principal —
  which is why it carries the `token_` prefix.
- `request.mount_class` — `provider`, `auth`, `audit`, `system`, or `ns_system`.
- `agent.namespace` / `request.namespace` — a namespace path: `""` for root, or
  `"team-a/"` / `"team-a/team-b/"` (trailing slash) for children. `agent.namespace` is
  where the token was **minted**; `request.namespace` is the namespace the request
  **targets**.

Functions available: the CEL standard library (`has()`, `size()`, `in`, `startsWith()` /
`endsWith()` / `contains()`, `all()` / `exists()`, the `? :` ternary), optional access
`x.?field.orValue(default)`, timezone-aware `now.getHours(tz)` / `now.getDayOfWeek(tz)`
(0 = Sunday) / `now.getMinutes(tz)`, `int(now)` for epoch seconds, and Warden's
`cidrContains(cidr, ip)`. Numeric comparisons mix integers and decimals freely, so
`call.args.amount <= 1500` works whichever form the value arrived in.

:::caution[Three rules that bite]
**Fail-closed** — any error or `false` denies, so a missing key denies unless you guard it.
**Runtime typing** — `request.data.amount` is compared as the type it arrived as; the
string `"1000"` does *not* satisfy `> 1000`, it denies. **Absent-is-OK** — when a missing
field should pass, use `has(...)` or `x.?field.orValue(default)` rather than a bare
reference.
:::

---

## Agent acting on its own behalf

Conditions on the workload making the request. These need no user principal and work on
every request, gateway or not.

### 1. Pin to a role

Gate on *which role was assumed*, distinct from which method authenticated it:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "agent.role == 'payments-writer'"
}
```

### 2. Require a specific auth method

Only accept callers that authenticated with SPIFFE (workload identity):

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "agent.token_type == 'spiffe_role'"
}
```

To require *any* hardware-backed method — certificate or SPIFFE, but not JWT or
Kubernetes: `agent.token_type in ['cert_role', 'spiffe_role']`.

### 3. Principal or trust-domain prefix

Match the verified principal — e.g. a SPIFFE trust domain:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "agent.principal.startsWith('spiffe://prod.example.org/')"
}
```

### 4. Match a login-derived metadata label

`agent.metadata` carries the claims the auth method projected at login:

```hcl
path "prod/*" {
  capabilities = ["update"]
  condition    = "agent.metadata.env == 'prod'"
}
```

Absent keys deny. If the label is optional, guard it:
`has(agent.metadata.env) && agent.metadata.env == 'prod'`.

### 5. Require a token that expires soon

`agent.token_ttl_seconds` is the credential's **remaining** lifetime, recomputed at
evaluation time — not the TTL it was issued with. So this refuses any token with more than
an hour left on a sensitive path:

```hcl
path "prod/break-glass/*" {
  capabilities = ["update"]
  condition    = "agent.token_ttl_seconds <= 3600"
}
```

`agent.token_expires_at` expresses the same bound as an absolute epoch second, so
`agent.token_expires_at - int(now) <= 3600` is equivalent. Prefer `token_ttl_seconds` for
a rolling window; reach for `token_expires_at` when comparing against a fixed instant.

### 6. Require an attached policy

`agent.policies` is the list of policies bound to the token:

```hcl
path "prod/break-glass/*" {
  capabilities = ["update"]
  condition    = "'break-glass' in agent.policies"
}
```

### 7. Reject implicit (transparent) tokens

`request.transparent` is `true` when the identity was established implicitly from a
forwarded JWT rather than an explicit login:

```hcl
path "admin/*" {
  capabilities = ["update", "delete"]
  condition    = "!request.transparent"
}
```

---

## Agent acting for a user

A gateway request can carry a second, verified **user** principal alongside the agent's own
credential (see [Delegation](/concepts/delegation/)). These recipes gate on that user.

:::note[The user leg is resolved for gateway requests only]
`user.present` is always `false` outside a gateway (streaming) request, and the user leg
only exists on a mount configured with `user_auth_path`. A `user.*` condition on a
non-gateway path denies every request.
:::

### 8. Require a user behind the agent

The guard form. `user.present` is `false` when no user credential rode the request:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "user.present == true"
}
```

A *bare* `user.present` is rejected at write time — see
[recipe 13](#13-what-user-does-not-give-you). Compare it explicitly as above, or use it as
a guard (`user.present && …`) as every recipe below does.

When this denies because no user was presented, Warden answers **`401` with a
`WWW-Authenticate: Bearer` challenge** rather than a bare `403`, so a client knows it
should authenticate a user and retry. A retry that presents a user and still fails gets a
terminal `403` — the exchange cannot loop.

### 9. Bind the user to the agent acting for them

The canonical binding, and the one that matters most. It is not enough that *a* user and
*an* agent are both present — the user must be paired with **this** agent. Otherwise any
agent holding a valid token could act for any user who happened to authenticate: two
identities present, entirely unrelated.

The pairing is attested on the **user's** token. [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
defines two claims for this, and which one your IdP emits depends on how it issues the
user's credential:

| Claim | RFC 8693 | Asserts | Use when |
| --- | --- | --- | --- |
| `may_act` | §4.4 | "one party is authorized to **become** the actor and act on behalf of another party" — a statement of permission, carried on the subject token | The user authenticates as themselves and their token names the agent allowed to act for them. **This is the usual shape for Warden's user leg.** |
| `act` | §4.1 | "delegation **has occurred**", identifying the party that currently holds delegated authority | The credential presented on the user leg is itself a post-exchange delegation token (subject = the user, actor = the agent) |

`metadata_claims` accepts any RFC 6901 JSON Pointer, so either maps the same way. Project
it on the *user's* auth-method role:

```hcl
metadata_claims = {
  "/may_act/sub" = "authorized_agent"
}
```

Then compare it to the agent presenting the request:

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "user.present && user.metadata.authorized_agent == agent.principal"
}
```

For a delegation token, map `"/act/sub" = "acting_agent"` and compare that instead. Note
that `act` chains nest — the outermost `act` names the *current* actor (the same identity
as `user.actors[0]`), while nested ones record prior actors, so a pointer at `/act/sub`
binds the party acting directly for the user rather than the far end of the chain.

Not every IdP emits either claim — a `client_credentials` grant typically emits neither.
Where there is no attestation to enforce, the pairing has to be decided at the gateway
instead, comparing some other value carried on the user's token against the agent's
identity. The claim mapping, the condition layer and the per-request evaluation are
identical; only the provenance of the compared value differs.

### 10. Same-team binding

Require the agent and the user to share an attribute, when a full consent chain is more
than you need:

```hcl
path "prod/deploy/*" {
  capabilities = ["update"]
  condition    = "user.present && agent.metadata.team == user.metadata.team"
}
```

### 11. Humans for writes, agents for reads

Step-up authorization: let an agent read unattended, but require a user for anything
mutating:

```hcl
path "prod/config/*" {
  capabilities = ["read", "list", "update", "delete"]
  condition    = "request.operation in ['read', 'list'] || user.present"
}
```

### 12. Scope by a verified user attribute

Gate on an attribute of the user rather than the workload:

```hcl
path "finance/reports/*" {
  capabilities = ["read", "list"]
  condition    = "user.present && user.metadata.department == 'finance'"
}
```

### 13. What `user` does not give you

Four constraints worth knowing before writing a `user` condition:

- **`user.policies` does not exist.** The user never authorizes — a request is authorized
  by the agent's token alone — so exposing it would read like an authorization check that
  it is not. Because `user` is a dynamic map, `'admin' in user.policies` **compiles
  cleanly and then denies every request at runtime**. It fails closed, but it fails
  silently; there is no write-time error to warn you.
- **A bare `user.present` is rejected at write time** with `condition must evaluate to
  bool, got dyn`. A dynamic-map field types as `dyn`, and a condition must be a boolean.
  Compare it explicitly (`user.present == true`) or use it as a guard (`user.present && …`).
- **`user.role` is not the person's job title.** It is the auth-mount role fixed by the
  mount's `user_auth_role` — the same value for every user on that mount. Gate on
  `user.metadata.<key>` instead.
- **`user.namespace` is always `request.namespace`.** It carries no independent
  information, so it is never worth comparing.

---

## Request shape, network and time

### 14. Cap a numeric body field

Bound a value in the request body — e.g. an LLM token budget:

```hcl
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "update"]
  condition    = "request.data.max_tokens <= 4096"
}
```

### 15. Pin a field to an allowlist

```hcl
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "update"]
  condition    = "request.data.model in ['claude-sonnet-4-5', 'claude-opus-4-1']"
}
```

### 16. Require a field to be present

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "has(request.data.justification)"
}
```

### 17. Optional field with a safe default

Cap a field *if present*, but allow the request when it is omitted:

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "request.data.?ttl_seconds.orValue(0) <= 3600"
}
```

### 18. Closed key set

Reject any request carrying a body field outside an allowed set:

```hcl
path "slack/role/+/gateway/chat.postMessage" {
  capabilities = ["create"]
  condition    = "request.data.all(k, k in ['channel', 'text', 'thread_ts'])"
}
```

### 19. Source-IP allowlist

```hcl
path "admin/*" {
  capabilities = ["update"]
  condition    = "cidrContains('10.0.0.0/8', request.client_ip)"
}
```

`request.client_ip` is only as trustworthy as your proxy chain — it derives from
`X-Real-IP` / `X-Forwarded-For`, which a client can forge if those headers are not
stripped at the edge.

### 20. Business hours, weekdays only

`getDayOfWeek` returns `0` for Sunday through `6` for Saturday:

```hcl
path "aws/role/+/*" {
  capabilities = ["update", "delete"]
  condition    = <<-CEL
    now.getDayOfWeek('America/New_York') in [1, 2, 3, 4, 5]
    && now.getHours('America/New_York') >= 9
    && now.getHours('America/New_York') <  17
  CEL
}
```

### 21. Read-only on a wildcard path

The `capabilities` list already selects the rule; a condition narrows which operations
actually proceed:

```hcl
path "secret/data/*" {
  capabilities = ["read", "list", "create", "update", "delete"]
  condition    = "request.operation in ['read', 'list']"
}
```

### 22. Confine a token to its own namespace

A token minted in a parent namespace can, by default, act in its children. `agent.namespace`
is where it was minted; `request.namespace` is what it targets:

```hcl
path "secret/data/*" {
  capabilities = ["read", "update", "delete"]
  condition    = "agent.namespace == request.namespace"
}
```

To let a parent-minted token read across children but write only at home:

```hcl
condition = "request.operation in ['read', 'list'] || agent.namespace == request.namespace"
```

---

## MCP tool calls

These conditions belong in an **MCP policy** (`warden policy write -type mcp`), whose
environment adds the `call.*` namespace. `agent.*` and `user.*` are available here too.

:::caution[`call` is not available in a capability policy]
Referencing `call.args` in a capability policy's `path` condition is a **compile-time
error**, not a silent deny — the two layers use separate CEL environments by design.
:::

### 23. Gate a single tool

```hcl
path "mcp/gateway/github/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools   { allowed = ["get_repository", "list_issues"] }
  condition = "call.tool != 'delete_repository'"
}
```

### 24. Constrain tool arguments

This is how argument restrictions are expressed. The former `allowed_params` /
`denied_params` keys are removed and rejected at write — a CEL condition over `call.args`
replaces them, and it is strictly more expressive:

```hcl
path "mcp/gateway/deploy/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["deploy_service"] }
  condition = "call.args.?env.orValue('') != 'prod'"
}
```

The optional access matters: a caller who simply omits `env` would otherwise deny on a
missing key.

### 25. Scope a condition to one method

A condition runs for **every** method its block governs. If the block covers more than
`tools/call`, an expression reading `call.args` fails closed on the others. Scope it:

```hcl
condition = "call.method != 'tools/call' || call.args.amount <= 1500"
```

### 26. Per-user tool arguments

Combine the user principal with the call to keep a user inside their own resources:

```hcl
path "mcp/gateway/github/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["*"] }
  condition = "user.present && call.args.?owner.orValue('') == user.metadata.github_login"
}
```

### 27. A full payments contract

The most complex case combines every layer — structural tool gates, per-tool budgets over
`call.args`, and identity, network and time context, all fail-closed:

```hcl
path "mcp/payments/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["create_payment", "refund"] }
  condition = <<-CEL
    cidrContains('10.0.0.0/8', request.client_ip)
    && now.getDayOfWeek('America/New_York') in [1, 2, 3, 4, 5]
    && now.getHours('America/New_York') >= 9
    && now.getHours('America/New_York') <  17
    && agent.metadata.env == 'prod'
    && user.present && user.metadata.authorized_agent == agent.principal
    && (call.tool == 'create_payment' ? call.args.amount <= 2500 :
        call.tool == 'refund'         ? call.args.amount <=  500 : false)
    && call.args.currency in ['USD', 'EUR', 'GBP']
  CEL
}
```

Remember that the capability policy governing this path must independently grant it —
MCP policies only restrict.

---

## Gotchas

- **`request.operation` is `update` for MCP gateway POSTs.** Operation-conditional logic
  there is moot; branch on `call.tool` instead.
- **A dynamic-map typo fails closed at runtime, not at write time.** `agent.metadta.env`
  compiles and denies every request. Only undeclared *namespaces* (a bare `token`, or
  `call` in a capability policy) are caught at write time.
- **Not every reference is audited.** The values a condition reads are recorded under
  `auth.policy_results.condition.inputs` (see [Audit](/concepts/audit/)), but `now.*` and
  bracket/optional access (`request.data["k"]`, `call.args.?x`) are not captured there —
  dotted field access (`request.data.model`) is.
- **Audit `salt_fields` selectors use these same names.** A selector still written against
  the old `token` namespace does not error after the v0.20.0 rename — it stops matching,
  and the value it protected begins logging in clear. See
  [Upgrading from v0.19.0](/upgrade/from-v0-19/).

## See also

- [Policies → Fine-grained access](/concepts/policies/#fine-grained-access) — condition
  semantics and cost bounds.
- [MCP](/concepts/mcp/) — the MCP policy type, its grammar, and the `call.*` namespace.
- [Delegation](/concepts/delegation/) — the user principal and how consent is established.
- [Audit](/concepts/audit/) — how a condition's inputs are recorded and salted.
