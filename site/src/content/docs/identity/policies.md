---
title: "Policies"
---

A **policy** is how Warden decides what an authenticated caller may do. Every
request takes the same path: Warden [authenticates](/identity/authentication/)
the caller, resolves the [role](/identity/roles/) the request names against the
caller's [groups](/identity/groups/), and authorizes the request against that
role's policies, allowing or rejecting it. No policy grants it, no access:
authorization is **default-deny**.

## Two Policy Types

Warden has two policy types. Both are HCL documents, and a role's `policies`
field lists them together, by name: a name is unique across the two types.

| | Capability policy (`cbp`) | MCP policy (`mcp`) |
|---|---|---|
| **Decides** | Which paths a caller may reach, and with which capabilities (`read`, `create`, …). | Which [MCP](/concepts/mcp/) calls a caller may make: the methods, tools, resources and prompts they name, and their arguments. |
| **Grants access** | Yes. It is the only type that grants. | No. It only narrows what a capability policy grants. |
| **Applies to** | Every request. | MCP traffic through a gateway, and the discovery server. |
| **With none in scope** | The request is denied. | MCP traffic is denied. |
| **Written with** | `warden policy write <name> <file>` | `warden policy write -type mcp <name> <file>` |

A request to an MCP gateway needs both: a capability policy that grants its path,
and an MCP policy that allows the call. When several MCP policies apply, one
that allows the call is enough.

Most of this page describes capability policies, which can also reach into a
proxied [provider](/concepts/providers/) request to authorize individual upstream
operations. MCP policies are covered in
[Authorizing Gateway Requests](#authorizing-gateway-requests) and, in full, on the
[MCP](/concepts/mcp/) page.

## How Policies Decide a Request

Policies are named, stored objects. A [role](/identity/roles/) lists them in its
`policies` field, and a [group](/identity/groups/) grants the role. Nothing is
kept on a [token](/identity/tokens/): the role is decided again on every
request. A service token, such as the root token, carries its own policies
instead and takes no role. At request time Warden:

1. **Authenticate.** Admits the caller's credential, or checks its ticket or
   service token.
2. **Resolve.** Works out the caller's groups and checks that one of them
   grants the role the request names. A request whose role is refused gets no
   policy at all.
3. **Authorize.** Compiles the role's policies (or the service token's), with
   the namespace's [built-in policies](#built-in-policies), into a single
   evaluatable rule set, and evaluates the request against it, allowing only if
   a rule grants the needed capability — and never if a rule explicitly denies
   it.

When several policies grant capabilities on the **same path**, those grants are
**unioned** (capabilities add up). When policies match a request through
*different* path patterns, the most specific pattern wins (see
[Path matching](#path-matching)). A `deny` is absolute: it overrides any allow
for that path, in any policy.

Besides the role's policies, every request that is not a root request gets the
[built-in policies](#built-in-policies) of its token's namespace. They grant
only discovery and the sponsor paths, so they change no decision on any other
path.

## Policy Format

A policy is HCL: one or more `path` blocks, each granting capabilities on a path
pattern.

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "secret/data/myapp/config" {
  capabilities = ["create", "read", "update", "delete"]
}
```

### Capabilities

A path block grants one or more capabilities, which map to request operations:

| Capability | Grants |
|------------|--------|
| `read` | read a path |
| `create` / `update` | write a path |
| `delete` | delete a path |
| `list` | list keys under a path |
| `scan` | recursively enumerate keys under a path |
| `patch` | partial update |
| `sudo` | access to root-protected paths (in addition to the operation capability) |
| `deny` | explicitly deny — overrides every other grant on the path |

A capability corresponds to the request's **HTTP method**, not the action it
ultimately triggers: a `GET` needs `read`, a `POST` needs `create`, a `PUT` needs
`update`, a `DELETE` needs `delete`, a `PATCH` needs `patch`. For a proxied
[gateway](/concepts/providers/) request, that is the workload's own method against the
upstream. (`create` and `update` are reconciled by an existence check, so writes
that allow both are simplest.)

### Path matching

Request paths are matched against the patterns in three ways, most specific
first:

- **Exact** — `secret/data/app` matches only that path.
- **Prefix** — a trailing `*` matches everything beneath: `secret/data/*`. The
  `*` is valid only as the final character and is not a regular expression.
- **Segment wildcard** — `+` matches exactly one path segment:
  `secret/+/config` matches `secret/app/config` but not `secret/app/x/config`.
  A `+` may be combined with a trailing `*` (`secret/+/data/*`).

When more than one pattern matches a request, **one** rule decides it — the most
specific — not the union of all matches. Specificity is resolved in this order:

1. **An exact path wins** over any pattern containing a wildcard.
2. Otherwise, the pattern that matches the most of the path **literally** wins —
   the one whose first `+` or `*` sits furthest to the right.
3. If still tied, a pattern that does **not** end in `*` beats one that does (a
   bounded match over an open-ended one).
4. Remaining ties break on **fewer `+` segments**, then the **longer** pattern.

In each row below both candidates match the request; the rule named is the one
that decides which applies:

| Deciding rule | Request | Candidate patterns | Winner |
|---------------|---------|--------------------|--------|
| Exact over wildcard | `secret/data/app` | `secret/data/app`, `secret/data/*` | `secret/data/app` |
| First wildcard furthest right | `secret/data/app` | `secret/+/app`, `secret/data/*` | `secret/data/*` |
| Not ending in `*` beats ending in `*` | `secret/data/x` | `secret/data/*`, `secret/data/+` | `secret/data/+` |
| Fewer `+` segments | `secret/x/data/y` | `secret/+/data/+`, `secret/+/data/y` | `secret/+/data/y` |
| Longer pattern | `secret/x/data/bar` | `secret/+/data/b*`, `secret/+/data/ba*` | `secret/+/data/ba*` |

Each row isolates one rule — the earlier rules are deliberately tied between the
two candidates, so the named rule is what breaks the tie.

(Capabilities are unioned only across policies that share that one winning
pattern — a different, less-specific pattern that also matches does not add its
capabilities.)

### Fine-grained access

A path block can gate access on request context and values with a
**`condition`** — a [CEL](https://cel.dev) expression that must evaluate to
`true` for the rule to apply. It expresses source IP, time of day, token
attributes, numeric comparisons, set membership, cross-field relationships, and
arbitrary boolean logic in one place:

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "request.data.ttl_seconds <= 3600 && agent.metadata.env == 'prod'"
}
```

A `condition` is evaluated against the request after capability and path
matching select the rule — it refines a grant, it does not create one.

**What an expression can read.** Conditions evaluate against a fixed set of
namespaces built from the request: `request` (path, operation, client IP, mount
details, body values), `agent` (the authenticating principal), `user` (the
optional second principal it acts for), and `now`. The
[CEL Condition Cookbook](/identity/cel-conditions/#quick-reference) carries the
full field reference; it is the single source for that table.

Secret material (the token value, accessor) is never exposed. `request.data` is
the request body for non-MCP providers; MCP tool-call arguments are exposed as
`call.args` in an [MCP policy](/concepts/mcp/), a separate policy type with its
own CEL environment — referencing `call` here is a compile-time error.

**Comments.** HCL `#` comments go anywhere outside a condition. Inside a
condition, including a multi-line `<<EOT` one, the text is CEL: a `#` there is
a syntax error and the policy is refused when written. Use CEL's `//` comment
there instead.

**Helpers beyond the CEL built-ins:**

- `cidrContains(cidr, ip)` — replaces `source_ip`, e.g.
  `cidrContains("10.0.0.0/8", request.client_ip)`.
- Time/day come from the built-ins on `now`: `now.getHours("America/New_York")`,
  `now.getDayOfWeek("UTC")` (`0` = Sunday).

**Semantics:**

- **Fail-closed.** A condition that evaluates `false` *or errors* (a type
  mismatch, or reading a key that isn't present) denies the request. This means
  reading an **absent** field denies — the safe default for an authorization
  gate. To treat a missing value as acceptable, say so explicitly with optional
  syntax: `request.data.?ttl_seconds.orValue(0) <= 3600`.
- **A body Warden did not read has no fields.** On a gateway, `request.data` holds the
  body only when it is JSON (`application/json`, `text/json`, any `+json` type, or
  unlabelled) or form data, within the mount's `max_body_size`; any other type streams
  through with no fields. So a default like `orValue(0)` lets a caller past a body
  condition by relabelling the body. Gate a body field with `has()` instead —
  `has(request.data.amount) && request.data.amount <= 100` — so an unread body is
  refused. See [Request bodies and policy](/provider-backends/configuration/#request-bodies-and-policy).
- **Typing is runtime.** `request.data` / `call.args` values are typed from the
  request, so `request.data.amount > 1000` is a real numeric comparison and a
  string `"1000"` does **not** satisfy it (it denies, fail-closed).
- **Identity-independent.** The expression is compiled
  once and evaluated against each token's own values at request time, so one
  compiled policy stays correct across every token that shares it.
- **Bounded.** Expressions are type-checked and cost-bounded at policy-write
  time; an invalid, non-boolean, or too-expensive expression is rejected when the
  policy is written, not at request time. Note this catches undeclared
  *namespaces*, not undeclared *fields*: because the namespaces are dynamic maps,
  a mistyped `agent.metadta.env` compiles and then fails closed at request time.

Examples:

```hcl
# numeric cap on a request-body field
condition = "request.data.ttl_seconds <= 3600"

# request-body constraints: require a field, restrict a value, forbid a key
condition = "has(request.data.owner) && request.data.tier in ['gold', 'silver'] && !has(request.data.internal)"

# set membership over agent metadata
condition = "agent.metadata.env in ['dev', 'staging']"

# require a delegate in the act chain
condition = "size(agent.actors) > 0"

# require a verified user bound to this agent
condition = "user.present && user.metadata.authorized_agent == agent.principal"
```

For worked examples in four classes — an agent acting alone, an agent acting for
a user, request/network/time shaping, and MCP tool calls — see the
[CEL Condition Cookbook](/identity/cel-conditions/).

### Path expiration

A path block can carry an `expiration` — an absolute time after which the rule
stops applying. It is how you write a grant that revokes itself, without a
follow-up edit or an external cleanup job:

```hcl
path "secret/data/incident-4821/*" {
  capabilities = ["read"]
  expiration   = "2026-07-01T00:00:00Z"
}
```

The value is an absolute instant, accepted as an RFC3339 timestamp (with or
without fractional seconds, e.g. `2026-07-01T00:00:00Z`) or as an integer Unix
epoch in seconds. It is **not** a duration — there is no `"24h"` form; compute
the wall-clock instant when you write the policy.

Once that instant passes, the rule is dropped as if it had never been
written — it is removed when the policy is compiled to evaluate a request, so no
separate cleanup step is involved. The effect is scoped to the single path
block: other `path` blocks in the same policy are untouched.

Expiration **removes a grant; it does not add a deny.** When a rule expires,
evaluation simply falls back to whatever other rules match the request — a
broader prefix in the same or another policy keeps applying, and if nothing else
matches, the request is denied by the [default-deny](#policies) baseline. To
guarantee a path becomes inaccessible at a deadline regardless of other grants,
use a `deny` rule, not an expiration.

A common pattern is time-boxed access: a temporary elevation for an incident, a
contractor grant that lapses on a known date, or a break-glass rule that admits
access for a fixed window and then closes on its own.

## Order of Evaluation

Within the single [most-specific](#path-matching) rule that decides a request,
the checks run as a fixed sequence of gates. Each must pass before the next is
even considered, and any failure denies the request immediately:

1. **Capability** — does the rule grant the capability for this operation? If
   not, the request is denied and nothing further runs.
2. **Condition** — does the path-level `condition` (CEL) hold?
3. **MCP policy** — for MCP traffic, does the parsed body pass the
   [MCP policies](/concepts/mcp/) in scope (including their per-call
   `condition`)? With no MCP policy in scope, MCP traffic is denied.

(For `list`/`scan` requests a final step clamps the pagination limit to the
rule's `pagination_limit` and applies any response key filter — this shapes the
response, it is not an access gate.)

This ordering is not incidental — it shapes how policies must be written:

- **Path + capability is the outer gate; `condition` and MCP policies only refine
  it.** An MCP policy never grants access on its own: the capability policy must
  already grant the operation, or the MCP gate is never reached. It only ever
  narrows, never widens.
- **A coarser gate that denies ends the request.** A failed `condition`
  denies *before* Warden parses the request body, so source-IP and time-of-day
  limits hold no matter what the MCP call contains — and they cost nothing on the
  body-parsing path.
- **Later gates cannot recover earlier denials.** Passing the MCP rules can't
  restore access the capability check refused. The sequence is strict and
  fail-closed, so write the outer gates (capability, condition) to admit exactly
  the traffic the inner gates are meant to refine.

## Authorizing Gateway Requests

This is where Warden policy goes beyond a path-and-capability ACL. Because a
provider [proxies a workload's request to an upstream](/concepts/providers/), a policy
can authorize the *content* of that request — which is essential for governing
what an AI agent is actually allowed to do at the other end of the gateway.

For **[Model Context Protocol](/concepts/mcp/) (MCP)** traffic, Warden parses the JSON-RPC
body of the proxied request and authorizes each call by method, by the tool /
resource / prompt it names, and by its arguments — before the request ever
reaches the upstream.

Those rules live in the MCP policy type (see [Two Policy Types](#two-policy-types)),
not in the capability policy. A capability policy governs *paths and operations*;
an MCP policy governs *calls*:

```bash
warden policy write -type mcp github-tools - <<'EOF'
path "mcp/gateway/*" {
  methods {
    allowed = ["tools/list", "tools/call"]
    denied  = ["tools/dangerous"]
  }
  tools {
    allowed = ["get_repository", "list_issues"]
    denied  = ["delete_*"]
  }
  condition = "call.args.?env.orValue('') != 'prod'"
}
EOF
```

The two compose as an **intersection**: a request must be granted by a capability
policy **and** permitted by the MCP policies in scope (when several apply, one
that allows the call is enough). An MCP policy is purely restrictive — it can
never grant access a capability policy withholds. MCP traffic with no MCP
policy in scope is denied.

See [MCP](/concepts/mcp/) for the full grammar and denial reasons. This is the
authorization step a provider performs after authentication and before injecting
a credential (see [How a request flows](/concepts/providers/#how-a-request-flows));
gating on body content is why a streaming provider may parse the request body.

## Built-in Policies

Every namespace holds three built-in policies. Warden writes them when the
namespace is created, and evaluates every request that is not a root request
under them, beside the policies of the role. They are the built-ins of the
token's namespace.

| Policy | Type | Grants |
|--------|------|--------|
| `default-cbp` | `cbp` | The discovery endpoints: `create`, `read` and `delete` on `sys/mcp` (the [discovery server](/concepts/discovery-and-skills/)), and `read` on `sys/introspect/roles`. |
| `default-mcp` | `mcp` | The discovery server's contract: its methods (`tools/list`, `tools/call`, `resources/list`, `resources/read`, `resources/templates/list`, `skills/list`, `skills/get`, `subscriptions/listen`, `logging/setLevel`), its tools `list_roles` and `read_skill`, and the `skill://*` resources. |
| `default-sponsor` | `cbp` | The [sponsor](/identity/sponsors/) paths: `read` on `sys/identity/sponsor/+`, and `create` and `update` on its `suspend`, `handover` and `accept` verbs. |

The discovery and sponsor paths are **identity paths**: they take no role.
Warden authorizes them on the credential or ticket the caller presents, under
the built-in policies. On the sponsor paths the handlers then decide who
sponsors what: the caller must be a person signed in with a ticket, and a
member of the entity's sponsor group.

Each body names its paths exactly (the sponsor paths by their exact shape, one
`+` for the entity name), never as a prefix, so evaluating every request
under them changes no decision on any other path. Read them like any other
policy:

```bash
warden policy read default-cbp
warden policy read -type mcp default-mcp
warden policy read default-sponsor
```

- **Edit them; you cannot delete them.** A delete is refused with
  `cannot delete built-in policy "default-cbp"; edit it instead`. Warden never
  overwrites an edit, an emptied body included.
- **Empty one to turn its feature off.** An emptied `default-cbp` turns
  discovery off in the namespace; an emptied `default-sponsor` turns sponsors
  off and leaves discovery alone:

  ```bash
  warden policy write default-sponsor - <<'EOF'
  # Sponsors are off in this namespace.
  EOF
  ```

- **Narrow them with an exact-path deny.** The built-ins merge with the other
  policies of the request. A condition or an MCP contract that another policy
  puts on a discovery path does not narrow what the built-ins grant there:
  the built-in's stanza has no condition, so the merged path is unconditional,
  and MCP contracts are alternatives. Warden warns when such a policy is
  written. A deny on the exact path does narrow it:

  ```hcl
  path "sys/mcp" {
    capabilities = ["deny"]
  }
  ```

  A request on an identity path takes no role, so a role's policies never
  reach it. To narrow discovery for every caller in the namespace, edit the
  built-in itself: a `default-mcp` without `read_skill` refuses that tool.

- **Keep them to their paths.** A built-in applies to every caller in the
  namespace, so a stanza you add to one for any other path applies to every
  caller. Warden warns when a built-in is written with such a stanza.

## The Root Policy

`root` grants every capability on every path and bypasses normal policy
evaluation. The built-in policies do not apply to a root request. `root`
exists only in the root [namespace](/concepts/namespaces/), a token holding
`root` may hold no other policy, and no role can list it. It is immutable — it
cannot be edited or deleted through the API.

Treat `root` as a break-glass grant: use it to bootstrap auth methods and
policies, then rely on least-privilege policies for ordinary work.

## Namespaces

Policies are per-[namespace](/concepts/namespaces/) and isolated. A policy's paths are
implicitly scoped to its own namespace. A request is evaluated against the
policies of its token's namespace — the namespace where the caller was
admitted — together with that namespace's built-in policies, so a grant there
can reach that namespace and the namespaces below it. A policy cannot grant
access in, or refer to, a parent or a sibling namespace.

## Managing Policies

Policies are written, read, listed, and deleted from the CLI. The policy body is
supplied as a file path, or `-` for stdin:

```bash
# Write a policy from a file (or stdin)
warden policy write app-ro ./app-ro.hcl
warden policy write app-ro - <<'EOF'
path "secret/data/app/*" {
  capabilities = ["read", "list"]
}
EOF

warden policy read   app-ro
warden policy list
warden policy delete app-ro          # prompts; -f to skip confirmation
```

Every subcommand takes a **`-type`** flag selecting which kind of policy it acts
on — `cbp` (capability-based, the default) or `mcp`:

```bash
warden policy write -type mcp github-tools ./github-tools.hcl
warden policy read   -type mcp github-tools
warden policy list   -type mcp
warden policy delete -type mcp github-tools
```

Capability policies are stored under `sys/policies/cbp/<name>` and MCP policies
under `sys/policies/mcp/<name>`. Names are unique **across** both types, so an
MCP policy cannot reuse a capability policy's name.

**Names have one spelling.** A policy name is lowercase letters, digits, `_`,
`-` and `.`, starting and ending with a letter, digit or `_`. The policy
endpoints accept a name only in that spelling; any other, such as `Admin`, is
refused with `400`:

```
policy name "Admin" is not canonical: use "admin"
```

**Reserved names.** `default` and every name starting `default-` are reserved
in both policy types: only the [built-in policy](#built-in-policies) of the
matching type can be written under one, and a role that lists such a name is
stored without it, with a warning. Role names starting `warden-` are reserved
for the [built-in operator roles](/identity/built-in-roles/).

Writes support a **check-and-set** version. It matters more for a policy than for
ordinary data: when two writers race, the change that gets silently clobbered is
often a *tightening*, so a lost update quietly restores access somebody
deliberately removed. Typical uses:

- **Concurrent edits.** Two operators or two pipelines each read version 7 and
  write back; the second write is refused instead of overwriting the first.
- **Reconcilers.** A controller reads version N and writes with `cas=N`, so if
  anything moved underneath it re-reconciles against current state rather than
  fighting.
- **Create-only provisioning.** `cas=-1` asserts the policy does *not* yet exist,
  so a name collision fails loudly instead of silently adopting a policy someone
  else owns.
- **A standing guardrail.** `cas_required` makes blind writes impossible on a
  high-value policy.

It is an API parameter rather than a CLI flag, so a guarded write goes through the
path directly:

```bash
warden write sys/policies/cbp/app-ro <<EOF
{
  "policy": "path \"secret/data/app/*\" { capabilities = [\"read\"] }",
  "cas": 7,
  "cas_required": true
}
EOF
```

A write is refused with `400` in three cases: `cas` omitted where check-and-set is
required, `cas` not matching the current version, and `cas=-1` against a policy
that already exists. These are deliberately client errors — a failed
check-and-set is the caller's race to lose, not a server fault.

`cas_required` is persisted with the policy and OR'd with the flag on **every**
write, so it cannot be dropped by accident: a policy that demands check-and-set
can still stop demanding it, but the write that lifts the flag must itself carry
a matching `cas`.

:::note[Changed in v0.20.0]
`cas_required` is now actually enforced — the write path never applied it before,
so a policy that set it was unguarded. A check-and-set refusal now answers `4xx`
instead of `500`. A deployment that set the flag and relied on writes succeeding
anyway will start seeing conflicts.
:::

## See Also

- [Roles](/identity/roles/) — how a role's `policies` reach a request.
- [Groups](/identity/groups/) — how a role is granted, per request.
- [Built-in roles](/identity/built-in-roles/) — operator roles whose grant is a policy body.
- [Tokens](/identity/tokens/) — what a policy is evaluated against.
- [CEL Condition Cookbook](/identity/cel-conditions/) — worked conditions and the field reference.
- [Providers](/concepts/providers/) — where gateway/MCP authorization is applied.
- [Authentication](/identity/authentication/) — what must happen before authorization.
- [Namespaces](/concepts/namespaces/) — the isolation boundary for policies.
- [Upgrading from v0.21.0](/upgrade/from-v0-21/) — for readers coming from v0.21.0.
