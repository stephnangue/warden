# Policies

A **policy** is how Warden decides what an authenticated caller may do. Once a
request is [authenticated](authentication.md) and its [token](tokens.md)
resolved, Warden evaluates the request against the policies attached to that
token and either allows it or rejects it. No policy grants it, no access:
authorization is **default-deny**.

Warden policies are **capability-based** (the policy type is `cbp`). A policy is
an HCL document that grants capabilities on paths — and, for proxied
[provider](providers.md) requests, can reach into the request itself to authorize
individual upstream operations.

## How Policies Attach to a Request

Policies are named, stored objects. A [role](roles.md)'s `token_policies` lists
the policy names a caller receives, and those names are recorded on the issued
[token](tokens.md). At request time Warden:

1. reads the policy names off the token,
2. compiles the named policies into a single evaluatable rule set,
3. evaluates the request against it, allowing only if a rule grants the needed
   capability — and never if a rule explicitly denies it.

When several policies grant capabilities on the **same path**, those grants are
**unioned** (capabilities add up). When policies match a request through
*different* path patterns, the most specific pattern wins (see
[Path matching](#path-matching)). A `deny` is absolute: it overrides any allow
for that path, in any policy.

There is **no implicit default policy** — a token carries exactly the policies
its role granted, nothing more. (The one built-in is [`root`](#the-root-policy).)

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
[gateway](providers.md) request, that is the workload's own method against the
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

### Parameter constraints

A path block can constrain the parameters of a request, not just the operation:

```hcl
path "secret/data/app" {
  capabilities = ["create", "update"]

  required_parameters = ["owner"]

  allowed_parameters = {
    "tier" = ["gold", "silver"]   # only these values
    "name" = []                   # any value, but the key is allowed
  }

  denied_parameters = {
    "internal" = []               # this key may never be set
  }
}
```

`required_parameters` must be present; `allowed_parameters` whitelists keys (and
optionally their values); `denied_parameters` forbids keys (an empty list denies
the key entirely).

### Conditions

A path block can gate access on request context with a `conditions` block —
source IP, time of day, day of week, and the calling token's metadata:

```hcl
path "secret/data/app/*" {
  capabilities = ["read"]
  conditions = {
    source_ip      = ["10.0.0.0/8"]
    time_window    = ["09:00-17:00 America/New_York"]
    day_of_week    = ["Mon", "Tue", "Wed", "Thu", "Fri"]
    token_metadata = ["env=prod", "team=platform*"]
  }
}
```

Different condition types are **AND**ed (all must hold); within one type, the
entries are **OR**ed (any one matches).

#### `token_metadata`

`token_metadata` matches the authenticating token's verified, login-derived
metadata. Each entry is `key=pattern`, where `pattern` is a glob, as in
`allowed_parameters`. The `*` is honored only at the **start and/or end** of the
pattern: a trailing `*` is a prefix match (`team=platform*` matches values
*starting with* `platform`), a leading `*` is a suffix match (`team=*-core` matches
values *ending with* `-core`), and both ends is a substring match (`team=*plat*`).
A `*` in the middle is literal, and a lone `*` is literal too — use `key=**` to
match any value (in effect, just requiring the key to be present, since a missing
key already fails closed). The metadata itself is populated by the auth method
that issued the token — JWT/SPIFFE claims, X.509 certificate fields, or Kubernetes
TokenReview attributes (see each method's *Token Metadata* section).

Semantics within the type:

- **AND across distinct keys** — every listed key must be present and match.
- **OR within one key** — repeating a key (`["tier=gold", "tier=platinum"]`)
  passes if the value matches any of its patterns.
- A key **absent** from the token's metadata fails closed.

```hcl
# only tokens whose metadata says env=prod AND team starts with "platform"
conditions = { token_metadata = ["env=prod", "team=platform*"] }
```

Because metadata is matched against the token's own values at request time (not
compiled into the policy), the same compiled policy stays correct for every
token — a token with `env=dev` is denied even though another token reusing the
same policy set is allowed.

### CEL conditions

When the structured `conditions` block can't express the rule — a numeric
comparison, set membership, a cross-field relationship, arbitrary boolean
logic — a path block can carry a **`condition`**: a [CEL](https://cel.dev)
expression that must evaluate to `true` for the rule to apply.

```hcl
path "db/issue-grant" {
  capabilities = ["create"]
  condition    = "request.data.ttl_seconds <= 3600 && token.metadata.env == 'prod'"
}
```

A `condition` is evaluated **in addition to** the structured `conditions` block
(both must pass) and against the same request — it does not replace capabilities
or path matching, which still select the rule.

**What an expression can read.** Conditions evaluate against a fixed set of
variables built from the request:

| Namespace | Fields |
| --- | --- |
| `request` | `path`, `operation`, `client_ip`, `mount_point`, `mount_type`, `mount_class`, `mount_accessor`, `transparent`, `data.<key>` |
| `token` | `principal`, `role`, `type`, `namespace`, `policies` (list), `metadata.<key>`, `actors` (list of `{subject, verified}`), `ttl_seconds`, `expires_at` |
| `now` | the request timestamp |

Secret material (the token value, accessor) is never exposed. `request.data` is
the request body for non-MCP providers; MCP tool-call arguments are exposed as
`call.args` inside an `mcp { }` block (see [MCP](mcp.md)).

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
- **Typing is runtime.** `request.data` / `call.args` values are typed from the
  request, so `request.data.amount > 1000` is a real numeric comparison and a
  string `"1000"` does **not** satisfy it (it denies, fail-closed).
- **Identity-independent.** Like `token_metadata`, the expression is compiled
  once and evaluated against each token's own values at request time, so one
  compiled policy stays correct across every token that shares it.
- **Bounded.** Expressions are type-checked and cost-bounded at policy-write
  time; an invalid, non-boolean, or too-expensive expression is rejected when the
  policy is written, not at request time.

Examples:

```hcl
# numeric cap on a request-body field
condition = "request.data.ttl_seconds <= 3600"

# set membership over token metadata
condition = "token.metadata.env in ['dev', 'staging']"

# require a verified on-behalf-of delegate in the chain
condition = "size(token.actors) > 0"

# operation-conditional (capability still selects the rule)
condition = "request.operation == 'read' ? true : token.metadata.role == 'writer'"
```

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
2. **Conditions** — do the `conditions` (source IP, time, day, token metadata)
   and the path-level `condition` (CEL) both hold?
3. **MCP block** — for a gateway request, does the parsed body pass the
   `mcp { }` rules (including its per-call `condition`)?
4. **Parameters** — finally, `required` / `allowed` / `denied` parameters.

This ordering is not incidental — it shapes how policies must be written:

- **Path + capability is the outer gate; `conditions` and `mcp` only refine it.**
  An `mcp { }` block never grants access on its own: the rule must already grant
  the operation's capability, or the block is never reached. Conversely, granting
  the capability *without* an `mcp` block allows **every** call on that path —
  the block only ever narrows, never widens.
- **A coarser gate that denies ends the request.** A failed `conditions` check
  denies *before* Warden parses the request body, so source-IP and time-of-day
  limits hold no matter what the MCP call contains — and they cost nothing on the
  body-parsing path.
- **Later gates cannot recover earlier denials.** Passing the MCP rules can't
  restore access the capability check refused. The sequence is strict and
  fail-closed, so write the outer gates (capability, conditions) to admit exactly
  the traffic the inner gates are meant to refine.

## Authorizing Gateway Requests

This is where Warden policy goes beyond a path-and-capability ACL. Because a
provider [proxies a workload's request to an upstream](providers.md), a policy
can authorize the *content* of that request — which is essential for governing
what an AI agent is actually allowed to do at the other end of the gateway.

For **[Model Context Protocol](mcp.md) (MCP)** traffic, a path block can carry an `mcp { }`
block. Warden parses the JSON-RPC body of the proxied request and authorizes each
call by method, by the tool / resource / prompt it names, and by its parameters —
before the request ever reaches the upstream:

```hcl
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods   = ["tools/list", "tools/call"]
    denied_methods    = ["tools/dangerous"]

    allowed_tools     = ["get_repository", "list_issues"]
    denied_tools      = ["delete_*", "force_*"]

    allowed_resources = ["github://repo/*"]
    denied_resources  = ["github://secrets/*"]

    allowed_prompts   = ["*"]
    denied_prompts    = ["sudo_*"]

    allowed_params = { path = ["docs/*", "specs/*"] }
    denied_params  = { env  = ["prod", "production"] }
  }
}
```

Semantics:

- **Deny is checked before allow.** A call matching a `denied_*` list is
  rejected; otherwise, if an `allowed_*` list is present, the call must match it.
- **Patterns use trailing `*` only.** `delete_*` and a bare `*` are valid; a `*`
  in any other position is rejected at parse time.
- **Multiple `mcp` blocks OR together** — adding policies can only widen what is
  allowed. In a batched JSON-RPC request, a single denied call denies the batch.

This is the authorization step a provider performs after authentication and
before injecting a credential (see [How a request flows](providers.md#how-a-request-flows));
gating on body content is why a streaming provider may parse the request body.

## The Root Policy

`root` is the one built-in policy. It grants every capability on every path and
bypasses normal policy evaluation. It exists only in the root
[namespace](namespaces.md), and a token holding `root` may hold no other policy.
It is immutable — it cannot be edited or deleted through the API.

Treat `root` as a break-glass grant: use it to bootstrap auth methods and
policies, then rely on least-privilege policies for ordinary work.

## Namespaces

Policies are per-[namespace](namespaces.md) and isolated. A policy's paths are
implicitly scoped to its own namespace, and a request is evaluated only against
policies in the namespace it resolves to. A policy in one namespace cannot grant
access in, or refer to, another.

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

Policies are stored under `sys/policies/cbp/<name>`. Writes support a
check-and-set (`cas`) version for safe concurrent updates.

## See Also

- [Roles](roles.md) — how `token_policies` attaches policies to an identity.
- [Tokens](tokens.md) — what a policy is evaluated against.
- [Providers](providers.md) — where gateway/MCP authorization is applied.
- [Authentication](authentication.md) — what must happen before authorization.
- [Namespaces](namespaces.md) — the isolation boundary for policies.
