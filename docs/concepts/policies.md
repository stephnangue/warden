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
source IP, time of day, and day of week:

```hcl
path "secret/data/app/*" {
  capabilities = ["read"]
  conditions = {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["09:00-17:00 America/New_York"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}
```

Different condition types are **AND**ed (all must hold); within one type, the
entries are **OR**ed (any one matches).

## Order of Evaluation

Within the single [most-specific](#path-matching) rule that decides a request,
the checks run as a fixed sequence of gates. Each must pass before the next is
even considered, and any failure denies the request immediately:

1. **Capability** — does the rule grant the capability for this operation? If
   not, the request is denied and nothing further runs.
2. **Conditions** — do the `conditions` (source IP, time, day) hold?
3. **MCP block** — for a gateway request, does the parsed body pass the
   `mcp { }` rules?
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
