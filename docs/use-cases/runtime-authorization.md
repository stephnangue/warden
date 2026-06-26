# Runtime authorization

_Control every tool call at runtime, down to the argument._

## Reaching a system shouldn't mean doing anything in it

Most access control is coarse and static. You grant an agent a credential — a
token, a scope, a key — and within whatever that credential covers, the agent can
do anything, for as long as the credential lives. The grant is made once and
reused for the whole session, and it answers only one question: *which systems can
you reach?* It says nothing about *what you may do* once you are there.

For an agent, that gap is the whole risk. "Can reach GitHub" silently becomes "can
delete any repository." "Can query the database" becomes "can read every table."
The grant that lets an agent do its narrow job also lets a hijacked or hallucinating
version of that agent do everything else the system allows. And because grants are
made per session and rarely narrowed, they accumulate: an agent ends up holding the
union of everything it has ever needed, long after it needs it.

MCP makes the gap concrete. An MCP server exposes a bundle of tools, and a
coarse grant hands the agent *all* of them, with *any* arguments — `delete_database`
sitting next to `get_repository`, `env=production` as reachable as `env=staging`.
Granting "the server" is granting every tool it will ever expose; there is no
natural place to say *this tool but not that one*, or *this tool only with these
arguments*.

## Authorize every call, down to the argument

Warden authorizes the **request**, not the session. Authority does not sit on the
connection; it rides on each call and is evaluated the moment the call arrives,
against the [policy](../concepts/policies.md) attached to the agent's
[role](../concepts/roles.md). Authorization is **default-deny** — a call succeeds
only if a rule grants exactly the capability it needs — and because [roles are
per-request](../concepts/roles.md#roles-are-per-request), the agent can run under
a read-only role for routine work and name a higher-privilege role only for the
one call that genuinely needs it. Nothing accumulates; each call is judged on its
own terms.

The check reaches past the path into the content of the request. A policy can gate
an operation on its [parameters](../concepts/policies.md#parameter-constraints) and
on request context — source IP, time of day, day of week — before any credential is
minted. For [MCP](../concepts/mcp.md) traffic it goes all the way inside the tool
call: Warden parses the JSON-RPC body and decides, per call, **which tool** the
agent may invoke, **which resource or prompt** it may name, and **which arguments**
it may pass — refusing the call before it ever reaches the upstream. That is how you
govern what an agent actually *does* through a server, not merely whether it can
reach it.

A denied MCP call comes back as an HTTP 403 with a short reason naming the offending
tool or parameter, so the agent can correct course instead of guessing at an opaque
failure — and every decision, allow or deny, is recorded.

## Benefits

- **Least privilege per step** — each call gets the narrowest role that fits it,
  not a session-wide grant that fits everything.
- **Down to the action and argument** — policy gates the specific tool, resource,
  and parameter values, not just which system is reachable.
- **No privilege accumulation** — authority is re-decided on every call, so nothing
  lingers on the connection to be misused later.

## In practice

An agent drives a GitHub MCP server through an `mcp` mount. Its policy allows the
`tools/call` method for `get_repository` and `list_issues`, denies any tool matching
`delete_*`, and denies the `env` argument when it is `prod`. The agent works
normally — listing issues, reading repositories — until a poisoned issue body
convinces it to call `delete_repository`. Warden parses the JSON-RPC body, matches
the denied-tools rule, and refuses the call with a 403 before it reaches GitHub. The
repository is untouched, and the attempt is in the [audit log](../concepts/audit.md)
with the exact tool that was blocked.

## See Also

- [Policies](../concepts/policies.md) — capabilities, conditions, parameter
  constraints, and the `mcp { }` rule grammar.
- [Roles](../concepts/roles.md#roles-are-per-request) — per-request role binding
  and changing role mid-session.
- [Model Context Protocol](../concepts/mcp.md) — authorizing individual tool calls
  by name and argument.
- [Breach containment](breach-containment.md) — the bounded blast radius this
  per-call control produces.
- [Audit & attribution](audit-attribution.md) — where every allow and deny is
  recorded.
