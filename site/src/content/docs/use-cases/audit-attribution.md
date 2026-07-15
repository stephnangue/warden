---
title: "Audit & attribution"
---

_Know exactly who did what, on whose behalf._

## Shared identities erase who actually acted

When something goes wrong, the first question is always the same: who did this? For
agents, that question is unusually hard to answer. Agents are created and destroyed
constantly, and the easy way to give a fleet of them access is to let them share a
service account. So when the upstream logs the call, it logs the shared account —
the same identity for every agent, every task, every user behind them. The one
record that survives points at all of them and therefore at none of them.

It gets harder a layer up. Many agents often share a single MCP server — one
process that authenticates with its own identity and makes calls on behalf of
whichever agent is using it. If attribution comes only from the authenticated
identity, every agent's actions collapse into the server's, and a request made
*for* a specific user or agent is indistinguishable from any other. You can see
that *something* happened; you cannot say *who* it was really for.

And the record itself is often unsafe to keep. Naive logging of requests captures
the very credentials and secrets in flight, so the audit trail becomes a second
copy of the thing you were trying to protect — too sensitive to ship to the SIEM
where it would actually be useful. Between shared identities, hidden delegators, and
secrets in the log, an incident becomes something you reconstruct by guesswork
rather than read off the record.

## Every request tied to a real identity

Warden sits in the path of every request, so it records every request — a
[forensic log](/concepts/audit/) of who asked for what, which policy decision
was made, and which credential was issued. Each operation produces paired request
and response entries carrying the principal and [role](/concepts/roles/), the
policies in force, the [namespace](/concepts/namespaces/), the upstream called,
and — for a brokered call — a description of the credential Warden minted. Because
the agent authenticated [as itself](/use-cases/access-brokering/), the identity on the entry
is the real one, not a shared key.

Attribution survives the extra hop. A request can carry a
[delegation](/concepts/delegation/) chain — the subjects it is being made *on
behalf of* — and Warden records them alongside the authenticated principal, each
flagged **verified** (cryptographically attested by a signed JWT `act` claim) or
**unverified** (self-reported by a trusted caller). A shared MCP server that reuses
one identity for many agents still produces correct per-call attribution, because
the per-request actor takes precedence over the token-bound one. Attribution is
kept deliberately orthogonal to authorization — naming who a call is for can never
*widen* what the caller may do — so it is safe to trust the chain for forensics
without it becoming an avenue for escalation.

The record is built to be kept. Secrets are **never written in clear**: sensitive
values are replaced with a keyed HMAC, deterministic enough to correlate
occurrences of a value across the log yet impossible to reverse, so the log is safe
to ship to a SIEM. For [MCP](/concepts/mcp/) traffic the detail goes per tool
call: every `mcp { }` decision is recorded on **both allow and deny**, with the tool
or parameter that decided it — a complete account of what an agent did through a
server, not just what it was blocked from doing.

## Benefits

- **A complete forensic record** — every request, its policy decision, and the
  credential issued, tied to the identity that actually made the call.
- **Attribution that survives the hop** — the on-behalf-of chain names the real
  agent or user behind a shared identity or a concentrator.
- **Safe to ship** — secrets are HMAC-hashed, never logged in clear, so the trail
  can live in your SIEM.

## In practice

A shared MCP server with the principal `mcp-gateway` forwards calls for many agents,
each request carrying an `X-Warden-On-Behalf-Of` header naming the agent it is
acting for. An investigation into an unexpected change reads the audit log and finds
the offending call attributed to the principal `mcp-gateway` *and* to the actor
`agents/alpha` — so the trail leads to the specific agent, not the shared server.
The credential Warden issued is described in the same entry, with its secret HMAC'd;
the investigator can confirm which value was used by hashing it the same way,
without the log ever holding a usable key.

## See Also

- [Audit](/concepts/audit/) — what is recorded, and how secrets are hashed.
- [Delegation](/concepts/delegation/) — the on-behalf-of actor chain and how it
  reaches the log.
- [Model Context Protocol](/concepts/mcp/) — per-tool-call decisions in the
  audit trail.
- [Access brokering](/use-cases/access-brokering/) — why the identity on each entry is the
  agent's own, not a shared key.
- [Runtime authorization](/use-cases/runtime-authorization/) — the policy decisions the log
  records.
