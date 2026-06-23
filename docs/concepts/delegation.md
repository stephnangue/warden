# Delegation (On-Behalf-Of)

A request is made *by* an authenticated principal, but it is often made *on behalf
of* someone else — an AI agent acting for a user, or a **concentrator** that holds
one identity and serves many agents through it. Warden lets a request carry that
chain of subjects, the **actors**, and records them in the [audit log](audit.md)
so attribution survives the hop.

The chain is for **attribution, not authorization** — see
[Attribution, Not Authorization](#attribution-not-authorization) below. It answers
"who was this *really* for?", not "is this allowed?".

## The Actor Chain

Each actor is a subject plus a trust flag:

| Field | Meaning |
|-------|---------|
| `subject` | The identity being acted for (e.g. `agents/alpha`, `user@example.com`). |
| `verified` | Whether the actor is cryptographically attested (`true`) or self-reported (`false`). |

A request can carry several actors, ordered from the nearest delegator outward,
and they appear as the `actors` array on the request's audit entry.

## Two Sources

An actor chain reaches Warden two ways, distinguished by whether it can be
cryptographically trusted.

### JWT `act` claim — verified

A JWT can carry an RFC 8693 §4.1 **`act`** ("actor") claim, and because the JWT is
signed by the identity provider, the chain it asserts is **attested** — recorded
as `verified: true`. The claim nests to express a chain:

```json
{ "sub": "gateway-service",
  "act": { "sub": "broker-beta",
           "act": { "sub": "agents/alpha" } } }
```

→ actors `[broker-beta (verified), agents/alpha (verified)]`. Warden walks the
nesting up to a depth of **4**, stopping gracefully at any malformed layer. These
actors are extracted at login and **persisted on the [token](tokens.md)**, so the
chain survives transparent-token caching.

### `X-Warden-On-Behalf-Of` header — unverified

When the delegator cannot embed the chain in a JWT — typically a concentrator
that authenticates with its own identity — it names the subject it is acting for
in the `X-Warden-On-Behalf-Of` header. Warden has no proof of this, so it is
recorded as `verified: false`:

```
X-Warden-On-Behalf-Of: agents/alpha
```

The header carries a **single** subject (1–256 chars, `[A-Za-z0-9._:@/+-]`, no
commas), is validated and dropped if malformed (never failing the request), is
**per-request**, and is **stripped before the request is proxied upstream** so it
never leaks past Warden.

## Verified vs. Unverified

The `verified` flag tells an audit reader how much to trust an actor:

- **`verified: true`** — the identity provider attested it by signing the JWT; the
  caller cannot forge it. Suitable for strong non-repudiation.
- **`verified: false`** — the authenticated principal simply asserted it via the
  header. Record it as context, but the *principal* is accountable for its
  accuracy.

In both cases the **authenticated principal** is still recorded separately; the
actors sit alongside it, they do not replace it.

## Per-Request Beats Token-Bound

This is the point of having both sources. A **concentrator** holds one transparent
JWT and reuses it — and so one cached token — for many downstream agents. If
attribution came only from the token, every agent's calls would collapse into the
concentrator's identity. So the per-request **header wins** over the token-bound
`act` chain:

```
agent alpha  ─▶ concentrator ─▶ Warden   X-Warden-On-Behalf-Of: agents/alpha
agent beta   ─▶ concentrator ─▶ Warden   X-Warden-On-Behalf-Of: agents/beta
```

Both calls reuse the concentrator's one token, but each audit entry shows the
right agent. When no header is present, the token's verified `act` chain is used
instead.

## Attribution, Not Authorization

Actors **never affect access decisions**. No [policy](policies.md) capability,
condition, or `mcp { }` rule consults them; a policy cannot allow or deny based on
who a request is on behalf of. The chain exists purely to enrich the
[audit](audit.md) trail and support non-repudiation. Keeping it orthogonal to
authorization is deliberate: a self-reported header must never be able to widen
what a caller may do.

## Example

A concentrator (principal `mcp-broker`) forwards an agent's call:

```
POST /v1/openai/gateway/v1/chat/completions
Authorization: Bearer <concentrator session token>
X-Warden-On-Behalf-Of: agents/alpha
```

The resulting audit entry attributes the call to both:

```json
{
  "auth": {
    "principal_id": "mcp-broker",
    "actors": [{ "subject": "agents/alpha", "verified": false }]
  }
}
```

Had the chain instead come from a signed JWT `act` claim, the same entry would
show `"verified": true`.

## Surface

Delegation is **header- and token-driven** — there is no CLI flag or environment
variable. The verified chain comes from the JWT your identity provider issues; the
unverified actor is a header an SDK or concentrator sets per request. Either way,
it lands in the audit log and nowhere else.

## See Also

- [Audit](audit.md) — where the actor chain is recorded.
- [Authentication](authentication.md) — the principal the actors act alongside.
- [Tokens](tokens.md) — where a verified `act` chain is persisted.
