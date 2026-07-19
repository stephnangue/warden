---
title: "Delegation and Impersonation"
---

A request is made *by* an authenticated principal, but it is often made *on behalf of*
someone else — an AI agent acting for a user. Warden supports this at the **credential
boundary**: when the [token-exchange driver](/credential-drivers/token-exchange/) mints a
downstream credential, it exchanges the caller's identity for a token that either *is* the
subject (impersonation) or names the acting party in a signed **`act` claim** (delegation),
which the upstream API and its authorization server enforce.

Separately, Warden records an **actor chain** in its [audit log](/concepts/audit/) so attribution
survives the hop — covered [at the end](#the-audit-actor-chain).

## Supported Standards

Warden does not invent a delegation protocol — it speaks the established ones, selected per
[credential source](/concepts/credentials/) by the `grant` setting so it interoperates with whatever
the upstream's authorization server expects:

| Standard | Role | Selected by |
|----------|------|-------------|
| **RFC 8693** — OAuth 2.0 Token Exchange | exchange a subject (and optional actor) for a scoped token | `grant=rfc8693` |
| **RFC 7523** — JWT Bearer assertion | present the subject as a signed `assertion` | `grant=jwt_bearer` |
| **Microsoft Entra ID On-Behalf-Of** | Entra's OBO (a jwt-bearer variant) | `grant=jwt_bearer` + `token_param.requested_token_use=on_behalf_of` |
| **ID-JAG** — Identity Assertion Authorization Grant | cross-app access: chain an ID-JAG from the home IdP to a resource authorization server | `grant=id_jag` |

Warden authenticates itself to the token endpoint with a client secret
(`client_secret_basic`/`client_secret_post`) or a signed **private_key_jwt** client assertion
(RFC 7523 §2.2) — configured independently of the grant.

## Impersonation vs Delegation

RFC 8693 §1.1 distinguishes the two by whether the **minted token carries an `act` claim**:

- **Impersonation** — the minted token represents *only the subject*; no acting party is recorded.
  Warden exchanges the caller's identity (or a user token the agent carries) for a downstream token
  that *is* that principal, with no trace of the agent.
- **Delegation** — the minted token carries an `act` chain ("agent A acting for user B"), so the
  downstream sees, and can enforce policy on, both the subject and the actor.

An `act` claim arises when Warden sends an `actor_token` during the exchange, **or** when the
subject token already carries an embedded `act` (a subject that is itself a delegated token yields
a delegated result even with no actor).

## The Subject and the Actor

Both the subject (who the action is *for*) and the optional actor (who is *acting*) are
caller-derived tokens, each with a trust **origin**:

| Origin | Source | Handling |
|--------|--------|----------|
| **Verified** | the caller's inbound JWT Warden authenticated at the auth mount (`…_token_source=auth_token`) | forwarded as-is |
| **Unverified** | a request header (`X-Warden-Subject-Token` / `X-Warden-Actor-Token`, `…_token_source=header`) | the driver validates signature, issuer, audience and expiry, or **fails closed** |

The canonical delegation shape is **agent-acting-for-user**: the agent carries the user's token as
the subject and its own verified inbound JWT as the actor, so the minted token reads "agent for
user" — with the agent's token sent once, not re-validated. Because the actor is a real, signed
token, it can serve as a cryptographic RFC 8693 actor; the audit label described below cannot.

See [Impersonation vs delegation](/credential-drivers/token-exchange/#impersonation-vs-delegation)
on the driver page for the full configuration and worked examples.

## The Audit Actor Chain

Independently of what is minted, Warden records who a request was *for* in the audit trail. This
chain is an **attribution** record; each actor is a subject plus a trust flag:

| Field | Meaning |
|-------|---------|
| `subject` | The identity being acted for (e.g. `agents/alpha`, `user@example.com`). |
| `verified` | Whether the actor is cryptographically attested (`true`) or self-reported (`false`). |

It reaches Warden two ways, and appears as the `actors` array on the request's audit entry.

### JWT `act` claim — verified

A signed JWT can carry an RFC 8693 §4.1 **`act`** claim; because the IdP signed it, the chain is
**attested** (`verified: true`) and nests to express a chain:

```json
{ "sub": "gateway-service",
  "act": { "sub": "broker-beta",
           "act": { "sub": "agents/alpha" } } }
```

→ actors `[broker-beta (verified), agents/alpha (verified)]`. Warden walks the nesting up to a depth
of **4**, and these actors are extracted at login and **persisted on the [token](/concepts/tokens/)**
so the chain survives transparent-token caching.

### `X-Warden-On-Behalf-Of` header — unverified

When the delegator cannot embed the chain in a JWT — typically a **concentrator** that
authenticates with its own identity and serves many agents — it names the subject it acts for in
the `X-Warden-On-Behalf-Of` header. Warden has no proof of this, so it is recorded as
`verified: false`:

```
X-Warden-On-Behalf-Of: agents/alpha
```

The header carries a **single** subject (1–256 chars, `[A-Za-z0-9._:@/+-]`, no commas), is validated
and dropped if malformed (never failing the request), is **per-request**, and is **stripped before
the request is proxied upstream** so it never leaks past Warden.

Being per-request, the header **wins** over the token-bound `act` chain — so a concentrator reusing
one cached token still attributes each call to the right agent; the token's verified `act` chain is
used only when no header is present:

```
agent alpha  ─▶ concentrator ─▶ Warden   X-Warden-On-Behalf-Of: agents/alpha
agent beta   ─▶ concentrator ─▶ Warden   X-Warden-On-Behalf-Of: agents/beta
```

This audit chain is a string-only attribution label; unlike the signed subject/actor tokens above,
it cannot serve as a cryptographic RFC 8693 actor token.

## See Also

- [Token Exchange](/credential-drivers/token-exchange/) — minting delegated/impersonated downstream tokens.
- [Audit](/concepts/audit/) — where the actor chain is recorded.
- [Authentication](/concepts/authentication/) — the principal the actors act alongside.
- [Tokens](/concepts/tokens/) — where a verified `act` chain is persisted.
