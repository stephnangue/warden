---
title: "Per-user access"
description: "Let an agent act as the verified person behind it — scoped, attributed, and at scale — even for upstreams with no on-behalf-of flow."
sidebar:
  order: 1
---

_Let an agent act as the person behind it — scoped, attributed, and at scale._

## One agent, many users, one blurred identity

An agent rarely acts for itself. It answers a question for Alice, files a ticket for
Bob, opens a pull request for a whole team. But the usual setup gives that agent a
single service identity, so every upstream call — Alice's, Bob's, everyone's — arrives
as the *same* principal. The upstream cannot scope access to the actual person, cannot
tell one user's action from another, and cannot record who a change was really for. The
human behind the request disappears the moment it reaches the agent.

Granting real per-user access the old way does not scale. You would provision a
credential, a role, or a policy per user — hundreds of near-identical roles to create,
rotate, and retire — and most upstreams that agents reach (GitHub, Slack, and many more)
have **no native on-behalf-of flow** at all, so there is no standard way to carry the
user's identity through to them.

## Two principals, and the user carried through

Warden resolves **two identities per request**: the **agent** that calls, and the
**[user](/concepts/delegation/)** it acts for — a human, or another agent — presented
per request and validated through the same auth methods. The user is identity-only, so
it never widens what the agent may do; it is there to *scope* and *attribute* the access.

Carrying the user through to the upstream works two ways:

- **Native on-behalf-of.** Where the upstream or its IdP supports it, Warden exchanges the
  user's token. With **RFC 8693** or **ID-JAG** the downstream token carries both identities
  (`sub`=user, `act`=agent); **RFC 7523** (jwt-bearer, e.g. Entra OBO) has no actor slot, so it
  is impersonation — `sub`=user, no `act`. And with
  [keyless federation](/federation/keyless-credentials/), a Warden assertion can carry the user
  under a `warden_user` claim — so a verifier that evaluates arbitrary claims (a GCP attribute
  condition, an OpenBao/Vault `jwt` auth mount) scopes access to that user while still binding
  the agent. (AWS and Azure STS bind trust only on `sub`/`aud`, so the `warden_user` claim is
  informational there.)
- **A per-user token from OpenBao / Vault — at scale.** For the many upstreams without
  ID-JAG, Warden reaches a Vault/OpenBao **OAuth-app secrets engine** (an OAuth secrets-engine
  plugin) with a per-user identity assertion; a single **templated policy** scopes the read to
  that user and vends a genuine per-user token, which Warden injects. One policy covers every
  user — no per-user role explosion — so on-behalf-of works for GitHub, Slack, and the rest, at
  fleet scale.

Either way the credential is minted per user, cached per user, and bounded by both the
agent's and the user's token TTLs — and every mint is attributed to the user in the
[audit log](/concepts/audit/) (`Auth.User`), without the raw user credential ever being
recorded.

## Benefits

- **Real per-user scope** — the upstream authorizes the actual person, not a shared agent
  identity.
- **On-behalf-of everywhere** — native exchange where it exists, and a per-user
  OpenBao/Vault token where it does not — with one templated policy, not one role per user.
- **Per-user attribution** — every action is tied to the verified human (or agent) behind
  it, the raw user credential never logged.

## In practice

An agent triages support tickets for many users. When it acts for Alice, her identity is
presented alongside the agent's; Warden reaches the OAuth-app engine with a per-user
assertion, the templated policy returns *Alice's* GitHub token, and the agent opens the
pull request **as Alice** — even though GitHub has no ID-JAG flow. The audit entry names
the agent as principal and Alice as `Auth.User`, so the change traces to the person, and
tomorrow's request for Bob reuses the same one policy with no new role to create.

## See Also

- [Delegation](/concepts/delegation/) — the dual-principal model and the two on-behalf-of mechanisms.
- [Keyless credential sources](/federation/keyless-credentials/) — carrying the user in the `warden_user` claim.
- [Credential chaining](/federation/credential-chaining/) — the per-user secret fetch.
- [Audit & attribution](/use-cases/audit-attribution/) — where the per-user action is recorded.
