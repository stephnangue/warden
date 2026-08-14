---
title: "Delegation, Impersonation & the User Principal"
description: "How an agent acts on behalf of a verified user — the dual-principal model, the on-behalf-of chain, and per-user access."
---

A request is made *by* an authenticated agent, but it is often made *on behalf of*
someone else — a human, or another agent, that the agent is acting for. Warden models
this with **two principals per request**, so the upstream can be told *who the request is
for*, not just which agent made it.

Throughout this page the second principal is called the **user** — read it as *a human
or another agent the agent acts for*, not necessarily a person.

## The dual-principal model

Every gateway request resolves up to two principals:

- The **agent** — the caller's own credential. It is authenticated, and **today it is
  the sole authorizer**: it alone drives the [policy](/concepts/policies/) decision.
- The **user** — a second, first-class token resolved from a separate request header
  (`X-Warden-User-Token` by default) through the same [auth methods](/auth-methods/), via
  **secondary transparent authentication**. The user is **identity-only**: it does not
  authorize the request and never appears in the policy engine.

> **Present behavior, not a permanent guarantee.** Today the user principal is used only
> for *attribution and scoping* — never authorization. The roadmap is for authorization
> to become the **intersection of the agent's and the user's permissions** (both must
> permit the request). Read "the user does not authorize" as *today*, not *never*.

The feature is opt-in and fail-closed: with no `user_auth_path` configured, the user
principal is absent and the request behaves exactly as before. When configured, a
present-but-invalid, cross-namespace, or agent-equal user credential fails closed.

## Impersonation vs delegation

When Warden brokers a downstream token via the
[token-exchange driver](/credential-drivers/token-exchange/), whether that token names an
actor decides the outcome (RFC 8693 §1.1):

- **Impersonation** — the token represents **only the subject**; no acting party is recorded.
- **Delegation** — the token carries an **`act` claim** ("agent A acting for user B"), so
  the upstream sees, and can authorize on, both.

## Subject and actor, by source

The subject (who the token is *for*) and the optional actor (who is *acting*) are each
drawn from a **source** — and every source is trusted at origin (there is no
caller-supplied, per-request-validated token path):

| Source value | Identity |
|---|---|
| `agent_identity` | The agent's verified inbound JWT. |
| `user_identity` | The user principal's own auth-method-validated credential. Valid only on a `token_exchange` source. |
| `warden_identity` | A [Warden-minted assertion](/federation/oidc-issuer/) for the caller. |
| `none` | Omitted. |

An actor is only meaningful in the delegation shape, so **`actor_token_source ≠ none`
requires `subject_token_source=user_identity`.** The canonical **agent-on-behalf-of-user**
shape puts the user as the subject and the agent as the actor:

```
subject_token_source=user_identity     # sub = the user
actor_token_source=warden_identity      # act = the agent (a Warden-minted assertion)
```

The actor may instead be `agent_identity` — the agent's **own inbound JWT** — for agents
authenticated via a JWT/bearer auth method:

```
subject_token_source=user_identity     # sub = the user
actor_token_source=agent_identity       # act = the agent's inbound JWT
```

Either way the minted token carries `sub`=user, `act`=agent, keyless.

## Two ways to act on behalf of a user

Not every upstream speaks the same on-behalf-of protocol. Warden supports two mechanisms.

### Native token exchange

When the upstream or its IdP supports it, the [token-exchange driver](/credential-drivers/token-exchange/)
forwards the user's token so the downstream token carries `sub`=user / `act`=agent — RFC
7523 `jwt-bearer`, RFC 8693 token-exchange, or ID-JAG cross-app access.

**RFC 7523 (`jwt-bearer`).** Warden exchanges the user's ID token at the IdP for an upstream access token — a single identity, no actor.

<p align="center"><img alt="RFC 7523 jwt-bearer: Warden exchanges the user's ID token at the IdP for an access token and injects it" src="/images/warden-cred-keyless-delegated-rfc7523.png" width="760"></p>

**RFC 8693 token exchange.** The user's token is the subject and the agent's is the actor, so the minted token reads `sub`=user, `act`=agent.

<p align="center"><img alt="RFC 8693: Warden presents the user's subject token and the agent's actor token and receives a token carrying sub=user, act=agent" src="/images/warden-cred-keyless-delegated-rfc8693.png" width="760"></p>

**ID-JAG cross-app access.** The home IdP issues an ID-JAG from the user and agent identities; Warden redeems it at the resource's authorization server for the final token.

<p align="center"><img alt="ID-JAG: the IdP issues an ID-JAG from the user and agent identities; Warden redeems it at the resource authorization server" src="/images/warden-cred-keyless-delegated-id-jag.png" width="820"></p>

### Per-user OAuth token from OpenBao / Vault

Many upstreams — GitHub, Slack, and more — do not (yet) support ID-JAG. For those, lean
on **OpenBao/Vault's OAuth-app secrets engine + templated policies** to mint a genuine
**per-user** OAuth access token: Warden authenticates to the vault keylessly with a
per-user identity assertion, the vault's templated policy scopes the read to that user,
and Warden injects the returned token — so the agent acts on behalf of the user against
an upstream with no native on-behalf-of flow.

**OpenBao/Vault are uniquely suited to do this at scale**: a single **templated policy**
scopes every user, so there is no per-user role explosion.

**Per-user OAuth from a vault.** A per-user identity assertion unlocks that user's OAuth token through a templated policy, which Warden injects into the non-ID-JAG upstream.

<p align="center"><img alt="Warden presents a per-user identity assertion to the secrets vault, whose templated policy returns that user's OAuth token, injected to the upstream" src="/images/warden-fed-per-user-secrets.png" width="760"></p>

## What pairing the user principal with federation unlocks

- **Per-user cloud credentials** — a `warden_identity` spec with
  [`assertion_user_claims`](/federation/assertion-claims/#the-user--warden_user) mints an
  assertion where the agent is `sub`/`warden_sub` but a nested `warden_user` claim names
  the user, so an upstream trust policy scopes access to that user while still binding the
  agent.
- **Per-user secrets** — a `kv2_read` `secret_path` and the `oauth2` mint method's
  `credential_name` may template `{{user.<claim>}}`, so a per-user secret or token is
  selected by a verified user claim.
- **Per-user cache & audit** — the minted credential is cached per user, bounded by *both*
  principals' TTLs (revoke or expire either and new mints stop), and every mint is
  attributed to the user via `Auth.User` in the [audit log](/concepts/audit/) — without
  the raw user credential ever being logged.

## The audit actor chain

Independently of what is minted, Warden records who a request was *for* in the audit
trail. The chain has a **single source — the cryptographically-verified RFC 8693 `act`
claim** on the caller's token — and appears as the `actors` array on the request's audit
entry. Each actor is `{subject}`; because every actor is verified, there is no `verified`
field.

A signed JWT can carry a nested `act` claim, so the chain expresses "gateway → broker →
agent"; Warden walks the nesting and persists the extracted actors on the
[token](/concepts/tokens/), so the chain survives transparent-token caching.

## Configuration

Set on the provider mount or namespace:

| Key | Default | Description |
|---|---|---|
| `user_auth_path` | *(off)* | The auth mount that validates the user credential. Bearer-format mounts only. Absent ⇒ no user principal. |
| `user_token_header` | `X-Warden-User-Token` | Request header carrying the user credential. |
| `user_auth_role` | *(mount default)* | Role the user auth uses. |

On a `warden_identity` spec, `assertion_user_claims` (comma-separated) discloses the user
under the `warden_user` claim.

**Fail-closed matrix** — the request is denied when: the user credential equals the
agent's; the user token is from another namespace; the user mount is not bearer-format; a
named user claim is absent; a `{{user.*}}` template resolves to an unsafe path segment; or
either token has expired.

## See also

- [Token Exchange](/credential-drivers/token-exchange/) — the exchange mechanics.
- [Credential chaining](/federation/credential-chaining/) — per-user secrets from a keyless vault.
- [Assertion claims](/federation/assertion-claims/) — the `warden_user` claim.
- [Audit](/concepts/audit/) — where the actor chain and `Auth.User` are recorded.
- [Tokens](/concepts/tokens/) — where a verified `act` chain is persisted.
