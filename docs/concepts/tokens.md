# Tokens

A **token** is Warden's internal representation of an authenticated identity.
When a caller authenticates — by logging in against an auth method, or by
presenting a credential that Warden resolves transparently — the result is a
token: a record that binds a set of policies, a namespace, a principal, an
expiry, and — when the role calls for it — a credential spec scoping what Warden
may mint for the caller. Every authorized request operates against a token,
whether the caller ever sees its value or not.

This document describes how tokens are structured, the token types Warden
issues, and how they are created, looked up, and revoked. For *how* a caller
authenticates in the first place, see [Authentication](authentication.md).

## Two Families of Token

Warden issues two broad families of token, distinguished by how the caller
obtains and presents them.

**Session tokens** are the familiar Vault-style flow. The caller logs in, Warden
returns an opaque bearer token, and the caller sends it on the `X-Warden-Token`
header with every subsequent request. The token is persisted and lives until it
expires or is revoked. The [root token](#the-root-token) is a session token.

**Transparent tokens** back [transparent authentication](authentication.md#transparent-authentication).
The caller never logs in or holds a Warden token; it presents its own credential
— a JWT, a TLS client certificate, a Kubernetes ServiceAccount token, a SPIFFE
identity — on each request, and Warden mints a token on its behalf. These tokens
are **cache-only**: they are never written to storage, and they are re-minted
automatically whenever the same credential arrives again.

## Token Types

Each token belongs to a typed implementation that defines its format and how it
is generated and identified. Warden ships five:

| Type | ID prefix | Auth method | Family | Default TTL |
|------|-----------|-------------|--------|-------------|
| `warden_token` | `wtkn_` | — (native) | session | 1 hour |
| `jwt_role` | `jwtr_` | `jwt` | transparent | 1 hour |
| `cert_role` | `cert_` | `cert` | transparent | 1 hour |
| `kubernetes_role` | `kubr_` | `kubernetes` | transparent | 1 hour |
| `spiffe_role` | `spif_` | `spiffe` | transparent | 1 hour |

The four role types correspond one-to-one with the [auth methods](authentication.md#auth-methods).
Only `warden_token` is a true bearer token the caller carries; the role types are
artifacts of resolving a presented credential and are bound to the
[role](roles.md) the caller authenticated against.

## Anatomy of a Token

### The Warden token value

A native session token is an opaque string with the prefix `cws.` followed by 64
random characters — 68 characters in total. Warden never stores the raw value;
it stores a hash, and derives the token's internal **ID** as `wtkn_` followed by
the first 32 hex characters of the SHA-256 of the value. A leaked storage
backend therefore does not yield usable tokens.

> **Note:** Transparent tokens have no `cws.`-style bearer value at all.
> Their identity *is* the presented credential. Warden computes their ID
> deterministically from the credential, the auth mount, and the role — so the
> same credential against the same role always maps to the same cached token,
> and a busy workload reuses one token instead of minting a new one per request.

### The accessor

Every token also has an **accessor**: a random 32-character reference (distinct
from the token value) used for operations that must act on a token *without*
handling its secret — looking up its metadata or revoking it. An accessor cannot
be used to authenticate; it only names a token.

### Token metadata

Each token record carries the context needed to authorize and audit it:

| Field | Meaning |
|-------|---------|
| `Type` | The token type (`warden_token`, `jwt_role`, …). |
| `Policies` | The [policies](policies.md) granted to the caller. |
| `NamespaceID` / `NamespacePath` | The [namespace](namespaces.md) the token was issued in. |
| `PrincipalID` / `RoleName` | The authenticated principal and the role it matched. |
| `CreatedAt` / `CreatedByIP` | When and from where the token was created. |
| `ExpireAt` | When the token stops being valid. |
| `CredentialSpec` | The credential the token is scoped to issue, if any. |
| `Actors` | A verified on-behalf-of chain (from a JWT `act` claim), preserved so [delegation](delegation.md) survives transparent-token caching. |

## Lifecycle

### Creation

Session tokens are created at the end of a successful explicit login. Transparent
tokens are created during implicit auth, the first time a given credential +
role is seen. In both cases Warden generates the token, indexes it, and — for
session tokens — persists it.

### Storage and caching

Tokens are served from an in-memory cache for fast lookup, backed by encrypted
storage for durability:

- **By ID** — the primary index, mapping a token's ID to its full record.
- **By accessor** — a secondary index, mapping an accessor to a token ID.

Session tokens are **written through** to the encrypted storage backend, so they
survive restarts and unseals. Transparent tokens are **cache-only** by
design — they are never persisted, and after a restart or seal they simply do
not exist until the next request re-mints them. This keeps high-volume,
per-request workload credentials out of durable storage entirely.

### Lookup and validation

To resolve a presented credential, Warden detects its token type, computes the
ID, and looks it up in the cache, falling back to storage for session tokens. A
token is accepted only if it passes every check:

- **Not expired** — the current time is before `ExpireAt`.
- **Namespace match** — the token is valid in its own namespace and any
  descendant, but not in a sibling or ancestor namespace (see
  [Namespaces](namespaces.md)).
- **Origin binding** — if the token is bound to a client IP, the request must
  originate from it.

### Expiration and renewal

All token types default to a **1-hour TTL**. Expiry is enforced by a timer-based
expiration manager (whose schedule is persisted for session tokens and held in
memory for transparent tokens).

Warden tokens are **not renewable**. A session token that expires requires a
fresh login; there is no extend-in-place operation. Transparent tokens need no
renewal at all — when one expires, the caller's next request presents the same
credential and Warden mints a new token automatically.

### Revocation

A token can be revoked ahead of its expiry:

- **By accessor** — revoke a specific token without handling its value.
- **By namespace** — revoke every token issued in a namespace at once (for
  example, when tearing the namespace down).

Revocation removes the token from the cache and from storage; subsequent use of
the value or accessor fails.

## The Root Token

The **root token** is a special `warden_token` carrying the built-in `root`
policy, the root namespace, and **no expiration**. It is the bootstrap identity:
the credential you use to enable auth methods, write policies, and configure the
server before any other identity exists.

A dedicated manager tracks the current root token in memory. Its lifecycle:

- **Created at initialization** — printed once in the [dev server](dev-server.md)
  startup banner, or returned by `warden operator init` on a production server.
- **Regenerated** — generating a new root token revokes the previous one, so only
  one is ever valid.
- **Custom value (dev only)** — `-dev-root-token` replaces the generated value
  with one you choose, which is convenient for fixtures and scripts.
- **Revocable** — the root token can be revoked outright once you have
  established narrower administrative identities.

Because the root token bypasses policy, treat it as a break-glass credential:
use it to establish least-privilege auth methods and policies, then prefer those
for day-to-day work.

## See Also

- [Authentication](authentication.md) — how a caller proves identity and obtains
  a token.
- [Roles](roles.md) — how an auth method maps a credential to policies and token
  settings.
- [Policies](policies.md) — what a token is authorized to do.
- [Namespaces](namespaces.md) — the isolation boundary every token is bound to.
