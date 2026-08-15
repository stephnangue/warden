---
title: "Assertion claims"
description: "How Warden shapes and scopes the identity assertion an upstream verifies — audience, resource, metadata, and per-user."
---

When an upstream trusts Warden's issuer, it decides *whether* to honor an
[identity assertion](/federation/oidc-issuer/) — and *how narrowly* to scope what it hands
back — by reading the assertion's **claims**. Shaping those claims is how you hold access to
least privilege at the token level: disclose only what a trust policy needs, pin one
assertion to a single resource, and carry the user when acting on their behalf.

This page covers the claims Warden puts in a `warden_identity` assertion and the spec keys
that shape them.

:::note[Internal use only]
An identity assertion is an **internal, per-request artifact**. Warden mints it and exchanges
it at the upstream itself — it is **never handed to the agent**. Agents present only their own
identity to Warden and never see, hold, or send a `warden_identity` assertion. The decoded
example below is here to explain what a *verifier* receives, not something a caller handles.
:::

Every assertion carries the standard `iss`, `aud`, `iat`, `nbf` (backdated by a small
skew leeway), `exp`, `jti`, and a subject that names the agent:

| Claim | Value |
|---|---|
| `sub` | `wid:<namespaceID>:<mountAccessor>:<principalID>` — globally unique across namespaces and auth mounts. |
| `warden_sub` | The agent's raw principal ID. |
| `warden_role` | The role the request assumed. |
| `warden_namespace` | The namespace path. |
| `warden_auth_mount` | The auth mount accessor the agent authenticated through. |

Everything below is opt-in scoping on top of that.

## A full assertion

A minted assertion is a signed JWT — `header.payload.signature`, base64url-encoded. Decoded,
a fully-populated one (an agent acting for a user, with metadata and a pinned resource) looks
like this.

**Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "warden-oidc-rs256-1"
}
```

**Payload:**

```json
{
  "iss": "https://warden.example.com",
  "sub": "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
  "aud": "sts.amazonaws.com",
  "iat": 1755248400,
  "nbf": 1755248370,
  "exp": 1755248700,
  "jti": "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
  "warden_sub": "agent-checkout-7",
  "warden_role": "orders-reader",
  "warden_namespace": "team-payments/",
  "warden_auth_mount": "auth_jwt_9c1e",
  "warden_resource": "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
  "warden_metadata": {
    "team": "payments",
    "env": "prod"
  },
  "warden_user": {
    "sub": "alice@example.com",
    "username": "alice"
  }
}
```

The standard and `warden_*` identity claims (down to `warden_auth_mount`) are **always**
present. `nbf` is `iat` minus the skew leeway and `exp` is `iat` plus the assertion TTL
(5 minutes by default). `sub` is the composite `wid:<namespaceID>:<mountAccessor>:<principalID>`,
while `warden_sub` carries the raw principal on its own so a verifier can bind it without
parsing the composite.

The final three — `warden_resource`, `warden_metadata`, and `warden_user` — are the
**opt-in scoping** the rest of this page explains. Each is omitted entirely when not
configured, so a minimal assertion stops at `warden_auth_mount`.

## Audience

The audience (`aud`) is a property of the source's federation trust, so it is usually
set **once on the source** and derived per driver. An explicit spec-level
**`assertion_audience`** takes precedence, and is required whenever no source-derived
fallback exists (for example, a Vault source forces the spec key when its `audience`
is unset).

## Signing

Every assertion is signed by the issuer's private key — which **may be held in an
external KMS** so it never lives in Warden (see [signer configuration](/configuration/signer/)).
**`assertion_algorithm`** selects the signature algorithm — `RS256` (default) or
`ES256`; the issuer keeps a key set per algorithm, so switching is a config change, not
a re-key.

## Pinning a resource — `warden_resource`

A minted assertion can name the **single downstream resource** the spec targets, under
a top-level `warden_resource` claim, so a verifier that checks arbitrary bound claims
can pin one assertion to one resource — least privilege at the token level.

The value is **auto-derived** from the spec's config (pure config reads — nothing
touches the network):

| Spec | `warden_resource` |
|---|---|
| AWS `secrets_manager` | `aws-secretsmanager:<secret_id>` |
| AWS `sts_assume_role` | `aws-iam:<role_arn>` |
| Azure `bearer_token` | `azure:<resource_uri>` (always emitted — `resource_uri` defaults to `https://management.azure.com/`) |
| GCP `impersonated_access_token` | `gcp-iam:<target_service_account>` |
| GCP `access_token` | `gcp-wif:<workload_identity_provider>` |
| Vault (`hvault`) | an **unprefixed** value per mint method — the `<kv2_mount>/<secret_path>`, `<aws_mount>/<role_name>`, `jwt_role`, etc. |
| `token_exchange` (single RFC 8707 resource) | `oauth-resource:<uri>` |

Override the derived value with **`assertion_resource=<value>`**, or suppress the claim
with **`assertion_resource=none`**. Treat the value as **opaque** — never parse it (a
resource id may itself contain `:`, and Vault values carry no prefix at all).

> Enforcement is verifier-side. AWS/Azure federation trust policies bind only on
> `sub`/`aud`, so there the claim is informational; it is enforced by a verifier that
> checks arbitrary bound claims — an external Vault/OpenBao `jwt` auth mount, or
> Warden's own JWT auth method — configured to trust Warden's issuer.

## Login metadata — `assertion_metadata_claims`

Set **`assertion_metadata_claims`** (comma-separated) to project selected
login-derived [token-metadata](/concepts/tokens/) keys into the assertion, so an
upstream trust policy can gate on attributes such as `team` or `env` without minting a
distinct upstream role per value.

It is least-disclosure: only the named keys are included — never the whole metadata map
— and they ride under a single nested **`warden_metadata`** claim so they cannot clobber
a registered or `warden_*` claim. The set is size-capped (the request fails closed if
exceeded) and folded into the credential-cache key.

## The user — `warden_user`

When a [user principal](/concepts/delegation/) is present, a `warden_identity` spec may
set **`assertion_user_claims`** to disclose the user under a nested **`warden_user`**
claim — the user's own `sub` plus allowlisted metadata — so an upstream trust policy can
scope access per user while the assertion still names the agent. This agent-plus-user
channel is detailed on the [Delegation](/concepts/delegation/) page, which owns the
user-principal model.

## Upgrade note

Any `warden_identity` spec with a derivable `warden_resource` (or a projected metadata
set) emits an additional claim, and its exchange cache key changes — a one-time re-mint
on upgrade. Set `assertion_resource=none` to keep the prior assertion bytes.

## See also

- [Keyless credential sources](/federation/keyless-credentials/) — where these assertions are exchanged.
- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what mints and signs them.
- [Delegation](/concepts/delegation/) — the user principal and `warden_user`.
