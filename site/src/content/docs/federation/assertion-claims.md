---
title: "Assertion claims"
description: "How Warden shapes and scopes the identity assertion an upstream verifies — audience, resource, metadata, and per-user."
---

An [identity assertion](/federation/oidc-issuer/) is a JWT, and what an upstream trust
policy can gate on is *its claims*. This page covers the claims Warden puts in a
`warden_identity` assertion and the spec keys that shape them.

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
