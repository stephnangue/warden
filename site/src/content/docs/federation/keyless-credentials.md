---
title: "Keyless credential sources"
description: "Federate a Warden identity assertion for a short-lived cloud credential — no stored cloud secret."
---

A credential source normally holds a secret Warden authenticates with — an access
key, a service-account key, a token. A **keyless** source holds **none**. Instead it
sets `auth_method = "oidc_federation"`: on each request Warden mints an
[identity assertion](/federation/oidc-issuer/) for the caller and exchanges it at the
cloud for a short-lived credential. The cloud is configured to trust Warden's issuer,
so it verifies the assertion and issues the credential itself.

Two config keys carry the whole idea, and they answer different questions:

- **`auth_method`** — *how* Warden authenticates the source: `static`/stored-key (the
  default) or `oidc_federation` (keyless).
- **`mint_method`** — *what* the source produces (an assumed role, a bearer token, a
  secret read). Unchanged by keyless mode.

## The subject: whose identity is federated

`subject_token_source` selects what the exchanged token asserts:

| `subject_token_source` | The upstream sees | Needs the Warden issuer? |
|---|---|---|
| `warden_identity` *(default)* | A Warden-issued assertion naming the agent (and, if present, the user). | Yes — the issuer must be configured and its keys reachable. |
| `agent_identity` | The **agent's own inbound JWT**, federated directly at the cloud's web-identity endpoint. | No — the cloud trusts the agent's original IdP. |

Use `warden_identity` for the full Warden identity model (per-user claims, resource
pinning); use `agent_identity` when the agent already carries a JWT the cloud can trust
and you want no Warden-issued hop.

For a **public-cloud** upstream, the assertion is verified against the JWKS at the
issuer's discovery URL — which a [publisher](/federation/oidc-issuer/#publishers-reaching-internet-facing-upstreams)
exposes on a bucket/CDN, so the cloud can reach it without Warden being internet-facing.

## Per-cloud support

This is the reference for which mint methods federate keylessly. Each driver page has
the full config; here is the map.

### AWS

- **`sts_assume_role`** — `AssumeRoleWithWebIdentity`: the assertion is exchanged for a
  short-lived STS session for `role_arn`. No `access_key_id`/`secret_access_key` on the
  source.
- **`secrets_manager`** — a keyless read: federate a short-lived role session, then
  `GetSecretValue`. `credential_type` (`aws_access_keys` default, or `api_key`) is valid
  **only** with this mint method.

The source sets `auth_method=oidc_federation` and `region`; the role's trust policy
federates Warden's issuer. See [AWS driver](/credential-drivers/aws/).

### Azure

- **`bearer_token`** — Warden presents the assertion to Entra as a `client_assertion`
  (JWT-bearer grant) instead of a `client_secret`. The source sets
  `auth_method=oidc_federation`, `tenant_id`, `client_id`, and the `audience`.
- **`key_vault_secret`** is **not** federated — a keyless source that targets it fails
  closed. See [Azure driver](/credential-drivers/azure/).

### GCP

- **Workload Identity Federation** at `sts.googleapis.com`, then a Google access token.
  Mint methods are **`access_token`** and **`impersonated_access_token`** (the latter
  impersonates a `target_service_account`). The source sets
  `auth_method=oidc_federation` and the full `workload_identity_provider` resource name.
  See [GCP driver](/credential-drivers/gcp/).

### OpenBao / Vault

- Keyless authenticates **per request against Vault's own JWT auth method**
  (`auth/<jwt_mount>/login` with `jwt_role`), then either vends that login token
  (`mint_method=vault_token`) or brokers a downstream secret with it. The `audience`
  must equal the Vault role's `bound_audiences`. A keyless source needs no
  `rotation_period`, and a keyless `vault_token` spec needs no `token_role`. See
  [Vault driver](/credential-drivers/vault/).

## Chaining a secret keylessly

Federation mints a credential the cloud issues. When the upstream instead needs a
**standing secret** Warden would otherwise store, *credential chaining* sources that
secret from a keyless-federated vault per request — so a secret-backed provider becomes
keyless at Warden too. The two features are designed to be used together.

## See also

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what mints and signs the assertion.
- [Assertion claims](/federation/assertion-claims/) — how the assertion is scoped (audience, resource, metadata, per-user).
- [Credentials](/concepts/credentials/) — the source / spec / credential model.
