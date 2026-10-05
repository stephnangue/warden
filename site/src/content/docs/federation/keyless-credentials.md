---
title: "Keyless credential sources"
description: "Federate a Warden identity assertion for a short-lived credential, with no stored secret — and have the server warn about, or refuse, writes that would store one."
---

A credential source normally has to hold a secret to reach its upstream — an access key,
a service-account key, a token. A **keyless** source holds **none**. Instead of presenting
a stored secret, on each request Warden proves *who the caller is* to the upstream with a
short-lived [identity assertion](/federation/oidc-issuer/); the upstream — set up to trust
Warden's issuer — verifies it and issues a short-lived credential itself. The secret that
used to sit in Warden simply no longer exists, so there is nothing there to leak or rotate.

Two config keys carry the whole idea, and they answer different questions:

- **`auth_method`** — *how* Warden authenticates the source: `static`/stored-key (the
  default on most drivers) or `oidc_federation` (keyless).
- **`mint_method`** — *what* the source produces (an assumed role, a bearer token, a
  secret read). Unchanged by keyless mode.

Where an upstream cannot federate at all, the secret it needs can still stay out of
Warden: [credential chaining](/federation/credential-chaining/) fetches it per request
from your own secret store, through a keyless source. Storing a secret in Warden is the
quick start, not the model — and with
[`keyless_enforcement_level`](#keyless-enforcement) a server warns about, or refuses,
writes that would store one.

## The subject: whose identity is federated

`subject_token_source` selects what the exchanged token asserts:

| `subject_token_source` | The upstream sees | Needs the Warden issuer? |
|---|---|---|
| `warden_identity` | A Warden-issued assertion naming the agent — or, when the spec [discloses a user](/federation/assertion-claims/#when-a-user-is-disclosed), the user with the agent in `act`. | Yes — the issuer must be configured and its keys reachable. |
| `agent_identity` | The **agent's own inbound JWT**, federated directly at the cloud's web-identity endpoint. | No — the cloud trusts the agent's original IdP. |

A keyless spec **must set `subject_token_source`** — it has no default, and a spec that
omits it fails closed at mint. Use `warden_identity` for the full Warden identity model
(per-user claims, resource pinning, a claim shape per verifier); use `agent_identity`
when the agent already carries a JWT the cloud can trust and you want no Warden-issued
hop. The Anthropic and OpenAI sources accept `warden_identity` only.

The shape of a `warden_identity` assertion is chosen per spec with
[`assertion_profile`](/federation/assertion-claims/#assertion-profiles): new AWS specs get
`aws` (session tags), new Azure specs `minimal` (registered claims only), and everything
else `default`.

For a **public** upstream, the assertion is verified against the JWKS at the
issuer's discovery URL — which a [publisher](/federation/oidc-issuer/#publishers-reaching-internet-facing-upstreams)
exposes on a bucket/CDN, so the upstream can reach it without Warden being internet-facing.

## Per-upstream support

This is the reference for which mint methods federate keylessly. Each driver page has
the full config; here is the map.

### AWS

- **`sts_assume_role`** — `AssumeRoleWithWebIdentity`: the assertion is exchanged for a
  short-lived STS session for `role_arn`. No `access_key_id`/`secret_access_key` on the
  source.
- **`secrets_manager`** — a keyless read: federate a short-lived role session, then
  `GetSecretValue`. `credential_type` (`aws_access_keys` default, or `api_key`) is valid
  **only** with this mint method.
- **`secret_read`** — the same read, vended verbatim as a chaining producer.

The source sets `auth_method=oidc_federation` and `region`; the role's trust policy
federates Warden's issuer. A new spec mints with `assertion_profile=aws`, so the trust
policy must allow **`sts:TagSession`** beside `sts:AssumeRoleWithWebIdentity`. See
[AWS driver](/credential-drivers/aws/).

### Azure

- **`bearer_token`** — Warden presents the assertion to Entra as a `client_assertion`
  (JWT-bearer grant) instead of a `client_secret`. The source sets just
  `auth_method=oidc_federation`; the **spec** carries the workload `client_id` and
  `tenant_id`, and `audience` is optional (defaults to `api://AzureADTokenExchange`).
- **`secret_read`** — a Key Vault read, authenticated the same way as the app
  registration the spec names; it can be the producer at the far end of a chain.

A new spec mints with `assertion_profile=minimal`, since Entra matches only `iss`, `sub`
and `aud`. See [Azure driver](/credential-drivers/azure/).

### GCP

- **Workload Identity Federation** at `sts.googleapis.com`, then a Google access token.
  Mint methods are **`access_token`** and **`impersonated_access_token`** (the latter
  impersonates a `target_service_account`), plus **`secret_read`** for Secret Manager. The
  source sets `auth_method=oidc_federation` and the full `workload_identity_provider`
  resource name. See [GCP driver](/credential-drivers/gcp/).

### OpenBao / Vault

- Keyless authenticates **per request against Vault's own JWT auth method**
  (`auth/<jwt_mount>/login` with `jwt_role`), then either vends that login token
  (`mint_method=vault_token`) or brokers a downstream secret with it. The `audience`
  must equal the Vault role's `bound_audiences`. A keyless source needs no
  `rotation_period`, and a keyless `vault_token` spec needs no `token_role`. See
  [Vault driver](/credential-drivers/vault/).

### Alibaba Cloud

- **`assume_role`** — STS `AssumeRoleWithOIDC`: the assertion is exchanged for a
  short-lived STS session. Set `oidc_provider_arn` on the source to name the OIDC
  provider Alibaba Cloud trusts. This is the **only** mint method that federates. RAM
  binds only `iss`, `aud` and `sub`, so no user is ever disclosed to it. See
  [Alibaba Cloud driver](/credential-drivers/alicloud/).

### Kubernetes

- The assertion is presented **directly as the bearer token** to the API server — there
  is no exchange hop, because the cluster verifies the issuer itself. The assertion
  `audience` must match one of the cluster authenticator's accepted audiences, or the
  API server rejects it. See [Kubernetes driver](/credential-drivers/kubernetes/).

### Anthropic

- An **`anthropic`** source exchanges the assertion at Anthropic's token endpoint (an
  RFC 7523 `jwt-bearer` grant, with no client authentication) for a short-lived API
  token, which the [Anthropic provider](/provider-backends/anthropic/) sends as a bearer.
  Federation is the source's only mode. The source sets `organization_id`; each spec
  names the `federation_rule_id` and `service_account_id`, and a `workspace_id` when the
  rule covers more than one workspace. See
  [Anthropic driver](/credential-drivers/anthropic/).

### OpenAI

- An **`openai`** source exchanges the assertion at `auth.openai.com` (an RFC 8693 token
  exchange, with no client authentication) for a short-lived token, which the
  [OpenAI provider](/provider-backends/openai/) sends as a bearer. Federation is the
  source's only mode. The source sets the `identity_provider_id` that trusts Warden's
  issuer; each spec names the `service_account_id` the token acts as. See
  [OpenAI driver](/credential-drivers/openai/).

## Chaining a secret keylessly

Federation mints a credential the upstream issues. When the upstream instead needs a
**standing secret** Warden would otherwise store, [credential chaining](/federation/credential-chaining/)
sources that secret from a keyless-federated store per request — so a secret-backed
provider becomes keyless at Warden too. The two features are designed to be used together.

The **`cloudflare`** source is built this way: it stores nothing, and each `cloudflare_keys`
spec names, in its own `secret_spec`, the spec that yields its API token and/or R2 key
pair. See [Cloudflare driver](/credential-drivers/cloudflare/).

## Keyless enforcement

**`keyless_enforcement_level`**, a top-level key in the
[server configuration](/configuration/), decides what happens to a write that would
leave a secret stored in Warden:

```hcl
keyless_enforcement_level = "enforce"
```

| Level | A write that would leave a secret stored in Warden |
|---|---|
| `off` | Is accepted silently. |
| `warn` *(default)* | Is accepted; the response carries a warning under `warnings`, and the server logs it. |
| `enforce` | Is refused with `400`, naming what would be stored and the keyless alternative. |

What counts as storing a secret:

- a **source** whose config holds a secret field — an access key, a client secret, a
  stored token — or, for a secrets-vault source, a token taken from the server's
  environment;
- a **spec** whose config holds one, such as an inline API key;
- **any spec on the `local` source**, whose config *is* the credential;
- an OAuth2 **`authorization_code`** spec, whose consent flow seals a refresh token —
  under `enforce`, `authorize` and `connect` are refused before the provider is reached;
- on **create**, a spec bound to a source that stores a secret.

The level applies to **operator writes only**, at write time. Sources and specs created
before it was raised keep minting, and Warden's own write-backs — rotation, a
refresh-token update — still go through. Under `enforce`, though, *any* operator edit to
a keyed object is refused, even an unrelated one such as `max_ttl`, until the secret is
removed; deleting it is always allowed. The level is read once at startup, applies to
every namespace, and changes with a restart.

Every source and spec read and list reports what it stores as **`stored_secrets`** —
field names only, never values — and omits it when nothing is stored:

```bash
warden cred source list
```

To move an object off a stored secret, **`warden cred source keyless-plan`** and
**`warden cred spec keyless-plan`** print the replacement — the upstream trust to set up,
the keyless objects to create beside the keyed ones, and what to delete once roles use
them. They write nothing. See [`warden cred`](/cli/cred/#keyless-plan).

## See also

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what mints and signs the assertion.
- [Assertion claims](/federation/assertion-claims/) — profiles, audience, resource, metadata, per-user.
- [Credential chaining](/federation/credential-chaining/) — a standing secret, fetched per request from your store.
- [Credentials](/concepts/credentials/) — the source / spec / credential model.
