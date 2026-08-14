---
title: "Credential Drivers"
description: "The component that mints the credential Warden injects — organized by what Warden stores and whose identity the upstream sees."
---

A **driver** is the component responsible for minting the credential that Warden
injects into the outbound request. A [credential source](/concepts/credentials/)
names a driver through its `type`; when a workload's request reaches a
[provider](/concepts/providers/) mount, the driver produces the scoped credential
for that upstream and Warden injects it into the proxied call. The workload
presents only its [identity](/concepts/authentication/) — it never holds the
credential itself.

See [Credentials](/concepts/credentials/) for the source / spec / credential model
these pages build on.

## Two axes

A driver supports combinations along **two orthogonal axes**, chosen per source/spec.
GitHub is the proof: the *same* driver stores its App key/PAT inline, **or** chains it
keylessly.

### Axis 1 — what Warden stores

This is the axis that matters for security: *does Warden hold a secret?* It is the
recommendation gradient — keyless first, static last. There are two categories:
**Keyless** and **Inline secret**.

#### Keyless (recommended)

Warden stores **nothing**. Either the source federates an
[identity assertion](/federation/oidc-issuer/) for a credential the upstream issues
([`oidc_federation`](/federation/keyless-credentials/)), or it
[chains](/federation/credential-chaining/) the secret from a keyless-federated vault
per request. This is the recommended mode, and it is coming to every driver.

The upstream verifies a short-lived assertion and issues a credential directly — no stored secret.

<p align="center"><img alt="Warden mints a short-lived identity assertion for the agent, the cloud STS verifies it against the trusted issuer and returns short-lived keys, which Warden injects" src="/images/warden-cred-keyless-federated-identity.png" width="760"></p>

#### Inline secret (discouraged)

:::caution
The **inline-secret mode** stores a secret in Warden — prefer keyless (promote via
[chaining](/federation/credential-chaining/)) or delegated. If you must store one,
**dynamic** beats **static**, and **static is not for production**.
:::

The secret is **stored in Warden** — any stored secret is attack surface, so promote it
to keyless via chaining. It has two sub-modes, both discouraged relative to keyless:

**Dynamic** — the least-bad inline option: Warden uses the stored secret to mint a **short-lived** credential from the upstream's token service, then injects that.

<p align="center"><img alt="The driver uses a stored key to call the upstream security token service, receives a short-lived token, and injects it" src="/images/warden-cred-inline-dynamic-shared-service.png" width="760"></p>

**Static** — the worst: Warden injects a **long-lived** stored secret unchanged.

<p align="center"><img alt="An agent presents its identity to Warden; the driver injects a stored static key into the request to the upstream" src="/images/warden-cred-inline-static-shared-service.png" width="760"></p>

:::note
**Chaining is the transition** that moves a driver from inline-secret to keyless:
instead of storing the secret, the driver sources it from a keyless-federated vault
per request. See [credential chaining](/federation/credential-chaining/).
:::

### Axis 2 — whose identity the upstream sees

Orthogonal to storage:

- **Shared service identity** — an inline stored/minted credential; the upstream
  sees Warden's own service account and can't tell callers apart.
- **Federated identity (agent + user)** — with native federation the assertion
  channels the agent (and, when present, the [user](/concepts/delegation/) via
  `warden_user`), so the upstream authorizes the real agent, and can gate on the user.
- **Delegated / on-behalf-of** — the [`token_exchange`/`oauth2`](/credential-drivers/token-exchange/)
  drivers forward the caller's token so the downstream token carries `sub`=user /
  `act`=agent (RFC 7523 / 8693 / ID-JAG). See [Delegation](/concepts/delegation/) for
  the flows and diagrams. `token_exchange` is *just another driver on Axis 1* — inline
  or keyless-via-chaining, like GitHub.

## Capability matrix

Because drivers are multi-mode, this is the authoritative "what can this driver do"
view. **Keyless** columns are best; **Inline: static** is discouraged.

| Driver (`type`) | Keyless: federation | Keyless: chaining | Inline: dynamic | Inline: static | Delegated |
|---|:--:|:--:|:--:|:--:|:--:|
| `aws` | ✓ | | ✓ | ✓ | |
| `azure` | ✓ | | ✓ | ✓ | |
| `gcp` | ✓ | | ✓ | | |
| `hvault` | ✓ | | ✓ | ✓ | |
| `token_exchange` | | ✓ | ✓ | | ✓ |
| `oauth2` | | ✓ | ✓ | | ✓ |
| `github` | | ✓ | ✓ | ✓ | |
| `gitlab` | | | ✓ | | |
| `kubernetes` | | | ✓ | | |
| `alicloud` | | | ✓ | | |
| `scaleway` | | | ✓ | ✓ | |
| `ovh` | | | ✓ | | |
| `ibm` | | | ✓ | | |
| `elastic` | | | ✓ | | |
| `grafana` | | | ✓ | | |
| `honeycomb` | | | | ✓ | |
| `local` | | | | ✓ | |
| `apikey` | | | | ✓ | |

Keyless is arriving across more drivers over time — treat this as the current map,
not a permanent one.

## Choosing your setup

Two questions, in order:

1. **Whose identity should the upstream see?** A **shared service identity** (an
   inline mint), the **agent ± user** via a [federation assertion](/federation/keyless-credentials/),
   or the **user on-behalf-of** — via native token exchange when the upstream supports
   it ([`token_exchange`/`oauth2`](/credential-drivers/token-exchange/)), or, for
   upstreams without ID-JAG (GitHub, Slack), a per-user OpenBao/Vault OAuth token via
   [templated policies](/concepts/delegation/#per-user-oauth-token-from-openbao--vault).
2. **Does Warden store a secret?** Prefer **keyless** (federation or
   [chaining](/federation/credential-chaining/)); fall back to **inline secret** only
   when you must, and there **dynamic** beats **static** (which is not for production).

## Reference

Every driver has its own page covering config keys, mint methods, credential types,
and rotation behaviour.

| Driver | `type` | Upstream |
|--------|--------|----------|
| [Alibaba Cloud](/credential-drivers/alicloud/) | `alicloud` | STS AssumeRole |
| [AWS](/credential-drivers/aws/) | `aws` | STS, Secrets Manager, RDS / Redshift IAM tokens |
| [Azure](/credential-drivers/azure/) | `azure` | Azure AD bearer tokens, Key Vault secrets |
| [Elasticsearch](/credential-drivers/elastic/) | `elastic` | `/_security` API keys |
| [GCP](/credential-drivers/gcp/) | `gcp` | IAM access tokens, service-account impersonation |
| [GitHub](/credential-drivers/github/) | `github` | App installation tokens and PATs |
| [GitLab](/credential-drivers/gitlab/) | `gitlab` | project and group access tokens |
| [Grafana](/credential-drivers/grafana/) | `grafana` | service-account tokens |
| [HashiCorp Vault / OpenBao](/credential-drivers/vault/) | `hvault` | KV, AWS/GCP/IBM engines, tokens, OAuth2 |
| [Honeycomb](/credential-drivers/honeycomb/) | `honeycomb` | V2 API keys |
| [IBM Cloud](/credential-drivers/ibm/) | `ibm` | IAM bearer tokens, COS keys |
| [Kubernetes](/credential-drivers/kubernetes/) | `kubernetes` | ServiceAccount tokens via the TokenRequest API |
| [Local](/credential-drivers/local/) | `local` | static secrets stored directly in the spec |
| [OAuth2](/credential-drivers/oauth2/) | `oauth2` | generic OAuth2 providers |
| [OVHcloud](/credential-drivers/ovh/) | `ovh` | OAuth2 bearer tokens, dynamic S3 credentials |
| [Scaleway](/credential-drivers/scaleway/) | `scaleway` | IAM static or dynamic API keys |
| [Static API Key](/credential-drivers/apikey/) | `apikey` | a static API key, held in the spec, for any HTTP API |
| [Token Exchange](/credential-drivers/token-exchange/) | `token_exchange` | RFC 8693 / RFC 7523 exchange at any OAuth2 STS (Entra OBO, ID-JAG) |

## See Also

- [Keyless credential sources](/federation/keyless-credentials/) — the recommended `oidc_federation` mode.
- [Credential chaining](/federation/credential-chaining/) — moving a driver from inline-secret to keyless.
- [Delegation](/concepts/delegation/) — the delegated / on-behalf-of identity dimension.
- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [`warden cred`](/cli/cred/) — the CLI for sources and specs.
