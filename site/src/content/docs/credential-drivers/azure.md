---
title: "Azure"
---

> Source `type`: `azure`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The Azure driver brokers credentials against **Entra ID** (Azure AD) and **Azure Key
Vault**. A **spec** mints short-lived **Entra bearer tokens** for a workload service
principal, or reads a **Key Vault secret** — for an agent, or as the producer at the far
end of a [credential chain](/federation/credential-chaining/). An operator reaches for
this driver to hand workloads scoped Azure access tokens without distributing a long-lived
client secret, or to read secrets out of Key Vault on demand.

Keyless, neither the source nor its specs hold a secret: each request presents a Warden
identity assertion to Entra in place of a client secret. With a stored secret, the
**source** holds a privileged service-principal login (tenant, client id and client
secret) that Warden uses to authenticate to Entra and to call **Microsoft Graph**, and a
bearer-token spec carries its own workload service principal's `client_id` and
`client_secret`. In that mode the driver rotates **both** its own source secret **and**
the secret embedded in a spec, through Microsoft Graph — the only driver that rotates a
spec's own secret.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no Azure secret**: instead
of a `client_secret`, Warden presents an [identity assertion](/federation/oidc-issuer/)
to Entra as a `client_assertion` (JWT-bearer grant). Both mint methods federate:

- **`bearer_token`** — a short-lived Entra token for the spec's workload app.
- **`secret_read`** — a Key Vault read, authenticated as the app registration the spec
  names.

The source may set `audience` (default `api://AzureADTokenExchange`); the spec sets
`subject_token_source` (`warden_identity` or `agent_identity`), and the `client_id` and
`tenant_id` of the app registration whose federated credential trusts Warden's issuer.
See [Keyless credential sources](/federation/keyless-credentials/).

An Entra federated identity credential matches `iss`, `sub` and `aud` exactly and reads no
other claim, so a new federated spec is written with
[`assertion_profile=minimal`](/federation/assertion-claims/#the-minimal-profile): the
registered claims only. The `sub` is the agent's composite `wid:…` subject — Entra cannot
bind a user, so none is ever disclosed to it.

## Credential issued

The default `bearer_token` method issues an `azure_bearer_token` — a **dynamic**
credential that carries the token's Entra TTL, and is **not revocable**: Azure bearer
tokens expire naturally, so revocation is a no-op. The `secret_read` method issues a
`key_value` credential — the secret's payload under its own key names, with no lease,
bounded by the secret's own `exp` when it has one. See
[the lifetime model](/concepts/credentials/#lifetime-and-revocation).

:::caution[`key_vault_secret` is removed]
The former `mint_method=key_vault_secret` fails every mint, and a write naming it is
refused. Read Key Vault secrets with **`secret_read`** (type `key_value`) instead. Writes
also refuse `azure_db_iam_token`, the retired `scopes` key (set `resource_uri`), and a
`client_id` or `tenant_id` that is not a UUID. See
[Upgrading from v0.20.0](/upgrade/from-v0-20/#6-azure-key_vault_secret-specs-fail-every-mint).
:::

## Capabilities

- **Source rotation** — **slow**: stages a new source `client_secret` (a fresh Azure AD
  password credential added via Microsoft Graph) and waits ~5m (default, tunable via the
  source's `activation_delay`) so it propagates across Azure AD before the old secret is
  destroyed. Requires the source service principal to hold `Application.ReadWrite.All`.
- **Spec rotation** — **slow**: rotates the workload service principal's `client_secret`
  stored in the spec, again through Microsoft Graph and with the same propagation wait.
  This is the only driver that rotates a spec's own embedded secret.

No spec verification.

## Examples

### Keyless (recommended)

The source stores no client secret; Warden presents an identity assertion to Entra as a
`client_assertion`.

```bash
warden cred source create azure-keyless -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation"
  }
}'
```

**Bearer token** — a short-lived Entra token for Azure Resource Manager:

```bash
warden cred spec create arm-token -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "bearer_token",
    "subject_token_source": "warden_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "resource_uri": "https://management.azure.com/"
  }
}'
```

The spec's `client_id` is the **workload** app — the Entra app registration that trusts
Warden's issuer as a federated credential. It carries no `client_secret`; the assertion is
presented as its `client_assertion`.

**Key Vault secret** — read a secret keylessly, for an agent or as a chaining producer:

```bash
warden cred spec create datadog-keys -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "secret_read",
    "subject_token_source": "warden_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "33333333-3333-3333-3333-333333333333",
    "vault_name": "acme-prod-kv",
    "secret_name": "datadog-keys"
  }
}'
```

The app registration needs read access to secrets in the vault. A consumer spec on
another driver names `datadog-keys` as its `secret_spec`, and the secret never sits in
Warden — see [credential chaining](/federation/credential-chaining/).

### Inline secret (discouraged)

With a stored secret, one source holds the privileged service-principal login; each
bearer-token spec carries its own workload service-principal credentials.

```bash
warden cred source create azure-prod \
  -type=azure \
  -config=tenant_id=00000000-0000-0000-0000-000000000000 \
  -config=client_id=11111111-1111-1111-1111-111111111111 \
  -config=client_secret=s3cr3t-value \
  -config=secret_id=22222222-2222-2222-2222-222222222222 \
  -rotation-period=720h
```

**Rotating bearer token** — a spec whose embedded `client_secret` Warden rotates on a
schedule through Microsoft Graph:

```bash
warden cred spec create graph-token \
  -source=azure-prod \
  -config=mint_method=bearer_token \
  -config=client_id=55555555-5555-5555-5555-555555555555 \
  -config=client_secret=workload-s3cr3t \
  -config=secret_id=66666666-6666-6666-6666-666666666666 \
  -config=resource_uri=https://graph.microsoft.com/ \
  -rotation-period=720h
```

**Key Vault secret** — on a static source, the source's own service principal reads:

```bash
warden cred spec create db-password \
  -source=azure-prod \
  -config=mint_method=secret_read \
  -config=vault_name=prod-kv \
  -config=secret_name=db-connection-string
```

## Source config

Keys for `warden cred source create <name> -type=azure`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `static` | How the source authenticates: `static` (stored client secret) or `oidc_federation` ([keyless](/federation/keyless-credentials/) — presents an assertion to Entra as a `client_assertion`). |
| `tenant_id` | For `static` | — | Entra tenant ID (UUID). |
| `client_id` | For `static` | — | Application (client) ID of the source service principal (UUID). |
| `client_secret` | For `static` | — | Client secret for the source service principal (masked). Refused for keyless. |
| `secret_id` | For `static` | — | Key ID of the current client secret, tracked so rotation can retire the old one. Refused for keyless. |
| `audience` | No | `api://AzureADTokenExchange` | Audience minted into the `warden_identity` assertion (`oidc_federation` only; refused on a `static` source). |
| `activation_delay` | No | `5m` | How long a rotated client secret propagates through Entra before Warden switches to it. |
| `login_endpoint` | No | `https://login.microsoftonline.com` | Override the Entra authority host every token request goes to. |
| `key_vault_endpoint` | No | `https://<vault_name>.vault.azure.net` | Override the Key Vault base URL for every vault this source reads. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

A source that sets `login_endpoint` or `key_vault_endpoint` cannot set a
`rotation_period`: rotation manages client secrets in the real tenant through Microsoft
Graph, which those overrides do not redirect.

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `bearer_token` (default) | `azure_bearer_token` — an Entra bearer token for a resource | `client_id`, `tenant_id` (keyless), `client_secret` + `secret_id` (static), `resource_uri` |
| `secret_read` | `key_value` — a Key Vault secret's payload | `vault_name`, `secret_name`, `client_id` + `tenant_id` (keyless) |

**`bearer_token`** keys:

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | No | `bearer_token` | Which credential to mint. |
| `subject_token_source` | For keyless | — | On an `oidc_federation` source: the federated subject — `warden_identity` or `agent_identity`. |
| `client_id` | Yes | — | Workload app's application (client) ID (UUID). |
| `tenant_id` | For keyless | source `tenant_id` | Tenant of the workload app (UUID). |
| `client_secret` | For static | — | Workload service-principal client secret. **Refused for keyless** — the assertion is the `client_assertion`. |
| `secret_id` | For static | — | Key ID of the spec's client secret, tracked for spec rotation. |
| `resource_uri` | No | `https://management.azure.com/` | Resource the token targets; the grant asks for its `.default` scope. |

**`secret_read`** keys (type `key_value`, inferred from the mint method):

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `vault_name` | Yes | — | Key Vault name: 3–24 letters, digits and hyphens. Not templatable. |
| `secret_name` | Yes | — | Secret name. Accepts `{{user.<claim>}}` and `{{agent.<claim>}}` templating. |
| `secret_version` | No | current | Pin a 32-character version identifier. A pinned spec does not follow rotation. |
| `json_key_map` | No | — | Comma-separated `srcKey=destKey` selection of the payload's fields; unnamed keys are not vended. Omit to vend the payload verbatim. |
| `subject_token_source` | For keyless | — | `warden_identity` or `agent_identity`. |
| `client_id`, `tenant_id` | For keyless | — | The app registration the caller's token is exchanged at (UUIDs). Refused without `subject_token_source` — a static source reads as itself. |

A disabled secret, one before its `nbf` or past its `exp`, and a value over 25 KB are
refused at read.

A `subject_token_source=warden_identity` spec also accepts the assertion-shaping keys
(`assertion_profile` — `minimal` by default on a new spec — `assertion_audience`,
`assertion_metadata_claims`, `assertion_user_claims`, `assertion_algorithm`,
`assertion_ttl`) — see [Assertion claims](/federation/assertion-claims/). Under `minimal`,
`assertion_resource` is refused.

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Azure provider](/provider-backends/azure/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
