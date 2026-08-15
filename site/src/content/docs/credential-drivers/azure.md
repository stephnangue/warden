---
title: "Azure"
---

> Source `type`: `azure`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The Azure driver brokers credentials against **Azure AD** and **Azure Key Vault**. Its
**source** holds a privileged service-principal login (tenant, client id, and client
secret) that Warden uses to authenticate to Azure AD and to call the **Microsoft Graph**
API. From that source, a **spec** mints short-lived **Azure AD bearer tokens** for a
workload service principal, or fetches a **Key Vault secret**. An operator reaches for
this driver to hand workloads scoped Azure access tokens without distributing a
long-lived client secret, or to read secrets out of Key Vault on demand.

This driver is unusual in two ways. First, the credentials it mints are supplied
**per spec** — each spec carries its own workload service-principal `client_id` and
`client_secret`, and the source login is used only to authenticate and to rotate. Second,
it is the only driver that rotates **both** its own source secret **and** the secret
embedded in a spec, both through Microsoft Graph.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no Azure secret**: instead
of a `client_secret`, Warden presents an [identity assertion](/federation/oidc-issuer/)
to Entra as a `client_assertion` (JWT-bearer grant) for a short-lived `bearer_token`.
The source sets `tenant_id`, `client_id`, and the `audience`; the spec sets
`subject_token_source` (`warden_identity` or `agent_identity`). Note `key_vault_secret`
is **not** federated — a keyless source targeting it fails closed. See
[Keyless credential sources](/federation/keyless-credentials/).

## Credential issued

The default `bearer_token` method issues an `azure_bearer_token` — a **dynamic**
credential that carries the token's Azure AD TTL, and is **not revocable**: Azure bearer
tokens expire naturally, so revocation is a no-op. The `key_vault_secret` method returns
the secret value as a **static** credential with no lease or TTL. See
[the lifetime model](/concepts/credentials/#lifetime-and-revocation).

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

The source stores no client secret; Warden presents an identity assertion to Entra as a `client_assertion`.

```bash
warden cred source create azure-keyless \
  -type=azure \
  -config=auth_method=oidc_federation \
  -config=tenant_id=00000000-0000-0000-0000-000000000000 \
  -config=client_id=11111111-1111-1111-1111-111111111111 \
  -config=audience=api://AzureADTokenExchange

warden cred spec create arm-token \
  -source=azure-keyless \
  -config=mint_method=bearer_token \
  -config=subject_token_source=warden_identity \
  -config=client_id=22222222-2222-2222-2222-222222222222 \
  -config=resource_uri=https://management.azure.com/
```

The spec's `client_id` is the **workload** service principal — the Entra app that trusts
Warden's issuer as a federated credential. It carries no `client_secret`; the assertion is
presented as its `client_assertion`. `tenant_id` defaults to the source's.

### Inline secret (discouraged)

One source holds the privileged service-principal login; each spec below picks a
`mint_method` and carries its own workload service-principal credentials.

```bash
warden cred source create azure-prod \
  -type=azure \
  -config=tenant_id=00000000-0000-0000-0000-000000000000 \
  -config=client_id=11111111-1111-1111-1111-111111111111 \
  -config=client_secret=s3cr3t-value \
  -config=secret_id=22222222-2222-2222-2222-222222222222 \
  -rotation-period=720h
```

**Bearer token** — a short-lived Azure AD token for the Azure Resource Manager API:

```bash
warden cred spec create arm-token \
  -source=azure-prod \
  -config=mint_method=bearer_token \
  -config=client_id=33333333-3333-3333-3333-333333333333 \
  -config=client_secret=workload-s3cr3t \
  -config=resource_uri=https://management.azure.com/
```

**Key Vault secret** — fetch a stored secret by vault and name:

```bash
warden cred spec create db-password \
  -source=azure-prod \
  -config=mint_method=key_vault_secret \
  -config=client_id=44444444-4444-4444-4444-444444444444 \
  -config=client_secret=workload-s3cr3t \
  -config=vault_name=prod-kv \
  -config=secret_name=db-connection-string
```

**Rotating workload secret** — a bearer-token spec whose embedded `client_secret` Warden
rotates on a schedule through Microsoft Graph:

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

## Source config

Keys for `warden cred source create <name> -type=azure -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `static` | How the source authenticates: `static` (stored client secret) or `oidc_federation` ([keyless](/federation/keyless-credentials/) — presents an assertion to Entra as a `client_assertion`). |
| `tenant_id` | Yes | — | Azure AD tenant ID (UUID). |
| `client_id` | Yes | — | Azure AD application (client) ID for the source service principal. |
| `client_secret` | For `static` | — | Client secret for the source service principal (masked). Omit for keyless. |
| `secret_id` | For `static` | — | Key ID of the current client secret, tracked so rotation can retire the old one. |
| `audience` | For keyless | — | Assertion audience presented to Entra (e.g. `api://AzureADTokenExchange`). |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

Source rotation also reads an optional `activation_delay` (duration) that tunes the
propagation wait described under Capabilities.

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `bearer_token` (default) | An Azure AD bearer token for a resource | `client_id`, `client_secret`, `resource_uri` |
| `key_vault_secret` | The value of a Key Vault secret | `client_id`, `client_secret`, `vault_name`, `secret_name` |

Keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | No | `bearer_token` | Which credential to mint. |
| `subject_token_source` | For keyless | — | On an `oidc_federation` source: the federated subject — `warden_identity` or `agent_identity`. (`key_vault_secret` is not federated.) |
| `tenant_id` | No | source `tenant_id` | Tenant of the workload service principal. |
| `client_id` | Yes | — | Workload service-principal application (client) ID. |
| `client_secret` | For inline | — | Workload service-principal client secret. **Omit for keyless** (`subject_token_source` set) — the assertion is the `client_assertion`. |
| `secret_id` | No | — | Key ID of the spec's client secret, tracked for spec rotation. |
| `resource_uri` | No | `https://management.azure.com/` | Resource the bearer token targets (`bearer_token` only). |
| `vault_name` | Yes* | — | Key Vault name (`key_vault_secret` only). |
| `secret_name` | Yes* | — | Secret name in the vault (`key_vault_secret` only). |
| `secret_version` | No | latest | Specific secret version (`key_vault_secret` only). |

\* Required when `mint_method=key_vault_secret`.

A `subject_token_source=warden_identity` spec also accepts the assertion-shaping keys
(`assertion_audience`, `assertion_resource`, `assertion_metadata_claims`,
`assertion_user_claims`, `assertion_algorithm`) — see
[Assertion claims](/federation/assertion-claims/).

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Azure provider](/provider-backends/azure/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
