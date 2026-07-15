---
title: "Azure"
---

> Source `type`: `azure`

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

## Source config

Keys for `warden cred source create <name> -type=azure -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `tenant_id` | Yes | — | Azure AD tenant ID (UUID). |
| `client_id` | Yes | — | Azure AD application (client) ID for the source service principal. |
| `client_secret` | Yes | — | Client secret for the source service principal (secret, masked on read). |
| `secret_id` | Yes | — | Key ID of the current client secret, tracked so rotation can retire the old one. |
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
| `tenant_id` | No | source `tenant_id` | Tenant of the workload service principal. |
| `client_id` | Yes | — | Workload service-principal application (client) ID. |
| `client_secret` | Yes | — | Workload service-principal client secret (secret). |
| `secret_id` | No | — | Key ID of the spec's client secret, tracked for spec rotation. |
| `resource_uri` | No | `https://management.azure.com/` | Resource the bearer token targets (`bearer_token` only). |
| `vault_name` | Yes* | — | Key Vault name (`key_vault_secret` only). |
| `secret_name` | Yes* | — | Secret name in the vault (`key_vault_secret` only). |
| `secret_version` | No | latest | Specific secret version (`key_vault_secret` only). |

\* Required when `mint_method=key_vault_secret`.

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

## Example

```bash
warden cred source create azure-prod \
  -type=azure \
  -config=tenant_id=00000000-0000-0000-0000-000000000000 \
  -config=client_id=11111111-1111-1111-1111-111111111111 \
  -config=client_secret=s3cr3t-value \
  -config=secret_id=22222222-2222-2222-2222-222222222222 \
  -rotation-period=720h

warden cred spec create arm-token \
  -source=azure-prod \
  -config=mint_method=bearer_token \
  -config=client_id=33333333-3333-3333-3333-333333333333 \
  -config=client_secret=workload-s3cr3t \
  -config=resource_uri=https://management.azure.com/
```

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Azure provider](/provider-backends/azure/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
