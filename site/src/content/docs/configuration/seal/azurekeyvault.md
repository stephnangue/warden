---
title: "Azure Key Vault Seal"
---

> `seal "azurekeyvault"`

Auto-unseal backed by **Azure Key Vault**. At startup Warden asks Key Vault to
decrypt the stored root key, so the node opens its barrier without an operator
present.

```hcl
seal "azurekeyvault" {
  tenant_id  = "<tenant-id>"
  vault_name = "warden-kv"
  key_name   = "warden-unseal"
}
```

When `client_id` / `client_secret` are omitted, Warden authenticates with the
ambient managed identity — the preferred setup on Azure-hosted nodes.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `tenant_id` | *(required)* | Azure Active Directory tenant ID. |
| `vault_name` | *(required)* | Name of the Key Vault. |
| `key_name` | *(required)* | Name of the key within the vault. |
| `client_id` | *(managed identity)* | App registration client ID. |
| `client_secret` | *(managed identity)* | App registration client secret. |
| `environment` | `AZUREPUBLICCLOUD` | Azure environment (e.g. `AZUREPUBLICCLOUD`, `AZUREGOVERNMENTCLOUD`). |
| `resource` | *(none)* | Resource identifier override for the vault endpoint. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
