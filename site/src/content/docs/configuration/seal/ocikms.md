---
title: "OCI KMS Seal"
---

> `seal "ocikms"`

Auto-unseal backed by **Oracle Cloud Infrastructure KMS**. Warden asks the KMS
vault to decrypt the stored root key at startup.

```hcl
seal "ocikms" {
  key_id              = "ocid1.key.oc1..<id>"
  crypto_endpoint     = "https://<vault>-crypto.kms.<region>.oraclecloud.com"
  management_endpoint = "https://<vault>-management.kms.<region>.oraclecloud.com"
}
```

By default Warden authenticates with instance principals. Set
`auth_type_api_key = true` to use a configured API key instead.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `key_id` | *(required)* | OCID of the KMS key. |
| `crypto_endpoint` | *(required)* | Cryptographic endpoint of the KMS vault. |
| `management_endpoint` | *(required)* | Management endpoint of the KMS vault. |
| `auth_type_api_key` | `false` | `true` to authenticate with an API key instead of instance principals. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
