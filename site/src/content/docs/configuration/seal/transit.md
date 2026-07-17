---
title: "Transit Seal"
---

> `seal "transit"`

Auto-unseal backed by an external **Vault / OpenBao Transit** mount. At startup
Warden asks that Transit mount to decrypt the stored root key, so the node opens
its barrier without an operator present.

```hcl
seal "transit" {
  address    = "https://vault.example.com:8200"
  token      = "{{ env "TRANSIT_TOKEN" }}"
  key_name   = "warden-unseal"
  mount_path = "transit/"
}
```

Keep the Transit token out of the file with [environment-variable
interpolation](/configuration/#environment-variables), as above.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `address` | *(required)* | Address of the Transit server. |
| `token` | *(required)* | Token used to authenticate to the Transit server. |
| `key_name` | *(required)* | Name of the Transit key used to encrypt the root key. |
| `mount_path` | `transit/` | Mount path of the Transit engine. |
| `namespace` | *(none)* | Namespace of the Transit mount. |
| `disable_renewal` | `false` | `"true"` to disable automatic renewal of the auth token. |
| `tls_ca_cert` | *(none)* | CA certificate for verifying the Transit server. |
| `tls_client_cert` | *(none)* | Client certificate for mTLS to the Transit server. |
| `tls_client_key` | *(none)* | Client private key paired with the client certificate. |
| `tls_server_name` | *(none)* | Expected server name for TLS verification. |
| `tls_skip_verify` | `false` | `"true"` to skip TLS verification (insecure). |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
