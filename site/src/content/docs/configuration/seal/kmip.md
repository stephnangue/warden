---
title: "KMIP Seal"
---

> `seal "kmip"`

Auto-unseal backed by a **KMIP** server. Warden connects over mTLS and asks the
server to unwrap the stored root key at startup.

```hcl
seal "kmip" {
  endpoint    = "kmip.example.com:5696"
  kms_key_id  = "<key-id>"
  client_cert = "/certs/kmip-client-cert.pem"
  client_key  = "/certs/kmip-client-key.pem"
  ca_cert     = "/certs/kmip-ca.pem"
}
```

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `endpoint` | *(required)* | Address of the KMIP server. |
| `kms_key_id` | *(required)* | Identifier of the key on the KMIP server. |
| `client_cert` | *(required)* | Client certificate for the KMIP connection. |
| `client_key` | *(required)* | Client private key paired with the certificate. |
| `ca_cert` | *(none)* | CA certificate for verifying the KMIP server. |
| `server_name` | *(none)* | Expected server name for TLS verification. |
| `timeout` | *(none)* | Connection timeout in seconds. |
| `encrypt_alg` | *(server default)* | Encryption algorithm to use. |
| `tls12_ciphers` | *(default suite)* | Allowed TLS 1.2 cipher suites. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
