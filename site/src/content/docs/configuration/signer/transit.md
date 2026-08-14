---
title: "Transit"
description: "Sign OIDC identity assertions with a non-exportable key in an OpenBao / Vault transit engine."
---

> `signer "transit"`

Remote signing backed by an external **OpenBao / Vault Transit** mount. The signing key
is created non-exportable in Transit and **never enters Warden** — Warden asks Transit to
sign each [identity assertion](/federation/oidc-issuer/) it mints, and caches the public
key locally.

```hcl
signer "transit" {
  address    = "https://bao.example.com:8200"
  token      = "{{ env "WARDEN_OIDC_SIGNER_TOKEN" }}"
  mount_path = "transit"
}
```

Warden signs with keys named `<key_name_prefix>-<alg>` (e.g. `warden-oidc-rs256`) under
the given transit mount. Keep the token out of the file with [environment-variable
interpolation](/configuration/#environment-variables), as above.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `mount_path` | *(required)* | Transit mount that holds the signing keys, e.g. `transit`. |
| `address` | *(from the API client env)* | Address of the Transit server. Falls back to the standard client environment when unset. |
| `token` | *(falls back to `VAULT_TOKEN`)* | Token used to authenticate to the Transit server. Prefer env interpolation. |
| `key_name_prefix` | `warden-oidc` | Prefix for the per-algorithm signing keys (`<prefix>-rs256`, `<prefix>-es256`). |
| `namespace` | *(none)* | Namespace on the Transit server, if applicable. |
| `request_timeout` | *(client default)* | Go duration bounding each KMS signing call. |
| `disable_renewal` | `false` | Disable automatic renewal of the auth token's lease. |
| `tls_ca_cert` | *(none)* | CA certificate file for verifying the Transit server. |
| `tls_ca_path` | *(none)* | Directory of CA certificates for verifying the Transit server. |
| `tls_client_cert` | *(none)* | Client certificate for mTLS to the Transit server. |
| `tls_client_key` | *(none)* | Client key paired with `tls_client_cert`. |
| `tls_server_name` | *(none)* | Expected server name (SNI) for TLS verification. |
| `tls_skip_verify` | `false` | Skip TLS verification. Not for production. |

## See also

- [Signer](/configuration/signer/) — the stanza and why remote signing.
- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what the signing key is for.
