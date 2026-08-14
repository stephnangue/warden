---
title: "Signer"
description: "Hold the OIDC issuer's signing key in an external KMS so the private key never enters Warden."
---

> Server config stanza: `signer "<type>"`

A `signer` stanza binds the [OIDC issuer's](/federation/oidc-issuer/) assertion-signing
key to an **external KMS**, so the private key is created in the KMS and **never enters
Warden**. Warden holds only a handle plus the cached public key, and asks the KMS to
sign each assertion (*remote signing*).

Omit the stanza entirely to use the default **in-process** keys, where Warden generates
and holds the signing key itself.

```hcl
signer "transit" {
  address    = "https://bao.example.com:8200"
  token      = "{{ env "WARDEN_OIDC_SIGNER_TOKEN" }}"
  mount_path = "transit"
}
```

The type label selects the backend. **`transit`** (an OpenBao / Vault Transit mount) is
supported today; the backend interface is built to add more KMS backends (cloud KMS,
PKCS#11 HSM) over time.

Like the [`seal`](/configuration/seal/) stanza, this is **node-local infrastructure**:
it lives in each node's config file, not the API. The issuer's runtime settings —
`issuer_url`, the TTLs, the rotation period — are managed separately through
[`warden oidc-issuer configure`](/cli/oidc-issuer/).

Keep the token out of the file with [environment-variable
interpolation](/configuration/#environment-variables), as above.

## Why remote signing

The signing key is what vouches for every identity Warden asserts. With a `signer`
stanza:

- The **private key never leaves the KMS** — it is created non-exportable, and Warden
  cannot read it, only request signatures.
- **Key rotation** happens against KMS-held keys; retired public keys remain in the
  JWKS so in-flight assertions still verify (see the [issuer](/federation/oidc-issuer/#key-rotation)).
- `warden oidc-issuer read` shows the signing-key **location**, so you can confirm the
  key lives in the KMS rather than in Warden.

## `signer "transit"` parameters

Warden signs with keys named `<key_name_prefix>-<alg>` (e.g. `warden-oidc-rs256`) under
the given transit mount.

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

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what the signing key is for.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — configure the issuer and inspect the key location.
- [Seal](/configuration/seal/) — the sibling stanza that guards the barrier at rest.
