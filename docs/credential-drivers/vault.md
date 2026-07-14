# HashiCorp Vault Driver

> Source `type`: `hvault`

The `hvault` driver brokers credentials out of **HashiCorp Vault** (or **OpenBao**). The **source** holds how Warden authenticates to the Vault server — typically an **AppRole** identity (`role_id` + `secret_id`) — plus the server address and optional namespace. That one source can back many **specs**, each of which selects a **mint method** naming which Vault engine to draw from and what shape of credential to hand back to the workload.

Reach for it when your secrets already live in Vault: static KV entries, dynamic cloud credentials from the AWS/GCP/IBM engines, OAuth2 bearer tokens from the oauthapp engine, or freshly minted Vault tokens. Warden authenticates once with the source's privileged AppRole, then mints per request against whatever engine the spec points at.

## Source config

Keys for `warden cred source create <name> -type=hvault -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `vault_address` | Yes | — | Vault/OpenBao server URL (`http://` or `https://`), e.g. `https://vault.example.com`. |
| `vault_namespace` | No | — | Namespace to scope all requests to. |
| `auth_method` | No | — | Authentication method; only `approle` is supported. Omit to use a pre-set token. |
| `role_id` | If approle | — | AppRole role ID. |
| `secret_id` | If approle | — | AppRole secret ID (secret, masked on read). |
| `approle_mount` | If approle | — | Mount path of the AppRole auth backend, e.g. `approle`. |
| `role_name` | If approle | — | AppRole role name; required so the source can rotate its own secret ID. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for outbound upstream calls (e.g. the IBM IAM token exchange used by `dynamic_ibm`). Does not affect the connection to the Vault/OpenBao server itself. |
| `tls_skip_verify` | No | `false` | Disable TLS verification on those outbound upstream calls (test only). Does not affect the Vault/OpenBao connection. |

The `token` and `secret_id_accessor` fields are also treated as sensitive and masked on read.

## Specs and mint methods

Each spec sets a `mint_method` that picks the Vault engine and the credential shape:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `static_aws` | AWS access keys | `kv2_mount`, `secret_path` |
| `static_apikey` | API key | `kv2_mount`, `secret_path` |
| `dynamic_aws` | AWS access keys | `aws_mount`, `role_name`, `role_arn`, `role_session_name`, `ttl` |
| `dynamic_gcp` | GCP access token | `gcp_mount`, `role_name`, `role_type` |
| `dynamic_ibm` | IBM Cloud keys | `ibm_mount`, `role_name`, `ttl`, `iam_endpoint`, `access_key_id`, `secret_access_key` |
| `vault_token` (or unset) | Vault token | `token_role`, `ttl`, `display_name`, `meta` |
| `oauth2` | OAuth bearer token | `oauth2_mount`, `credential_name` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `kv2_mount` | For static | — | KV v2 mount holding the secret. |
| `secret_path` | For static | — | Path of the secret within the KV mount. |
| `aws_mount` | For `dynamic_aws` | — | Mount of the AWS secrets engine. |
| `gcp_mount` | For `dynamic_gcp` | — | Mount of the GCP secrets engine. |
| `ibm_mount` | For `dynamic_ibm` | — | Mount of the IBM secrets engine. |
| `oauth2_mount` | For `oauth2` | — | Mount of the OAuth2 (oauthapp) engine. |
| `role_name` | For dynamic aws/gcp/ibm | — | Engine role to generate credentials from. |
| `role_type` | No | `roleset` | GCP role kind: `roleset` or `static-account`. |
| `credential_name` | For `oauth2` | — | Named credential on the OAuth2 mount. |
| `token_role` | For `vault_token` | — | Token role for `auth/token/create/<role>`. |
| `ttl` | No | — | Requested lease TTL; validated against the spec's min/max bounds. |
| `iam_endpoint` | No | IBM IAM default | Endpoint used to exchange the IBM API key for a bearer token. |
| `role_arn` | No | — | AWS role ARN to assume (`dynamic_aws`). |
| `role_session_name` | No | — | AWS session name (`dynamic_aws`). |
| `access_key_id` / `secret_access_key` | No | — | Optional COS HMAC keys added to IBM credentials. |
| `display_name` | No | — | Display name for a minted Vault token. |
| `meta` | No | — | Metadata for a minted Vault token. |

## Credential issued

The credential `type` depends on the mint method: `static_aws`/`dynamic_aws` issue `aws_access_keys`, `static_apikey` issues `api_key`, `dynamic_gcp` issues `gcp_access_token`, `dynamic_ibm` issues `ibmcloud_keys`, `oauth2` issues `oauth_bearer_token`, and `vault_token` issues `vault_token`.

Static KV secrets are **static** — no lease, no TTL, not revocable. Every dynamic method (`dynamic_aws`, `dynamic_gcp`, `dynamic_ibm`, `oauth2`, `vault_token`) is **dynamic** — it carries a lease/TTL and is **revocable**: Vault leases are revoked by lease ID and Vault tokens by accessor. See [the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **fast**: prepares and activates in one step (immediately-consistent upstream). Rotates the source's own AppRole `secret_id` by generating a new one, re-authenticating, then destroying the old secret ID by accessor. Requires `auth_method=approle` and `role_name`.

No spec verification. Static KV mints only fetch and revoke.

## Example

```bash
warden cred source create prod-vault \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=role-id-uuid \
  -config=secret_id=secret-id-uuid \
  -config=approle_mount=approle \
  -config=role_name=warden-source-role \
  -rotation-period=720h

warden cred spec create prod-aws \
  -source=prod-vault \
  -config=mint_method=dynamic_aws \
  -config=aws_mount=aws \
  -config=role_name=deploy \
  -config=ttl=30m
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [Vault provider](../provider-backends/vault.md) — full operator setup guide.
- [Credential drivers](README.md) — every driver.
