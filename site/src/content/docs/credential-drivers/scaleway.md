---
title: "Scaleway"
---

> Source `type`: `scaleway`

The Scaleway driver brokers credentials from **Scaleway IAM**. A **source** holds the connection details for the Scaleway API and, when dynamic minting or rotation is used, a privileged **management key** (an access-key/secret-key pair with IAM permission to create and delete API keys). Each **spec** decides how a credential is produced: either by handing back a pre-existing key pair stored on the spec, or by asking the IAM API to mint a fresh, expiring API key on demand.

Operators reach for this driver to give workloads Scaleway API keys without embedding long-lived secrets in the workload. Static keys are convenient when a key pair already exists; dynamic keys let Warden create short-lived keys per lease and revoke them automatically when the lease ends.

## Source config

Keys for `warden cred source create <name> -type=scaleway -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `scaleway_url` | No | `https://api.scaleway.com` | Base URL for the Scaleway API. |
| `management_access_key` | No | — | Access key of the management key (starts with `SCW`). Required for rotation. |
| `management_secret_key` | No | — | Secret key with IAM permission to create/delete API keys (UUID format). Required for dynamic minting and rotation. (secret, masked on read) |
| `iam_api_path` | No | `/iam/v1alpha1` | IAM API path prefix. Update when Scaleway promotes the API to stable. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs. (secret, masked on read) |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

The spec's `mint_method` selects how the credential is produced:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `static_keys` (default) | A pre-existing key pair read straight from the spec | `access_key`, `secret_key` |
| `dynamic_keys` | A fresh API key created via the IAM API, revoked on expiry | `application_id`, `ttl`, `description`, `default_project_id` |

Spec-config keys (`warden cred spec create ... -config=key=value`):

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | No | `static_keys` | `static_keys` or `dynamic_keys`. |
| `access_key` | Yes (static) | — | Access key returned as the credential. |
| `secret_key` | Yes (static) | — | Secret key returned as the credential. |
| `application_id` | Yes (dynamic) | — | IAM application the new key is bound to. |
| `ttl` | No (dynamic) | `1h` | Lifetime of the minted key; sets its `expires_at`. |
| `description` | No (dynamic) | `warden-<spec>` | Description recorded on the created key. |
| `default_project_id` | No (dynamic) | — | Default project scoped to the created key. |

## Credential issued

Both mint methods issue credentials of type `scaleway_keys` (an `access_key` / `secret_key` pair).

- `static_keys` credentials are **static** — no lease, no TTL, not revocable by Warden.
- `dynamic_keys` credentials are **dynamic** — they carry a lease/TTL and are **revocable**: Warden deletes the API key via the IAM API when the lease expires or is revoked.

See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time. For `static_keys` it confirms the key pair resolves against the IAM API; for `dynamic_keys` it checks that the source has a management key and the spec sets `application_id`.
- **Source rotation** — **slow**: stages a newly minted management key alongside the old one and waits ~30 seconds (default, tunable via the source's `activation_delay`) so it propagates before the old key is destroyed. Rotates the source's `management_access_key` / `management_secret_key`; requires both to be present.

## Example

```bash
warden cred source create scw-prod \
  -type=scaleway \
  -config=management_access_key=SCWXXXXXXXXXXXXXXXXX \
  -config=management_secret_key=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -rotation-period=720h

warden cred spec create scw-app-keys \
  -source=scw-prod \
  -config=mint_method=dynamic_keys \
  -config=application_id=11111111-2222-3333-4444-555555555555 \
  -config=ttl=1h
```

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Scaleway provider](/provider-backends/scaleway/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
