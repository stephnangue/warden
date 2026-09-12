---
title: "Scaleway"
---

> Source `type`: `scaleway`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The Scaleway driver brokers credentials from **Scaleway IAM**. A **source** holds the connection details for the Scaleway API and, when dynamic minting or rotation is used, a privileged **management key** (an access-key/secret-key pair with IAM permission to create and delete API keys). Each **spec** decides how a credential is produced: either by handing back a pre-existing key pair stored on the spec, or by asking the IAM API to mint a fresh, expiring API key on demand.

Operators reach for this driver to give workloads Scaleway API keys without embedding long-lived secrets in the workload. Static keys are convenient when a key pair already exists; dynamic keys let Warden create short-lived keys per lease and revoke them automatically when the lease ends.

## Keyless (via chaining)

The management secret key does not have to be stored on the source: set `secret_spec` to
fetch it from another cred spec via [credential chaining](/federation/credential-chaining/)
at mint time, so nothing is stored at Warden.

The referenced credential's `management_secret_key` field is used by default; name a
different one with `secret_field`.

## Credential issued

Both mint methods issue credentials of type `scaleway_keys` (an `access_key` / `secret_key` pair).

- `static_keys` credentials are **static** — no lease, no TTL, not revocable by Warden.
- `dynamic_keys` credentials are **dynamic** — they carry a lease/TTL and are **revocable**: Warden deletes the API key via the IAM API when the lease expires or is revoked.

See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time. For `static_keys` it confirms the key pair resolves against the IAM API; for `dynamic_keys` it checks that the source has a management key and the spec sets `application_id`.
- **Source rotation** — **slow**: stages a newly minted management key alongside the old one and waits ~30 seconds (default, tunable via the source's `activation_delay`) so it propagates before the old key is destroyed. Rotates the source's `management_access_key` / `management_secret_key`; requires both to be present.

## Examples

### Keyless (via chaining, recommended)

The source stores no secret: the management secret key is fetched from a keyless-federated
vault per request.

The **consumer** is the same whichever producer you use — only the `secret_spec` name
changes:

```bash
warden cred source create scw-keyless \
  -type=scaleway \
  -config=secret_spec=scaleway-secret-in-vault

warden cred spec create scw-app-keys \
  -source=scw-keyless \
  -config=mint_method=dynamic_keys \
  -config=application_id=11111111-2222-3333-4444-555555555555 \
  -config=ttl=1h
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create scaleway-secret-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=scaleway/management-key \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create scaleway-secret-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/scaleway/management-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create scaleway-secret-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=scaleway-management-key \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A management key per project.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. Each Public Cloud project has its own management key, so a workload can only mint API keys inside the project it belongs to.

```bash
warden cred spec create scaleway-key-per-project \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=scaleway/projects/{{agent.metadata.project}}/management-key \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=project
```

An agent claim other than `sub` resolves only if the spec lists it in
`assertion_metadata_claims`. Resolution is fail-closed at mint: a claim the login does not
carry fails the request rather than falling back to a shared secret. `{{user.<claim>}}`
works the same way via `assertion_user_claims`, and the two can be combined in one path.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

The source carries a management key when dynamic minting or rotation is in play. Each spec then picks a `mint_method`.

```bash
warden cred source create scw-prod \
  -type=scaleway \
  -config=management_access_key=SCWXXXXXXXXXXXXXXXXX \
  -config=management_secret_key=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -rotation-period=720h
```

**Dynamic keys** — Warden mints a fresh, expiring API key per lease bound to an IAM application, and revokes it on expiry:

```bash
warden cred spec create scw-app-keys \
  -source=scw-prod \
  -config=mint_method=dynamic_keys \
  -config=application_id=11111111-2222-3333-4444-555555555555 \
  -config=ttl=1h
```

**Static keys** — hand back a pre-existing key pair stored on the spec, with no lease or revocation:

```bash
warden cred spec create scw-legacy \
  -source=scw-prod \
  -config=mint_method=static_keys \
  -config=access_key=SCWYYYYYYYYYYYYYYYYY \
  -config=secret_key=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
```

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

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Scaleway provider](/provider-backends/scaleway/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
