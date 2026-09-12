---
title: "Grafana"
---

> Source `type`: `grafana`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The Grafana driver mints **Grafana service-account tokens** by talking to the Grafana HTTP API. For every mint it creates a **temporary service account**, generates a bounded-TTL token on it, and hands the token to the workload; on **revoke** it deletes that service account (and with it every token), so minted credentials are fully revocable.

The privileged secret lives in the **source**: an `admin_token` (an admin service-account token with permission to create and delete service accounts) plus the `grafana_url` to reach. Each **spec** decides the shape of what gets minted — the role granted, the naming prefix, an optional org, and the token TTL. An operator reaches for this driver to grant workloads short-lived, least-privilege Grafana access without ever sharing the standing admin token.

## Keyless (via chaining)

The Grafana admin token does not have to be stored on the source: set `secret_spec` to
fetch it from another cred spec via [credential chaining](/federation/credential-chaining/)
at mint time, so nothing is stored at Warden.

The referenced credential's `admin_token`, `api_key` or `token` field is used; name one
explicitly with `secret_field` when the payload carries more than one.

## Credential issued

Issues a credential of type `api_key`. It is **dynamic** — it carries a lease and a TTL equal to `token_expiry` — and it is **revocable**: revoking deletes the backing service account and invalidates the token. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates the source's admin token at spec create/update time with a lightweight service-account listing call.

Mint and revoke otherwise; no source or spec rotation. Create the source with `-rotation-period=0`.

## Examples

### Keyless (via chaining, recommended)

The source stores no secret: the admin token is fetched from a keyless-federated
vault per request.

The **consumer** is the same whichever producer you use — only the `secret_spec` name
changes:

```bash
warden cred source create grafana-keyless \
  -type=grafana \
  -config=grafana_url=https://grafana.example.com \
  -config=secret_spec=grafana-admin-in-vault
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create grafana-admin-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=grafana/admin-token \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create grafana-admin-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/grafana/admin-token \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create grafana-admin-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=grafana-admin-token \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A token per environment.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. Staging and production run separate Grafana orgs with separate admin tokens. One spec serves both, and a staging workload can never resolve the production token.

```bash
warden cred spec create grafana-admin-per-env \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=grafana-admin-{{agent.metadata.env}} \
  -config=project=my-project \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=env
```

An agent claim other than `sub` resolves only if the spec lists it in
`assertion_metadata_claims`. Resolution is fail-closed at mint: a claim the login does not
carry fails the request rather than falling back to a shared secret. `{{user.<claim>}}`
works the same way via `assertion_user_claims`, and the two can be combined in one path.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

One source holds the standing admin token; each spec below decides the role, org, and token TTL.

```bash
warden cred source create grafana-cloud \
  -type=grafana \
  -config=grafana_url=https://mystack.grafana.net \
  -config=admin_token=glsa_xxxxxxxxxxxxxxxxxxxx \
  -rotation-period=0
```

**Viewer token** — read-only dashboard access with a 1h lifetime:

```bash
warden cred spec create grafana-dashboards \
  -source=grafana-cloud \
  -config=role=Viewer \
  -config=name_prefix=warden- \
  -config=token_expiry=1h
```

**Editor token scoped to an org** — write access within a specific Grafana organization:

```bash
warden cred spec create grafana-editor \
  -source=grafana-cloud \
  -config=role=Editor \
  -config=org_id=2 \
  -config=token_expiry=4h
```

## Source config

Keys for `warden cred source create <name> -type=grafana -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `grafana_url` | Yes | — | Grafana API base URL, e.g. `https://mystack.grafana.net`. Must be `https://` (or `http://` only with `tls_skip_verify`). |
| `admin_token` | Yes* | — | Admin service-account token with ServiceAccount admin permissions (secret, masked on read). |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

\* Required only when the source is **not** keyless. A source that sets
`secret_spec` (chaining) or `auth_method=oidc_federation` must **omit** it — setting
both is rejected at write. See [Keyless](#keyless-via-chaining).

## Specs and mint methods

A single mint method: each mint creates a service account and issues one token on it. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `role` | No | `Viewer` | Role granted to the service account: `Viewer`, `Editor`, or `Admin`. |
| `name_prefix` | No | `warden-` | Prefix for the generated service-account name. |
| `org_id` | No | — | Grafana organization ID to scope the service account to; omit for the default org. |
| `token_expiry` | No | `1h` | TTL of the minted token. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Grafana provider](/provider-backends/grafana/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
