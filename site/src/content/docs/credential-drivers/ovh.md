---
title: "OVHcloud"
---

> Source `type`: `ovh`

The OVHcloud driver mints credentials for **OVHcloud** APIs and Public Cloud services. It talks to OVHcloud's OAuth2 token endpoint and cloud API to issue either short-lived **bearer tokens**, **S3 credentials** for object storage, or both together. The choice is made per **spec** through the `mint_method` parameter.

The privileged, long-lived secret is an OAuth2 service account — its `client_id` and `client_secret` — held in the **source** config. The source also carries optional default `project_id` and `user_id` for S3 credential management; a **spec** may override these. One source can back many specs that mint different credential shapes from the same service account.

## Credential issued

All methods issue the credential type `ovh_keys`. Credentials are **dynamic**: they carry a lease and TTL derived from the OAuth2 token (~1h). The bearer token expires naturally, while S3 key pairs are **revocable** — Warden deletes them via the cloud API when the lease expires or is revoked. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time: confirms the `mint_method` is supported and, for the S3 methods, that `project_id` and `user_id` resolve from the source or spec.

Mint and revoke otherwise — no source or spec rotation.

## Examples

One source holds the OAuth2 service account; each spec picks a `mint_method`.

```bash
warden cred source create ovh-prod \
  -type=ovh \
  -config=client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -config=client_secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=ovh_endpoint=ovh-eu \
  -config=project_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=user_id=12345 \
  -rotation-period=0
```

**OAuth2 bearer token** — a short-lived token for the OVHcloud API:

```bash
warden cred spec create ovh-api \
  -source=ovh-prod \
  -config=mint_method=oauth2_token
```

**Dynamic S3 credentials** — a revocable access/secret key pair for object storage:

```bash
warden cred spec create ovh-s3 \
  -source=ovh-prod \
  -config=mint_method=dynamic_s3
```

**Both** — a bearer token and an S3 key pair, overriding the source's project and user:

```bash
warden cred spec create ovh-combined \
  -source=ovh-prod \
  -config=mint_method=oauth2_token_and_s3 \
  -config=project_id=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy \
  -config=user_id=67890
```

## Source config

Keys for `warden cred source create <name> -type=ovh -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `client_id` | Yes | — | OAuth2 service account client ID. |
| `client_secret` | Yes | — | OAuth2 service account client secret (secret, masked on read). |
| `ovh_endpoint` | No | `ovh-eu` | Regional endpoint: `ovh-eu`, `ovh-ca`, or `ovh-us`. |
| `project_id` | No | — | Default Public Cloud project ID for S3 credential management. |
| `user_id` | No | — | Default Public Cloud user ID for S3 credential management. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

Set `mint_method` on the spec to choose what to mint:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `oauth2_token` | Bearer token (~1h TTL) via OAuth2 client_credentials grant | none |
| `dynamic_s3` | S3 access/secret key pair (revocable) | `project_id`, `user_id` |
| `oauth2_token_and_s3` | Both a bearer token and an S3 key pair | `project_id`, `user_id` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | Yes | — | One of `oauth2_token`, `dynamic_s3`, `oauth2_token_and_s3`. |
| `project_id` | For S3 methods | source value | Public Cloud project ID; overrides the source default. Required (on source or spec) for `dynamic_s3` and `oauth2_token_and_s3`. |
| `user_id` | For S3 methods | source value | Public Cloud user ID; overrides the source default. Required (on source or spec) for `dynamic_s3` and `oauth2_token_and_s3`. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [OVHcloud provider](/provider-backends/ovh/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
