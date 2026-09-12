---
title: "OVHcloud"
---

> Source `type`: `ovh`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The OVHcloud driver mints credentials for **OVHcloud** APIs and Public Cloud services. It talks to OVHcloud's OAuth2 token endpoint and cloud API to issue either short-lived **bearer tokens** or an existing **S3 key pair** served from elsewhere. The choice is made per **spec** through the `mint_method` parameter.

The privileged, long-lived secret is an OAuth2 service account — its `client_id` and `client_secret` — held in the **source** config. One source can back many specs that mint different credential shapes from the same service account.

## Keyless (via chaining)

The OVHcloud credential does not have to be stored on the source: set `secret_spec` to
fetch it from another cred spec via [credential chaining](/federation/credential-chaining/)
at mint time, so nothing is stored at Warden.

What the chained material means depends on the mint method: `oauth2_token` reads a
`client_id` / `client_secret` pair to mint a bearer token, while `access_keys` reads an
existing S3 key pair and serves it. Use `secret_field` to disambiguate a multi-key payload.

## Credential issued

All methods issue the credential type `ovh_keys`. An `oauth2_token` credential is **dynamic**, carrying a lease and TTL derived from the OAuth2 token (~1h), and expires naturally. An `access_keys` credential serves a pair Warden did not create, so it is **not revocable** and issues no lease — revocation is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time, confirming the `mint_method` is supported.

Mint and revoke otherwise — no source or spec rotation.

## Examples

### Keyless (via chaining, recommended)

The source stores no OVHcloud credential; it is fetched from a keyless-federated vault
per request.

```bash
warden cred source create ovh-keyless \
  -type=ovh \
  -config=secret_spec=ovh-client-in-vault

warden cred spec create ovh-token \
  -source=ovh-keyless \
  -config=mint_method=oauth2_token
```

### Inline secret (discouraged)

One source holds the OAuth2 service account; each spec picks a `mint_method`.

```bash
warden cred source create ovh-prod \
  -type=ovh \
  -config=client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -config=client_secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=ovh_endpoint=ovh-eu \
  -rotation-period=0
```

**OAuth2 bearer token** — a short-lived token for the OVHcloud API:

```bash
warden cred spec create ovh-api \
  -source=ovh-prod \
  -config=mint_method=oauth2_token
```

**S3 access keys** — an existing pair, served from a spec that sources it by
[chaining](/federation/credential-chaining/):

```bash
warden cred spec create ovh-s3 \
  -source=ovh-prod \
  -config=mint_method=access_keys \
  -config=secret_spec=ovh-keys-in-vault
```

:::caution[Removed in v0.20.0]
The `dynamic_s3` and `oauth2_token_and_s3` mint methods are gone, along with the source's
`api_url` key. Replace them with `access_keys`, which serves a pair held elsewhere rather
than minting one — so revocation is a no-op and no leases are issued. **Drain any
credentials minted by the removed methods before upgrading**: they keep their lease ids
and are not cleaned up afterwards. See
[Upgrading from v0.19.0](/upgrade/from-v0-19/#8-ovh-dynamic_s3-and-oauth2_token_and_s3-are-removed).
:::

## Source config

Keys for `warden cred source create <name> -type=ovh -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `client_id` | Yes | — | OAuth2 service account client ID. |
| `client_secret` | Yes | — | OAuth2 service account client secret (secret, masked on read). |
| `ovh_endpoint` | No | `ovh-eu` | Regional endpoint: `ovh-eu`, `ovh-ca`, or `ovh-us`. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

Set `mint_method` on the spec to choose what to mint:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `oauth2_token` | Bearer token (~1h TTL) via OAuth2 client_credentials grant | none |
| `access_keys` | An existing S3 access/secret key pair, served not minted | `secret_spec` (chained) |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | Yes | — | One of `oauth2_token` or `access_keys`. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [OVHcloud provider](/provider-backends/ovh/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
