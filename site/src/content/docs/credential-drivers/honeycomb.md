---
title: "Honeycomb"
---

> Source `type`: `honeycomb`

The **Honeycomb** driver mints **Honeycomb V2 API keys** from the key-management API. The privileged secret is a **management key** (an ID and secret pair) that lives in the **source** config and can create and delete API keys for a team. Each **spec** then decides the environment, key type, naming, and permissions of the keys minted from that management key.

Reach for this driver when a workload needs a short-lived Honeycomb **ingest** or **configuration** key rather than a long-lived hand-issued one. Minted key secrets are **capture-once** — Honeycomb returns the secret only at creation time, so Warden captures it then and injects it on demand. Keys do not expire natively, so the spec's `key_ttl` governs the Warden lease.

## Source config

Keys for `warden cred source create <name> -type=honeycomb -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `honeycomb_url` | No | `https://api.honeycomb.io` | Honeycomb API base URL (must be `https://`). |
| `management_key_id` | Yes | — | Management key ID (`hcxmk_` prefix). (secret, masked on read) |
| `management_key_secret` | Yes | — | Management key secret paired with the key ID. (secret, masked on read) |
| `team_slug` | Yes | — | Honeycomb team slug used in API paths (e.g. `my-team`). |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom or self-signed CAs. (secret, masked on read) |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

A single mint method issues Honeycomb API keys. Keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `environment_id` | Yes | — | Honeycomb environment the key is scoped to. |
| `key_type` | No | `ingest` | Key type: `ingest` or `configuration`. |
| `key_name_prefix` | No | `warden-` | Prefix for the generated key name (name is `<prefix><spec>-<timestamp>`). |
| `permissions` | No | — | JSON permission object; allowed only for `configuration` keys. |
| `key_ttl` | No | `24h` | Warden lease duration for the minted key. |

## Credential issued

Issues a credential of type `api_key`. It is **dynamic** — it carries a lease whose TTL comes from the spec's `key_ttl` — and it is **revocable**: expiry or explicit revoke deletes the underlying Honeycomb key. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates the spec's `environment_id` and `key_type`, then lists API keys with a page size of 1 to confirm the management key and team slug work at spec create/update time.

Mint and revoke otherwise; no source or spec rotation.

## Example

```bash
warden cred source create honeycomb-prod \
  -type=honeycomb \
  -config=team_slug=my-team \
  -config=management_key_id=hcxmk_abc123 \
  -config=management_key_secret=s3cr3t \
  -rotation-period=0

warden cred spec create honeycomb-ingest \
  -source=honeycomb-prod \
  -config=environment_id=env_prod01 \
  -config=key_type=ingest \
  -config=key_ttl=12h
```

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Honeycomb provider](/provider-backends/honeycomb/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
