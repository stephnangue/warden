# Elasticsearch Driver

> Source `type`: `elastic`

The Elasticsearch driver mints short-lived **API keys** from an Elasticsearch cluster's Security API. The privileged secret is a pre-encoded API key held in the **source** config; Warden authenticates to the cluster with it and, for each **credential**, creates a scoped, expiring API key via the cluster's Security API.

Operators reach for this driver when a workload needs to talk to Elasticsearch and should carry its own narrowly-scoped key rather than a shared cluster credential. Per-spec parameters control the key's name, lifetime, and role descriptors, so one source can back many specs with different privilege sets.

## Source config

Keys for `warden cred source create <name> -type=elastic -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `elastic_url` | Yes | — | Cluster URL; must use `https` (plain `http` allowed only with `tls_skip_verify`). |
| `api_key` | Yes | — | Pre-encoded API key, base64 of `id:api_key` (secret, masked on read). |
| `api_key_id` | No | derived | API key ID; extracted from `api_key` if omitted. |
| `activation_delay` | No | `10s` | Wait for key propagation during source rotation. |
| `key_name_prefix` | No | `warden` | Prefix for generated API key names. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

A single mint method: each spec creates one Elasticsearch API key. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `key_name` | No | `<prefix>-<spec>-<unix>` | Name for the generated API key. |
| `expiration` | No | `1h` | Key expiration, e.g. `30d`; sets the credential's TTL. |
| `role_descriptors` | No | — | JSON string of role descriptors scoping the key's privileges. |

## Credential issued

`InferCredentialType` always returns `api_key`. The minted key is **dynamic** — it carries a TTL derived from the cluster's returned expiration timestamp — and **revocable**: Warden invalidates the key through the Security API when the lease ends. See [the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates the source credentials with a light authenticate call at create/update time.
- **Source rotation** — **slow** — stages a newly minted API key and waits ~10s (default, tunable via the source's `activation_delay`) for in-cluster propagation before invalidating the old key. Rotates the driver's own source API key via the Security API; requires the `manage_api_key` or `manage_own_api_key` cluster privilege.

## Example

```bash
warden cred source create es-prod \
  -type=elastic \
  -config=elastic_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  -config=api_key=dXNlcjpwYXNzd29yZA== \
  -rotation-period=720h

warden cred spec create es-search-ro \
  -source=es-prod \
  -config=expiration=24h \
  -config=role_descriptors={"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [Elasticsearch provider](../provider-backends/elastic.md) — full operator setup guide.
- [Credential drivers](README.md) — every driver.
