---
title: "Elasticsearch"
---

> Source `type`: `elastic`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The Elasticsearch driver mints short-lived **API keys** from an Elasticsearch cluster's Security API. The privileged secret is a pre-encoded API key held in the **source** config; Warden authenticates to the cluster with it and, for each **credential**, creates a scoped, expiring API key via the cluster's Security API.

Operators reach for this driver when a workload needs to talk to Elasticsearch and should carry its own narrowly-scoped key rather than a shared cluster credential. Per-spec parameters control the key's name, lifetime, and role descriptors, so one source can back many specs with different privilege sets.

## Keyless (via chaining)

The management credential does not have to be stored on the source: set `secret_spec` to
fetch it from another cred spec via [credential chaining](/federation/credential-chaining/)
at mint time, so nothing is stored at Warden.

The chained payload may carry either an already-`encoded` API key, or an `id` /
`api_key_id` plus `api_key` pair that the driver encodes itself. Use `secret_field` when
the payload holds more than one candidate.

## Credential issued

`InferCredentialType` always returns `api_key`. The minted key is **dynamic** — it carries a TTL derived from the cluster's returned expiration timestamp — and **revocable**: Warden invalidates the key through the Security API when the lease ends. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates the source credentials with a light authenticate call at create/update time.
- **Source rotation** — **slow** — stages a newly minted API key and waits ~10s (default, tunable via the source's `activation_delay`) for in-cluster propagation before invalidating the old key. Rotates the driver's own source API key via the Security API; requires the `manage_api_key` or `manage_own_api_key` cluster privilege.

## Examples

### Keyless (via chaining, recommended)

The source stores no secret: the cluster API key is fetched from a keyless-federated
vault per request.

The **consumer** is the same whichever producer you use — only the `secret_spec` name
changes:

```bash
warden cred source create es-keyless \
  -type=elastic \
  -config=elastic_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  -config=secret_spec=elastic-key-in-vault

warden cred spec create es-search-ro \
  -source=es-keyless \
  -config=expiration=24h
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create elastic-key-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=elastic/cluster-key \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create elastic-key-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/elastic/cluster-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create elastic-key-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=elastic-cluster-key \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A key per squad.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. Each squad holds its own cluster key so its minted keys inherit only that squad's index privileges. The squad travels on the agent's login, so no user need be present.

```bash
warden cred spec create elastic-key-per-squad \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=elastic/{{agent.metadata.squad}}/api-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=squad
```

An agent claim other than `sub` resolves only if the spec lists it in
`assertion_metadata_claims`. Resolution is fail-closed at mint: a claim the login does not
carry fails the request rather than falling back to a shared secret. `{{user.<claim>}}`
works the same way via `assertion_user_claims`, and the two can be combined in one path.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

One source holds the pre-encoded cluster API key; each spec creates a scoped, expiring key from it.

```bash
warden cred source create es-prod \
  -type=elastic \
  -config=elastic_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  -config=api_key=dXNlcjpwYXNzd29yZA== \
  -rotation-period=720h
```

**Scoped read-only key** — role descriptors restrict the key to reading `logs-*` indices, with a 24h lifetime:

```bash
warden cred spec create es-search-ro \
  -source=es-prod \
  -config=expiration=24h \
  -config=role_descriptors={"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}
```

**Named unscoped key** — no role descriptors (inherits the source key's privileges), a custom key name, and a short 1h lifetime:

```bash
warden cred spec create es-ingest \
  -source=es-prod \
  -config=key_name=ingest-writer \
  -config=expiration=1h
```

## Source config

Keys for `warden cred source create <name> -type=elastic -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `elastic_url` | Yes | — | Cluster URL; must use `https` (plain `http` allowed only with `tls_skip_verify`). |
| `api_key` | Yes* | — | Pre-encoded API key, base64 of `id:api_key` (secret, masked on read). |
| `api_key_id` | No | derived | API key ID; extracted from `api_key` if omitted. |
| `activation_delay` | No | `10s` | Wait for key propagation during source rotation. |
| `key_name_prefix` | No | `warden` | Prefix for generated API key names. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

\* Required only when the source is **not** keyless. A source that sets
`secret_spec` (chaining) or `auth_method=oidc_federation` must **omit** it — setting
both is rejected at write. See [Keyless](#keyless-via-chaining).

## Specs and mint methods

A single mint method: each spec creates one Elasticsearch API key. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `key_name` | No | `<prefix>-<spec>-<unix>` | Name for the generated API key. |
| `expiration` | No | `1h` | Key expiration, e.g. `30d`; sets the credential's TTL. |
| `role_descriptors` | No | — | JSON string of role descriptors scoping the key's privileges. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Elasticsearch provider](/provider-backends/elastic/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
