---
title: "Cloudflare"
description: "Serve a Cloudflare API token and R2 key pair chained from your secret store — the source stores nothing."
---

> Source `type`: `cloudflare`

:::tip[Keyless by design]
A `cloudflare` source stores nothing. Each spec fetches its credential per request from
your own secret store through [credential chaining](/federation/credential-chaining/).
:::

The Cloudflare driver serves **Cloudflare credentials that live somewhere else**: an
**API token** for the REST API, an **R2 key pair** for object storage, or both. The
**source** has no config at all. Each **spec** names, in its own `secret_spec`, the spec
that yields its credential — a Vault KV read, an AWS, GCP or Azure secret read — and on
each request Warden fetches it **as the caller** and hands it to the
[Cloudflare provider](/provider-backends/cloudflare/), which sends the token as a bearer
and signs R2 requests with the key pair. The driver makes no request to Cloudflare
itself.

An operator reaches for this driver to put agents behind Cloudflare without copying a
Cloudflare token into Warden: the token stays in the secret store that already holds it,
and the producer can itself be keyless, so nothing standing is stored at either hop.

## Credential issued

The credential type is **`cloudflare_keys`**, inferred from the source. It carries
`api_token`, `access_key_id` and `secret_access_key` — whichever the fetched secret
holds. It lives for the spec's `secret_cache_ttl`, or **30 minutes** by default, and then
the chain is walked again; it is **not revocable**. A chained credential also expires
with the secret it was read from. See
[the lifetime model](/concepts/credentials/#lifetime-and-revocation).

How the fetched secret is read:

- **API token** — the field `secret_field` names; otherwise the `api_token` field;
  otherwise, when the secret has a single field, that field.
- **R2 pair** — the `access_key_id` and `secret_access_key` fields, by name, both or
  neither.

A secret holding neither a token nor the pair, or only half the pair, fails the request.

## Capabilities

- **No rotation** — there is nothing on the source to rotate. Rotate the token where it
  is stored.
- **No spec verification** — a chained spec is exercised on its first request.

## Examples

The producer: a keyless read of the token from your secret store.

```bash
warden cred spec create cloudflare-token-in-vault -json '{
  "source": "vault-keyless",
  "config": {
    "mint_method": "kv2_read",
    "kv2_mount": "secret",
    "secret_path": "cloudflare/api",
    "subject_token_source": "warden_identity"
  }
}'
```

The consumer: a `cloudflare` source with no config, and a spec that chains the token.

```bash
warden cred source create cloudflare -json '{
  "type": "cloudflare",
  "config": {}
}'

warden cred spec create cloudflare-dns -json '{
  "source": "cloudflare",
  "config": {
    "secret_spec": "cloudflare-token-in-vault"
  }
}'
```

**A token stored under another field name** — say which one:

```bash
warden cred spec create cloudflare-dns -json '{
  "source": "cloudflare",
  "config": {
    "secret_spec": "cloudflare-token-in-vault",
    "secret_field": "token"
  }
}'
```

**R2** — store `access_key_id` and `secret_access_key` (and, if the same agents call the
REST API, `api_token`) in one secret, and chain it the same way.

## Source config

None. A `cloudflare` source takes an empty `config`. `secret_spec`, `secret_field` and
`secret_cache_ttl` are refused on the source: the credential is each spec's own.

## Spec config

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `secret_spec` | Yes | — | The spec that yields the credential: `api_token`, and/or `access_key_id` + `secret_access_key`. |
| `secret_field` | No | `api_token` | Field of the fetched secret that holds the API token, when it is stored under another name. It cannot name an R2 field. |
| `secret_cache_ttl` | No | `30m` | How long the credential is served before the chain is walked again. |

The inline `api_token`, `access_key_id` and `secret_access_key` are refused on a
`cloudflare` source — the referenced spec supplies them.

:::note[A static token on the `local` source]
`cloudflare_keys` also works on the built-in [`local`](/credential-drivers/local/) source,
with the token and R2 pair inline in the spec. That stores the credential in Warden — the
quick start, not the production setup — and a server at
`keyless_enforcement_level=enforce` refuses it. Chaining is not available on `local`.
:::

## See Also

- [Cloudflare provider](/provider-backends/cloudflare/) — the gateway that injects the token and signs R2 requests.
- [Credential chaining](/federation/credential-chaining/) — producers and guarantees.
- [Credential drivers](/credential-drivers/) — every driver.
