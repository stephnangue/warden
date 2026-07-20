---
title: "Local"
---

> Source `type`: `local`

The **local** driver serves **static credentials** that live directly in the **spec** config. There is no upstream to talk to and no privileged secret held by the **source** — the source is an empty shell whose only job is to name the driver. Whatever key/value pairs an operator puts on the spec become the credential data, verbatim.

Reach for `local` when you already hold a fixed secret — a pre-issued token, a shared password, a static connection string — and simply want Warden to broker it to a workload. Because a local source can serve many different credential shapes, the credential `type` cannot be inferred and must be stated explicitly on the spec with `-type=`.

## Credential issued

The credential `type` is whatever you pass to `-type=` on the spec (the driver serves many types). Local credentials are **static**: they carry no lease and no TTL, and they are **not revocable** — revocation is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

Mint only — no verification, no rotation, and revocation and cleanup are no-ops.

## Examples

One empty source can back specs of many different credential shapes; each spec states its own `-type=`.

```bash
warden cred source create my-static \
  -type=local \
  -rotation-period=0
```

**Static API key** — a pre-issued Slack bot token served as the `api_key` type:

```bash
warden cred spec create slack-bot-token \
  -source=my-static \
  -type=api_key \
  -config=api_key=xoxb-EXAMPLE-STATIC-TOKEN
```

The spec config becomes the credential data verbatim, so the fields you set must
match what the chosen `-type` expects — here the `api_key` type reads an `api_key`
field.

**Multi-field secret** — a fixed username/password/URL bundle served under a chosen type:

```bash
warden cred spec create legacy-db \
  -source=my-static \
  -type=database \
  -config=username=app \
  -config=password=s3cr3t \
  -config=url=postgres://db.example.com:5432/app
```

## Source config

Keys for `warden cred source create <name> -type=local -config=key=value ...`:

The local driver takes **no configuration**. The source needs only a name and the `-type=local` flag; any config passed is accepted but ignored, and there are no required keys and no secret fields.

## Specs and mint methods

A local spec has a single, implicit mint method: it copies every field of the spec config into the minted credential. There are no reserved keys — the config is just arbitrary key/value pairs that become the credential data (for example `token`, `username`, `password`, `url`).

Because the source cannot infer a type, `-type=` must be set explicitly when creating the spec.

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `<any>` | No | — | Arbitrary field copied verbatim into the credential data. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [`apikey`](/credential-drivers/apikey/) — a static API key with an upstream verify check, when the key targets an HTTP API.
- [Credential drivers](/credential-drivers/) — every driver.
