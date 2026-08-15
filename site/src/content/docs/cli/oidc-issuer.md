---
title: "oidc-issuer"
description: "Configure Warden's OIDC issuer — its runtime settings, signing key, and publisher."
---

Configure Warden as an [OIDC issuer](/federation/oidc-issuer/): the runtime settings
that shape identity assertions, and the publisher that exposes the public keys to
internet-facing upstreams.

The signing key's *location* (in-process vs. an external KMS) is set separately, in the
server config's [`signer` stanza](/configuration/signer/) — not here.

## Usage

```text
warden oidc-issuer <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `configure` | Enable the issuer and set its runtime settings. |
| `read` | Show the issuer's state, signing-key location, and rotation status. |
| `set-publisher` | Configure where the public JWKS/discovery is published. |
| `disable` | Disable the issuer. |

### `oidc-issuer configure`

Enable the issuer and set its runtime settings. On first enable, `-issuer-url` is
required; later calls change only the flags you pass and keep the rest.

```bash
# First enable
warden oidc-issuer configure -issuer-url=https://warden.example.com

# Change just the rotation cadence later (issuer_url and the rest are kept)
warden oidc-issuer configure -key-rotation-period=168h
```

| Flag | Default | Description |
|---|---|---|
| `-issuer-url` | *(required on first enable)* | Public HTTPS URL upstreams fetch discovery/JWKS from; also the `iss` claim. An `http://` loopback host is allowed for local dev. |
| `-assertion-ttl` | `5m` | Lifetime of a minted identity assertion. |
| `-key-rotation-period` | *(none)* | Signing-key rotation cadence. `0` disables automatic rotation. |
| `-jwks-cache-ttl` | `1m` | `Cache-Control` max-age of the published JWKS; also the minimum pre-publication age of a new key. |
| `-retired-key-grace` | `1h` | Margin beyond the assertion TTL before a retired key is pruned from the JWKS. |
| `-json`, `-j` | | Full JSON payload (`<json>`, `@file.json`, or `-` for stdin). Mutually exclusive with the typed flags. |

### `oidc-issuer read`

Show the issuer's state — whether it is enabled and ready, the `issuer_url`, the
runtime settings, the signing **mode** (`in_process` or `external_kms`, plus the
`backend` when external — from the [`signer` stanza](/configuration/signer/)), and a
`key_rotation` status block.

```bash
warden oidc-issuer read
```

### `oidc-issuer set-publisher`

Configure where the public JWKS/discovery is pushed — the external bucket or endpoint
that becomes the `issuer_url` upstreams fetch from. The type is selected with `-type`;
every other field is a repeatable `-config=key=value` pair (so new publisher fields
need no new flags). Use `@file` to read a value from a file (e.g. a secret). Set
`-type=none` to remove the publisher.

```bash
# Publish to an S3 bucket
warden oidc-issuer set-publisher -type=s3 \
  -config=bucket=my-jwks -config=region=us-east-1 \
  -config=access_key_id=AKIA... \
  -config=secret_access_key=@/run/secrets/s3

# Publish to Azure Blob with a service principal, rotating its write credential
warden oidc-issuer set-publisher -type=azure_blob -rotation-period=720h \
  -config=account_name=wardenoidc -config=container=jwks \
  -config=tenant_id=<tenant> -config=client_id=<app-id> \
  -config=client_secret=@/run/secrets/sp -config=secret_id=<keyId>

# Publish to a GCS bucket
warden oidc-issuer set-publisher -type=gcs -rotation-period=720h \
  -config=bucket=my-jwks \
  -config=credentials_json=@/run/secrets/sa.json

# Remove the publisher
warden oidc-issuer set-publisher -type=none
```

| Flag | Description |
|---|---|
| `-type` | Publisher type: `none`, `local_file`, `http_put`, `s3`, `azure_blob`, or `gcs`. |
| `-config` | Type-specific config as `key=value` (repeatable). `@file` reads a value from a file. |
| `-rotation-period` | Cadence for self-rotating the publisher's own write credential. |
| `-json`, `-j` | Full publisher JSON block (mutually exclusive with `-type`/`-config`). |

Switching `-type` drops the previous type's fields; secrets are preserved when omitted
(or may be sent masked). The publisher's write credential is self-rotated on the
`-rotation-period`, and the JWKS is automatically re-published when the signing key
rotates.

#### Publisher parameters

Every field except `-type` is passed as a `-config=key=value`; secret fields are masked on read. Each type's parameters are documented on its own page under [Publishers](/federation/publishers/): [`s3`](/federation/publishers/s3/), [`gcs`](/federation/publishers/gcs/), [`azure_blob`](/federation/publishers/azure-blob/), [`http_put`](/federation/publishers/http-put/), and [`local_file`](/federation/publishers/local-file/). `-type=none` removes the publisher.

### `oidc-issuer disable`

Disable the issuer. It stops minting assertions until re-enabled.

```bash
warden oidc-issuer disable
```

## See also

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — the concept behind these commands.
- [Signer configuration](/configuration/signer/) — where the signing key lives.
