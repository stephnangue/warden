---
title: "Warden as an OIDC Issuer"
description: "Warden mints short-lived, signed identity assertions and publishes the keys to verify them — the foundation for keyless federation."
---

Warden can act as its own **OpenID Connect issuer**. It mints short-lived, signed JWT
**identity assertions** that describe the authenticated caller, and publishes the
matching **JWKS** and **OIDC discovery** document so anything that trusts an OIDC
issuer can verify those assertions on its own.

That single capability is what makes *keyless* access possible. Instead of Warden
holding a long-lived secret for an upstream, the upstream is configured to trust
Warden's issuer; on each request Warden mints an assertion for the caller, and the
upstream — a cloud STS, an identity provider, a secrets vault — exchanges that
assertion for a short-lived credential. No secret is stored on either side.

## The identity assertion

An assertion is a JWT whose subject identifies the agent that authenticated to Warden,
regardless of *how* it authenticated (certificate, JWT, Kubernetes, SPIFFE). The
subject has the form:

```
wid:<namespaceID>:<mountAccessor>:<principalID>
```

so a federated identity is globally unique across namespaces and auth mounts. Along
with the standard `iss`, `aud`, `iat`, and `exp` claims, the assertion carries a small
set of Warden claims — the agent's role, namespace, and auth mount, and (when a user
principal is present) the user. How those claims are shaped and scoped is covered on
the assertion-claims page in this section.

Assertions are **short-lived** — five minutes by default — because they are minted
fresh per request and consumed immediately by the upstream exchange.

## Enabling the issuer

The issuer is configured through the API with [`warden oidc-issuer configure`](/cli/oidc-issuer/).
The one required field on first enable is the **`issuer_url`** — the public HTTPS URL
that upstreams fetch discovery and JWKS from, and the value of the `iss` claim.

```bash
warden oidc-issuer configure --issuer-url=https://warden.example.com
```

The issuer **fails closed until an active signing key is installed**: until then it
mints nothing, so a half-configured issuer never emits an unsigned or unverifiable
assertion.

### Runtime settings

| Setting | Default | Description |
|---|---|---|
| `issuer_url` | *(required on first enable)* | Public HTTPS URL upstreams fetch discovery/JWKS from; also the `iss` claim. |
| `assertion_ttl` | `5m` | Lifetime of a minted assertion. |
| `key_rotation_period` | *(none)* | Signing-key rotation cadence. `0` disables automatic rotation. |
| `jwks_cache_ttl` | `1m` | `Cache-Control` max-age of the published JWKS; also the minimum pre-publication age of a new key. |
| `retired_key_grace` | `1h` | Margin beyond the assertion TTL before a retired key is pruned from the JWKS. |

For local development you may set an `http://` `issuer_url` for a loopback host
(`localhost`/`127.0.0.1`); production upstreams require HTTPS.

## Key rotation

The signing key rotates on the `key_rotation_period` cadence. Rotation is designed so
verification **never breaks**:

- A newly generated key is **published to the JWKS before it is used** — it must reach
  the minimum pre-publication age (`jwks_cache_ttl`) so caches and publishers can pick
  it up — and only then does Warden begin signing new assertions with it.
- The **previous key is retired, not deleted**: it stays in the JWKS for
  `retired_key_grace` beyond the assertion TTL, so any assertion already in flight
  still verifies.

The result is a rolling window in which both the current and the just-retired key are
publishable, and no upstream ever sees an assertion signed by a key it cannot fetch.

## The signing key: in-process or an external KMS

Every assertion is signed by the issuer's **private signing key**. Where that key
lives is a core security decision.

By default the key is generated and held **in-process**. But Warden does not have to
hold it at all: with a [`signer` stanza](/configuration/signer/) the key is created and
kept in an **external KMS**, and **the private key never leaves the KMS**. Warden keeps
only a handle and the cached public key, and asks the KMS to **sign each assertion**.

Today the supported backend is an **OpenBao / Vault transit** engine; the signer
interface is built to add more backends (cloud KMS, PKCS#11 HSM) over time. See
[Signer configuration](/configuration/signer/) for the stanza and its keys.

`warden oidc-issuer read` reports the current signing-key **location** (in-process or
the KMS handle) alongside a `key_rotation` status block, so you can confirm at a glance
where the key that vouches for every identity actually resides.

## Publishers: reaching internet-facing upstreams

A public cloud STS — AWS, GCP, Entra — verifies an assertion by fetching Warden's
discovery document and JWKS **over the internet**. Rather than exposing Warden itself,
a **publisher** pushes those public documents to an external bucket or CDN, and *that*
public location becomes the `issuer_url` the upstream trusts and fetches from.

Publisher types: `s3`, `gcs`, `azure_blob` (object stores), plus `http_put` and
`local_file`. Configure one with
[`warden oidc-issuer set-publisher`](/cli/oidc-issuer/); `-type=none` removes it.

Two things rotate here, and it is worth keeping them apart:

1. **The published public key.** On signing-key rotation, Warden **automatically
   re-publishes** the updated JWKS to the bucket — the new key is added and retired
   keys are retained — gated by the same pre-publication age so Warden only starts
   signing with a key once it is live in the published document. Verification stays
   current with **no manual step**.
2. **The publisher's own write credential.** The credential Warden uses to *push* to
   the bucket (an `s3` access key, a `gcs` service account, an `azure_blob` service
   principal) is **self-rotated on a cadence**, so the write path does not accumulate a
   long-lived secret either.

The upshot: point a public bucket at the issuer once, and both the published signing
key and the bucket-write credential keep themselves fresh.

## See also

- [Signer configuration](/configuration/signer/) — hold the signing key in an external KMS.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — `configure`, `read`, `set-publisher`, `disable`.
- [Credentials](/concepts/credentials/) — the source / spec / credential model the keyless sources build on.
