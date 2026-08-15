---
title: "Warden as an OIDC Issuer"
description: "Warden mints short-lived, signed identity assertions and publishes the keys to verify them — the foundation for keyless federation."
---

Keyless access rests on a simple shift: instead of Warden holding a long-lived secret for
an upstream, the upstream is set up to **trust Warden's word about who the caller is**. On
each request Warden vouches for the caller with a short-lived, **signed statement of
identity**; the upstream — a cloud STS, an identity provider, a secrets vault — verifies
that statement on its own and hands back a short-lived credential. **No secret is stored on
either side.**

Warden does this by acting as its own **OpenID Connect (OIDC) issuer**. The signed
statements are JWT **identity assertions** describing the authenticated caller, and Warden
publishes the public keys to verify them — the **JWKS** and **OIDC discovery** documents.
This is the same mechanism any OIDC provider uses, so anything that already trusts an OIDC
issuer can verify a Warden assertion with no custom integration.

**The issuer at a glance** (both add-ons below are optional — the defaults are an
in-process key and no publisher). The **signer** can hold the private key in an external
KMS/HSM and sign each assertion there; a **publisher** can push the public key to a bucket
after every rotation; and the upstream cloud/platform fetches that public key to verify
assertions — so Warden sends requests carrying no standing secret.

<p align="center"><img alt="Warden's OIDC issuer signs assertions via a signer backed by a private key in an external KMS/HSM, a publisher pushes the public key to a public bucket after each rotation, and the public cloud/platform fetches the public key to verify assertions Warden sends without any standing secret" src="/images/warden-oidc-issuer.png" width="900"></p>

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

Assertions are **short-lived** — five minutes by default — minted on demand (on a
credential-cache miss) and consumed immediately by the upstream exchange.

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
| `key_rotation_period` | *(none)* | Signing-key rotation cadence. `0` disables automatic rotation. When set, it must be **greater than `jwks_cache_ttl`** (a key must be publishable before it is used). |
| `jwks_cache_ttl` | `1m` | `Cache-Control` max-age of the published JWKS; also the minimum pre-publication age of a new key. |
| `retired_key_grace` | `1h` | Margin beyond the assertion TTL before a retired key is pruned from the JWKS. |

For local development you may set an `http://` `issuer_url` for a loopback host
(`localhost`/`127.0.0.1`); production upstreams require HTTPS.

## Endpoints

The issuer serves two public documents, and **the configured `issuer_url` is the base of
both** — it is also the `iss` claim, and the discovery document it serves advertises
`jwks_uri` as `<issuer_url>/oidc/jwks`. The paths live at the origin root (not under
`/v1/`) and are unauthenticated:

| Document | URL |
|---|---|
| OIDC discovery | `<issuer_url>/.well-known/openid-configuration` |
| JWKS | `<issuer_url>/oidc/jwks` |

Warden **always** serves these two paths on its own listener, so you construct them by
setting `issuer_url` to match how the verifier reaches the keys:

- **Internal verifiers** (a Vault/OpenBao JWT mount, a private STS — anything that can
  reach Warden). Set `issuer_url` to Warden's own reachable address, e.g.
  `https://warden.internal:8400`. The endpoints are then
  `https://warden.internal:8400/.well-known/openid-configuration` and
  `https://warden.internal:8400/oidc/jwks`, served directly by Warden — **no publisher
  needed**.
- **Internet-facing verifiers** (AWS STS, GCP, Entra — cannot reach Warden). Set
  `issuer_url` to a **public** bucket/CDN location and add a
  [publisher](/federation/publishers/) to push both documents there; the endpoints are
  then `<public_url>/.well-known/openid-configuration` and `<public_url>/oidc/jwks`.
  (Warden still serves the same documents on its own listener, so an internal verifier
  that trusts the same `iss` can point its discovery straight at Warden.)

### Serving internal and public verifiers at once

Enabling a publisher does **not** stop Warden serving the endpoints on its own listener —
it does both. Every assertion's `iss` claim is the configured `issuer_url` (the public
location), so **all** verifiers trust that one issuer — but each fetches the keys from
wherever it can reach:

| Verifier | Trusts `iss` | Fetches discovery / JWKS from |
|---|---|---|
| **Internet-facing** (AWS STS, GCP, Entra) | `issuer_url` (public) | the published public location — `<issuer_url>/.well-known/openid-configuration` and `<issuer_url>/oidc/jwks` (the bucket/CDN). |
| **Internal** (Vault/OpenBao, private STS) | `issuer_url` (public) | Warden's own listener directly — `https://<warden-host>/.well-known/openid-configuration` and `https://<warden-host>/oidc/jwks`. |

Because Warden serves the **same** documents — same `iss`, same keys — at both places,
either fetch yields a valid verification. An internal verifier uses its ability to set the
key/discovery URL **separately** from the trusted issuer: e.g. an OpenBao/Vault JWT mount
with `bound_issuer` = the public `issuer_url` and `jwks_url` (or `oidc_discovery_url`)
pointing at Warden's own host — so it validates `iss` against the public URL while pulling
keys straight from Warden.

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

`warden oidc-issuer read` reports the signing **mode** (`in_process` or `external_kms`)
and, when external, the `backend` (e.g. `transit`), alongside a `key_rotation` status
block — so you can confirm where the key that vouches for every identity actually resides.

## Publishers: reaching internet-facing upstreams

A public cloud STS — AWS, GCP, Entra — verifies an assertion by fetching Warden's
discovery document and JWKS **over the internet**. Rather than exposing Warden itself,
a **publisher** pushes those public documents to an external bucket or CDN, and *that*
public location becomes the `issuer_url` the upstream trusts and fetches from (the
[internet-facing case](#endpoints) above).

A publisher is only for verifiers that can't reach Warden directly — an internal verifier
fetches the [endpoints](#endpoints) from Warden's own listener and needs none.

[Publisher types](/federation/publishers/): `s3`, `gcs`, `azure_blob` (object stores),
plus `http_put` and `local_file` — each with its own parameters. Configure one with
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

- [Signer](/configuration/signer/) — hold the signing key in an external KMS.
- [Publishers](/federation/publishers/) — push the public keys to a bucket/CDN, per type.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — `configure`, `read`, `set-publisher`, `disable`.
- [Credentials](/concepts/credentials/) — the source / spec / credential model the keyless sources build on.
