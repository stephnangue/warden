---
title: "Publishers"
description: "Push the OIDC issuer's public discovery + JWKS to a bucket or CDN so internet-facing upstreams can verify assertions."
---

A public cloud — AWS, GCP, Entra — verifies Warden's [identity assertions](/federation/oidc-issuer/)
by fetching its public keys **over the internet**. But you usually don't want to put Warden
itself on the internet to be reached. A **publisher** resolves that tension: it pushes the
issuer's public **discovery** and **JWKS** documents out to a location the cloud *can* reach —
a bucket or CDN — and *that* location becomes the `issuer_url` upstreams fetch from. So a
public-cloud STS verifies Warden's assertions **without Warden ever being internet-facing**.

A publisher is **runtime** configuration, set through the API with
[`warden oidc-issuer set-publisher`](/cli/oidc-issuer/) (not a server-config stanza).
`-type=none` removes it, and the issuer then serves discovery/JWKS only from Warden's own
endpoint.

**A publisher is only for upstreams that can't reach Warden.** Warden always serves its
own discovery and JWKS [endpoints](/federation/oidc-issuer/#endpoints) at the origin root,
so an **internal** verifier (a Vault/OpenBao JWT mount, a private STS, anything on the same
network) points its issuer URL straight at Warden and needs no publisher. Reach for a
publisher when the verifier is an **internet-facing** cloud (AWS STS, GCP, Entra) that must
fetch the keys from a public location.

You can also run **both at once** — a publisher for internet-facing clouds while internal
systems verify against Warden directly. See
[serving both at once](/federation/oidc-issuer/#serving-internal-and-public-verifiers-at-once)
on the issuer page.

## Two rotations, kept distinct

- **The published public key auto-rotates.** On signing-key rotation the updated JWKS is
  **automatically re-published**, gated by a pre-publication age so Warden only begins
  signing with a key once it is live in the published document — verification never breaks.
- **The publisher's own write credential self-rotates.** For the credential-bearing
  publishers (`s3`, `gcs`, `azure_blob`), Warden rotates the credential it uses to *push*
  on a configured `rotation_period` (**minimum 24h**).

## Types

| Type | Target |
|------|--------|
| [`s3`](/federation/publishers/s3/) | An AWS S3 (or S3-compatible) bucket. |
| [`gcs`](/federation/publishers/gcs/) | A Google Cloud Storage bucket. |
| [`azure_blob`](/federation/publishers/azure-blob/) | An Azure Storage container. |
| [`http_put`](/federation/publishers/http-put/) | An HTTP origin Warden PUTs each document to (e.g. a Cloudflare Worker / R2). |
| [`local_file`](/federation/publishers/local-file/) | A local directory an external process syncs to the bucket/CDN. |

## See also

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what is being published, and why.
- [`warden oidc-issuer set-publisher`](/cli/oidc-issuer/) — the command that configures a publisher.
