---
title: "Signer"
description: "Hold the OIDC issuer's signing key in an external KMS so the private key never enters Warden."
---

> Server config stanza: `signer "<type>"`

A `signer` stanza binds the [OIDC issuer's](/federation/oidc-issuer/) assertion-signing
key to an **external KMS**, so the private key is created in the KMS and **never enters
Warden**. Warden holds only a handle plus the cached public key, and asks the KMS to
sign each assertion (*remote signing*).

Omit the stanza entirely to use the default **in-process** keys, where Warden generates
and holds the signing key itself.

The type label selects the backend. Like the [`seal`](/configuration/seal/) stanza, this
is **node-local infrastructure**: it lives in each node's config file, not the API. The
issuer's runtime settings — `issuer_url`, the TTLs, the rotation period — are managed
separately through [`warden oidc-issuer configure`](/cli/oidc-issuer/).

## Why remote signing

The signing key is what vouches for every identity Warden asserts. With a `signer`
stanza:

- The **private key never leaves the KMS** — it is created non-exportable, and Warden
  cannot read it, only request signatures.
- **Key rotation** happens against KMS-held keys; retired public keys remain in the
  JWKS so in-flight assertions still verify (see the [issuer](/federation/oidc-issuer/#key-rotation)).
- `warden oidc-issuer read` shows the signing-key **location**, so you can confirm the
  key lives in the KMS rather than in Warden.

## Backends

The `oidcsign` backend interface is built to add more KMS backends (cloud KMS, PKCS#11
HSM) over time. Supported today:

| Type | Backend |
|------|---------|
| [`transit`](/configuration/signer/transit/) | An OpenBao / Vault Transit mount. |

## See also

- [Warden as an OIDC issuer](/federation/oidc-issuer/) — what the signing key is for.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — configure the issuer and inspect the key location.
- [Seal](/configuration/seal/) — the sibling stanza that guards the barrier at rest.
