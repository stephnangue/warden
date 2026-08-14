---
title: "Federation & keyless identity"
description: "How Warden proves identity to upstreams and mints credentials without holding a stored secret."
---

The pages in this section are about one idea: letting an upstream trust **who the
caller is** instead of **what secret Warden holds** — so Warden can broker access
while storing nothing.

At the centre is Warden's own **[OIDC issuer](/federation/oidc-issuer/)**. It mints
short-lived, signed *identity assertions* that describe the authenticated agent (and,
when present, the user), and publishes the matching public keys so any system that
trusts an OIDC issuer — a cloud STS, an identity provider, a secrets vault — can
verify those assertions directly.

Everything else builds on that:

- **[Warden as an OIDC issuer](/federation/oidc-issuer/)** — how the issuer mints and
  signs assertions, where the signing key lives (in-process or an external KMS), and
  how the public keys reach internet-facing upstreams through a publisher.

More pages join this section as the keyless story is documented — keyless credential
sources, assertion claims, and credential chaining. For the security property that
makes it all work, start with the issuer.

## See also

- [Signer configuration](/configuration/signer/) — hold the issuer's signing key in an
  external KMS.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — configure the issuer, its signing key,
  and its publisher.
- [Credentials](/concepts/credentials/) — the source / spec / credential model the
  keyless sources plug into.
