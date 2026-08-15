---
title: "Local File"
description: "Write the OIDC issuer's public keys to a local directory for an external process to sync."
---

> `set-publisher -type=local_file`

Writes the discovery + JWKS documents to a **local directory**. An external process (with
its own credentials) syncs that directory to the bucket/CDN — so **Warden holds no bucket
write credential** at all.

```bash
warden oidc-issuer set-publisher -type=local_file \
  -config=dir=/var/lib/warden/oidc-public
```

## Parameters

| Key | Required | Description |
|---|---|---|
| `dir` | yes | Local directory the discovery + JWKS documents are written to. |

## See also

- [Publishers](/federation/publishers/) — what a publisher does.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — the CLI.
