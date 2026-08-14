---
title: "HTTP PUT"
description: "Publish the OIDC issuer's public keys by PUT-ing them to an HTTP origin."
---

> `set-publisher -type=http_put`

Warden **PUTs** each discovery + JWKS document under an HTTP origin — for example a
Cloudflare Worker / R2 endpoint that serves them publicly.

```bash
warden oidc-issuer set-publisher -type=http_put \
  -config=base_url=https://oidc.example.com \
  -config=auth_value=@/run/secrets/put-token
```

## Parameters

| Key | Required | Description |
|---|---|---|
| `base_url` | yes | Origin Warden PUTs the documents under. |
| `auth_header` | no | Header name for the write credential (default `Authorization`). |
| `auth_value` | no | Write credential value, e.g. `Bearer <token>` (masked; use `@file`). |

> **Protect the origin.** The published JWKS is the trust root — an unauthenticated origin
> lets anyone overwrite it. Set `auth_value`, or protect the origin another way (mTLS /
> network).

## See also

- [Publishers](/federation/publishers/) — what a publisher does.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — the CLI.
