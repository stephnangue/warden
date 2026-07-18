---
title: "Provider configuration"
---

Warden's reverse-proxy providers share a common set of top-level provider-config
fields — request handling, the auth mount to authenticate against, and TLS
options for reaching the upstream. This page documents those shared fields once,
so the provider guides can link here instead of repeating them. (A few
providers — the access backends and providers that don't front an HTTP upstream —
don't expose these fields; their guides set only the options they support.)

Set these on the provider config, for example:

```bash
warden write <provider>/config <<EOF
{
  "proxy_domains": ["localhost"],
  "max_body_size": 10485760,
  "timeout": "30s",
  "auto_auth_path": "auth/jwt/",
  "default_role": "<role>"
}
EOF
```

## Common provider config fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy_domains` | list(string) | `["localhost"]` | Domains Warden listens on for proxied requests. In production, set this to your Warden server's domain. |
| `max_body_size` | int | `10485760` (10 MB) | Maximum request body size in bytes (max 100 MB). |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`). |
| `auto_auth_path` | string | Required | Path to the auth mount used for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`). See [JWT auth](/auth-methods/jwt/) and [Certificate auth](/auth-methods/cert/). |
| `default_role` | string | — | Default auth role to use when the request doesn't specify one. When set, it takes precedence over any role encoded in the request. |

## TLS options

These two fields control how Warden makes its outbound TLS connection to the
upstream. They apply both to the provider config and to any credential source
config that talks to an upstream over TLS (e.g. a Vault credential source), and
are documented here so the per-provider references don't repeat them.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` upstream URLs. **Development only** — never enable in production. |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for reaching an upstream that presents a custom or self-signed CA. |

:::caution
`tls_skip_verify` disables certificate verification for the upstream connection
and permits plaintext `http://` URLs. Use it only for local development. For a
private CA in production, supply the CA with `ca_data` instead.
:::

## See Also

- [JWT auth](/auth-methods/jwt/) — configuring the `auth/jwt/` mount referenced by `auto_auth_path`.
- [Certificate auth](/auth-methods/cert/) — configuring the `auth/cert/` mount for mTLS-based providers.
- [Local dev setup](/provider-backends/local-dev-setup/) — the local Warden + identity-provider environment the guides assume.
