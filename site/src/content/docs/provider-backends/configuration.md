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
| `timeout` | duration | per provider | How long a **single** proxied call may take. The `mcp` and `mcp_aws` providers default to `60s`; others carry their own default. |
| `listen_timeout` | duration | `10m` | **`mcp` / `mcp_aws` only.** Bounds a long-lived stream — `subscriptions/listen` and the legacy SSE GET — instead of `timeout`. |
| `auto_auth_path` | string | Required | Path to the auth mount used for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`). See [JWT auth](/auth-methods/jwt/) and [Certificate auth](/auth-methods/cert/). |
| `default_role` | string | — | Auth role used when the request names none. It is the **lowest**-precedence source, not the highest — see [Selecting a role](/concepts/roles/#selecting-a-role). |

## Secondary user authentication

To let an agent act on behalf of a [user](/concepts/delegation/) — a human or another
agent — a provider (or namespace) can resolve a **second** principal from a separate
request header, in addition to the agent's own credential. This is opt-in: with
`user_auth_path` unset, no user principal is resolved and behavior is unchanged.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_auth_path` | string | — | Auth mount that validates the user credential. **Bearer-format mounts only.** Absent ⇒ no user principal. |
| `user_auth_role` | string | *(mount default)* | Role the user auth uses. |

:::caution[Changed in v0.20.0]
`user_token_header` is retired, and `user_auth_path` is read from the **mount only** — no
longer from namespace metadata, so a deployment that set it at the namespace level must
re-set it per mount. On a mount with `user_auth_path`, the user's credential now arrives in
`Authorization` and the agent moves to `X-Warden-Agent-Token` or a client certificate. See
[Upgrading from v0.19.0](/upgrade/from-v0-19/#2-dual-token-extraction-user_token_header-retired).
:::

The user principal is **identity-only** — it never authorizes the request. See
[Delegation](/concepts/delegation/) for the full model and the fail-closed rules.

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

## Selecting a role

Which role a request runs under is resolved per request, and the order differs between
gateway traffic and transparent operations — the `X-Warden-Role` header wins on the
former, the `role=` query parameter on the latter. Both chains are documented once in
[Roles → Selecting a role](/concepts/roles/#selecting-a-role).

## See Also

- [JWT auth](/auth-methods/jwt/) — configuring the `auth/jwt/` mount referenced by `auto_auth_path`.
- [Certificate auth](/auth-methods/cert/) — configuring the `auth/cert/` mount for mTLS-based providers.
- [Local dev setup](/provider-backends/local-dev-setup/) — the local Warden + identity-provider environment the guides assume.
