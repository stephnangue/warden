---
title: "Alibaba Cloud"
---

> Source `type`: `alicloud`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The Alibaba Cloud driver mints temporary credentials from **Alibaba Cloud STS** (Security Token Service). It exposes a single mint method — **`assume_role`** — which calls STS `AssumeRole` and returns a session-based access key trio (ID, secret, and security token) scoped to a RAM role. RAM dynamic access keys are intentionally not offered: freshly created RAM keys take seconds to minutes to propagate across regions, so first requests routinely fail; STS session tokens sidestep that window.

The privileged **management access key** lives in the **source** config, and it is what STS signs mint requests with. Each **spec** names the `role_arn` to assume and optional session parameters. An operator reaches for this driver to hand short-lived, role-scoped Alibaba Cloud credentials to a workload without ever exposing the long-lived management key.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no Alibaba Cloud secret**:
instead of an AccessKey pair, Warden mints an
[identity assertion](/federation/oidc-issuer/) and exchanges it via STS
`AssumeRoleWithOIDC` for a short-lived session. Set `oidc_provider_arn` on the source to
name the OIDC provider Alibaba Cloud trusts, and the RAM role's trust policy federates
Warden's issuer.

`assume_role` is the **only** mint method that federates. The spec sets
`subject_token_source` (`warden_identity` or `agent_identity`), and a `warden_identity`
subject additionally requires an audience — set `audience` on the source (or
`assertion_audience` on the spec), matching a client id registered on the RAM OIDC
provider. Without one the spec is rejected at create. See
[Keyless credential sources](/federation/keyless-credentials/).

## Credential issued

`InferCredentialType` always returns `alicloud_keys`. The credential is **dynamic** — it carries the STS session TTL (900s–3600s) as its lease — but it is **not revocable**: STS tokens are self-expiring and have no server-side revocation handle, so revoke is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time with a live pre-flight STS `AssumeRole` (minimum 900s duration, result discarded), catching broken management keys, a bad `role_arn`, or trust-policy misconfig before first mint.
- **Source rotation** — **slow** — rotates the management RAM access key: it creates a new key for `management_user_name` while the old one stays valid, then waits ~5 minutes (default `DefaultAlicloudActivationDelay`, tunable via the source's `activation_delay`) for RAM eventual consistency before marking the old key Inactive and deleting it. Requires `access_key_id`, `access_key_secret`, and `management_user_name`.

## Examples

### Keyless (recommended)

The source stores no AccessKey pair; Warden federates an identity assertion to STS
`AssumeRoleWithOIDC` on each request.

```bash
warden cred source create alicloud-keyless \
  -type=alicloud \
  -config=auth_method=oidc_federation \
  -config=oidc_provider_arn=acs:ram::123456789012:oidc-provider/warden \
  -config=audience=warden

warden cred spec create alicloud-app \
  -source=alicloud-keyless \
  -config=mint_method=assume_role \
  -config=role_arn=acs:ram::123456789012:role/app-reader \
  -config=subject_token_source=warden_identity
```

### Inline secret (discouraged)

One source holds the management access key; each spec below assumes a RAM role via STS.

```bash
warden cred source create alicloud-prod \
  -type=alicloud \
  -config=access_key_id=LTAIxxxxxxxxxxxxxxxx \
  -config=access_key_secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=management_user_name=warden-management \
  -config=activation_delay=5m \
  -rotation-period=720h
```

**STS AssumeRole** — session credentials scoped to a RAM role:

```bash
warden cred spec create alicloud-app \
  -source=alicloud-prod \
  -config=mint_method=assume_role \
  -config=role_arn=acs:ram::123456789012:role/app-reader \
  -config=role_session_name=warden-session \
  -config=duration_seconds=3600
```

**STS AssumeRole with an inline session policy** — further restrict the returned credentials:

```bash
warden cred spec create alicloud-scoped \
  -source=alicloud-prod \
  -config=mint_method=assume_role \
  -config=role_arn=acs:ram::123456789012:role/data-role \
  -config=role_session_name=warden-analytics \
  -config=duration_seconds=900 \
  -config=policy='{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Resource":["acs:oss:*:*:reports/*"]}]}'
```

## Source config

Keys for `warden cred source create <name> -type=alicloud -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `access_key_id` | No | — | Management access key ID (usually starts with `LTAI`). |
| `access_key_secret` | No | — | Management access key secret (secret, masked on read). |
| `sts_endpoint` | No | `https://sts.aliyuncs.com` | STS API endpoint. |
| `ram_endpoint` | No | `https://ram.aliyuncs.com` | RAM API endpoint (used for rotation). |
| `management_user_name` | No | — | RAM user that owns the management access key (required for rotation). |
| `activation_delay` | No | `5m` | Wait between creating a new management key and using it, for RAM eventual consistency. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

Although the schema marks no key required, `assume_role` needs `access_key_id` and `access_key_secret`, and rotation additionally needs `management_user_name`.

## Specs and mint methods

Only `assume_role` is supported. Set these with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | Yes | — | Must be `assume_role`. |
| `role_arn` | Yes | — | ARN of the RAM role to assume. |
| `role_session_name` | No | `warden-session` | Session name recorded on the assumed-role session. |
| `duration_seconds` | No | `1h` | Session lifetime, clamped to 900s–3600s. |
| `policy` | No | — | Inline session policy to further restrict the returned credentials. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Alibaba Cloud provider](/provider-backends/alicloud/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
