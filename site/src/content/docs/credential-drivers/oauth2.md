---
title: "OAuth2"
---

> Source `type`: `oauth2`

The **OAuth2 driver** exchanges OAuth2 credentials for short-lived **bearer tokens** against any standards-compliant provider. It supports two flows: the **client_credentials** flow (machine-to-machine, no user present) and the **authorization_code** flow with refresh-token rotation (acting on behalf of a user who granted consent once). Reach for it when a workload needs an OAuth2 access token and no purpose-built driver exists for the provider.

The token endpoint and connection options live in the **source** config (`token_url` required). The `client_id` and `client_secret` may live on the source — natural for `client_credentials` — or be supplied per **spec**, resolved spec-over-source. For the `authorization_code` flow, per-user tokens are sealed onto the spec by a one-time interactive consent step, and the driver refreshes them at mint time.

## Credential issued

Always `oauth_bearer_token`. It is **dynamic** when the provider returns an expiry (the credential carries a lease TTL and is re-minted on expiry) and **static** (non-expiring) when it does not. Bearer tokens are not revocable — they expire naturally, so revocation is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — mints a token and, when `verify_url` is set, calls it to confirm the token works before the spec is accepted.
- **OAuth2 authorization-code consent** — this is the only OAuth2 authorizer. For an `authorization_code` spec, run the one-time interactive `warden cred spec connect <name>`: it opens the provider's authorize URL, captures the returned code on a loopback redirect, exchanges it for tokens, and seals the resulting refresh token (or static access token) onto the spec. Later mints refresh from the sealed grant with no user present.

No source rotation — the source secret is not rotated by the driver.

## Examples

**client_credentials** — machine-to-machine, client credentials on the source:

```bash
warden cred source create pagerduty \
  -type=oauth2 \
  -config=token_url=https://identity.pagerduty.com/oauth/token \
  -config=client_id=your-client-id \
  -config=client_secret=your-client-secret \
  -config=default_scopes="read write" \
  -config=verify_url=https://api.pagerduty.com/users/me \
  -rotation-period=0

warden cred spec create pagerduty-readonly \
  -source=pagerduty \
  -config=auth_method=client_credentials \
  -config=scope="read"
```

**authorization_code** — acting on behalf of a user who consents once. Set `auth_url` on the source and leave the token keys unset; they are sealed onto the spec by the consent step:

```bash
warden cred source create google-user \
  -type=oauth2 \
  -config=token_url=https://oauth2.googleapis.com/token \
  -config=auth_url=https://accounts.google.com/o/oauth2/v2/auth \
  -config=client_id=your-client-id \
  -config=client_secret=your-client-secret \
  -config=introspection_url=https://openidconnect.googleapis.com/v1/userinfo \
  -config=metadata_fields=sub,email \
  -rotation-period=0

warden cred spec create google-calendar \
  -source=google-user \
  -config=auth_method=authorization_code \
  -config=scope="https://www.googleapis.com/auth/calendar.readonly"

# one-time interactive consent seals the refresh token onto the spec
warden cred spec connect google-calendar
```

## Source config

Keys for `warden cred source create <name> -type=oauth2 -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `token_url` | Yes | — | OAuth2 token endpoint (HTTPS). |
| `client_id` | No | — | OAuth2 client ID (source-level for client_credentials; may be set per-spec). |
| `client_secret` | No | — | OAuth2 client secret (secret, masked on read). |
| `auth_url` | No | — | Authorization endpoint (HTTPS); required for authorization_code specs. |
| `introspection_url` | No | — | Userinfo/introspection endpoint called at mint to fetch identity fields for opaque tokens. |
| `metadata_fields` | No | `sub` | Comma-separated identity fields copied into the credential's non-secret, audit-logged metadata (empty disables). |
| `default_scopes` | No | — | Default OAuth2 scopes (space-separated). |
| `verify_url` | No | — | Endpoint to verify minted tokens (skipped if empty). |
| `verify_method` | No | `GET` | HTTP method for `verify_url` (GET or POST). |
| `auth_header_type` | No | `bearer` | How to attach the token for verification: `bearer`, `token`, or `custom_header`. |
| `auth_header_name` | No | — | Header name when `auth_header_type=custom_header` (required in that case). |
| `display_name` | No | `OAuth2` | Human-readable label for logs and errors. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

The spec's `auth_method` selects the flow:

| `auth_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `client_credentials` (default) | Bearer token from client credentials | `scope`, `client_id`, `client_secret` |
| `authorization_code` | Bearer token refreshed from a sealed grant | `refresh_token`, `access_token`, expiry keys (set by consent) |

Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `client_credentials` | Flow to use: `client_credentials` or `authorization_code`. |
| `scope` | No | source `default_scopes` | Scopes requested for `client_credentials`. |
| `client_id` | No | source `client_id` | Client ID, resolved spec-over-source. |
| `client_secret` | No | source `client_secret` | Client secret, resolved spec-over-source. |
| `refresh_token` | No | — | Sealed refresh token for `authorization_code` (set by consent). |
| `access_token` | No | — | Sealed static access token for providers that issue no refresh token (set by consent). |
| `access_token_expires_at` | No | — | RFC3339 expiry of a sealed static access token. |
| `refresh_token_expires_at` | No | — | RFC3339 expiry of a sealed refresh token. |

For `authorization_code`, do not set the token keys by hand — they are populated by the one-time consent flow (see Capabilities). When the provider rotates the refresh token during a refresh, the driver surfaces the new value to the minting layer automatically, so the sealed grant stays current.

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [OAuth2 consent](/concepts/credentials/#oauth2-consent) — the authorization-code flow.
- [Credential drivers](/credential-drivers/) — every driver.
