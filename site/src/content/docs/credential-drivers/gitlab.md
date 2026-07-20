---
title: "GitLab"
---

> Source `type`: `gitlab`

The GitLab driver mints **project access tokens** and **group access tokens** from a GitLab server. Warden calls the GitLab API to create short-lived, scoped tokens on demand and revokes them when their lease ends, so workloads never hold a long-lived credential.

The privileged secret lives in the **source** config. The driver authenticates to GitLab one of two ways, set by `auth_method`: **PAT mode** (default) uses a **personal access token**, and **OAuth2 mode** uses an application ID and secret via the client-credentials flow. Each **spec** then names a project or group and the scopes the minted token should carry. An operator reaches for this driver to broker CI and automation access to specific GitLab projects or groups without distributing standing tokens.

## Credential issued

Both mint methods issue a `gitlab_access_token`. It is **dynamic** — it carries a lease and TTL derived from `ttl` — and **revocable**: Warden deletes the token via the GitLab API when the lease ends. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **fast**, prepares and activates in one step (immediately-consistent upstream). The driver rotates its own source credential: in PAT mode it calls GitLab's atomic PAT rotate endpoint; in OAuth2 mode it renews the application secret. In both cases GitLab invalidates the old credential as part of the rotate, so the new one is committed inline with no propagation delay.

## Examples

**PAT source, project access token** — authenticate with a personal access token and mint a project-scoped token:

```bash
warden cred source create gitlab-ci \
  -type=gitlab \
  -config=gitlab_address=https://gitlab.example.com \
  -config=auth_method=pat \
  -config=personal_access_token=glpat-xxxxxxxxxxxx \
  -rotation-period=720h

warden cred spec create gitlab-app-deploy \
  -source=gitlab-ci \
  -config=mint_method=project_access_token \
  -config=project_id=42 \
  -config=scopes=api,read_repository \
  -config=ttl=24h
```

**OAuth2 source, group access token** — authenticate with an application ID and secret and mint a group-scoped token:

```bash
warden cred source create gitlab-oauth \
  -type=gitlab \
  -config=gitlab_address=https://gitlab.example.com \
  -config=auth_method=oauth2 \
  -config=application_id=your-application-id \
  -config=application_secret=your-application-secret \
  -rotation-period=720h

warden cred spec create gitlab-group-ci \
  -source=gitlab-oauth \
  -config=mint_method=group_access_token \
  -config=group_id=100 \
  -config=scopes=read_repository \
  -config=access_level=30 \
  -config=ttl=24h
```

## Source config

Keys for `warden cred source create <name> -type=gitlab -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `gitlab_address` | Yes | — | GitLab server address (`http://` or `https://`), e.g. `https://gitlab.example.com`. |
| `auth_method` | No | `pat` | Authentication method: `pat` or `oauth2`. |
| `personal_access_token` | Yes (pat) | — | GitLab personal access token (secret, masked on read). Required in PAT mode. |
| `application_id` | Yes (oauth2) | — | GitLab OAuth2 application ID. Required in OAuth2 mode. |
| `application_secret` | Yes (oauth2) | — | GitLab OAuth2 application secret (secret, masked on read). Required in OAuth2 mode. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `project_access_token` | A project access token | `project_id` |
| `group_access_token` | A group access token | `group_id` |

Spec-config keys for `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | Yes | — | `project_access_token` or `group_access_token`. |
| `project_id` | Yes (project) | — | Project ID or URL-encoded path. Used by `project_access_token`. |
| `group_id` | Yes (group) | — | Group ID or URL-encoded path. Used by `group_access_token`. |
| `token_name` | No | `warden-minted` | Display name for the created token. |
| `scopes` | No | `api` | Comma-separated token scopes. |
| `access_level` | No | `30` | Access level for the token (30 = developer). |
| `ttl` | No | `24h` | Token lifetime; sets the expiry date and the lease TTL. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [GitLab provider](/provider-backends/gitlab/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
