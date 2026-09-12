---
title: "GitLab"
---

> Source `type`: `gitlab`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The GitLab driver mints **project access tokens** and **group access tokens** from a GitLab server. Warden calls the GitLab API to create short-lived, scoped tokens on demand and revokes them when their lease ends, so workloads never hold a long-lived credential.

The privileged secret lives in the **source** config. The driver authenticates to GitLab one of two ways, set by `auth_method`: **PAT mode** (default) uses a **personal access token**, and **OAuth2 mode** uses an application ID and secret via the client-credentials flow. Each **spec** then names a project or group and the scopes the minted token should carry. An operator reaches for this driver to broker CI and automation access to specific GitLab projects or groups without distributing standing tokens.

## Keyless (via chaining)

The Personal Access Token does not have to be stored: set `secret_spec` to source it from
another cred spec via [credential chaining](/federation/credential-chaining/). Warden
fetches the PAT from a keyless-federated vault at mint time and uses it to mint the
downstream token, so nothing is stored at Warden.

The referenced credential's `personal_access_token` field is used by default; name a
different one with `secret_field`.

## Credential issued

Both mint methods issue a `gitlab_access_token`. It is **dynamic** — it carries a lease and TTL derived from `ttl` — and **revocable**: Warden deletes the token via the GitLab API when the lease ends. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **fast**, prepares and activates in one step (immediately-consistent upstream). The driver rotates its own source credential: in PAT mode it calls GitLab's atomic PAT rotate endpoint; in OAuth2 mode it renews the application secret. In both cases GitLab invalidates the old credential as part of the rotate, so the new one is committed inline with no propagation delay.

## Examples

### Keyless (via chaining, recommended)

The source stores no secret: the personal access token is fetched from a keyless-federated
vault per request.

The **consumer** is the same whichever producer you use — only the `secret_spec` name
changes:

```bash
warden cred source create gitlab-keyless \
  -type=gitlab \
  -config=gitlab_address=https://gitlab.example.com \
  -config=secret_spec=gitlab-pat-in-vault

warden cred spec create gitlab-ro \
  -source=gitlab-keyless \
  -config=mint_method=project_access_token \
  -config=project_id=42 \
  -config=token_name=warden-ro \
  -config=access_level=20 \
  -config=scopes=read_repository \
  -config=ttl=24h
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create gitlab-pat-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=gitlab/warden-pat \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create gitlab-pat-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/gitlab/warden-pat \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create gitlab-pat-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=gitlab-warden-pat \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A PAT per engineer, inside their group.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. GitLab attributes every push to a token owner, so a shared PAT loses the trail. **Both namespaces template into one path**: the agent's group scopes the tree, the verified user picks the engineer's own PAT.

```bash
warden cred spec create gitlab-pat-per-engineer \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=gitlab/{{agent.metadata.group}}/engineers/{{user.username}}/pat \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=group \
  -config=assertion_user_claims=username
```

A claim is only resolvable if the spec projects it: `assertion_metadata_claims` for the
agent, `assertion_user_claims` for the user. Resolution is fail-closed at mint — a missing
claim fails the request rather than falling back to a shared secret, and a `{{user.…}}`
template on a request with no user fails too, so a per-user secret cannot be reached
without a user.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

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
  -config=token_name=warden-deploy \
  -config=access_level=30 \
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
  -config=token_name=warden-group-ro \
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
