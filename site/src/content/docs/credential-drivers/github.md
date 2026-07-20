---
title: "GitHub"
---

> Source `type`: `github`

The GitHub driver mints **GitHub tokens** for workloads that call the GitHub REST API — github.com or a GitHub Enterprise instance. Unusually, the privileged auth material does **not** live on the **source**. The source config holds only connection details (`github_url` plus TLS options); the actual credentials — a GitHub App private key or a Personal Access Token — are supplied per **spec** and read at mint time. This means many specs, each carrying a different PAT or App installation, can share a single source.

Each spec picks an **`auth_method`**: `app` (the default) uses a GitHub App private key to mint short-lived installation access tokens (~1h TTL), while `pat` passes through a static Personal Access Token. An operator reaches for this driver whenever a workload needs to authenticate to GitHub without holding the long-lived App key or PAT itself.

## Credential issued

The driver always issues the `github_token` type. In `app` mode the token is **dynamic** — it carries a TTL (~1h) tied to the installation token's expiry. In `pat` mode the token is **static** — no lease, no TTL. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation). GitHub App installation tokens are revocable and expire naturally; the driver relies on their short lifetime rather than tracking leases for explicit revocation.

## Capabilities

- **Spec verification** — validates a spec at create/update time. In `pat` mode it confirms the token with a lightweight identity call; in `app` mode the spec is exercised by a trial mint against the GitHub API.
- **Not rotatable — by design.** GitHub App installation tokens are ephemeral (~1h) and are simply re-minted on demand, and GitHub exposes no API to rotate a PAT. There is nothing long-lived on the source to rotate, so the driver does not implement source rotation.

## Examples

One source holds only connection details; each spec below picks an `auth_method`.

```bash
warden cred source create github-prod \
  -type=github \
  -config=github_url=https://api.github.com \
  -rotation-period=0
```

**GitHub App** — mint short-lived installation access tokens from an App private key:

```bash
warden cred spec create ci-deploy \
  -source=github-prod \
  -config=auth_method=app \
  -config=app_id=123456 \
  -config=installation_id=7891011 \
  -config=private_key="$(cat app-private-key.pem)"
```

**Personal Access Token** — pass a static PAT through unchanged:

```bash
warden cred spec create readonly-pat \
  -source=github-prod \
  -config=auth_method=pat \
  -config=token=ghp_xxxxxxxxxxxxxxxxxxxx
```

## Source config

Keys for `warden cred source create <name> -type=github -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `github_url` | No | `https://api.github.com` | GitHub API URL — the default for github.com, or a GitHub Enterprise URL. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom or self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

The `auth_method` spec key selects how the token is obtained:

| `auth_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `app` (default) | Short-lived GitHub App installation access token (~1h TTL) | `private_key`, `app_id`, `installation_id` |
| `pat` | Static Personal Access Token, passed through unchanged | `token` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `app` | Auth mode: `app` or `pat`. |
| `private_key` | For `app` | — | PEM-encoded RSA private key for the GitHub App (PKCS1 or PKCS8). |
| `app_id` | For `app` | — | GitHub App ID (JWT issuer). |
| `installation_id` | For `app` | — | Installation ID the token is minted for. |
| `token` | For `pat` | — | The Personal Access Token to pass through. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [GitHub provider](/provider-backends/github/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
