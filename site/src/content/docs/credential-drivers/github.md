---
title: "GitHub"
---

> Source `type`: `github`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The GitHub driver mints **GitHub tokens** for workloads that call the GitHub REST API — github.com or a GitHub Enterprise instance. Unusually, the privileged auth material does **not** live on the **source**. The source config holds only connection details (`github_url` plus TLS options); the actual credentials — a GitHub App private key or a Personal Access Token — are supplied per **spec** and read at mint time. This means many specs, each carrying a different PAT or App installation, can share a single source.

Each spec picks a **`mint_method`**: `app` uses a GitHub App private key to mint short-lived installation access tokens (~1h TTL), while `pat` passes through a static Personal Access Token. An operator reaches for this driver whenever a workload needs to authenticate to GitHub without holding the long-lived App key or PAT itself.

## Keyless (via chaining)

The App private key or PAT does not have to be stored. Unusually for this driver the
reference goes on the **spec**, because that is where GitHub credentials live: set
`secret_spec` and Warden fetches the key or PAT from a keyless-federated vault at mint
time — `app` signs an installation token with it, `pat` passes it through — so nothing is
stored at Warden. Use `secret_field` when the referenced payload has more than one key.

```bash
warden cred spec create gh-app \
  -source=github-src \
  -config=mint_method=app \
  -config=app_id=123456 \
  -config=installation_id=7891011 \
  -config=secret_spec=github-key-in-vault
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create github-key-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=github/app-private-key \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create github-key-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/github/app-private-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create github-key-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=github-app-private-key \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: An App key per organisation.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. A GitHub App is registered per organisation, so its private key is too. The agent's org decides which key signs the installation token.

```bash
warden cred spec create github-key-per-org \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=github/{{agent.metadata.org}}/app-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=org
```

An agent claim other than `sub` resolves only if the spec lists it in
`assertion_metadata_claims`. Resolution is fail-closed at mint: a claim the login does not
carry fails the request rather than falling back to a shared secret. `{{user.<claim>}}`
works the same way via `assertion_user_claims`, and the two can be combined in one path.

See [credential chaining](/federation/credential-chaining/#producers).

## Credential issued

The driver always issues the `github_token` type. In `app` mode the token is **dynamic** — it carries a TTL (~1h) tied to the installation token's expiry. In `pat` mode the token is **static** — no lease, no TTL. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation). GitHub App installation tokens are revocable and expire naturally; the driver relies on their short lifetime rather than tracking leases for explicit revocation.

## Capabilities

- **Spec verification** — validates a spec at create/update time. In `pat` mode it confirms the token with a lightweight identity call; in `app` mode the spec is exercised by a trial mint against the GitHub API.
- **Not rotatable — by design.** GitHub App installation tokens are ephemeral (~1h) and are simply re-minted on demand, and GitHub exposes no API to rotate a PAT. There is nothing long-lived on the source to rotate, so the driver does not implement source rotation.

## Examples

### Keyless (via chaining, recommended)

The App private key / PAT is not stored on the spec; it is chained from another cred spec (e.g. a keyless Vault `kv2_read`), fetched at mint time.

```bash
warden cred spec create ci-deploy-keyless \
  -source=github-prod \
  -config=mint_method=app \
  -config=app_id=123456 \
  -config=installation_id=7891011 \
  -config=secret_spec=github-app-key
```

### Inline secret (discouraged)

One source holds only connection details; each spec below picks a `mint_method`.

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
  -config=mint_method=app \
  -config=app_id=123456 \
  -config=installation_id=7891011 \
  -config=private_key="$(cat app-private-key.pem)"
```

**Personal Access Token** — pass a static PAT through unchanged:

```bash
warden cred spec create readonly-pat \
  -source=github-prod \
  -config=mint_method=pat \
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

The `mint_method` spec key selects which token is minted:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `app` | Short-lived GitHub App installation access token (~1h TTL) | `private_key`, `app_id`, `installation_id` |
| `pat` | Static Personal Access Token, passed through unchanged | `token` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | Yes | — | Which token to mint: `app` or `pat`. |
| `private_key` | For `app` (inline) | — | PEM-encoded RSA private key for the GitHub App (PKCS1 or PKCS8). Omit when chained via `secret_spec`. |
| `app_id` | For `app` | — | GitHub App ID (JWT issuer). |
| `installation_id` | For `app` | — | Installation ID the token is minted for. |
| `token` | For `pat` (inline) | — | The Personal Access Token to pass through. Omit when chained via `secret_spec`. |
| `secret_spec` | No | — | Source the App private key / PAT from another cred spec via [credential chaining](/federation/credential-chaining/) (keyless). |
| `secret_field` | No | — | Field of the referenced `secret_spec`'s credential holding the key/PAT, when its payload has multiple keys. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [GitHub provider](/provider-backends/github/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
