---
title: "GitHub"
---

The GitHub provider enables proxied access to both the GitHub REST API and Git smart-HTTP (clone, fetch, push) through Warden. It supports both **GitHub App** and **Personal Access Token (PAT)** authentication, and works with GitHub.com and GitHub Enterprise Server.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Git over HTTPS](#git-over-https)
- [Authentication Methods](#authentication-methods)
- [Configuration Reference](#configuration-reference)
- [GitHub Enterprise Server](#github-enterprise-server)

## Prerequisites

- Docker and Docker Compose installed and running
- One of the following:
  - **GitHub App** with a private key and installation ID, OR
  - **Personal Access Token** (classic or fine-grained)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Download the latest Warden binary:**
> ```bash
> # macOS (Apple Silicon)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz
>
> # macOS (Intel)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz
>
> # Linux (x86_64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz
>
> # Linux (ARM64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
> ```
>
> **3. Add the binary to your PATH:**
> ```bash
> export PATH="$PWD:$PATH"
> ```
>
> **4. Start the Warden server** in dev mode:
> ```bash
> warden server -dev -dev-root-token=root
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="root"
> ```

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/github-user \
    token_policies="github-access" \
    user_claim=sub \
    cred_spec_name=github-ops
```

## Step 2: Mount and Configure the Provider

Enable the GitHub provider at a path of your choice:

```bash
warden provider enable github
```

To mount at a custom path:

```bash
warden provider enable -path=github-prod github
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write github/config <<EOF
{
  "github_url": "https://api.github.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read github/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info. Auth credentials (PAT, App private key) are stored on the credential spec below.

```bash
warden cred source create github-src \
  -type=github \
  -rotation-period=0 \
  -config=github_url=https://api.github.com
```

Verify the source was created:

```bash
warden cred source read github-src
```

Create a credential spec that references the credential source. The spec carries the auth credentials and gets associated with tokens at login time.

### Option A: GitHub App (Recommended)

1. Go to **Settings > Developer settings > GitHub Apps** and create a new app.
2. Note the **App ID** from the app settings page.
3. Generate a **private key** (RSA, PEM format) and download it.
4. Install the app on your organization or account and note the **Installation ID** from the URL.

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=app \
  -config app_id=<your-app-id> \
  -config private_key=@/path/to/private-key.pem \
  -config installation_id=<your-installation-id>
```

### Option B: Personal Access Token

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=pat \
  -config token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Verify:

```bash
warden cred spec read github-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the GitHub provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write github-access - <<EOF
# Role taken from the URL path (/v1/github/role/<role>/gateway/...).
# Used when callers pin the role per request via the URL.
path "github/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

# Role taken from the Basic Auth username (git clone), the X-Warden-Role
# header, or the mount's default_role. URL has no /role/<role>/ segment.
# Both REST and Git smart-HTTP can land on either rule — the distinction
# is the URL shape, not the protocol.
path "github/gateway/*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict repository deletion to trusted networks during business hours while leaving read and create access unconditional:

```bash
warden policy write github-prod-restricted - <<EOF
path "github/role/+/gateway/repos/+/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "github/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [Policies → CEL conditions](/concepts/policies/#cel-conditions)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read github-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the GitHub token automatically.

The URL pattern is: `/v1/github/role/{role}/gateway/{github-api-path}`

Export GITHUB_ENDPOINT as environment variable:
```bash
export GITHUB_ENDPOINT="${WARDEN_ADDR}/v1/github/role/github-user/gateway"
```

> **Note:** The available GitHub API endpoints depend on your auth method. GitHub App installation tokens and Personal Access Tokens have different scopes — see the examples below.

### GitHub App Examples

GitHub App installation tokens are scoped to the repositories where the app is installed. Use `/installation/` and `/repos/` endpoints.

#### List Repositories the App Is Installed On

```bash
curl "${GITHUB_ENDPOINT}/installation/repositories" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get a Specific Repository

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### List Pull Requests

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name/pulls?state=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Create an Issue

```bash
curl -X POST "${GITHUB_ENDPOINT}/repos/owner/repo-name/issues" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Bug report",
    "body": "Description of the issue"
  }'
```

#### List Organization Members

```bash
curl "${GITHUB_ENDPOINT}/orgs/my-org/members" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Personal Access Token (PAT) Examples

PATs are scoped to the authenticated user. Use `/user/` endpoints in addition to `/repos/`.

#### List Repositories for the Authenticated User

```bash
curl "${GITHUB_ENDPOINT}/user/repos" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get the Authenticated User's Profile

```bash
curl "${GITHUB_ENDPOINT}/user" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get a Specific Repository

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### List Pull Requests

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name/pulls?state=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Git over HTTPS

The same `github/` mount also proxies Git smart-HTTP (`git clone`, `fetch`, `push`) to the Git host (`github.com` by default; the corresponding host for GHE). REST paths continue to proxy to `api.github.com` unchanged — the provider dispatches per-request based on the path shape, so no separate mount or configuration is needed.

### Clone, fetch, push (path-routed form)

The clone URL carries the Warden role as the HTTP Basic Auth **username** and the Warden JWT as the **password**:

```bash
git clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/v1/github/gateway/<owner>/<repo>.git"
cd <repo>
git pull
git push
```

The Git credential helpers on macOS (`osxkeychain`), Linux (`libsecret`), and Windows (`git-credential-manager`) key cached credentials on **URL + username**, so two roles cloning the same repo land in distinct cache entries — switching roles does not invalidate the other's cache. Subsequent `pull`/`push` against the cloned remote re-use the same role automatically.

To avoid putting the JWT in shell history or `.git/config`, use a credential helper that prompts on demand:

```bash
git config --global credential.helper "store"
# or, better, a short-lived in-memory cache:
git config --global credential.helper "cache --timeout=900"
```

### Header-routed form (`X-Warden-Provider`)

Operators who want a clone URL that looks like a real Git URL (no Warden-specific path prefix) can use header routing instead. Set `X-Warden-Provider: github` via Git's `http.extraheader` config:

```bash
git -c http.extraheader="X-Warden-Provider: github" \
    clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/<owner>/<repo>.git"
```

`http.extraheader` persists into `.git/config` at clone time, so follow-up `pull`/`push` against the cloned remote carry the header automatically. Warden synthesises the canonical `github/gateway/<owner>/<repo>.git/...` path before mount lookup, so the dispatch and credential flows behave identically to the path-routed form.

### Cert-auth clients

Cert-auth clients (mTLS or `X-SSL-Client-Cert` from a TLS-terminating proxy) still need to populate Git's password slot because the Git protocol requires it. Any placeholder works — the github provider's token extractor skips the Basic Auth password when `X-SSL-Client-Cert` is set, so the placeholder is never sent to the JWT validator:

```bash
git clone "https://<role>:cert@${WARDEN_HOST}/v1/github/gateway/<owner>/<repo>.git"
```

Mixing a malformed cert with a valid JWT in the Basic Auth password is intentionally not a fallback path: if cert auth fails the request fails with a clear cert-auth error rather than silently switching schemes.

### Role precedence

Role resolution follows core ordering, with the Basic Auth username consulted after path/header roles but before `default_role`:

1. `X-Warden-Role` header
2. Path-embedded role (`/v1/github/role/<role>/gateway/...`)
3. **Basic Auth username** (Git smart-HTTP only)
4. `default_role` from the mount config

So `git clone https://<role>:$JWT@<host>/...` resolves to the username even when a mount-level `default_role` is configured; the default is used only when none of the higher-precedence sources contribute. REST callers are unaffected — the Basic Auth username is consulted only on Git smart-HTTP paths.

### Sizing `git_max_body_size` and `timeout`

- **`git_max_body_size`** caps Git request bodies in bytes. Default 2 GiB; valid range 1 MiB to 10 GiB. The existing `max_body_size` field controls REST POST bodies separately (default 10 MiB, 100 MiB ceiling) — do not raise `max_body_size` to accommodate Git pushes, that is what `git_max_body_size` is for.
- **Do not crank `git_max_body_size` to the 10 GiB ceiling reflexively.** The ceiling is a sanity cap, not a recommended value. Bodies stream through Warden chunk-by-chunk so memory is fine, but each accepted request pins one goroutine, one outbound socket, and 2× the body's bandwidth (ingress + egress to the Git host) for the duration of the transfer. Size to your actual largest expected push, not the maximum theoretical push.
- **Tune `timeout` for the longest expected push.** The mount-level `timeout` controls how long Warden will wait for the full request/response cycle. The default suits REST API calls, not multi-minute Git pushes. Rough heuristic: `timeout ≥ (git_max_body_size / smallest expected client bandwidth) × 2`, rounded up generously. Example: a 2 GiB cap with clients on a 100 Mbps link needs at least 320 s — set `timeout = 600s`. Too-tight `timeout` shows up as half-uploaded pushes that fail at the same byte count, which is a confusing failure mode.

### GHE: deriving the Git host

For GitHub Enterprise Server, the Git host is derived from the REST URL: `https://ghe.example.com/api/v3` → `https://ghe.example.com`. Setting `github_url` alone is sufficient for both REST and Git.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Authentication Methods

| Method | Auth Header | Token Lifetime | Rotation |
|--------|-------------|----------------|----------|
| **App** | Installation token (auto-minted) | 1 hour (auto-refreshed) | Not needed — tokens are ephemeral |
| **PAT** | Static personal access token | No expiration | Not supported — manage PAT lifecycle on GitHub |

**GitHub App** is recommended because:
- Tokens are short-lived (1 hour) and automatically refreshed
- Fine-grained permissions scoped to the app installation
- No long-lived secrets stored after initial setup
- Audit trail tied to the app identity

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `-dev-tls` to enable TLS with auto-generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=github-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/github-user \
    allowed_common_names="agent-*" \
    token_policies="github-access" \
    cred_spec_name=github-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write github/config <<EOF
{
  "github_url": "https://api.github.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
# Role in URL path
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/github/role/github-user/gateway/repos/owner/repo-name

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/github/gateway/repos/owner/repo-name
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `github_url` | string | `https://api.github.com` | GitHub API base URL (must be HTTPS) |
| `api_version` | string | `2022-11-28` | GitHub REST API version header (latest: `2026-03-10`) |
| `git_max_body_size` | int | 2147483648 (2 GiB) | Maximum request body size for Git smart-HTTP requests in bytes (range: 1 MiB to 10 GiB) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size for REST requests in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`); raise for large Git pushes — see [Git over HTTPS](#git-over-https) |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `github_url` | string | `https://api.github.com` | GitHub API base URL (must be HTTPS) |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` URLs (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Credential Spec Config (App Mode)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `auth_method` | string | Yes | Must be `app` |
| `app_id` | string | Yes | GitHub App ID |
| `private_key` | string | Yes | PEM-encoded RSA private key (PKCS1 or PKCS8) |
| `installation_id` | string | Yes | GitHub App installation ID |

### Credential Spec Config (PAT Mode)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `auth_method` | string | Yes | Must be `pat` |
| `token` | string | Yes | Personal Access Token |

## GitHub Enterprise Server

To use with GitHub Enterprise Server, set `github_url` to your instance's API endpoint:

```bash
warden write github/config <<EOF
{
  "github_url": "https://github.example.com/api/v3"
}
EOF
```

All gateway requests will be proxied to the configured Enterprise Server instance.

### Custom CA Certificate

If your GitHub Enterprise instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write github/config <<EOF
{
  "github_url": "https://github.internal.corp/api/v3",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a GitHub Enterprise instance without TLS:

```bash
warden write github/config <<EOF
{
  "github_url": "http://localhost:3000/api/v3",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
