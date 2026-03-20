# GitLab Provider

The GitLab provider enables proxied access to the GitLab REST API through Warden. It supports **Personal Access Token (PAT)** and **OAuth2** authentication, can mint scoped project and group access tokens on demand, and works with both GitLab.com and self-hosted instances.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Minting Project and Group Access Tokens](#minting-project-and-group-access-tokens)
- [Authentication Methods](#authentication-methods)
- [Credential Rotation](#credential-rotation)
- [Configuration Reference](#configuration-reference)
- [Self-Hosted GitLab](#self-hosted-gitlab)

## Prerequisites

- Docker and Docker Compose installed and running
- One of the following:
  - **OAuth2 application** credentials (`application_id` and `application_secret`), OR
  - **Personal Access Token** with `api` scope (and `admin` scope if rotation is needed)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
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
> warden server --dev
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="<your-token>"
> ```

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gitlab-user \
    token_policies="gitlab-access" \
    user_claim=sub \
    cred_spec_name=gitlab-project-token \
    token_ttl=1h
```

## Step 2: Mount and Configure the Provider

Enable the GitLab provider at a path of your choice:

```bash
warden provider enable --type=gitlab
```

To mount at a custom path:

```bash
warden provider enable --type=gitlab gitlab-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with transparent mode enabled. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.com",
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read gitlab/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds the connection info and auth credentials for GitLab.

### Option A: OAuth2 Application (Recommended)

1. In GitLab, go to **Admin Area > Applications** (or **User Settings > Applications**).
2. Create an OAuth2 application and note the `Application ID` and `Secret`.

```bash
warden cred source create gitlab-oauth \
  --type=gitlab \
  --rotation-period=720h \
  --config=gitlab_address=https://gitlab.com \
  --config=auth_method=oauth2 \
  --config=application_id=<your-application-id> \
  --config=application_secret=<your-application-secret>
```

### Option B: Personal Access Token

1. In GitLab, go to **User Settings > Access Tokens**.
2. Create a token with the required scopes (`api` at minimum, `admin` for rotation support).

```bash
warden cred source create gitlab-pat \
  --type=gitlab \
  --rotation-period=720h \
  --config=gitlab_address=https://gitlab.com \
  --config=auth_method=pat \
  --config=personal_access_token=glpat-xxxxxxxxxxxxxxxxxxxx
```

Verify the source was created:

```bash
warden cred source read gitlab-pat
```

Create a credential spec that references the credential source. The spec defines what type of token to mint (project access token, group access token, etc.).

### Project Access Token

```bash
warden cred spec create gitlab-project-token \
  --type=gitlab_access_token \
  --source=gitlab-pat \
  --min-ttl=1h \
  --max-ttl=24h \
  --config=mint_method=project_access_token \
  --config=project_id=123 \
  --config=token_name=warden-minted \
  --config=scopes=api,read_api \
  --config=access_level=30
```

### Group Access Token

```bash
warden cred spec create gitlab-group-token \
  --type=gitlab_access_token \
  --source=gitlab-pat \
  --min-ttl=1h \
  --max-ttl=24h \
  --config=mint_method=group_access_token \
  --config=group_id=79644309 \
  --config=token_name=warden-minted \
  --config=scopes=api \
  --config=access_level=30
```

Verify:

```bash
warden cred spec read gitlab-project-token
```

## Step 4: Create a Policy

Create a policy that grants access to the GitLab provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write gitlab-access - <<EOF
path "gitlab/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict project deletion to trusted networks during business hours while leaving read and create access unconditional:

```bash
warden policy write gitlab-prod-restricted - <<EOF
path "gitlab/role/+/gateway/api/v4/projects/*" {
  capabilities = ["delete"]
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "gitlab/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read gitlab-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

With transparent mode, requests use role-based paths. Warden performs implicit JWT authentication and injects the GitLab token automatically. Note that GitLab API paths start with `/api/v4/`.

The URL pattern is: `/v1/gitlab/role/{role}/gateway/{gitlab-api-path}`

Export GITLAB_ENDPOINT as environment variable:
```bash
export GITLAB_ENDPOINT="${WARDEN_ADDR}/v1/gitlab/role/gitlab-user/gateway"
```

### List Projects

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Get a Specific Project

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Merge Requests

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/merge_requests?state=opened" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Pipelines

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/pipelines" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Group Projects

```bash
curl "${GITLAB_ENDPOINT}/api/v4/groups/my-group/projects" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create an Issue

```bash
curl -X POST "${GITLAB_ENDPOINT}/api/v4/projects/123/issues" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Bug report",
    "description": "Description of the issue"
  }'
```

### List Repository Branches

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/repository/branches" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Minting Project and Group Access Tokens

Warden mints short-lived, scoped access tokens for GitLab projects and groups through credential specs (configured in Step 4).

### Access Levels

| Value | Role |
|-------|------|
| 10 | Guest |
| 20 | Reporter |
| 30 | Developer |
| 40 | Maintainer |

### Available Scopes

`api`, `read_api`, `read_user`, `read_repository`, `write_repository`, `read_registry`, `write_registry`, `sudo`, `admin_mode`, `create_runner`, `manage_runner`, `ai_features`, `k8s_proxy`

## Authentication Methods

| Method | Header Used | Token Caching | Rotation |
|--------|-------------|---------------|----------|
| **PAT** | `PRIVATE-TOKEN` | N/A | Supported via GitLab rotate API |
| **OAuth2** | `Authorization: Bearer` | Cached with 30s expiry buffer | Supported via application secret rotate API |

**OAuth2** is recommended because the application identity is organization-owned and not tied to a personal account. **PAT** is simpler to set up but creates a dependency on a single user account.

## Credential Rotation

GitLab credentials support the two-stage async rotation pattern:

- **PAT mode:** Rotates via `POST /api/v4/personal_access_tokens/{id}/rotate`. GitLab immediately revokes the old token and issues a new one.
- **OAuth2 mode:** Rotates via `POST /api/v4/applications/{id}/rotate_secret`. GitLab immediately invalidates the old secret.

The default activation delay is **1 minute** (configurable via `activation_delay` in the credential source config). No cleanup is needed since GitLab automatically invalidates old credentials during rotation.

## TLS Certificate Authentication

Steps 4–5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). It does not work in dev mode, which uses plain HTTP. Start Warden with a TLS listener, or place it behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1–3 (provider setup) are identical. Replace Steps 4–5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=gitlab-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/gitlab-user \
    allowed_common_names="agent-*" \
    token_policies="gitlab-access" \
    cred_spec_name=gitlab-project-token \
    token_ttl=1h
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth for transparent mode:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.com",
  "transparent_mode": true,
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
    https://warden.internal/v1/gitlab/role/gitlab-user/gateway/api/v4/projects

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/gitlab/gateway/api/v4/projects
```

### Explicit Login with Certificates

To use cert auth for explicit login (without transparent mode):

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    token_type=warden \
    default_role=gitlab-user

warden write auth/cert/role/gitlab-user \
    allowed_common_names="agent-*" \
    token_type=warden \
    token_policies="gitlab-access" \
    cred_spec_name=gitlab-project-token \
    token_ttl=1h
```

Then authenticate with the CLI:

```bash
warden login --method=cert --role=gitlab-user \
    --cert=./client.pem --key=./client-key.pem
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gitlab_address` | string | — | GitLab instance URL (required, e.g., `https://gitlab.com`) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `transparent_mode` | bool | `false` | Enable implicit authentication (JWT or TLS certificate) |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (PAT Mode)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `gitlab_address` | string | Yes | GitLab instance URL |
| `auth_method` | string | Yes | Must be `pat` |
| `personal_access_token` | string | Yes | Personal access token with `api` scope |
| `activation_delay` | duration | No | Delay before activating rotated credentials (default: `1m`) |

### Credential Source Config (OAuth2 Mode)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `gitlab_address` | string | Yes | GitLab instance URL |
| `auth_method` | string | Yes | Must be `oauth2` |
| `application_id` | string | Yes | OAuth2 application ID |
| `application_secret` | string | Yes | OAuth2 application secret |
| `activation_delay` | duration | No | Delay before activating rotated credentials (default: `1m`) |

### Credential Spec Config (Project Access Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `project_access_token` |
| `project_id` | string | Yes | GitLab project ID (numeric or URL-encoded path) |
| `token_name` | string | No | Token name (default: `warden-minted`) |
| `scopes` | string | No | Comma-separated scopes (default: `api`) |
| `access_level` | int | No | Access level: 10/20/30/40 (default: `30`) |
| `ttl` | duration | No | Token TTL (default: `24h`, max: 365 days) |

### Credential Spec Config (Group Access Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `group_access_token` |
| `group_id` | string | Yes | GitLab group ID (numeric or URL-encoded path) |
| `token_name` | string | No | Token name (default: `warden-minted`) |
| `scopes` | string | No | Comma-separated scopes (default: `api`) |
| `access_level` | int | No | Access level: 10/20/30/40 (default: `30`) |
| `ttl` | duration | No | Token TTL (default: `24h`, max: 365 days) |

## Self-Hosted GitLab

To use with a self-hosted GitLab instance, set `gitlab_address` in both the provider config and credential source config:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.example.com",
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```

All gateway requests will be proxied to the configured GitLab instance.
