# GitLab Provider

The GitLab provider enables proxied access to the GitLab REST API through Warden. It supports **Personal Access Token (PAT)** and **OAuth2** authentication, can mint scoped project and group access tokens on demand, and works with both GitLab.com and self-hosted instances.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Mount the GitLab Provider](#step-1-mount-the-gitlab-provider)
- [Step 2: Configure the Provider](#step-2-configure-the-provider)
- [Step 3: Create a Credential Source](#step-3-create-a-credential-source)
- [Step 4: Create a Credential Spec](#step-4-create-a-credential-spec)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Configure JWT Auth and Create a Role](#step-6-configure-jwt-auth-and-create-a-role)
- [Step 7: Get a JWT](#step-7-get-a-jwt)
- [Step 8: Make Requests Through the Gateway](#step-8-make-requests-through-the-gateway)
- [Minting Project and Group Access Tokens](#minting-project-and-group-access-tokens)
- [Authentication Methods](#authentication-methods)
- [Credential Rotation](#credential-rotation)
- [Configuration Reference](#configuration-reference)
- [Self-Hosted GitLab](#self-hosted-gitlab)

## Prerequisites

- A running Warden server
- The Warden CLI installed and configured
- One of the following:
  - **OAuth2 application** credentials (`application_id` and `application_secret`), OR
  - **Personal Access Token** with `api` scope (and `admin` scope if rotation is needed)

> **New to Warden?** Download the binary from the [latest release](https://github.com/stephnangue/warden/releases/latest), then start the identity provider and Warden in dev mode:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ./warden server --dev
> ```

```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<your-token>"
```

## Step 1: Mount the GitLab Provider

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

## Step 2: Configure the Provider

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

## Step 3: Create a Credential Source

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

## Step 4: Create a Credential Spec

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

## Step 5: Create a Policy

Create a policy that grants access to the GitLab provider gateway:

```bash
warden policy write gitlab-access - <<EOF
path "gitlab/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOF
```

Verify:

```bash
warden policy read gitlab-access
```

## Step 6: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gitlab-user \
    token_type=jwt_role \
    token_policies="gitlab-access" \
    user_claim=sub \
    cred_spec_name=gitlab-project-token \
    token_ttl=1h
```

## Step 7: Get a JWT

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

## Step 8: Make Requests Through the Gateway

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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gitlab_address` | string | — | GitLab instance URL (required, e.g., `https://gitlab.com`) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
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
