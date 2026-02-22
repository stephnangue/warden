# GitHub Provider

The GitHub provider enables proxied access to the GitHub REST API through Warden. It supports both **GitHub App** and **Personal Access Token (PAT)** authentication, and works with GitHub.com and GitHub Enterprise Server.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Mount the GitHub Provider](#step-1-mount-the-github-provider)
- [Step 2: Configure the Provider](#step-2-configure-the-provider)
- [Step 3: Create a Credential Source](#step-3-create-a-credential-source)
- [Step 4: Create a Credential Spec](#step-4-create-a-credential-spec)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Configure JWT Auth and Create a Role](#step-6-configure-jwt-auth-and-create-a-role)
- [Step 7: Get a JWT](#step-7-get-a-jwt)
- [Step 8: Make Requests Through the Gateway](#step-8-make-requests-through-the-gateway)
- [Authentication Methods](#authentication-methods)
- [Configuration Reference](#configuration-reference)
- [GitHub Enterprise Server](#github-enterprise-server)

## Prerequisites

- A running Warden server
- The Warden CLI installed and configured
- One of the following:
  - **GitHub App** with a private key and installation ID, OR
  - **Personal Access Token** (classic or fine-grained)

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

## Step 1: Mount the GitHub Provider

Enable the GitHub provider at a path of your choice:

```bash
warden provider enable --type=github
```

To mount at a custom path:

```bash
warden provider enable --type=github github-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

## Step 2: Configure the Provider

Configure the provider with transparent mode enabled. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write github/config <<EOF
{
  "github_url": "https://api.github.com",
  "transparent_mode": true,
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

## Step 3: Create a Credential Source

The credential source holds only connection info. Auth credentials (PAT, App private key) are stored on the credential spec (Step 4).

```bash
warden cred source create github-src \
  --type=github \
  --rotation-period=0 \
  --config=github_url=https://api.github.com
```

Verify the source was created:

```bash
warden cred source read github-src
```

## Step 4: Create a Credential Spec

Create a credential spec that references the credential source. The spec carries the auth credentials and gets associated with tokens at login time.

### Option A: GitHub App (Recommended)

1. Go to **Settings > Developer settings > GitHub Apps** and create a new app.
2. Note the **App ID** from the app settings page.
3. Generate a **private key** (RSA, PEM format) and download it.
4. Install the app on your organization or account and note the **Installation ID** from the URL.

```bash
warden cred spec create github-ops \
  --type github_token \
  --source github-src \
  --config auth_method=app \
  --config app_id=<your-app-id> \
  --config private_key=@/path/to/private-key.pem \
  --config installation_id=<your-installation-id>
```

### Option B: Personal Access Token

```bash
warden cred spec create github-ops \
  --type github_token \
  --source github-src \
  --config auth_method=pat \
  --config token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Verify:

```bash
warden cred spec read github-ops
```

## Step 5: Create a Policy

Create a policy that grants access to the GitHub provider gateway:

```bash
warden policy write github-access - <<EOF
path "github/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOF
```

Verify:

```bash
warden policy read github-access
```

## Step 6: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/github-user \
    token_type=jwt_role \
    token_policies="github-access" \
    user_claim=sub \
    cred_spec_name=github-ops \
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

With transparent mode, requests use role-based paths. Warden performs implicit JWT authentication and injects the GitHub token automatically.

The URL pattern is: `/v1/github/role/{role}/gateway/{github-api-path}`

Export GITHUB_ENDPOINT as environment variable:
```bash
export GITHUB_ENDPOINT="${WARDEN_ADDR}/v1/github/role/github-user/gateway"
```
### List Repositories

```bash
curl "${GITHUB_ENDPOINT}/user/repos" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Get a Specific Repository

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Pull Requests

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name/pulls?state=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create an Issue

```bash
curl -X POST "${GITHUB_ENDPOINT}/repos/owner/repo-name/issues" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Bug report",
    "body": "Description of the issue"
  }'
```

### List Organization Members

```bash
curl "${GITHUB_ENDPOINT}/orgs/my-org/members" \
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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `github_url` | string | `https://api.github.com` | GitHub API base URL (must be HTTPS) |
| `api_version` | string | `2022-11-28` | GitHub REST API version header |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `github_url` | string | `https://api.github.com` | GitHub API base URL (must be HTTPS) |

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
