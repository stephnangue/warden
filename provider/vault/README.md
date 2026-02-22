# Vault Provider

The Vault provider enables proxied access to HashiCorp Vault (or OpenBao) through Warden. It intercepts client requests, injects a real Vault token obtained from the credential manager, and forwards the request to the target Vault instance. This allows Warden to broker Vault access without distributing long-lived Vault tokens to clients.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Create an AppRole in Vault](#step-1-create-an-approle-in-vault)
- [Step 2: Mount the Vault Provider](#step-2-mount-the-vault-provider)
- [Step 3: Configure the Provider](#step-3-configure-the-provider)
- [Step 4: Create a Credential Source](#step-4-create-a-credential-source)
- [Step 5: Create Credential Specs](#step-5-create-credential-specs)
- [Step 6: Create a Policy](#step-6-create-a-policy)
- [Step 7: Configure JWT Auth and Create a Role](#step-7-configure-jwt-auth-and-create-a-role)
- [Step 8: Get a JWT](#step-8-get-a-jwt)
- [Step 9: Make Requests Through the Gateway](#step-9-make-requests-through-the-gateway)
- [Architecture Overview](#architecture-overview)
- [Mint Methods](#mint-methods)
- [Transparent Mode](#transparent-mode)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- A running Warden server
- The Warden CLI installed and configured
- HashiCorp Vault running and unsealed
- Vault CLI (for initial AppRole setup)

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

## Step 1: Create an AppRole in Vault

Create a dedicated AppRole for Warden with policies that grant access to the secrets engines it needs.

### Create a Vault Policy

```bash
vault policy write warden-source - <<EOF
# KV v2 read access
path "secret/data/*" {
  capabilities = ["read"]
}

# Database credential generation
path "database/creds/*" {
  capabilities = ["read"]
}

# AWS credential generation
path "aws/creds/*" {
  capabilities = ["read", "create", "update"]
}

# Token creation via roles
path "auth/token/create/*" {
  capabilities = ["create", "update"]
}

# Lease revocation
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Token revocation via accessor
path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}

# Self-manage secret_id for rotation
path "auth/warden_approle/role/warden-source/secret-id" {
  capabilities = ["create", "update"]
}
path "auth/warden_approle/role/warden-source/secret-id-accessor/destroy" {
  capabilities = ["update"]
}
EOF
```

### Enable AppRole and Create the Role

```bash
# Enable AppRole auth at a custom mount
vault auth enable -path=warden_approle approle

# Create the role
vault write auth/warden_approle/role/warden-source \
  token_policies="warden-source" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=0 \
  secret_id_ttl=0
```

### Generate Credentials

```bash
# Get the role_id (static, does not change)
vault read auth/warden_approle/role/warden-source/role-id

# Generate a secret_id (Warden will rotate this automatically)
vault write -f auth/warden_approle/role/warden-source/secret-id
```

Save the `role_id`, `secret_id`, and `secret_id_accessor` from the output.

## Step 2: Mount the Vault Provider

Enable the Vault provider at a path of your choice:

```bash
warden provider enable --type=vault
```

To mount at a custom path:

```bash
warden provider enable --type=vault vault-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

## Step 3: Configure the Provider

Configure the provider with the Vault server address:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify:

```bash
warden read vault/config
```

## Step 4: Create a Credential Source

The credential source tells Warden how to authenticate to Vault using the AppRole created in Step 1.

```bash
warden cred source create vault-prod \
  --type hvault \
  --rotation-period 24h \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=<role-id> \
  --config secret_id=<secret-id> \
  --config secret_id_accessor=<accessor> \
  --config approle_mount=warden_approle \
  --config role_name=warden-source
```

For Vault Enterprise/HCP Vault with namespaces or OpenBao, add `vault_namespace` to scope all Warden API calls (AppRole auth, credential minting) to that namespace:

```bash
warden cred source create vault-prod \
  --type hvault \
  --rotation-period 24h \
  --config vault_address=https://vault.example.com:8200 \
  --config auth_method=approle \
  --config role_id=<role-id> \
  --config secret_id=<secret-id> \
  --config secret_id_accessor=<accessor> \
  --config approle_mount=warden_approle \
  --config role_name=warden-source \
  --config vault_namespace=admin/team-a
```

The `--rotation-period` controls how often Warden rotates the AppRole `secret_id`. During rotation, Warden generates a new `secret_id`, verifies it works, persists the new config, then destroys the old one. Both credentials remain valid during the transition — there is no downtime.

Set to `0` to disable rotation (not recommended for production).

Verify:

```bash
warden cred source read vault-prod
```

## Step 5: Create a Credential Spec

The Vault provider gateway requires a credential spec of type `vault_token`. Warden mints child Vault tokens via token roles and injects them into proxied requests.

```bash
# Read-only Vault token
warden cred spec create vault-reader \
  --type vault_token \
  --source vault-prod \
  --config mint_method=vault_token \
  --config token_role=reader \
  --min-ttl 600s \
  --max-ttl 2h

# Admin Vault token with custom TTL
warden cred spec create vault-admin \
  --type vault_token \
  --source vault-prod \
  --config mint_method=vault_token \
  --config token_role=admin \
  --config ttl=4h \
  --min-ttl 1h \
  --max-ttl 8h
```

**Note**: The Vault credential source also supports other mint methods (`kv2_static`, `dynamic_database`, `dynamic_aws`) for returning credentials directly to clients via login — but these are NOT compatible with the gateway proxy. See [docs/vault-credentials.md](../../docs/vault-credentials.md) for details on those mint methods.

## Step 6: Create a Policy

Create a policy that grants access to the Vault provider gateway:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF
```

For transparent mode, also grant access to role-based paths:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete"]
}
path "vault/role/+/gateway*" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF
```

Verify:

```bash
warden policy read vault-access
```

## Step 7: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy:

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/vault-user \
    token_type=vault_token \
    token_policies="vault-access" \
    user_claim=sub \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

## Step 8: Get a JWT

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

## Step 9: Make Requests Through the Gateway

There are two ways to use the gateway: **explicit login** (standard mode) and **transparent mode** (implicit JWT auth). Both proxy requests to Vault with automatic token injection.

### Option A: Explicit Login (Standard Mode)

Login to Warden to get a session token, then use that token for gateway requests:

```bash
LOGIN_OUTPUT=$(warden login --method=jwt --token=$JWT --role=vault-user)

export WARDEN_SESSION_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "| token" | awk '{print $NF}')
```

Point the Vault CLI or SDK at the Warden gateway endpoint:

```bash
export VAULT_ADDR=http://localhost:8400/v1/vault/gateway
export VAULT_TOKEN=$WARDEN_SESSION_TOKEN
```

Then use the Vault CLI as normal — all requests are proxied through Warden:

```bash
# Read a KV secret
vault kv get secret/myapp

# List secrets
vault kv list secret/

# Issue a PKI certificate
vault write pki/issue/my-role common_name=example.com

# Read database credentials
vault read database/creds/my-role
```

### Option B: Transparent Mode (No Login Step)

With transparent mode enabled (see [Transparent Mode](#transparent-mode)), clients skip the Warden login entirely. The JWT is sent directly with each request and Warden performs implicit authentication on every call.

First, enable transparent mode on the provider (one-time setup):

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

The URL pattern includes the role name: `/v1/vault/role/{role}/gateway/{vault-api-path}`

```bash
export VAULT_ADDR=http://localhost:8400/v1/vault/role/vault-user/gateway
export VAULT_TOKEN=$JWT
```

Then use the Vault CLI identically:

```bash
# Read a KV secret
vault kv get secret/myapp

# List secrets
vault kv list secret/

# Issue a PKI certificate
vault write pki/issue/my-role common_name=example.com
```

Or use `curl` directly:

```bash
VAULT_ENDPOINT="${WARDEN_ADDR}/v1/vault/role/vault-user/gateway"

# Read a secret
curl "${VAULT_ENDPOINT}/secret/data/myapp" \
  -H "Authorization: Bearer ${JWT}"

# List secrets
curl "${VAULT_ENDPOINT}/secret/metadata/?list=true" \
  -H "Authorization: Bearer ${JWT}"
```

Transparent mode is useful for CI/CD pipelines and services that already have a JWT but shouldn't manage a separate Warden login step.

---

In both modes, Warden injects the real Vault token (minted from the credential spec) into each proxied request. The `X-Vault-Token` or `Authorization` header sent by the client is replaced before forwarding.

### Vault Namespaces

The gateway preserves `X-Vault-Namespace` headers from client requests. This allows clients to target specific Vault namespaces through the proxy:

```bash
# Read a secret in the admin/team-a namespace
vault kv get -namespace=admin/team-a secret/myapp

# Or set it as an environment variable
export VAULT_NAMESPACE=admin/team-a
vault kv get secret/myapp
```

Note that the `vault_namespace` on the **credential source** (Step 3) and the `X-Vault-Namespace` on **client requests** serve different purposes:
- **Source `vault_namespace`**: Scopes Warden's own Vault API calls (AppRole auth, credential minting)
- **Client `X-Vault-Namespace`**: Scopes the proxied request to a namespace in the target Vault instance

These can differ — for example, Warden may authenticate in the `admin` namespace while clients target `admin/team-a`.

### Path Rewriting

The gateway automatically prepends `/v1` to API paths when not already present:

```
/vault/gateway/secret/data/my-secret    → /v1/secret/data/my-secret
/vault/gateway/v1/secret/data/my-secret → /v1/secret/data/my-secret
/vault/gateway/sys/health               → /v1/sys/health
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Architecture Overview

```
                +--------------------------------------+
                |  HashiCorp Vault                     |
                |                                      |
                |  AppRole: warden-source              |
                |  - Policies: warden-source           |
                |  - secret_id auto-rotated            |
                |                                      |
                |  Token Roles:                        |
                |  - reader (read-only policies)       |
                |  - admin (elevated policies)         |
                +--------+-----------------------------+
                         |
                         | AppRole auth
                         | (rotates secret_id)
                         |
                +--------v-----------------------------+
                |  Warden Vault Provider               |
                |                                      |
                |  Credential Source (hvault)          |
                |    mint_method: vault_token          |
                |    → Mints child Vault tokens        |
                |                                      |
                |  Gateway Proxy                       |
                |    → Injects token into requests     |
                +--------------------------------------+
```

### Request Flow

1. Client authenticates to Warden and receives a session token
2. Client sends request to Warden gateway with session token (`X-Vault-Token` or `Authorization: Bearer`)
3. Warden validates the session and retrieves a Vault token from the credential spec
4. Warden strips client auth headers and injects the real Vault token as `X-Vault-Token`
5. Request is forwarded to the configured Vault instance
6. Response is returned to the client

### Security Model

- **Least privilege on the AppRole**: The Warden AppRole only has access to the specific secret paths it needs. Compromise of the `secret_id` is limited to those paths.
- **Automatic secret_id rotation**: Warden rotates the AppRole credentials on the configured schedule, limiting exposure of any single `secret_id`.
- **Short-lived consumer credentials**: Dynamic credentials (database, AWS, tokens) have bounded TTLs. Vault automatically revokes them on expiration.
- **Lease revocation**: Warden can proactively revoke credentials before they expire. Database and AWS leases are revoked via `sys/leases/revoke`; Vault tokens are revoked via their accessor.

### Rotation

Warden automatically rotates the AppRole `secret_id` on the configured schedule using a three-phase protocol:

1. **Prepare**: Generate a new `secret_id` (both old and new remain valid)
2. **Commit**: Persist the new config and re-authenticate with the new `secret_id`
3. **Cleanup**: Destroy the old `secret_id` using its accessor

If cleanup fails, it is retried daily for up to 7 days. Rotation requires `auth_method=approle` with `role_name` set.

## Mint Methods

| Mint Method | Credential Type | Description |
|-------------|-----------------|-------------|
| `kv2_static` | `aws_access_keys` | Fetch static secrets from Vault KV v2 |
| `dynamic_aws` | `aws_access_keys` | Generate temporary AWS credentials via Vault AWS engine |
| `vault_token` | `vault_token` | Create a child Vault token via token roles |

## Transparent Mode

Transparent mode allows clients to authenticate implicitly with their JWT — no separate Warden login step is needed. The provider extracts the role from the URL path, performs implicit JWT auth against the configured auth mount, and issues a short-lived token for the request.

### Enable Transparent Mode

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

### URL Pattern

```
/v1/vault/role/{role}/gateway/{vault-api-path}
```

### Example Requests

```bash
VAULT_ENDPOINT="${WARDEN_ADDR}/v1/vault/role/vault-user/gateway"

# Read a secret
curl "${VAULT_ENDPOINT}/secret/data/myapp" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List secrets
curl "${VAULT_ENDPOINT}/secret/metadata/?list=true" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Unauthenticated Paths

Certain read-only PKI endpoints are forwarded without authentication, matching Vault's own unauthenticated access policy. This enables tools like Terraform to fetch CA chains without requiring a Warden session:

- `/v1/{mount}/ca/pem`, `/v1/{mount}/ca`
- `/v1/{mount}/ca_chain`, `/v1/{mount}/cert/ca`
- `/v1/{mount}/crl`, `/v1/{mount}/crl/pem`
- `/v1/{mount}/issuer/{id}/pem`, `/v1/{mount}/issuer/{id}/der`
- `/v1/{mount}/cert/{serial}`

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vault_address` | string | — | Base URL of the Vault instance (required, e.g., `https://vault.example.com:8200`) |
| `max_body_size` | int | `10485760` (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in the URL path |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vault_address` | string | Yes | Vault server address |
| `auth_method` | string | No | Authentication method (`approle` or omit for pre-set token) |
| `role_id` | string | If approle | AppRole role ID |
| `secret_id` | string | If approle | AppRole secret ID (rotated automatically) |
| `secret_id_accessor` | string | If approle | Secret ID accessor (used for rotation cleanup) |
| `approle_mount` | string | If approle | AppRole auth mount path |
| `role_name` | string | If approle | AppRole role name (required for rotation) |
| `vault_namespace` | string | No | Vault namespace for multi-tenancy setups |

### Credential Spec Config — vault_token

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `vault_token` |
| `token_role` | string | Yes | Token role name (configured at `auth/token/roles/` in Vault) |
| `ttl` | duration | No | Token TTL (clamped to min/max bounds) |
| `display_name` | string | No | User-friendly name attached to the token |
| `meta` | string | No | Metadata attached to the token |

### Credential Spec Config — kv2_static

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `kv2_static` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

### Credential Spec Config — dynamic_database

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_database` |
| `database_mount` | string | Yes | Vault database engine mount path |
| `role_name` | string | Yes | Database role name configured in Vault |
| `database` | string | No | Database name (passed through to credential data) |

### Credential Spec Config — dynamic_aws

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_aws` |
| `aws_mount` | string | Yes | Vault AWS engine mount path |
| `role_name` | string | Yes | AWS role name configured in Vault |
| `role_arn` | string | No | ARN of the role to assume (for STS) |
| `role_session_name` | string | No | Session name for the STS assumption |
| `ttl` | duration | No | Credential TTL (clamped to min/max bounds) |

### TTL Bounds

- `--min-ttl`: Minimum credential TTL. Requests for shorter TTLs are clamped up.
- `--max-ttl`: Maximum credential TTL. Requests for longer TTLs are clamped down.

## Troubleshooting

### "Vault provider not configured" error

The `vault_address` has not been set. Configure the provider:

```bash
warden write vault/config vault_address=https://vault.example.com:8200
```

### "Unauthorized" on gateway requests

1. Verify the credential spec is correctly bound to the JWT role.
2. Check that the Vault AppRole policy grants access to the paths being requested.
3. Ensure the Warden session token is being sent as `X-Vault-Token` or `Authorization: Bearer`.

### Transparent mode returns 403

1. Verify `transparent_mode` is enabled and `auto_auth_path` is set.
2. Ensure the JWT role exists and is bound to a `vault_token` credential spec.
3. Check the Warden policy grants access to `vault/role/+/gateway*`.

### TLS certificate errors

For development with self-signed certificates:

```bash
warden write vault/config vault_address=https://vault.local:8200 tls_skip_verify=true
```

Do not use `tls_skip_verify` in production. Instead, ensure the Vault TLS certificate is signed by a trusted CA.

### Debug Logging

Enable trace-level logging to see request proxying details:

```hcl
log_level = "trace"
```
