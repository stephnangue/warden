# Vault Provider

The Vault provider enables proxied access to HashiCorp Vault (or OpenBao) through Warden. It intercepts client requests, injects a short-lived Vault token minted from a credential spec, and forwards the request to the target Vault instance. This allows Warden to broker Vault access without distributing long-lived credentials to clients.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Create an AppRole in Vault](#step-1-create-an-approle-in-vault)
- [Step 2: Configure JWT Auth and Create a Role](#step-2-configure-jwt-auth-and-create-a-role)
- [Step 3: Mount and Configure the Provider](#step-3-mount-and-configure-the-provider)
- [Step 4: Create a Credential Source and Specs](#step-4-create-a-credential-source-and-specs)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Get a JWT and Make Requests](#step-6-get-a-jwt-and-make-requests)
- [Architecture Overview](#architecture-overview)
- [Mint Methods](#mint-methods)
- [Transparent Mode](#transparent-mode)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker and Docker Compose installed and running
- HashiCorp Vault running and unsealed
- Vault CLI (for initial AppRole setup)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 2 and 6:
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
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="<your-token>"
> ```

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

## Step 2: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy:

> **This step must come before enabling transparent mode on the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/vault-user \
    token_policies="vault-access" \
    user_claim=sub \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

## Step 3: Mount and Configure the Provider

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

## Step 4: Create a Credential Source and Specs

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

## Step 5: Create a Policy

Create a policy that grants access to the Vault provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For transparent mode, also grant access to role-based paths:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
path "vault/role/+/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect sensitive Vault paths. For example, restrict secret deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write vault-prod-restricted - <<EOF
path "vault/gateway/secret/data/*" {
  capabilities = ["delete"]
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "vault/gateway*" {
  capabilities = ["read", "create", "update", "patch"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read vault-access
```

## Step 6: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

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

Note that the `vault_namespace` on the **credential source** (Step 4) and the `X-Vault-Namespace` on **client requests** serve different purposes:
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

Transparent mode allows clients to authenticate implicitly with their JWT or TLS client certificate — no separate Warden login step is needed. The provider extracts the role from the URL path, performs implicit auth against the configured auth mount, and issues a short-lived token for the request.

### Enable Transparent Mode

> **Prerequisite**: The auth backend referenced by `auto_auth_path` must be mounted **before** setting this field (see [Step 2](#step-2-configure-jwt-auth-and-create-a-role)). Warden validates at configuration time that the backend exists.

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

## TLS Certificate Authentication

Steps 2 and 6 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). It does not work in dev mode, which uses plain HTTP. Start Warden with a TLS listener, or place it behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1, 3–5 (provider setup) are identical. Replace Steps 2 and 6 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=vault-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/vault-user \
    allowed_common_names="agent-*" \
    token_policies="vault-access" \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

The `token_type` defaults to `transparent` — you don't need to specify it.

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Transparent Mode with Certificates

Configure the provider to use cert auth for transparent mode:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "transparent_mode": true,
  "auto_auth_path": "auth/cert/",
  "timeout": "30s"
}
EOF
```

When `auto_auth_path` points to a cert auth mount, Warden extracts the client certificate from the TLS handshake (mTLS) and authenticates implicitly — no `Authorization` header needed. The role can be specified in the URL path or falls back to `default_role` on the cert auth config:

```bash
# Role in URL path
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/vault/role/vault-user/gateway/secret/data/myapp

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/vault/gateway/secret/data/myapp
```

With the Warden CLI:

```bash
export WARDEN_ADDR=https://warden.internal
export WARDEN_CACERT=/path/to/warden-ca.pem
export WARDEN_CLIENT_CERT=./client.pem
export WARDEN_CLIENT_KEY=./client-key.pem

# Reads use the default role (no --role needed)
warden read vault/gateway/secret/data/myapp

# Writes escalate to a privileged role
warden --role=vault-admin write vault/gateway/secret/data/myapp key=value
```

### Explicit Login with Certificates

To use cert auth for explicit login (without transparent mode):

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    token_type=warden \
    default_role=vault-user
```

Create a role with token type `warden`:

```bash
warden write auth/cert/role/vault-user \
    allowed_common_names="agent-*" \
    token_type=warden \
    token_policies="vault-access" \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

Then authenticate with the CLI:

```bash
warden login --method=cert --role=vault-user \
    --cert=./client.pem --key=./client-key.pem
```

Or use environment variables:

```bash
export WARDEN_CLIENT_CERT=./client.pem
export WARDEN_CLIENT_KEY=./client-key.pem
warden login --method=cert --role=vault-user
```

Then make gateway requests using the session token, exactly as shown in [Step 6 Option A](#option-a-explicit-login-standard-mode).

### Explicit Login with JWT

Steps 2 and 6 above use transparent mode. To use explicit login with JWT instead, set `token_type=warden` on the role:

```bash
warden write auth/jwt/config \
    mode=jwt \
    jwks_url=http://localhost:4444/.well-known/jwks.json
```

Create a role with token type `warden`:

```bash
warden write auth/jwt/role/vault-user \
    token_type=warden \
    token_policies="vault-access" \
    user_claim=sub \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

Then authenticate with the CLI:

```bash
warden login --method=jwt --token=$JWT --role=vault-user
```

Then make gateway requests using the session token, exactly as shown in [Step 6 Option A](#option-a-explicit-login-standard-mode).

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vault_address` | string | — | Base URL of the Vault instance (required, e.g., `https://vault.example.com:8200`) |
| `max_body_size` | int | `10485760` (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `transparent_mode` | bool | `false` | Enable implicit authentication (JWT or TLS certificate) |
| `auto_auth_path` | string | — | Auth mount path, e.g. `auth/jwt/` or `auth/cert/` (required when `transparent_mode` is true) |
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

### Cert Auth Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trusted_ca_pem` | string | — | PEM-encoded CA certificates that sign client certificates |
| `principal_claim` | string | `cn` | Identity source: `cn`, `dns_san`, `email_san`, `uri_san`, `spiffe_id`, `serial` |
| `default_role` | string | — | Default role when no role is specified in the URL or request |
| `token_ttl` | duration | `1h` | Default token TTL |
| `token_type` | string | `transparent` | Default token type for roles; allowed values: `aws`, `warden`, `transparent` |
| `revocation_mode` | string | `none` | Certificate revocation checking: `none`, `crl`, `ocsp`, `best_effort` |

### Cert Auth Role Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowed_common_names` | list | No* | Glob patterns for allowed certificate CNs |
| `allowed_dns_sans` | list | No* | Glob patterns for allowed DNS SANs |
| `allowed_email_sans` | list | No* | Glob patterns for allowed email SANs |
| `allowed_uri_sans` | list | No* | URI SAN patterns (`+` matches one segment, trailing `*` matches one or more) |
| `allowed_organizational_units` | list | No* | Allowed organizational units |
| `certificate` | string | No | Role-specific CA PEM (overrides global trusted CAs) |
| `token_policies` | list | Yes | Policies to assign to tokens |
| `token_type` | string | No | Defaults to `transparent`; allowed values: `aws`, `warden`, `transparent` |
| `token_ttl` | duration | No | Token TTL (default: 1h) |
| `cred_spec_name` | string | No | Credential spec for gateway access |
| `principal_claim` | string | No | Override global `principal_claim` for this role |

*At least one constraint (`allowed_common_names`, `allowed_dns_sans`, etc.) should be specified.

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
