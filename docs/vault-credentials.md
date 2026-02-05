# Vault Credential Source & Spec Configuration

This guide covers how to configure Warden to manage credentials through HashiCorp Vault, including static KV secrets, dynamic database credentials, dynamic AWS credentials, and Vault tokens.

## Architecture Overview

```
                     +-------------------------------+
                     |  HashiCorp Vault              |
                     |                               |
                     |  Engines:                     |
                     |  - KV v2 (static secrets)     |
                     |  - Database (dynamic creds)   |
                     |  - AWS (dynamic STS creds)    |
                     |  - Token (child tokens)       |
                     +--------+----------------------+
                              |
                     AppRole auth
                     (auto-rotated)
                              |
                     +--------v----------------------+
                     |  Warden                       |
                     |  Vault Credential Source       |
                     |                               |
                     |  Mint Methods:                |
                     |  - kv2_static                 |
                     |  - dynamic_database           |
                     |  - dynamic_aws                |
                     |  - vault_token                |
                     +--------+----------------------+
                              |
              +---------------+---------------+
              |               |               |
     database_userpass   aws_access_keys  vault_token
     (static or dynamic) (static or dynamic) (child tokens)
```

## Prerequisites

- HashiCorp Vault running and unsealed
- Warden server running
- Vault CLI (for initial setup)

## Step 1: Create an AppRole in Vault

Create a dedicated AppRole for Warden with policies that grant access to the secrets engines it needs.

### Create a Policy

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

## Step 2: Create the Credential Source in Warden

```bash
warden -n PROD/SEC cred source create vault-prod \
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

### Source Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `vault_address` | Yes | Vault server address |
| `auth_method` | No | Authentication method (`approle` or omit for pre-set token) |
| `role_id` | If approle | AppRole role ID |
| `secret_id` | If approle | AppRole secret ID (rotated automatically) |
| `secret_id_accessor` | If approle | Secret ID accessor (used for rotation cleanup) |
| `approle_mount` | If approle | AppRole auth mount path |
| `role_name` | If approle | AppRole role name (required for rotation) |
| `vault_namespace` | No | Vault namespace for multi-tenancy setups |

### Rotation Period

The `--rotation-period` controls how often Warden rotates the AppRole `secret_id`. During rotation, Warden generates a new `secret_id`, verifies it works, persists the new config, then destroys the old one. Both credentials remain valid during the transition -- there is no downtime.

Set to `0` to disable rotation (not recommended for production).

## Step 3: Create Credential Specs

A credential spec defines what credentials Warden mints for consumers. Each spec references a source and specifies a `mint_method` that determines how credentials are obtained.

### Available Mint Methods

| mint_method | Credential Type | Description |
|-------------|-----------------|-------------|
| `kv2_static` | `database_userpass`, `aws_access_keys` | Fetch static secrets from Vault KV v2 |
| `dynamic_database` | `database_userpass` | Generate temporary database credentials |
| `dynamic_aws` | `aws_access_keys` | Generate temporary AWS credentials via Vault AWS engine |
| `vault_token` | `vault_token` | Create a child Vault token |

### Static KV Secrets (kv2_static)

Fetches credentials stored in Vault's KV v2 engine. No lease or TTL -- the secret is returned as-is.

```bash
# Static database credentials from KV
warden -n PROD/SEC cred spec create db-static \
  --type database_userpass \
  --source vault-prod \
  --config mint_method=kv2_static \
  --config kv2_mount=secret \
  --config secret_path=prod/database/main

# Static AWS credentials from KV
warden -n PROD/SEC cred spec create aws-static \
  --type aws_access_keys \
  --source vault-prod \
  --config mint_method=kv2_static \
  --config kv2_mount=secret \
  --config secret_path=prod/aws/readonly
```

| Key | Required | Description |
|-----|----------|-------------|
| `kv2_mount` | Yes | KV v2 mount path in Vault |
| `secret_path` | Yes | Path to the secret within the mount |

### Dynamic Database Credentials (dynamic_database)

Generates temporary database credentials using Vault's database secrets engine. Each request creates a new, unique username/password pair with a Vault lease.

```bash
# Dynamic PostgreSQL credentials
warden -n PROD/SEC cred spec create db-app \
  --type database_userpass \
  --source vault-prod \
  --config mint_method=dynamic_database \
  --config database_mount=database \
  --config role_name=app-readonly \
  --config database=production \
  --min-ttl 15m \
  --max-ttl 8h

# Dynamic MySQL credentials for CI
warden -n PROD/SEC cred spec create db-ci \
  --type database_userpass \
  --source vault-prod \
  --config mint_method=dynamic_database \
  --config database_mount=database \
  --config role_name=ci-readwrite \
  --min-ttl 10m \
  --max-ttl 1h
```

| Key | Required | Description |
|-----|----------|-------------|
| `database_mount` | Yes | Vault database engine mount path |
| `role_name` | Yes | Database role name configured in Vault |
| `database` | No | Database name (passed through to credential data) |

### Dynamic AWS Credentials (dynamic_aws)

Generates temporary AWS credentials (STS) using Vault's AWS secrets engine.

```bash
# AWS credentials for developers
warden -n PROD/SEC cred spec create aws-dev \
  --type aws_access_keys \
  --source vault-prod \
  --config mint_method=dynamic_aws \
  --config aws_mount=aws \
  --config role_name=dev-readonly \
  --config ttl=1h \
  --min-ttl 600s \
  --max-ttl 4h

# AWS credentials with role assumption
warden -n PROD/SEC cred spec create aws-deploy \
  --type aws_access_keys \
  --source vault-prod \
  --config mint_method=dynamic_aws \
  --config aws_mount=aws \
  --config role_name=deploy-role \
  --config role_arn=arn:aws:iam::123456789:role/deploy \
  --config role_session_name=warden-deploy \
  --config ttl=30m \
  --min-ttl 600s \
  --max-ttl 2h
```

| Key | Required | Description |
|-----|----------|-------------|
| `aws_mount` | Yes | Vault AWS engine mount path |
| `role_name` | Yes | AWS role name configured in Vault |
| `role_arn` | No | ARN of the role to assume (for STS) |
| `role_session_name` | No | Session name for the STS assumption |
| `ttl` | No | Credential TTL (clamped to min/max bounds) |

### Vault Tokens (vault_token)

Creates child Vault tokens via token roles. The token inherits policies from the role.

```bash
# Read-only Vault token
warden -n PROD/SEC cred spec create vault-reader \
  --type vault_token \
  --source vault-prod \
  --config mint_method=vault_token \
  --config token_role=reader \
  --min-ttl 600s \
  --max-ttl 2h

# Admin Vault token with custom TTL
warden -n PROD/SEC cred spec create vault-admin \
  --type vault_token \
  --source vault-prod \
  --config mint_method=vault_token \
  --config token_role=admin \
  --config ttl=4h \
  --min-ttl 1h \
  --max-ttl 8h
```

| Key | Required | Description |
|-----|----------|-------------|
| `token_role` | Yes | Token role name (configured at `auth/token/roles/` in Vault) |
| `ttl` | No | Token TTL (clamped to min/max bounds) |
| `display_name` | No | User-friendly name attached to the token |
| `meta` | No | Metadata attached to the token |

### TTL Bounds

- `--min-ttl`: Minimum credential TTL. Requests for shorter TTLs are clamped up.
- `--max-ttl`: Maximum credential TTL. Requests for longer TTLs are clamped down.

## Step 4: Use the Credentials

Consumers authenticate to Warden and receive credentials:

```bash
# Authenticate and get database credentials
LOGIN_OUTPUT=$(warden -n PROD/SEC login --method=jwt --token=$JWT --role=db-user)

# Authenticate and get a Vault token
LOGIN_OUTPUT=$(warden -n PROD/SEC login --method=jwt --token=$JWT --role=vault-reader)
export VAULT_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*token=\([^ ]*\).*/\1/')
```

Or use the Warden Vault gateway proxy for transparent access:

```bash
export VAULT_ADDR=http://localhost:5000/v1/PROD/SEC/vault/gateway
vault kv get secret/myapp
```

## Rotation

Warden automatically rotates the AppRole `secret_id` on the configured schedule. The rotation uses a three-phase protocol:

1. **Prepare**: Generate a new `secret_id` (both old and new remain valid)
2. **Commit**: Persist the new config and re-authenticate with the new `secret_id`
3. **Cleanup**: Destroy the old `secret_id` using its accessor

If cleanup fails, it is retried daily for up to 7 days.

Rotation requires `auth_method=approle` with `role_name` set. Sources without AppRole auth do not support rotation.

## Security Model

```
Vault
  |
  +-- AppRole: warden-source
  |     |-- Policies: warden-source
  |     +-- secret_id rotated by Warden on schedule
  |
  +-- Secrets Engines (accessed via warden-source policy)
        |-- KV v2 (static secrets)
        |-- Database (dynamic credentials, Vault manages lifecycle)
        |-- AWS (dynamic STS credentials, Vault manages lifecycle)
        +-- Token (child tokens with scoped policies)
```

Key principles:
- **Least privilege on the AppRole**: The Warden AppRole only has access to the specific secret paths it needs. Compromise of the `secret_id` is limited to those paths.
- **Automatic secret_id rotation**: Warden rotates the AppRole credentials on the configured schedule, limiting exposure of any single `secret_id`.
- **Short-lived consumer credentials**: Dynamic credentials (database, AWS, tokens) have bounded TTLs. Vault automatically revokes them on expiration.
- **Lease revocation**: Warden can proactively revoke credentials before they expire. Database and AWS leases are revoked via `sys/leases/revoke`; Vault tokens are revoked via their accessor.
