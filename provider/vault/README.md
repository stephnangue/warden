# Vault Provider

The Vault provider enables proxied access to HashiCorp Vault (or OpenBao) through Warden. It intercepts client requests, injects a short-lived Vault token minted from a credential spec, and forwards the request to the target Vault instance. This allows Warden to broker Vault access without distributing long-lived credentials to clients.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Create an AppRole in Vault](#step-1-create-an-approle-in-vault)
- [Step 2: Configure Cert Auth and Create a Role](#step-2-configure-cert-auth-and-create-a-role)
- [Step 3: Mount and Configure the Provider](#step-3-mount-and-configure-the-provider)
- [Step 4: Create a Credential Source and Specs](#step-4-create-a-credential-source-and-specs)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Make Requests with Client Certificates](#step-6-make-requests-with-client-certificates)
- [Architecture Overview](#architecture-overview)
- [Mint Methods](#mint-methods)
- [JWT Authentication](#jwt-authentication)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- HashiCorp Vault running and unsealed
- Vault CLI (for initial AppRole setup)
- OpenSSL (for generating certificates)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Download the latest Warden binary:**
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
> **2. Add the binary to your PATH:**
> ```bash
> export PATH="$PWD:$PATH"
> ```
>
> **3. Generate certificates** for the server and a client:
> ```bash
> CERT_DIR=certs
> mkdir -p "$CERT_DIR"
>
> # Generate a CA certificate and key
> openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca.key"
> openssl req -new -x509 -sha256 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" -days 365 \
>     -subj "/CN=Warden Dev CA/O=Warden Dev"
>
> # Generate a server certificate signed by the CA
> openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server.key"
> openssl req -new -sha256 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
>     -subj "/CN=localhost/O=Warden Dev"
> openssl x509 -req -sha256 -in "$CERT_DIR/server.csr" \
>     -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
>     -CAcreateserial -out "$CERT_DIR/server.pem" -days 365 \
>     -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
>
> # Generate a client certificate signed by the same CA
> openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/client.key"
> openssl req -new -sha256 -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
>     -subj "/CN=agent-quickstart/O=Warden Dev"
> openssl x509 -req -sha256 -in "$CERT_DIR/client.csr" \
>     -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
>     -CAcreateserial -out "$CERT_DIR/client.pem" -days 365
> ```
>
> **4. Start the Warden server** in dev mode with TLS and mTLS:
> ```bash
> warden server --dev --dev-root-token=root \
>     --dev-tls-cert-file=$CERT_DIR/server.pem \
>     --dev-tls-key-file=$CERT_DIR/server.key \
>     --dev-tls-ca-cert-file=$CERT_DIR/ca.pem \
>     --dev-tls-require-client-cert
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> CERT_DIR=certs
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="https://127.0.0.1:8400"
> export WARDEN_CACERT="$PWD/$CERT_DIR/ca.pem"
> export WARDEN_CLIENT_CERT="$PWD/$CERT_DIR/client.pem"
> export WARDEN_CLIENT_KEY="$PWD/$CERT_DIR/client.key"
> export WARDEN_TOKEN="root"
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

path "auth/warden_approle/role/warden-source" {
  capabilities = ["read"]
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

### Create Token Roles

Warden mints child Vault tokens via [token roles](https://developer.hashicorp.com/vault/docs/auth/token#token-roles). Create the roles referenced by the credential specs in Step 4:

```bash
# Read-only token role (used by the vault-reader cred spec)
vault write auth/token/roles/reader \
  allowed_policies="warden-source" \
  orphan=true \
  token_period=1h \
  renewable=true

# Elevated token role (used by the vault-admin cred spec)
vault write auth/token/roles/admin \
  allowed_policies="warden-source" \
  orphan=true \
  token_period=4h \
  renewable=true
```

### Generate Credentials

```bash
# Get the role_id (static, does not change)
vault read auth/warden_approle/role/warden-source/role-id

# Generate a secret_id (Warden will rotate this automatically)
vault write -f auth/warden_approle/role/warden-source/secret-id
```

Save the `role_id`, `secret_id`, and `secret_id_accessor` from the output.

## Step 2: Configure Cert Auth and Create a Role

Set up a TLS certificate auth method and create a role that binds the credential spec and policy. This uses the same CA that signed the client certificate generated in the Prerequisites.

> Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable cert auth
warden auth enable --type=cert

# Configure with the CA that signs client certificates
warden write auth/cert/config \
    trusted_ca_pem=@$CERT_DIR/ca.pem \
    default_role=vault-user

# Create a role that binds the credential spec and policy
warden write auth/cert/role/vault-user \
    allowed_common_names="agent-*" \
    token_policies="vault-access" \
    cred_spec_name=vault-reader
```

The `allowed_common_names` field supports glob patterns. The client certificate generated in the Prerequisites has CN `agent-quickstart`, which matches `agent-*`. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

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

Configure the provider with the Vault server address and the cert auth mount from Step 2:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "auto_auth_path": "auth/cert/",
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
  --source vault-prod \
  --config mint_method=vault_token \
  --config token_role=reader \
  --min-ttl 600s \
  --max-ttl 2h

# Admin Vault token with custom TTL
warden cred spec create vault-admin \
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

For use cases where the role will be provided in the path, also grant access to role-based paths:

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

## Step 6: Make Requests with Client Certificates

No login step is required. The client certificate is presented during the TLS handshake and Warden performs implicit authentication on every call — no session token to manage.

The URL pattern includes the role name: `/v1/vault/role/{role}/gateway/{vault-api-path}`

### Using curl

```bash
VAULT_ENDPOINT="https://127.0.0.1:8400/v1/vault/role/vault-user/gateway"

# Read a secret
curl --cert $CERT_DIR/client.pem --key $CERT_DIR/client.key --cacert $CERT_DIR/ca.pem \
    "${VAULT_ENDPOINT}/secret/data/myapp"

# List secrets
curl --cert $CERT_DIR/client.pem --key $CERT_DIR/client.key --cacert $CERT_DIR/ca.pem \
    "${VAULT_ENDPOINT}/secret/metadata/?list=true"
```

### Using the Vault CLI

Set the gateway as the Vault address and configure the client certificate:

```bash
export VAULT_ADDR=https://127.0.0.1:8400/v1/vault/role/vault-user/gateway
export VAULT_CACERT=$PWD/$CERT_DIR/ca.pem
export VAULT_CLIENT_CERT=$PWD/$CERT_DIR/client.pem
export VAULT_CLIENT_KEY=$PWD/$CERT_DIR/client.key

# Read a KV secret
vault kv get secret/myapp

# List secrets
vault kv list secret/

# Issue a PKI certificate
vault write pki/issue/my-role common_name=example.com

# Read database credentials
vault read database/creds/my-role
```

Auth with certificates is the simplest and most secure approach — there is no bearer token to leak. It is ideal for workloads that already have X.509 identities: Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

---

Warden injects the real Vault token (minted from the credential spec) into each proxied request. The client never sees or handles the Vault token directly.

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

To stop Warden:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Remove generated certificates
rm -rf $CERT_DIR/
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

1. Client presents its TLS certificate during the mTLS handshake with Warden
2. Client sends request to Warden gateway
3. Warden validates the client certificate against the trusted CA and authenticates the client
4. Warden retrieves a Vault token from the credential spec bound to the cert auth role
5. Warden strips client auth headers and injects the real Vault token as `X-Vault-Token`
6. Request is forwarded to the configured Vault instance
7. Response is returned to the client

### Security Model

- **Mutual TLS (mTLS)**: Both server and client authenticate via certificates, providing strong identity verification without shared secrets.
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
| `static_aws` | `aws_access_keys` | Fetch static AWS credentials from Vault KV v2 |
| `static_apikey` | `api_key` | Fetch static API keys from Vault KV v2 |
| `dynamic_aws` | `aws_access_keys` | Generate temporary AWS credentials via Vault AWS engine |
| `dynamic_gcp` | `gcp_access_token` | Generate GCP access tokens via Vault GCP engine |
| `vault_token` | `vault_token` | Create a child Vault token via token roles |
| `oauth2` | `oauth_bearer_token` | Fetch OAuth2 tokens via Vault OAuth2 plugin (openbao-plugin-secrets-oauthapp) |

## JWT Authentication

Steps 2 and 6 above use TLS certificate authentication. Alternatively, you can authenticate with a JWT. This is useful for workloads that obtain tokens from an identity provider (OIDC/OAuth2) — CI/CD pipelines, cloud functions, or services with federated identity.

> **Prerequisite:** JWT authentication requires an identity provider that issues JWTs. The quickstart uses [Ory Hydra](https://www.ory.sh/hydra/) via Docker Compose:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```

Steps 1, 3-5 (provider setup) are identical. Replace Steps 2 and 6 with the following.

### Enable JWT Auth

```bash
# Enable JWT auth
warden auth enable --type=jwt

# Configure JWT with the identity provider's JWKS endpoint
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/vault-user \
    token_policies="vault-access" \
    user_claim=sub \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

### JWT auth method

Configure the provider to use JWT auth:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

Get a JWT from the identity provider and make requests:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')

VAULT_ENDPOINT="${WARDEN_ADDR}/v1/vault/role/vault-user/gateway"

# Read a secret
curl "${VAULT_ENDPOINT}/secret/data/myapp" \
  -H "Authorization: Bearer ${JWT}"

# List secrets
curl "${VAULT_ENDPOINT}/secret/metadata/?list=true" \
  -H "Authorization: Bearer ${JWT}"
```

Or set environment variables for the Vault CLI:

```bash
export VAULT_ADDR=${WARDEN_ADDR}/v1/vault/role/vault-user/gateway
export VAULT_TOKEN=$JWT

vault kv get secret/myapp
vault kv list secret/
```

### Cleanup (JWT)

To stop the identity provider containers:

```bash
docker compose -f docker-compose.quickstart.yml down -v
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vault_address` | string | — | Base URL of the Vault instance (required, e.g., `https://vault.example.com:8200`) |
| `max_body_size` | int | `10485760` (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only). Note: `http://` URLs are always allowed for `vault_address` |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication, e.g. `auth/cert/` or `auth/jwt/` |
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

### Credential Spec Config — static_aws

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_aws` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

### Credential Spec Config — static_apikey

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

### Credential Spec Config — dynamic_aws

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_aws` |
| `aws_mount` | string | Yes | Vault AWS engine mount path |
| `role_name` | string | Yes | AWS role name configured in Vault |
| `role_arn` | string | No | ARN of the role to assume (for STS) |
| `role_session_name` | string | No | Session name for the STS assumption |
| `ttl` | duration | No | Credential TTL (clamped to min/max bounds) |

### Credential Spec Config — dynamic_gcp

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_gcp` |
| `gcp_mount` | string | Yes | Vault GCP secrets engine mount path |
| `role_name` | string | Yes | GCP roleset or static account name |
| `role_type` | string | No | `roleset` (default) or `static-account` |

### Credential Spec Config — oauth2

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `oauth2` |
| `oauth2_mount` | string | Yes | Vault OAuth2 secrets engine mount path |
| `credential_name` | string | Yes | Credential name configured in the OAuth2 plugin |

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
| `token_ttl` | duration | No | Token TTL (default: 1h) |
| `cred_spec_name` | string | No | Credential spec for gateway access |
| `principal_claim` | string | No | Override global `principal_claim` for this role |

*At least one constraint (`allowed_common_names`, `allowed_dns_sans`, etc.) should be specified.

### JWT Auth Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `jwt` | Auth mode: `jwt` or `oidc` |
| `jwks_url` | string | — | URL to the JWKS endpoint for token verification |
| `default_role` | string | — | Default role when no role is specified |

### JWT Auth Role Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_claim` | string | Yes | JWT claim to use as the user identity (e.g., `sub`) |
| `token_policies` | list | Yes | Policies to assign to tokens |
| `token_ttl` | duration | No | Token TTL (default: 1h) |
| `cred_spec_name` | string | No | Credential spec for gateway access |

## Troubleshooting

### "Vault provider not configured" error

The `vault_address` has not been set. Configure the provider:

```bash
warden write vault/config vault_address=https://vault.example.com:8200
```

### "Unauthorized" on gateway requests

1. Verify the credential spec is correctly bound to the cert auth role.
2. Check that the Vault AppRole policy grants access to the paths being requested.
3. Ensure the client certificate CN matches the `allowed_common_names` pattern on the role.
4. Verify the client certificate is signed by the CA configured in `trusted_ca_pem`.

### Request returns 403

1. Verify `auto_auth_path` is set in the provider config.
2. Ensure the cert auth role exists and is bound to a `vault_token` credential spec.
3. Check the Warden policy grants access to `vault/role/+/gateway*`.

### TLS certificate errors

Verify the client certificate, server certificate, and CA are consistent:

```bash
# Verify server cert is signed by the CA
openssl verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/server.pem

# Verify client cert is signed by the CA
openssl verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/client.pem

# Test the TLS connection
openssl s_client -connect 127.0.0.1:8400 -CAfile $CERT_DIR/ca.pem \
    -cert $CERT_DIR/client.pem -key $CERT_DIR/client.key
```

For development with self-signed Vault certificates:

```bash
warden write vault/config vault_address=https://vault.local:8200 tls_skip_verify=true
```

Do not use `tls_skip_verify` in production. Instead, ensure the Vault TLS certificate is signed by a trusted CA.

### Debug Logging

Enable trace-level logging to see request proxying details:

```hcl
log_level = "trace"
```
