# OVH Provider

The OVH provider enables proxied access to the OVHcloud REST API through Warden. It forwards requests to OVH endpoints (account info, cloud projects, domains, IPs, etc.) with automatic credential injection and policy evaluation. Two credential modes are supported: OAuth2 client credentials (`oauth2` source type) and Vault/OpenBao dynamic secrets (`hvault` source type).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Regional Endpoints](#regional-endpoints)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- An **OVHcloud OAuth2 service account** (`client_id` and `client_secret` from [OVHcloud IAM](https://www.ovh.com/auth/))

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
> warden server --dev --dev-root-token=root
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
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/ovh-user \
    token_policies="ovh-access" \
    user_claim=sub \
    cred_spec_name=ovh-ops
```

## Step 2: Mount and Configure the Provider

Enable the OVH provider at a path of your choice:

```bash
warden provider enable --type=ovh
```

To mount at a custom path:

```bash
warden provider enable --type=ovh ovh-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read ovh/config
```

## Step 3: Create a Credential Source and Spec

### Option A: OAuth2 Client Credentials

The source holds the OAuth2 service account credentials (`client_id`, `client_secret`). Tokens are minted dynamically on each credential request.

```bash
warden cred source create ovh-oauth-src \
  --type=oauth2 \
  --rotation-period=0 \
  --config=client_id=your-client-id \
  --config=client_secret=your-client-secret \
  --config=token_url=https://www.ovh.com/auth/oauth2/token \
  --config=verify_url=https://eu.api.ovh.com/1.0/me \
  --config=display_name=OVH
```

Create a credential spec that references the credential source. The spec optionally specifies the OAuth2 scope.

```bash
warden cred spec create ovh-ops \
  --source ovh-oauth-src \
  --config scope="all"
```

The spec is validated at creation time: Warden mints a test token and verifies it by calling `GET /1.0/me` on the OVH API. If the credentials are invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing OAuth2 credentials directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- An OAuth2 secrets engine (openbao-plugin-secrets-oauthapp) configured with OVH credentials
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create ovh-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h
```

Create a credential spec using the `oauth2` mint method:

```bash
warden cred spec create ovh-ops \
  --source ovh-vault-src \
  --config mint_method=oauth2 \
  --config oauth2_mount=oauth2 \
  --config credential_name=ovh
```

Verify:

```bash
warden cred spec read ovh-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the OVH provider gateway:

```bash
warden policy write ovh-access - <<EOF
path "ovh/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which OVH resources and actions a role can use:

```bash
warden policy write ovh-readonly - <<EOF
path "ovh/role/+/gateway/me" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/cloud/project" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/domain" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/ip" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read ovh-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the OVH bearer token automatically.

The URL pattern is: `/v1/ovh/role/{role}/gateway/{api-path}`

Export OVH_ENDPOINT as environment variable:
```bash
export OVH_ENDPOINT="${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"
```

### Get Account Info

```bash
curl -s "${OVH_ENDPOINT}/me" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Projects

```bash
curl -s "${OVH_ENDPOINT}/cloud/project" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Domains

```bash
curl -s "${OVH_ENDPOINT}/domain" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List IP Addresses

```bash
curl -s "${OVH_ENDPOINT}/ip" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Cloud Project Details

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Project Instances

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}/instance" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Regional Endpoints

OVHcloud operates three regional API endpoints. Each region has its own API base URL and OAuth2 token URL. Configure both when setting up the provider and credential source for your region.

| Region | API Base URL | OAuth2 Token URL |
|--------|-------------|-----------------|
| Europe (default) | `https://eu.api.ovh.com/1.0` | `https://www.ovh.com/auth/oauth2/token` |
| Canada | `https://ca.api.ovh.com/1.0` | `https://ca.ovh.com/auth/oauth2/token` |
| United States | `https://api.us.ovhcloud.com/1.0` | `https://us.ovhcloud.com/auth/oauth2/token` |

To use a non-EU region, update both the provider config and the credential source:

```bash
# Example: configure for the US region
warden write ovh/config <<EOF
{
  "ovh_url": "https://api.us.ovhcloud.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

warden cred source create ovh-oauth-src \
  --type=oauth2 \
  --rotation-period=0 \
  --config=client_id=your-client-id \
  --config=client_secret=your-client-secret \
  --config=token_url=https://us.ovhcloud.com/auth/oauth2/token \
  --config=verify_url=https://api.us.ovhcloud.com/1.0/me \
  --config=display_name=OVH-US
```

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=ovh-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/ovh-user \
    allowed_common_names="agent-*" \
    token_policies="ovh-access" \
    cred_spec_name=ovh-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/ovh/role/ovh-user/gateway/me" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ovh_url` | string | `https://eu.api.ovh.com/1.0` | OVH API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | OAuth2 service account client ID |
| `client_secret` | string | Yes | OAuth2 service account client secret (sensitive — masked in output) |
| `token_url` | string | Yes | OAuth2 token endpoint (e.g., `https://www.ovh.com/auth/oauth2/token`) |
| `default_scopes` | string | No | Default OAuth2 scopes (space-separated) |
| `verify_url` | string | No | Endpoint to verify minted tokens (e.g., `https://eu.api.ovh.com/1.0/me`) |
| `verify_method` | string | No | HTTP method for verify_url (default: `GET`) |
| `auth_header_type` | string | No | How to attach token for verification: `bearer`, `token`, `custom_header` (default: `bearer`) |
| `auth_header_name` | string | No | Header name when `auth_header_type=custom_header` |
| `display_name` | string | No | Human-readable label for logs/errors (default: `OAuth2`) |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification; also allows `http://` URLs (default: `false`) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Credential Spec Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scope` | string | No | OAuth2 scope to request |

### Credential Source Config (Vault/OpenBao)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vault_address` | string | Yes | Vault server address (e.g., `https://vault.example.com`) |
| `vault_namespace` | string | No | Vault namespace (Enterprise/HCP only) |
| `auth_method` | string | No | Authentication method (`approle`) |
| `role_id` | string | Yes* | AppRole role ID (*required when `auth_method=approle`) |
| `secret_id` | string | Yes* | AppRole secret ID (*required when `auth_method=approle`) |
| `approle_mount` | string | Yes* | AppRole auth mount path (*required when `auth_method=approle`) |
| `role_name` | string | Yes* | AppRole role name for rotation (*required when `auth_method=approle`) |

### Credential Spec Config (Vault — oauth2)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `oauth2` |
| `oauth2_mount` | string | Yes | Vault OAuth2 secrets engine mount path |
| `credential_name` | string | Yes | Credential name configured in the OAuth2 plugin |

## Token Management

### OAuth2 Client Credentials

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source |
| **Validation** | Spec is verified at creation by minting a test token and calling `GET /1.0/me` |
| **Rotation** | Client credentials are managed in OVHcloud IAM; bearer tokens are minted automatically |
| **Lifetime** | Bearer tokens have a TTL set by OVHcloud's `expires_in` response field |

Bearer tokens are minted on demand and cached for their TTL. When a token expires, Warden automatically mints a new one using the stored client credentials.

**To rotate OAuth2 client credentials:**

1. Generate new credentials in OVHcloud IAM
2. Update the credential source:
   ```bash
   warden cred source update ovh-oauth-src \
     --config=client_id=new-client-id \
     --config=client_secret=new-client-secret
   ```
3. Revoke the old credentials in OVHcloud IAM
