# Sentry Provider

The Sentry provider enables proxied access to the Sentry REST API through Warden. It forwards requests to Sentry endpoints (organizations, projects, issues, events, etc.) with automatic credential injection and policy evaluation. Credentials are static Internal Integration tokens created in the Sentry UI (`apikey` source type).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Sentry Internal Integration Token** (from Sentry > Settings > Developer Settings > Internal Integrations)

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
warden write auth/jwt/role/sentry-user \
    token_policies="sentry-access" \
    user_claim=sub \
    cred_spec_name=sentry-ops
```

## Step 2: Mount and Configure the Provider

Enable the Sentry provider at a path of your choice:

```bash
warden provider enable --type=sentry
```

To mount at a custom path:

```bash
warden provider enable --type=sentry sentry-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write sentry/config <<EOF
{
  "sentry_url": "https://sentry.io/api/0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read sentry/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Internal Integration Token

The credential source holds only connection info (`api_url`). The auth token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

First, create an Internal Integration in Sentry:
1. Go to **Settings > Developer Settings > Internal Integrations**
2. Click **Create New Integration**
3. Give it a name and select the required permission scopes
4. Copy the generated token (it is only displayed once)

```bash
warden cred source create sentry-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://sentry.io/api/0 \
  --config=verify_endpoint=/ \
  --config=display_name=Sentry
```

Create a credential spec that references the credential source. The spec carries the auth token and gets associated with tokens at login time.

```bash
warden cred spec create sentry-ops \
  --source sentry-src \
  --config api_key=your-sentry-internal-integration-token
```

The token is validated at creation time via a `GET /` call to the Sentry API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing the auth token directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Sentry token (e.g., at `secret/sentry/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create sentry-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h
```

Create a credential spec using the `static_apikey` mint method:

```bash
warden cred spec create sentry-ops \
  --source sentry-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=sentry/ops
```

The KV v2 secret at `secret/sentry/ops` should contain at minimum an `api_key` field. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read sentry-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Sentry provider gateway:

```bash
warden policy write sentry-access - <<EOF
path "sentry/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Sentry resources and actions a role can use:

```bash
warden policy write sentry-readonly - <<EOF
path "sentry/role/+/gateway/organizations/*" {
  capabilities = ["read"]
}

path "sentry/role/+/gateway/projects/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read sentry-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Sentry token automatically.

The URL pattern is: `/v1/sentry/role/{role}/gateway/{api-path}`

Export SENTRY_ENDPOINT as environment variable:
```bash
export SENTRY_ENDPOINT="${WARDEN_ADDR}/v1/sentry/role/sentry-user/gateway"
```

### List Organizations

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Projects

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/{org}/projects/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Issues

```bash
curl -s "${SENTRY_ENDPOINT}/projects/{org}/{project}/issues/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Issue Details

```bash
curl -s "${SENTRY_ENDPOINT}/issues/{issue_id}/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Project Events

```bash
curl -s "${SENTRY_ENDPOINT}/projects/{org}/{project}/events/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Organization Members

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/{org}/members/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Resolve an Issue

```bash
curl -s -X PUT "${SENTRY_ENDPOINT}/issues/{issue_id}/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved"
  }'
```

### Create a Project

```bash
curl -s -X POST "${SENTRY_ENDPOINT}/teams/{org}/{team}/projects/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-new-project"
  }'
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

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
    default_role=sentry-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/sentry-user \
    allowed_common_names="agent-*" \
    token_policies="sentry-access" \
    cred_spec_name=sentry-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write sentry/config <<EOF
{
  "sentry_url": "https://sentry.io/api/0",
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
    -s "https://warden.internal/v1/sentry/role/sentry-user/gateway/organizations/" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sentry_url` | string | `https://sentry.io/api/0` | Sentry API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (default: `https://sentry.io/api/0`) |
| `verify_endpoint` | string | No | Verification path (e.g., `/`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Sentry Internal Integration token (sensitive — masked in output) |

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

### Credential Spec Config (Vault — static_apikey)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

## Token Management

### Static Internal Integration Token

| Aspect | Details |
|--------|---------|
| **Storage** | Token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /` on the Sentry API |
| **Rotation** | Manual — regenerate in Sentry and update the spec |
| **Lifetime** | Static — Internal Integration tokens do not expire |

Sentry does not support OAuth2 client credentials flow. For machine-to-machine access, Sentry recommends Internal Integration tokens.

**To rotate a static token:**

1. Generate a new token in Sentry (Settings > Developer Settings > Internal Integrations)
2. Update the credential spec:
   ```bash
   warden cred spec update sentry-ops \
     --config api_key=your-new-token
   ```
3. Revoke the old token in Sentry
