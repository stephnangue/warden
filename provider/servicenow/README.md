# ServiceNow Provider

The ServiceNow provider enables proxied access to a ServiceNow instance REST API through Warden. It forwards requests to ServiceNow endpoints (Table API, CMDB, Import Sets, Attachments, etc.) with automatic credential injection and policy evaluation. Two credential modes are supported: static API tokens (`apikey` source type) and OAuth2 client credentials (`oauth2` source type).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [OAuth2 Client Credentials Mode](#oauth2-client-credentials-mode)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **ServiceNow instance** with REST API access enabled
- A **ServiceNow user account** with REST API access (for Basic Auth via the `apikey` source type) **or** a **ServiceNow OAuth2 App** (client_id and client_secret from System OAuth > Application Registry)

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
warden write auth/jwt/role/servicenow-user \
    token_policies="servicenow-access" \
    user_claim=sub \
    cred_spec_name=servicenow-ops
```

## Step 2: Mount and Configure the Provider

Enable the ServiceNow provider at a path of your choice:

```bash
warden provider enable --type=servicenow
```

To mount at a custom path:

```bash
warden provider enable --type=servicenow servicenow-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write servicenow/config <<EOF
{
  "servicenow_url": "https://mycompany.service-now.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "60s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read servicenow/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Token

The credential source holds only connection info (`api_url`). The API token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

```bash
warden cred source create servicenow-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://mycompany.service-now.com \
  --config=verify_endpoint=/api/now/table/sys_user?sysparm_limit=1 \
  --config=display_name=ServiceNow
```

Create a credential spec that references the credential source. The spec carries the API token and gets associated with tokens at login time.

```bash
warden cred spec create servicenow-ops \
  --source servicenow-src \
  --config api_key=your-servicenow-api-token
```

The API token is validated at creation time via a `GET /api/now/table/sys_user?sysparm_limit=1` call to the ServiceNow API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: OAuth2 Client Credentials

See [OAuth2 Client Credentials Mode](#oauth2-client-credentials-mode) below for setup with `client_id` and `client_secret`.

### Option C: Vault/OpenBao as Credential Source

Instead of storing the API token directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your ServiceNow API token (e.g., at `secret/servicenow/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create servicenow-vault-src \
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
warden cred spec create servicenow-ops \
  --source servicenow-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=servicenow/ops
```

The KV v2 secret at `secret/servicenow/ops` should contain at minimum an `api_key` field. Warden fetches the secret from Vault on each credential request.

You can also use the `oauth2` mint method if you have an OAuth2 plugin (openbao-plugin-secrets-oauthapp) configured in Vault:

```bash
warden cred spec create servicenow-ops \
  --source servicenow-vault-src \
  --config mint_method=oauth2 \
  --config oauth2_mount=oauth2 \
  --config credential_name=servicenow
```

Verify:

```bash
warden cred spec read servicenow-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the ServiceNow provider gateway:

```bash
warden policy write servicenow-access - <<EOF
path "servicenow/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which ServiceNow resources and actions a role can use:

```bash
warden policy write servicenow-readonly - <<EOF
path "servicenow/role/+/gateway/api/now/table/incident" {
  capabilities = ["read"]
}

path "servicenow/role/+/gateway/api/now/table/sys_user" {
  capabilities = ["read"]
}

path "servicenow/role/+/gateway/api/now/table/change_request" {
  capabilities = ["read"]
}

path "servicenow/role/+/gateway/api/now/cmdb/instance/*" {
  capabilities = ["read"]
}

path "servicenow/role/+/gateway/api/now/stats/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read servicenow-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the ServiceNow token automatically.

The URL pattern is: `/v1/servicenow/role/{role}/gateway/{api-path}`

Export SN_ENDPOINT as environment variable:
```bash
export SN_ENDPOINT="${WARDEN_ADDR}/v1/servicenow/role/servicenow-user/gateway"
```

### List Incidents

```bash
curl -s "${SN_ENDPOINT}/api/now/table/incident?sysparm_limit=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get a Specific Incident

```bash
curl -s "${SN_ENDPOINT}/api/now/table/incident/INC0010001" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Users

```bash
curl -s "${SN_ENDPOINT}/api/now/table/sys_user?sysparm_limit=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Query CMDB Servers

```bash
curl -s "${SN_ENDPOINT}/api/now/cmdb/instance/cmdb_ci_server?sysparm_limit=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Incident Statistics

```bash
curl -s "${SN_ENDPOINT}/api/now/stats/incident?sysparm_count=true" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create an Incident

```bash
curl -s -X POST "${SN_ENDPOINT}/api/now/table/incident" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "short_description": "Server unreachable",
    "urgency": "1",
    "impact": "2",
    "category": "Network",
    "assignment_group": "Service Desk"
  }'
```

### Update an Incident

```bash
curl -s -X PATCH "${SN_ENDPOINT}/api/now/table/incident/INC0010001" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "state": "2",
    "work_notes": "Investigating the issue"
  }'
```

### Create a Change Request

```bash
curl -s -X POST "${SN_ENDPOINT}/api/now/table/change_request" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "short_description": "Deploy v2.1.0 to production",
    "type": "standard",
    "category": "Software",
    "priority": "3"
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

## OAuth2 Client Credentials Mode

Instead of a static API token, you can use OAuth2 client credentials to have Warden mint short-lived bearer tokens automatically. This is recommended for production deployments.

### Create an OAuth2 Credential Source

The source holds the OAuth2 app credentials (`client_id`, `client_secret`). Tokens are minted dynamically on each credential request.

```bash
warden cred source create servicenow-oauth-src \
  --type=oauth2 \
  --rotation-period=0 \
  --config=client_id=your-client-id \
  --config=client_secret=your-client-secret \
  --config=token_url=https://mycompany.service-now.com/oauth_token.do \
  --config=verify_url=https://mycompany.service-now.com/api/now/table/sys_user?sysparm_limit=1 \
  --config=display_name=ServiceNow
```

### Create an OAuth2 Credential Spec

The spec optionally specifies the OAuth2 scope. If omitted, the `default_scopes` value from the credential source is used.

```bash
warden cred spec create servicenow-ops \
  --source servicenow-oauth-src \
  --config scope="useraccount"
```

The spec is validated at creation time: Warden mints a test token and verifies it by calling `GET /api/now/table/sys_user?sysparm_limit=1` on the ServiceNow API. If the credentials are invalid, spec creation will fail.

### Update the JWT Role

Make sure the JWT role references the OAuth2 spec:

```bash
warden write auth/jwt/role/servicenow-user \
    token_policies="servicenow-access" \
    user_claim=sub \
    cred_spec_name=servicenow-ops
```

All gateway requests work identically — Warden transparently injects the minted bearer token.

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
    default_role=servicenow-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/servicenow-user \
    allowed_common_names="agent-*" \
    token_policies="servicenow-access" \
    cred_spec_name=servicenow-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write servicenow/config <<EOF
{
  "servicenow_url": "https://mycompany.service-now.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "60s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/servicenow/role/servicenow-user/gateway/api/now/table/incident" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `servicenow_url` | string | — (required) | ServiceNow instance URL (must be HTTPS, e.g., `https://mycompany.service-now.com`) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `60s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (e.g., `https://mycompany.service-now.com`) |
| `verify_endpoint` | string | No | Verification path (e.g., `/api/now/table/sys_user?sysparm_limit=1`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Source Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | OAuth2 application client ID |
| `client_secret` | string | Yes | OAuth2 application client secret (sensitive — masked in output) |
| `token_url` | string | Yes | OAuth2 token endpoint (e.g., `https://mycompany.service-now.com/oauth_token.do`) |
| `default_scopes` | string | No | Default OAuth2 scopes (space-separated) |
| `verify_url` | string | No | Endpoint to verify minted tokens (e.g., `https://mycompany.service-now.com/api/now/table/sys_user?sysparm_limit=1`) |
| `verify_method` | string | No | HTTP method for verify_url (default: `GET`) |
| `auth_header_type` | string | No | How to attach token for verification: `bearer`, `token`, `custom_header` (default: `bearer`) |
| `auth_header_name` | string | No | Header name when `auth_header_type=custom_header` |
| `display_name` | string | No | Human-readable label for logs/errors (default: `OAuth2`) |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification; also allows `http://` URLs (default: `false`) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Credential Spec Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | ServiceNow API token (sensitive — masked in output) |

### Credential Spec Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scope` | string | No | OAuth2 scope to request (e.g., `useraccount`) |

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

### Credential Spec Config (Vault — oauth2)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `oauth2` |
| `oauth2_mount` | string | Yes | Vault OAuth2 secrets engine mount path |
| `credential_name` | string | Yes | Credential name configured in the OAuth2 plugin |

## Token Management

### Static API Token

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /api/now/table/sys_user?sysparm_limit=1` |
| **Rotation** | Manual — regenerate in ServiceNow and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate a static API token:**

1. Generate new credentials in ServiceNow
2. Update the credential spec:
   ```bash
   warden cred spec update servicenow-ops \
     --config api_key=your-new-api-token
   ```
3. Revoke the old credentials in ServiceNow

### OAuth2 Client Credentials

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source |
| **Validation** | Spec is verified at creation by minting a test token and calling `GET /api/now/table/sys_user?sysparm_limit=1` |
| **Rotation** | Client credentials are managed in ServiceNow; bearer tokens are minted automatically |
| **Lifetime** | Bearer tokens have a TTL set by ServiceNow's `expires_in` response field |

Bearer tokens are minted on demand and cached for their TTL. When a token expires, Warden automatically mints a new one using the stored client credentials.

**To rotate OAuth2 client credentials:**

1. Generate new credentials in ServiceNow (System OAuth > Application Registry)
2. Update the credential source:
   ```bash
   warden cred source update servicenow-oauth-src \
     --config=client_id=new-client-id \
     --config=client_secret=new-client-secret
   ```
3. Revoke the old credentials in ServiceNow

## Custom CA Certificate

If your ServiceNow instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write servicenow/config <<EOF
{
  "servicenow_url": "https://mycompany.service-now.com",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

## Development / Testing (no TLS)

For local development against a ServiceNow instance without TLS:

```bash
warden write servicenow/config <<EOF
{
  "servicenow_url": "http://localhost:8080",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
