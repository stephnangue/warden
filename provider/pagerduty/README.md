# PagerDuty Provider

The PagerDuty provider enables proxied access to the PagerDuty REST API v2 through Warden. It forwards requests to PagerDuty endpoints (incidents, services, users, schedules, etc.) with automatic credential injection and policy evaluation. Two credential modes are supported: static API tokens and OAuth2 client credentials.

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
- A **PagerDuty API Token** (from PagerDuty > Integrations > API Access Keys) **or** a **PagerDuty OAuth2 App** (client_id and client_secret from PagerDuty > Integrations > App Registration)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o deploy/docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f deploy/docker-compose.quickstart.yml up -d
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
warden write auth/jwt/role/pagerduty-user \
    token_policies="pagerduty-access" \
    user_claim=sub \
    cred_spec_name=pagerduty-ops
```

## Step 2: Mount and Configure the Provider

Enable the PagerDuty provider at a path of your choice:

```bash
warden provider enable --type=pagerduty
```

To mount at a custom path:

```bash
warden provider enable --type=pagerduty pagerduty-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write pagerduty/config <<EOF
{
  "pagerduty_url": "https://api.pagerduty.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read pagerduty/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Token

The credential source holds only connection info (`api_url`). The API token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

```bash
warden cred source create pagerduty-src \
  --type=pagerduty \
  --rotation-period=0 \
  --config=api_url=https://api.pagerduty.com
```

Create a credential spec that references the credential source. The spec carries the API token and gets associated with tokens at login time.

```bash
warden cred spec create pagerduty-ops \
  --source pagerduty-src \
  --config api_key=your-pagerduty-api-token
```

The API token is validated at creation time via a `GET /users/me` call to the PagerDuty API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: OAuth2 Client Credentials

See [OAuth2 Client Credentials Mode](#oauth2-client-credentials-mode) below for setup with `client_id` and `client_secret`.

Verify:

```bash
warden cred spec read pagerduty-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the PagerDuty provider gateway:

```bash
warden policy write pagerduty-access - <<EOF
path "pagerduty/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which PagerDuty resources and actions a role can use:

```bash
warden policy write pagerduty-readonly - <<EOF
path "pagerduty/role/+/gateway/incidents" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/services" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/users" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/schedules" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/escalation_policies" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read pagerduty-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the PagerDuty token automatically.

The URL pattern is: `/v1/pagerduty/role/{role}/gateway/{api-path}`

Export PD_ENDPOINT as environment variable:
```bash
export PD_ENDPOINT="${WARDEN_ADDR}/v1/pagerduty/role/pagerduty-user/gateway"
```

### List Incidents

```bash
curl -s "${PD_ENDPOINT}/incidents" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Current User

```bash
curl -s "${PD_ENDPOINT}/users/me" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Services

```bash
curl -s "${PD_ENDPOINT}/services" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List On-Call Schedules

```bash
curl -s "${PD_ENDPOINT}/schedules" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Escalation Policies

```bash
curl -s "${PD_ENDPOINT}/escalation_policies" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create an Incident

```bash
curl -s -X POST "${PD_ENDPOINT}/incidents" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "incident": {
      "type": "incident",
      "title": "Server unreachable",
      "service": {
        "id": "PSERVICE1",
        "type": "service_reference"
      },
      "urgency": "high"
    }
  }'
```

### Acknowledge an Incident

```bash
curl -s -X PUT "${PD_ENDPOINT}/incidents/PINCIDENT1" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "incident": {
      "type": "incident_reference",
      "status": "acknowledged"
    }
  }'
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f deploy/docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## OAuth2 Client Credentials Mode

Instead of a static API token, you can use OAuth2 client credentials to have Warden mint short-lived bearer tokens automatically. This is recommended for production deployments.

### Create an OAuth2 Credential Source

The source holds the OAuth2 app credentials (`client_id`, `client_secret`). Tokens are minted dynamically on each credential request.

```bash
warden cred source create pagerduty-oauth-src \
  --type=pagerduty_oauth2 \
  --rotation-period=0 \
  --config=client_id=your-client-id \
  --config=client_secret=your-client-secret
```

Optionally, override the default token endpoint:

```bash
warden cred source create pagerduty-oauth-src \
  --type=pagerduty_oauth2 \
  --rotation-period=0 \
  --config=client_id=your-client-id \
  --config=client_secret=your-client-secret \
  --config=token_url=https://identity.pagerduty.com/oauth/token
```

### Create an OAuth2 Credential Spec

The spec optionally specifies the OAuth2 scope. If omitted, the default scope from the provider configuration is used.

```bash
warden cred spec create pagerduty-ops \
  --source pagerduty-oauth-src \
  --config scope="read write"
```

The spec is validated at creation time: Warden mints a test token and verifies it by calling `GET /users/me` on the PagerDuty API. If the credentials are invalid, spec creation will fail.

### Update the JWT Role

Make sure the JWT role references the OAuth2 spec:

```bash
warden write auth/jwt/role/pagerduty-user \
    token_policies="pagerduty-access" \
    user_claim=sub \
    cred_spec_name=pagerduty-ops
```

All gateway requests work identically — Warden transparently injects the minted bearer token.

## TLS Certificate Authentication

Steps 1-3 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=pagerduty-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/pagerduty-user \
    allowed_common_names="agent-*" \
    token_policies="pagerduty-access" \
    cred_spec_name=pagerduty-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write pagerduty/config <<EOF
{
  "pagerduty_url": "https://api.pagerduty.com",
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
    -s "https://warden.internal/v1/pagerduty/role/pagerduty-user/gateway/incidents" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pagerduty_url` | string | `https://api.pagerduty.com` | PagerDuty API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Token)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_url` | string | `https://api.pagerduty.com` | PagerDuty API base URL (must be HTTPS) |

### Credential Source Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | PagerDuty OAuth2 application client ID |
| `client_secret` | string | Yes | PagerDuty OAuth2 application client secret (sensitive — masked in output) |
| `token_url` | string | No | OAuth2 token endpoint (default: `https://identity.pagerduty.com/oauth/token`) |

### Credential Spec Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | PagerDuty API token (sensitive — masked in output) |

### Credential Spec Config (OAuth2 Client Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scope` | string | No | OAuth2 scope to request |

## Token Management

### Static API Token

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /users/me` |
| **Rotation** | Manual — regenerate in PagerDuty and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate a static API token:**

1. Generate a new API token in PagerDuty (Integrations > API Access Keys)
2. Update the credential spec:
   ```bash
   warden cred spec update pagerduty-ops \
     --config api_key=your-new-api-token
   ```
3. Revoke the old token in PagerDuty

### OAuth2 Client Credentials

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source |
| **Validation** | Spec is verified at creation by minting a test token and calling `GET /users/me` |
| **Rotation** | Client credentials are managed in PagerDuty; bearer tokens are minted automatically |
| **Lifetime** | Bearer tokens have a TTL set by PagerDuty's `expires_in` response field |

Bearer tokens are minted on demand and cached for their TTL. When a token expires, Warden automatically mints a new one using the stored client credentials.

**To rotate OAuth2 client credentials:**

1. Generate new credentials in PagerDuty (Integrations > App Registration)
2. Update the credential source:
   ```bash
   warden cred source update pagerduty-oauth-src \
     --config=client_id=new-client-id \
     --config=client_secret=new-client-secret
   ```
3. Revoke the old credentials in PagerDuty
