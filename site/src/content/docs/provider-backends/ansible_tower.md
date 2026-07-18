---
title: "Ansible Tower"
---

The Ansible Tower provider enables proxied access to the Ansible Tower (AWX / Red Hat Ansible Automation Platform) REST API through Warden. It forwards requests to Ansible Tower API endpoints (Job Templates, Jobs, Inventories, Projects, Hosts, Workflow Templates, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header using Personal Access Tokens (PATs) or OAuth2 application tokens. One credential mode is supported: static bearer tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- An **Ansible Tower** (v3.5+), **AWX** (v18.0+), or **Red Hat Ansible Automation Platform** (v2.0+) instance
- A **Personal Access Token (PAT)** with appropriate permissions (see [Token Management](#token-management))

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/ansible-tower-user \
    token_policies="ansible-tower-access" \
    user_claim=sub \
    cred_spec_name=ansible-tower-ops
```

## Step 2: Mount and Configure the Provider

Enable the Ansible Tower provider at a path of your choice:

```bash
warden provider enable ansible_tower
```

To mount at a custom path:

```bash
warden provider enable -path=ansible-tower-prod ansible_tower
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write ansible_tower/config <<EOF
{
  "ansible_tower_url": "https://tower.example.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Set `ansible_tower_url` to your Ansible Tower instance URL. HTTPS is required:

| Deployment | URL |
|------------|-----|
| AWX | `https://awx.example.com` |
| AAP Controller (direct) | `https://controller.example.com` |
| AAP Platform Gateway | `https://aap.example.com` |
| Self-hosted Tower | `https://tower.example.com` |

Verify the configuration:

```bash
warden read ansible_tower/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Personal Access Token

The credential source holds only connection info (`api_url`). The PAT is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

First, create a Personal Access Token in Ansible Tower:

```bash
# Via Ansible Tower REST API (requires admin access)
curl -k -u admin:password -X POST \
  "https://tower.example.com/api/v2/users/1/personal_tokens/" \
  -H "Content-Type: application/json" \
  -d '{"scope": "write"}'
```

Save the token from the response, then create the Warden credential source and spec:

```bash
warden cred source create ansible-tower-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://tower.example.com \
  -config=verify_endpoint=/api/v2/ping/ \
  -config=auth_header_type=bearer \
  -config=display_name=Ansible\ Tower
```

Create a credential spec that references the credential source. The spec carries the PAT and gets associated with tokens at login time.

```bash
warden cred spec create ansible-tower-ops \
  -source ansible-tower-src \
  -config api_key=your-ansible-tower-pat
```

The PAT is validated at creation time via a `GET /api/v2/ping/` call to the Ansible Tower API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing PATs directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Ansible Tower token (e.g., at `secret/ansible-tower/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create ansible-tower-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h
```

Create a credential spec using the `static_apikey` mint method:

```bash
warden cred spec create ansible-tower-ops \
  -source ansible-tower-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=ansible-tower/ops
```

The KV v2 secret at `secret/ansible-tower/ops` should contain an `api_key` field with the Ansible Tower PAT. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read ansible-tower-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Ansible Tower provider gateway:

```bash
warden policy write ansible-tower-access - <<EOF
path "ansible_tower/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Ansible Tower endpoints a role can access:

```bash
warden policy write ansible-tower-readonly - <<EOF
# Job templates (read-only: list and view)
path "ansible_tower/role/+/gateway/api/v2/job_templates/" {
  capabilities = ["read"]
}

path "ansible_tower/role/+/gateway/api/v2/job_templates/*" {
  capabilities = ["read"]
}

# Jobs (read-only: list and check status)
path "ansible_tower/role/+/gateway/api/v2/jobs/" {
  capabilities = ["read"]
}

path "ansible_tower/role/+/gateway/api/v2/jobs/*" {
  capabilities = ["read"]
}

# Inventories (read-only)
path "ansible_tower/role/+/gateway/api/v2/inventories/" {
  capabilities = ["read"]
}

path "ansible_tower/role/+/gateway/api/v2/inventories/*" {
  capabilities = ["read"]
}

# Projects (read-only)
path "ansible_tower/role/+/gateway/api/v2/projects/" {
  capabilities = ["read"]
}

# Hosts (read-only)
path "ansible_tower/role/+/gateway/api/v2/hosts/" {
  capabilities = ["read"]
}

# Ping (health check)
path "ansible_tower/role/+/gateway/api/v2/ping/" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read ansible-tower-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Ansible Tower PAT automatically.

The URL pattern is: `/v1/ansible_tower/role/{role}/gateway/{api-path}`

Export TOWER_ENDPOINT as environment variable:
```bash
export TOWER_ENDPOINT="${WARDEN_ADDR}/v1/ansible_tower/role/ansible-tower-user/gateway"
```

### Ping (Health Check)

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/ping/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Current User

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/me/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Job Templates

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/job_templates/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Launch a Job Template

```bash
curl -s -X POST "${TOWER_ENDPOINT}/api/v2/job_templates/42/launch/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"target_host": "web01", "deploy_version": "1.2.3"}}'
```

### Check Job Status

```bash
# Replace <JOB_ID> with the job ID from the launch response
curl -s "${TOWER_ENDPOINT}/api/v2/jobs/<JOB_ID>/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Inventories

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/inventories/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Projects

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/projects/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Hosts

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/hosts/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Workflow Job Templates

```bash
curl -s "${TOWER_ENDPOINT}/api/v2/workflow_job_templates/" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Launch a Workflow Job Template

```bash
curl -s -X POST "${TOWER_ENDPOINT}/api/v2/workflow_job_templates/10/launch/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"environment": "staging"}}'
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

Steps 1-3 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1-3 (provider setup) are identical. Replace Steps 1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=ansible-tower-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/ansible-tower-user \
    allowed_common_names="agent-*" \
    token_policies="ansible-tower-access" \
    cred_spec_name=ansible-tower-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write ansible_tower/config <<EOF
{
  "ansible_tower_url": "https://tower.example.com",
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
    -s "https://warden.internal/v1/ansible_tower/role/ansible-tower-user/gateway/api/v2/ping/"
```

## Token Management

### Token Types

Ansible Tower supports two token types:

| Type | Lifetime | Best For |
|------|----------|----------|
| **Personal Access Token (PAT)** | Configurable expiration | Service accounts, long-lived integrations |
| **OAuth2 Application Token** | Configurable expiration | Third-party application access |

For Warden, **Personal Access Tokens** are recommended as they provide stable, user-scoped credentials for service-to-service access.

### Token Scopes

| Scope | Description |
|-------|-------------|
| `read` | Read-only access to resources |
| `write` | Full read/write permissions (includes read) |

### Creating Tokens in Ansible Tower

**Via Ansible Tower Web UI:**
Users > (select user) > Tokens > Add

**Via REST API:**

```bash
# Create a PAT with write scope
curl -k -u admin:password -X POST \
  "https://tower.example.com/api/v2/users/1/personal_tokens/" \
  -H "Content-Type: application/json" \
  -d '{"scope": "write"}'
```

The token value is returned only once in the response. Store it securely.

### Token Rotation

| Aspect | Details |
|--------|---------|
| **Storage** | PAT is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /api/v2/ping/` |
| **Rotation** | Manual — create a new token in Ansible Tower and update the spec |
| **Lifetime** | Configurable via `ACCESS_TOKEN_EXPIRE_SECONDS` in Tower settings |

**To rotate Ansible Tower PATs:**

1. Create a new token in Ansible Tower:
   ```bash
   curl -k -u admin:password -X POST \
     "https://tower.example.com/api/v2/users/1/personal_tokens/" \
     -H "Content-Type: application/json" \
     -d '{"scope": "write"}'
   ```
2. Update the credential spec:
   ```bash
   warden cred spec update ansible-tower-ops \
     -config api_key=your-new-pat
   ```
3. Delete the old token in Ansible Tower:
   ```bash
   curl -k -u admin:password -X DELETE \
     "https://tower.example.com/api/v2/tokens/<OLD_TOKEN_ID>/"
   ```

### AWX vs Red Hat Ansible Automation Platform

| Aspect | AWX (Community) | AAP (Red Hat) |
|--------|----------------|---------------|
| API version | `/api/v2/` | `/api/v2/` (direct) or `/api/controller/v2/` (platform gateway) |
| Token auth | PATs and OAuth2 | PATs and OAuth2 |
| Default port | 443 (HTTPS) | 443 (HTTPS) |
| External user tokens | Enabled by default | Disabled by default (admin setting) |
| Token expiration | Configurable | Configurable |
| Latest version | CalVer (25.x) | AAP 2.6 |
