---
title: "Ansible Tower"
---

The Ansible Tower provider enables proxied access to the Ansible Tower (AWX / Red Hat Ansible Automation Platform) REST API through Warden. It forwards requests to Ansible Tower API endpoints (Job Templates, Jobs, Inventories, Projects, Hosts, Workflow Templates, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header using Personal Access Tokens (PATs) or OAuth2 application tokens. One credential mode is supported: static bearer tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The question is where that
OAuth2 token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Ansible Automation Platform OAuth2 token from an external vault at a path templated by the agent's team and environment, and injects it to the Ansible Automation Platform API" src="/images/warden-prov-awx-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/awx/{{agent.team}}/{{agent.env}}`.
6. The vault returns the OAuth2 token for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Ansible Automation Platform OAuth2 token from its encrypted storage and injects it to the Ansible Automation Platform API for every caller" src="/images/warden-prov-awx-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Ansible Automation Platform sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Ansible Automation Platform exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- An **Ansible Tower** (v3.5+), **AWX** (v18.0+), or **Red Hat Ansible Automation Platform** (v2.0+) instance
- A **Personal Access Token (PAT)** with appropriate permissions (see [Token Management](#token-management))

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

```bash
# The store Warden reads from, reached keylessly — no vault token in Warden
warden cred source create vault-keyless -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create ansible-tower-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "awx/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the credential under **`api_key`**.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Option B: Inline

⚠️ 
```bash
warden cred source create ansible-tower-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://awx.example.com/api/v2",
    "verify_endpoint": "/ping/",
    "display_name": "Ansible Automation Platform"
  }
}'

printf '{"source":"ansible-tower-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/awx-token)" | warden cred spec create ansible-tower-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
