---
title: "Splunk"
---

The Splunk provider enables proxied access to the Splunk REST API through Warden. It forwards requests to Splunk management endpoints (Search Jobs, Saved Searches, Dashboards, Indexes, Token Management, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header using Splunk's JWT token authentication (v7.3+). One credential mode is supported: static bearer tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- A **Splunk instance** (Enterprise 7.3+ or Cloud 8.0.2007+) with token authentication enabled
- A **Splunk Bearer Token** with appropriate capabilities (see [Token Management](#token-management))

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
warden write auth/jwt/role/splunk-user \
    token_policies="splunk-access" \
    user_claim=sub \
    cred_spec_name=splunk-ops
```

## Step 2: Mount and Configure the Provider

Enable the Splunk provider at a path of your choice:

```bash
warden provider enable splunk
```

To mount at a custom path:

```bash
warden provider enable -path=splunk-prod splunk
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.example.com:8089",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Set `splunk_url` to your Splunk management endpoint (port 8089). HTTPS is required:

| Deployment | URL |
|------------|-----|
| Enterprise (remote) | `https://splunk.example.com:8089` |
| Splunk Cloud | `https://<stack-name>.splunkcloud.com:8089` |

Verify the configuration:

```bash
warden read splunk/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Bearer Token

The credential source holds only connection info (`api_url`). The bearer token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

First, create a static bearer token in Splunk:

```bash
# Via Splunk REST API (requires admin access)
curl -k -u admin:password -X POST \
  "https://splunk.example.com:8089/services/authorization/tokens?output_mode=json" \
  --data name=warden-service \
  --data audience=warden \
  --data type=static \
  --data-urlencode "expires_on=+365d"
```

Save the token from the response, then create the Warden credential source and spec:

```bash
warden cred source create splunk-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://splunk.example.com:8089 \
  -config=verify_endpoint=/services/server/info \
  -config=auth_header_type=bearer \
  -config=display_name=Splunk
```

Create a credential spec that references the credential source. The spec carries the bearer token and gets associated with tokens at login time.

```bash
warden cred spec create splunk-ops \
  -source splunk-src \
  -config api_key=your-splunk-bearer-token
```

The bearer token is validated at creation time via a `GET /services/server/info` call to the Splunk API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing bearer tokens directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Splunk token (e.g., at `secret/splunk/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create splunk-vault-src \
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
warden cred spec create splunk-ops \
  -source splunk-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=splunk/ops
```

The KV v2 secret at `secret/splunk/ops` should contain an `api_key` field with the Splunk bearer token. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read splunk-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Splunk provider gateway:

```bash
warden policy write splunk-access - <<EOF
path "splunk/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Splunk endpoints a role can access:

```bash
warden policy write splunk-readonly - <<EOF
# Search jobs (read-only: list and get results)
path "splunk/role/+/gateway/services/search/jobs" {
  capabilities = ["read"]
}

path "splunk/role/+/gateway/services/search/jobs/*" {
  capabilities = ["read"]
}

# Saved searches (read-only)
path "splunk/role/+/gateway/services/saved/searches" {
  capabilities = ["read"]
}

# Server info
path "splunk/role/+/gateway/services/server/info" {
  capabilities = ["read"]
}

# Apps (read-only)
path "splunk/role/+/gateway/services/apps/local" {
  capabilities = ["read"]
}

# Dashboards (read-only via namespace)
path "splunk/role/+/gateway/servicesNS/+/search/data/ui/views" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read splunk-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Splunk bearer token automatically.

The URL pattern is: `/v1/splunk/role/{role}/gateway/{api-path}`

Export SPLUNK_ENDPOINT as environment variable:
```bash
export SPLUNK_ENDPOINT="${WARDEN_ADDR}/v1/splunk/role/splunk-user/gateway"
```

### Server Info

```bash
curl -s "${SPLUNK_ENDPOINT}/services/server/info?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create a Search Job

```bash
curl -s -X POST "${SPLUNK_ENDPOINT}/services/search/jobs" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "search=search index=main earliest=-1h | head 10" \
  --data-urlencode "output_mode=json"
```

### Get Search Results

```bash
# Replace <SID> with the search ID from the previous response
curl -s "${SPLUNK_ENDPOINT}/services/search/jobs/<SID>/results?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Saved Searches

```bash
curl -s "${SPLUNK_ENDPOINT}/services/saved/searches?output_mode=json&count=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Indexes

```bash
curl -s "${SPLUNK_ENDPOINT}/services/data/indexes?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Installed Apps

```bash
curl -s "${SPLUNK_ENDPOINT}/services/apps/local?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Submit an Event via REST

```bash
curl -s -X POST "${SPLUNK_ENDPOINT}/services/receivers/simple?source=warden&sourcetype=json&index=main" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"event": "test event from warden", "severity": "info"}'
```

### List Authentication Tokens

```bash
curl -s "${SPLUNK_ENDPOINT}/services/authorization/tokens?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Namespace-Scoped Requests

Splunk supports namespace-scoped endpoints via `/servicesNS/{owner}/{app}/`:

```bash
# List dashboards in the "search" app for all users
curl -s "${SPLUNK_ENDPOINT}/servicesNS/-/search/data/ui/views?output_mode=json&count=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List saved searches for a specific user
curl -s "${SPLUNK_ENDPOINT}/servicesNS/admin/search/saved/searches?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
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

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=splunk-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/splunk-user \
    allowed_common_names="agent-*" \
    token_policies="splunk-access" \
    cred_spec_name=splunk-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.example.com:8089",
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
    -s "https://warden.internal/v1/splunk/role/splunk-user/gateway/services/server/info?output_mode=json"
```

## Token Management

### Splunk Token Types

Splunk supports three JWT token types (v7.3+):

| Type | Lifetime | Modifiable | Best For |
|------|----------|------------|----------|
| **Static** | Indefinite (or custom expiry) | Yes | Service accounts, long-lived integrations |
| **Ephemeral** | Max 6 hours | No | Short-lived automation tasks |
| **Interactive** | Most restricted | No | User sessions |

For Warden, **static tokens** are recommended as they provide stable, long-lived credentials for service-to-service access.

### Required Splunk Capabilities

The Splunk user associated with the bearer token needs appropriate capabilities:

| Capability | Description |
|------------|-------------|
| `search` | Run searches |
| `list_inputs` | List data inputs |
| `list_settings` | View server settings |
| `rest_apps_view` | View apps |
| `edit_tokens_own` | Manage own tokens (for rotation) |

### Creating Tokens in Splunk

**Via Splunk Web:**
Settings > Tokens > New Token

**Via REST API:**

```bash
curl -k -u admin:password -X POST \
  "https://splunk.example.com:8089/services/authorization/tokens?output_mode=json" \
  --data name=warden-service \
  --data audience=warden-proxy \
  --data type=static \
  --data-urlencode "expires_on=+365d"
```

### Token Rotation

| Aspect | Details |
|--------|---------|
| **Storage** | Bearer token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /services/server/info` |
| **Rotation** | Manual — create a new token in Splunk and update the spec |
| **Lifetime** | Configurable — static tokens can be set to never expire |

**To rotate Splunk bearer tokens:**

1. Create a new token in Splunk (with `not_before` set to allow overlap):
   ```bash
   curl -k -u admin:password -X POST \
     "https://splunk.example.com:8089/services/authorization/tokens?output_mode=json" \
     --data name=warden-service \
     --data audience=warden-proxy \
     --data type=static \
     --data-urlencode "expires_on=+365d"
   ```
2. Update the credential spec:
   ```bash
   warden cred spec update splunk-ops \
     -config api_key=your-new-bearer-token
   ```
3. Delete the old token in Splunk:
   ```bash
   curl -k -u admin:password -X DELETE \
     "https://splunk.example.com:8089/services/authorization/tokens/warden-service?output_mode=json" \
     -d id=old-token-id
   ```

### Splunk Cloud Considerations

| Aspect | Splunk Enterprise | Splunk Cloud |
|--------|------------------|--------------|
| Token auth available | v7.3+ | v8.0.2007+ |
| REST API access | Full (all endpoints) | Search tier only |
| Management port | 8089 (configurable) | 8089 (fixed) |
| Endpoint restrictions | None | Many endpoints restricted |
| Token creation | REST API or Web UI | Web UI or support ticket |

When using Splunk Cloud, ensure that the REST API endpoints you need are in the allowed list for your Splunk Cloud version.

## Self-Hosted Splunk

### Custom CA Certificate

If your Splunk instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.internal.corp:8089",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a Splunk instance without TLS:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "http://localhost:8089",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
