---
title: "GCP"
---

The GCP provider enables proxied access to Google Cloud Platform APIs through Warden. It authenticates using service account keys, supports OAuth2 token minting and service account impersonation, and handles automated key rotation.

## Prerequisites

- Docker and Docker Compose installed and running
- A GCP **service account key** (JSON format) with appropriate IAM permissions

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

### Creating a Service Account Key

1. Go to the [GCP Console](https://console.cloud.google.com/) > **IAM & Admin > Service Accounts**.
2. Select or create a service account.
3. Go to the **Keys** tab and click **Add Key > Create new key > JSON**.
4. Download the JSON key file.

For key rotation support, the service account also needs:
- `iam.serviceAccountKeys.create`
- `iam.serviceAccountKeys.delete`

For impersonation, the source service account needs `iam.serviceAccounts.getAccessToken` on the target service account.

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gcp-user \
    token_policies="gcp-access" \
    user_claim=sub \
    cred_spec_name=gcp-cloud-platform
```

## Step 2: Mount and Configure the Provider

Enable the GCP provider at a path of your choice:

```bash
warden provider enable gcp
```

To mount at a custom path:

```bash
warden provider enable -path=gcp-prod gcp
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write gcp/config <<EOF
{
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read gcp/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds the service account key used to authenticate with GCP.

```bash
warden cred source create gcp-sa \
  -type=gcp_access_token \
  -rotation-period=720h \
  -config=source=gcp \
  -config=service_account_key=@/path/to/service-account-key.json
```

The `@` prefix reads the file contents into the config value.

Verify the source was created:

```bash
warden cred source read gcp-sa
```

Create a credential spec that references the credential source. The spec defines how Warden mints OAuth2 tokens and gets associated with tokens at login time.

### Option A: Direct Access Token (Recommended)

Mint OAuth2 access tokens using the source service account directly:

```bash
warden cred spec create gcp-cloud-platform \
  -source=gcp-sa \
  -min-ttl=5m \
  -max-ttl=1h \
  -config=mint_method=access_token \
  -config=scopes=https://www.googleapis.com/auth/cloud-platform
```

### Option B: Impersonated Access Token

Mint tokens on behalf of another service account:

```bash
warden cred spec create gcp-impersonated \
  -source=gcp-sa \
  -min-ttl=5m \
  -max-ttl=1h \
  -config=mint_method=impersonated_access_token \
  -config=target_service_account=target@my-project.iam.gserviceaccount.com \
  -config=scopes=https://www.googleapis.com/auth/cloud-platform \
  -config=lifetime=3600s
```

### Option C: Vault/OpenBao GCP Secret Engine

Instead of storing a service account key in Warden, you can use the Vault GCP secret engine to dynamically mint access tokens. Vault manages the service account lifecycle.

**Prerequisites:** A Vault/OpenBao instance with:
- The GCP secret engine mounted and configured with a roleset or static account
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create gcp-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h

# Create a credential spec using the dynamic_gcp mint method (roleset)
warden cred spec create gcp-cloud-platform \
  -source gcp-vault-src \
  -config mint_method=dynamic_gcp \
  -config gcp_mount=gcp \
  -config role_name=my-roleset

# Or using a static account instead of a roleset
warden cred spec create gcp-static \
  -source gcp-vault-src \
  -config mint_method=dynamic_gcp \
  -config gcp_mount=gcp \
  -config role_name=my-static-account \
  -config role_type=static-account
```

Verify:

```bash
warden cred spec read gcp-cloud-platform
```

## Step 4: Create a Policy

Create a policy that grants access to the GCP provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write gcp-access - <<EOF
path "gcp/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict Compute Engine instance deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write gcp-prod-restricted - <<EOF
path "gcp/role/+/gateway/compute.googleapis.com/compute/v1/projects/+/zones/+/instances/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "gcp/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read gcp-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the OAuth2 Bearer token automatically.

The URL pattern is: `/v1/gcp/role/{role}/gateway/{googleapis-host}/{path}`

The first path segment after `gateway/` is the GCP API host, and the rest is the API path.

Export GCP_ENDPOINT as environment variable:
```bash
export GCP_ENDPOINT="${WARDEN_ADDR}/v1/gcp/role/gcp-user/gateway"
```

### Cloud Storage — List Buckets

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b?project=my-project" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Cloud Storage — Get Object

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b/my-bucket/o/my-object" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Compute Engine — List Instances

```bash
curl "${GCP_ENDPOINT}/compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Secret Manager — List Secrets

```bash
curl "${GCP_ENDPOINT}/secretmanager.googleapis.com/v1/projects/my-project/secrets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### BigQuery — List Datasets

```bash
curl "${GCP_ENDPOINT}/bigquery.googleapis.com/bigquery/v2/projects/my-project/datasets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### IAM — List Service Accounts

```bash
curl "${GCP_ENDPOINT}/iam.googleapis.com/v1/projects/my-project/serviceAccounts" \
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

## Mint Methods

| Method | Description | Token Lifetime | Use Case |
|--------|-------------|----------------|----------|
| `access_token` | OAuth2 token from source SA key | ~1 hour (auto-refreshed) | Direct access with source SA permissions |
| `impersonated_access_token` | Token minted on behalf of another SA | Configurable via `lifetime` (default: 1h) | Least-privilege delegation without sharing target SA keys |
| `dynamic_gcp` | Token from Vault GCP secret engine | ~1 hour | Vault-managed service accounts — no SA key in Warden |

Both `access_token` and `impersonated_access_token` return tokens that expire naturally and cannot be revoked. `dynamic_gcp` delegates token minting to the Vault GCP engine.

### Returned Credential Data

```json
{
  "access_token": "ya29.xxx...",
  "project_id": "my-project",
  "scopes": "https://www.googleapis.com/auth/cloud-platform",
  "token_type": "Bearer",
  "target_service_account": "target@my-project.iam.gserviceaccount.com"
}
```

The `target_service_account` field is only present for impersonated tokens.

## Credential Rotation

The GCP provider supports the two-stage async rotation pattern for service account keys:

1. **Prepare**: Creates a new service account key via the IAM API.
2. **Activate**: After the activation delay, switches to the new key and invalidates all cached tokens.
3. **Cleanup**: Deletes the old service account key via the IAM API.

The default activation delay is **2 minutes** (configurable via `activation_delay` in the credential source config). This accounts for IAM propagation time across GCP.

When the source key rotates, all credential specs sharing that source automatically use the new key — no per-spec rotation is needed.

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
    default_role=gcp-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/gcp-user \
    allowed_common_names="agent-*" \
    token_policies="gcp-access" \
    cred_spec_name=gcp-cloud-platform
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write gcp/config <<EOF
{
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
# Role in URL path
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/gcp/role/gcp-user/gateway/storage.googleapis.com/storage/v1/b?project=my-project"

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/gcp/gateway/storage.googleapis.com/storage/v1/b?project=my-project"
```
