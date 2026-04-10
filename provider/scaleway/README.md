# Scaleway Provider

The Scaleway provider enables proxied access to Scaleway APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `X-Auth-Token` header with the Scaleway secret key. Covers Instances, Kubernetes, Databases, IAM, Load Balancers, Registries, and all other Scaleway products.
- **S3 Object Storage** — Verifies the client's SigV4 signature, re-signs with real Scaleway credentials, and forwards to `s3.{region}.scw.cloud`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [S3 Object Storage](#s3-object-storage)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Scaleway account** with an API key (access key + secret key) — generate one at [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)

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
warden write auth/jwt/role/scaleway-user \
    token_policies="scaleway-access" \
    user_claim=sub \
    cred_spec_name=scaleway-ops
```

## Step 2: Mount and Configure the Provider

Enable the Scaleway provider at a path of your choice:

```bash
warden provider enable --type=scaleway
```

To mount at a custom path:

```bash
warden provider enable --type=scaleway scaleway-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write scaleway/config <<EOF
{
  "scaleway_url": "https://api.scaleway.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read scaleway/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Keys

Create a Scaleway credential source and spec with your API key pair. The spec is validated at creation time by calling `GET /iam/v1alpha1/api-keys/{access_key}` to verify the key exists.

```bash
warden cred source create scaleway-src \
  --type=scaleway \
  --config=scaleway_url=https://api.scaleway.com

warden cred spec create scaleway-ops \
  --source scaleway-src \
  --config mint_method=static_keys \
  --config access_key=SCWXXXXXXXXXXXXXXXXX \
  --config secret_key=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Option B: Dynamic API Keys (Recommended)

Have Warden create short-lived API keys on demand via the Scaleway IAM API. Keys are automatically revoked when they expire. No long-lived secrets are stored in credential specs.

> **Note:** The Scaleway IAM API is currently `v1alpha1`. While it has been stable in practice (used by the CLI, Terraform, and all SDKs), Scaleway may introduce breaking changes without a deprecation period. If the API version changes, update the `iam_api_path` config on the credential source (e.g., `--config=iam_api_path=/iam/v2`). No code changes required.

**Prerequisites:**
- A **management API key** with IAM permissions to create and delete API keys
- A **Scaleway IAM application** that the dynamic keys will be attached to

```bash
warden cred source create scaleway-dynamic-src \
  --type=scaleway \
  --rotation-period=24h \
  --config=scaleway_url=https://api.scaleway.com \
  --config=management_secret_key=your-management-secret-key \
  --config=management_access_key=SCWXXXXXXXXXXXXXXXXX

warden cred spec create scaleway-ops \
  --source scaleway-dynamic-src \
  --config mint_method=dynamic_keys \
  --config application_id=your-iam-application-id \
  --config default_project_id=your-project-id \
  --config ttl=1h \
  --config description=warden-managed
```

Each credential request creates a fresh API key via `POST /iam/v1alpha1/api-keys` with the configured TTL. When the lease expires, Warden revokes the key via `DELETE /iam/v1alpha1/api-keys/{access_key}`.

### Option C: Vault/OpenBao as Credential Source

Store your Scaleway keys in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Scaleway keys (e.g., at `secret/scaleway/prod` with `access_key` and `secret_key` fields)
- An AppRole configured for Warden access

```bash
warden cred source create scaleway-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h

warden cred spec create scaleway-ops \
  --source scaleway-vault-src \
  --type=scaleway_keys \
  --config mint_method=static_scaleway \
  --config kv2_mount=secret \
  --config secret_path=scaleway/prod
```

The KV v2 secret at `secret/scaleway/prod` should contain `access_key` and `secret_key` fields.

Verify:

```bash
warden cred spec read scaleway-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Scaleway provider gateway:

```bash
warden policy write scaleway-access - <<EOF
path "scaleway/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Scaleway APIs and regions a role can use:

```bash
warden policy write scaleway-readonly - <<EOF
# Allow read-only access to instances in fr-par
path "scaleway/role/+/gateway/instance/v1/zones/fr-par-*" {
  capabilities = ["read"]
}

# Allow read-only access to Kubernetes clusters
path "scaleway/role/+/gateway/k8s/v1/regions/*" {
  capabilities = ["read"]
}

# Allow read-only access to IAM
path "scaleway/role/+/gateway/iam/*" {
  capabilities = ["read"]
}

# Allow read-only access to databases
path "scaleway/role/+/gateway/rdb/v1/regions/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read scaleway-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Scaleway credentials automatically.

The URL pattern is: `/v1/scaleway/role/{role}/gateway/{api-path}`

Export SCW_ENDPOINT as environment variable:
```bash
export SCW_ENDPOINT="${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"
```

### List Instances

```bash
curl -s "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Kubernetes Clusters

```bash
curl -s "${SCW_ENDPOINT}/k8s/v1/regions/fr-par/clusters" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Database Instances

```bash
curl -s "${SCW_ENDPOINT}/rdb/v1/regions/fr-par/instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List API Keys (IAM)

```bash
curl -s "${SCW_ENDPOINT}/iam/v1alpha1/api-keys" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Load Balancers

```bash
curl -s "${SCW_ENDPOINT}/lb/v1/zones/fr-par-1/lbs" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create an Instance

```bash
curl -s -X POST "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-instance",
    "commercial_type": "DEV1-S",
    "image": "ubuntu_jammy",
    "project": "your-project-id"
  }'
```

### Delete an Instance

```bash
curl -s -X DELETE "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers/{server-id}" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## S3 Object Storage

The Scaleway provider auto-detects S3 requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### S3 Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region fr-par
```

### S3 Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "scaleway-user"
aws configure set aws_secret_access_key "scaleway-user"
aws configure set region fr-par
```

### S3 Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"
```

### Supported S3 Regions

| Region | Location | S3 Endpoint |
|--------|----------|-------------|
| `fr-par` | Paris, France | `s3.fr-par.scw.cloud` |
| `nl-ams` | Amsterdam, Netherlands | `s3.nl-ams.scw.cloud` |
| `pl-waw` | Warsaw, Poland | `s3.pl-waw.scw.cloud` |
| `it-mil` | Milan, Italy | `s3.it-mil.scw.cloud` |

The region is extracted from the SigV4 Authorization header and used to route to the correct Scaleway S3 endpoint.

## Terraform Provider Limitation

The native [Scaleway Terraform provider](https://registry.terraform.io/providers/scaleway/scaleway/latest) (`scaleway/scaleway`) validates that `secret_key` is a UUID, which is incompatible with Warden's JWT-based transparent authentication. It cannot be used to manage Scaleway resources through the Warden gateway.

**Workarounds for Terraform users:**

- **Standard API** — Use the [`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi) provider with the JWT in the `Authorization: Bearer` header. This covers all Scaleway API operations (instances, IAM, databases, etc.).
- **S3 Object Storage** — Use the [`hashicorp/aws`](https://registry.terraform.io/providers/hashicorp/aws) provider with `skip_region_validation = true` and the S3 endpoint set to the Warden gateway URL. The AWS provider performs real SigV4 signing, which Warden detects and re-signs with real Scaleway credentials.

See [`e2e_test/`](e2e_test/) for a working example of this approach.

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
    default_role=scaleway-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/scaleway-user \
    allowed_common_names="agent-*" \
    token_policies="scaleway-access" \
    cred_spec_name=scaleway-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write scaleway/config <<EOF
{
  "scaleway_url": "https://api.scaleway.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

Standard API:

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/scaleway/role/scaleway-user/gateway/instance/v1/zones/fr-par-1/servers" \
    -H "Content-Type: application/json"
```

S3 Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/scaleway/role/scaleway-user/gateway"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scaleway_url` | string | `https://api.scaleway.com` | Scaleway API base URL |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Scaleway)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scaleway_url` | string | No | Scaleway API URL (default: `https://api.scaleway.com`) |
| `management_secret_key` | string | Yes* | Secret key with IAM permissions to create/delete API keys (*required for `dynamic_keys` and rotation) |
| `management_access_key` | string | Yes* | Access key matching the management secret key (*required for rotation) |
| `activation_delay` | duration | No | Delay before activating rotated management key (default: `30s`) |
| `iam_api_path` | string | No | IAM API path prefix (default: `/iam/v1alpha1`). Update when Scaleway promotes the API to stable. |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom CAs |
| `tls_skip_verify` | bool | No | Skip TLS verification (development only) |

### Credential Spec Config (static_keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_keys` |
| `access_key` | string | Yes | Scaleway access key (starts with `SCW`) |
| `secret_key` | string | Yes | Scaleway secret key (UUID format, sensitive — masked in output) |

### Credential Spec Config (dynamic_keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_keys` |
| `application_id` | string | Yes | IAM application ID to attach keys to |
| `default_project_id` | string | No | Default project for Object Storage |
| `ttl` | duration | No | Key lifetime (default: `1h`) |
| `description` | string | No | Description for created keys (max 200 chars, default: `warden-{spec-name}`) |

### Credential Spec Config (Vault — static_scaleway)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_scaleway` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

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

## Token Management

### Static API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | Access key and secret key are stored on the credential spec |
| **Rotation** | Manual — regenerate in Scaleway Console and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |
| **Revocation** | Scaleway API keys can be deleted via `DELETE /iam/v1alpha1/api-keys/{access_key}` |

**To rotate static API keys:**

1. Generate a new API key in [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)
2. Update the credential spec:
   ```bash
   warden cred spec update scaleway-ops \
     --config access_key=SCWNEWKEYXXXXXXXXXX \
     --config secret_key=new-uuid-secret-key
   ```
3. Delete the old API key in Scaleway Console

### Dynamic API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | Management key on the source; no long-lived keys on specs |
| **Minting** | Fresh API key created via `POST /iam/v1alpha1/api-keys` on each credential request |
| **Lifetime** | Configurable via `ttl` (default: 1h); Scaleway enforces `expires_at` on the key |
| **Revocation** | Automatic — Warden calls `DELETE /iam/v1alpha1/api-keys/{access_key}` on lease expiry |
| **Rotation** | Not needed — keys are ephemeral |

**Automatic management key rotation:**

When both `management_secret_key` and `management_access_key` are configured on the source, Warden can automatically rotate the management key itself. Set a `rotation-period` on the source to enable it:

```bash
warden cred source create scaleway-dynamic-src \
  --type=scaleway \
  --rotation-period=24h \
  --config=scaleway_url=https://api.scaleway.com \
  --config=management_secret_key=your-management-secret-key \
  --config=management_access_key=SCWXXXXXXXXXXXXXXXXX
```

The rotation flow:
1. Warden creates a new management key via `POST /iam/v1alpha1/api-keys` for the same IAM application or user
2. Waits `activation_delay` (default: 30s) for propagation
3. Activates the new key in the driver
4. Deletes the old key via `DELETE /iam/v1alpha1/api-keys/{old_access_key}`

Both old and new keys remain valid during the overlap period, ensuring zero downtime.

**Manual management key rotation:**

If automatic rotation is not configured, rotate manually:

1. Generate a new management API key in [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)
2. Update the credential source:
   ```bash
   warden cred source update scaleway-dynamic-src \
     --config=management_secret_key=new-management-secret-key \
     --config=management_access_key=SCWNEWKEYXXXXXXXXXX
   ```
3. Delete the old management API key in Scaleway Console
