# IBM Cloud Provider

The IBM Cloud provider enables proxied access to IBM Cloud APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `Authorization: Bearer` with an IBM Cloud IAM token and forwards to the IBM Cloud service whose hostname is embedded in the request path. One mount handles every IBM Cloud service (Resource Controller, VPC, Kubernetes Service, Code Engine, etc.).
- **COS Object Storage** — Verifies the client's SigV4 signature, re-signs with real IBM COS HMAC credentials, and forwards to `s3.<region>.cloud-object-storage.appdomain.cloud`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## Table of Contents

- [Prerequisites](#prerequisites)
- [URL format](#url-format)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Client configuration](#client-configuration)
- [Unsupported clients](#unsupported-clients)
- [COS Object Storage](#cos-object-storage)
- [Security considerations](#security-considerations)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## URL format

All API requests follow this pattern:

```
/v1/ibmcloud/role/{role}/gateway/{ibm-host}/{service-path}
```

`{ibm-host}` is the IBM Cloud service hostname. `{service-path}` is the path that SDKs and docs use for that service (e.g., `/v2/resource_instances`).

| Service | Example |
|---------|---------|
| Resource Controller / Resource Groups | `…/gateway/resource-controller.cloud.ibm.com/v2/resource_instances` |
| IAM Identity | `…/gateway/iam.cloud.ibm.com/v1/accounts/{id}` |
| VPC (regional) | `…/gateway/us-south.iaas.cloud.ibm.com/v1/vpcs?version=2024-06-01` |
| Kubernetes Service (IKS) | `…/gateway/containers.cloud.ibm.com/global/v2/vpc/getClusters` |
| Code Engine (regional) | `…/gateway/api.eu-de.codeengine.cloud.ibm.com/v2/projects` |
| COS Object Storage | S3 SigV4 client points at `…/role/{role}/gateway` — see [COS Object Storage](#cos-object-storage) |

Only hosts matching the `allowed_host_suffixes` list (default: `.cloud.ibm.com`, `.appdomain.cloud`) are forwarded. Anything else returns HTTP 400.

## Prerequisites

- Docker and Docker Compose installed and running
- An **IBM Cloud account** with:
  - An API key (from IBM Cloud Console > Manage > Access (IAM) > API keys) for the REST API
  - COS HMAC credentials (access key ID + secret access key) for Object Storage — generate via IBM Cloud Console > Cloud Object Storage > Service credentials > New credential (include HMAC keys)

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
warden write auth/jwt/role/ibmcloud-user \
    token_policies="ibmcloud-access" \
    user_claim=sub \
    cred_spec_name=ibmcloud-ops
```

## Step 2: Mount and Configure the Provider

Enable the IBM Cloud provider at a path of your choice:

```bash
warden provider enable --type=ibmcloud
```

To mount at a custom path:

```bash
warden provider enable --type=ibmcloud ibmcloud-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. The `ibmcloud_url` field is retained for framework compatibility but is **ignored in API mode** — the target host is taken from the request path. Optional `allowed_host_suffixes` narrows or widens which IBM hostnames are proxyable.

```bash
warden write ibmcloud/config <<EOF
{
  "ibmcloud_url": "https://cloud.ibm.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

To restrict which IBM hostnames the gateway will forward to (recommended for production):

```bash
warden write ibmcloud/config <<EOF
{
  "ibmcloud_url": "https://cloud.ibm.com",
  "auto_auth_path": "auth/jwt/",
  "allowed_host_suffixes": ".resource-controller.cloud.ibm.com,.containers.cloud.ibm.com,.appdomain.cloud",
  "timeout": "30s"
}
EOF
```

Each suffix must start with `.`. Use `*` (by itself) to disable host checking.

Verify the configuration:

```bash
warden read ibmcloud/config
```

## Step 3: Create a Credential Source and Spec

### Option A: IBM Source (IAM Token + COS HMAC)

The IBM driver exchanges your API key for a short-lived IAM token and combines it with static COS HMAC keys:

**Dual-mode (API + COS):**

```bash
warden cred source create ibmcloud-src \
  --type=ibm \
  --config=api_key=your-ibm-api-key

warden cred spec create ibmcloud-ops \
  --source ibmcloud-src \
  --type=ibmcloud_keys \
  --config mint_method=iam_with_cos \
  --config access_key_id=your-cos-access-key-id \
  --config secret_access_key=your-cos-secret-access-key
```

**API-only (no COS):**

```bash
warden cred spec create ibmcloud-api-only \
  --source ibmcloud-src \
  --type=ibmcloud_keys \
  --config mint_method=iam_with_cos
```

### Option B: Vault/OpenBao — Dynamic IBM Secrets Engine

Use Vault's IBM secrets engine to generate dynamic API keys with automatic lease revocation:

```bash
warden cred source create ibmcloud-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h

warden cred spec create ibmcloud-ops \
  --source ibmcloud-vault-src \
  --type=ibmcloud_keys \
  --config mint_method=dynamic_ibm \
  --config ibm_mount=ibmcloud \
  --config role_name=my-ibm-role \
  --config access_key_id=your-cos-access-key-id \
  --config secret_access_key=your-cos-secret-access-key
```

Warden calls the Vault IBM secrets engine to get a dynamic API key, exchanges it for an IAM token, and optionally merges static COS HMAC keys from the spec config.

Verify:

```bash
warden cred spec read ibmcloud-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the IBM Cloud provider gateway:

```bash
warden policy write ibmcloud-access - <<EOF
path "ibmcloud/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control:

```bash
warden policy write ibmcloud-readonly - <<EOF
path "ibmcloud/role/+/gateway/resource-controller.cloud.ibm.com/v2/resource_instances" {
  capabilities = ["read"]
}

path "ibmcloud/role/+/gateway/containers.cloud.ibm.com/*" {
  capabilities = ["read"]
}

path "ibmcloud/role/+/gateway/us-south.iaas.cloud.ibm.com/v1/vpcs" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read ibmcloud-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths with the **IBM service hostname as the first path segment**. Warden performs implicit JWT authentication and injects the real IBM Cloud IAM token server-side — clients present a Warden JWT, not an IBM API key.

The URL pattern is: `/v1/ibmcloud/role/{role}/gateway/{ibm-host}/{service-path}`

Export the base endpoint:
```bash
export IBM_BASE="${WARDEN_ADDR}/v1/ibmcloud/role/ibmcloud-user/gateway"
```

### List Resource Instances (Resource Controller)

```bash
curl -s "${IBM_BASE}/resource-controller.cloud.ibm.com/v2/resource_instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Resource Groups

```bash
curl -s "${IBM_BASE}/resource-controller.cloud.ibm.com/v2/resource_groups" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List VPCs (regional — Dallas)

```bash
curl -s "${IBM_BASE}/us-south.iaas.cloud.ibm.com/v1/vpcs?version=2024-06-01&generation=2" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

For other regions, change the host prefix: `eu-de.iaas.cloud.ibm.com`, `jp-tok.iaas.cloud.ibm.com`, etc.

### List Kubernetes Clusters (IKS)

```bash
curl -s "${IBM_BASE}/containers.cloud.ibm.com/global/v2/vpc/getClusters" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

Note the `/global/` prefix — it's part of the IKS API path, not the Warden mount.

### List Code Engine Projects (regional — Frankfurt)

```bash
curl -s "${IBM_BASE}/api.eu-de.codeengine.cloud.ibm.com/v2/projects" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## Client configuration

**Critical rule:** clients must **not** be configured with an IBM Cloud API key. Clients hold a Warden-issued JWT (or a TLS client cert). Warden strips the client auth and injects the real IAM token server-side. Passing an API key to an SDK causes it to call `iam.cloud.ibm.com/identity/token` directly, bypassing Warden entirely.

Configure the SDK's base URL to `{warden}/v1/ibmcloud/role/{role}/gateway/{ibm-host}` and use the SDK's bearer-token authenticator with your Warden JWT.

### IBM Cloud Go SDK

```go
import (
    "github.com/IBM/go-sdk-core/v5/core"
    "github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
)

svc, err := resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
    URL: "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/resource-controller.cloud.ibm.com",
    Authenticator: &core.BearerTokenAuthenticator{BearerToken: jwt},
})
```

### IBM Cloud Python SDK

```python
from ibm_platform_services import ResourceControllerV2
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator

svc = ResourceControllerV2(authenticator=BearerTokenAuthenticator(jwt))
svc.set_service_url(
    "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/resource-controller.cloud.ibm.com"
)
```

### IBM Cloud Node.js SDK

```javascript
const { ResourceControllerV2 } = require('@ibm-cloud/platform-services');
const { BearerTokenAuthenticator } = require('ibm-cloud-sdk-core');

const svc = new ResourceControllerV2({
  authenticator: new BearerTokenAuthenticator({ bearerToken: jwt }),
  serviceUrl: 'https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/resource-controller.cloud.ibm.com',
});
```

### Terraform IBM provider

Configure one `endpoints` entry per service you use. Leave `ibmcloud_api_key` empty and export `IC_IAM_TOKEN` (the Warden JWT) to the environment.

```hcl
provider "ibm" {
  ibmcloud_api_key = ""   # empty — Warden injects the IAM token

  endpoints {
    resource_controller_endpoint = "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/resource-controller.cloud.ibm.com"
    iam_endpoint                 = "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/iam.cloud.ibm.com"
    is_endpoint                  = "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/us-south.iaas.cloud.ibm.com"
    container_endpoint           = "https://warden.example.com/v1/ibmcloud/role/ibmcloud-user/gateway/containers.cloud.ibm.com"
  }
}
```

```bash
export IC_IAM_TOKEN="${JWT_TOKEN}"
terraform plan
```

### Raw HTTP / curl

Already covered in [Step 5](#step-5-get-a-jwt-and-make-requests). Any tool that can set a bearer header on an arbitrary URL works.

### COS clients

Use any S3-compatible client (AWS CLI, boto3, s3cmd, MinIO, rclone) with the Warden gateway URL as the endpoint. See [COS Object Storage](#cos-object-storage).

## Unsupported clients

Some IBM tooling cannot be pointed through Warden:

- **`ibmcloud` CLI** — hardcodes service endpoints and calls `iam.cloud.ibm.com/identity/token` itself from a stored API key. Use the SDKs above or raw HTTP for anything you'd otherwise run through the CLI.
- **`kubectl` for IKS** — `kubectl` talks directly to a cluster-specific master URL from kubeconfig, not to the IKS control-plane API. IKS control-plane calls (list/create/delete clusters, workers, etc.) can go through Warden via the REST API at `containers.cloud.ibm.com`, but in-cluster traffic cannot.
- **Anything that hardcodes `*.cloud.ibm.com`** and doesn't expose a per-service endpoint override.

For these, either use an alternate client or accept that they bypass Warden's credential brokering.

## COS Object Storage

The IBM Cloud provider auto-detects COS requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### COS Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region us-south
```

### COS Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "ibmcloud-user"
aws configure set aws_secret_access_key "ibmcloud-user"
aws configure set region us-south
```

### COS Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/ibmcloud/role/ibmcloud-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/ibmcloud/role/ibmcloud-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ibmcloud/role/ibmcloud-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ibmcloud/role/ibmcloud-user/gateway"
```

### COS Regions

| Region | COS Endpoint |
|--------|-------------|
| us-south | `s3.us-south.cloud-object-storage.appdomain.cloud` |
| us-east | `s3.us-east.cloud-object-storage.appdomain.cloud` |
| eu-gb | `s3.eu-gb.cloud-object-storage.appdomain.cloud` |
| eu-de | `s3.eu-de.cloud-object-storage.appdomain.cloud` |
| au-syd | `s3.au-syd.cloud-object-storage.appdomain.cloud` |
| jp-tok | `s3.jp-tok.cloud-object-storage.appdomain.cloud` |

The region used for SigV4 signing must match the bucket's location. Configure the AWS CLI region to match.

### COS Endpoint Types

IBM COS exposes three endpoint variants per region. Select one via the `cos_endpoint_type` provider config field:

| Type | Pattern | Use case |
|------|---------|----------|
| `public` (default) | `s3.{region}.cloud-object-storage.appdomain.cloud` | General internet access |
| `private` | `s3.private.{region}.cloud-object-storage.appdomain.cloud` | VPC workloads (no egress cost) |
| `direct` | `s3.direct.{region}.cloud-object-storage.appdomain.cloud` | Classic Infrastructure (SoftLayer) |

## Security considerations

The provider injects a real IBM Cloud IAM token into every outbound request. Without a hostname allowlist, a compromised Warden client could use the gateway as an open proxy — sending arbitrary HTTP requests to any host with a valid IAM token attached. `allowed_host_suffixes` prevents this.

- **Default allowlist**: `.cloud.ibm.com` and `.appdomain.cloud` — covers every IBM Cloud service hostname plus COS.
- **Tighten for production**: list only the specific suffixes your workload needs, e.g., `.resource-controller.cloud.ibm.com,.containers.cloud.ibm.com`.
- **Suffix entries must start with a dot**. `cloud.ibm.com` (no leading dot) is rejected at config parse time so that `evilcloud.ibm.com` cannot accidentally match `cloud.ibm.com`.
- **IP literals are rejected** at the forwarding layer to block tricks like targeting `169.254.169.254` (cloud metadata endpoints).
- **Ports and userinfo in the host** (`host:port`, `user@host`) are rejected.
- **HTTPS-only** — the hook always constructs `https://` URLs; clients cannot downgrade by tweaking the path.
- **Wildcard** (`allowed_host_suffixes: "*"`) disables host checking. Do not use in production.

Combine this with fine-grained Warden policies (see [Step 4](#step-4-create-a-policy)) to restrict which roles can reach which service paths.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## TLS Certificate Authentication

Steps 1-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=ibmcloud-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/ibmcloud-user \
    allowed_common_names="agent-*" \
    token_policies="ibmcloud-access" \
    cred_spec_name=ibmcloud-ops
```

### Configure Provider for Cert Auth

```bash
warden write ibmcloud/config <<EOF
{
  "ibmcloud_url": "https://cloud.ibm.com",
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
    -s "https://warden.internal/v1/ibmcloud/role/ibmcloud-user/gateway/resource-controller.cloud.ibm.com/v2/resource_instances" \
    -H "Content-Type: application/json"
```

COS Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/ibmcloud/role/ibmcloud-user/gateway"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ibmcloud_url` | string | `https://cloud.ibm.com` | Retained for framework compatibility; **ignored in API mode** (the target host is encoded in the request path). |
| `allowed_host_suffixes` | list(string) | `.cloud.ibm.com,.appdomain.cloud` | Hostname suffixes permitted as API gateway targets. Each entry must start with `.`. Use `*` alone to disable (not recommended). |
| `cos_endpoint_type` | string | `public` | IBM COS endpoint type: `public`, `private` (VPC-only), or `direct` (Classic Infrastructure) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Spec Config (iam_with_cos — IBM Source)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `iam_with_cos` |
| `access_key_id` | string | COS mode | IBM COS HMAC access key ID (required with `secret_access_key`) |
| `secret_access_key` | string | COS mode | IBM COS HMAC secret access key (sensitive — required with `access_key_id`) |

### Credential Spec Config (dynamic_ibm — Vault IBM Secrets Engine)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_ibm` |
| `ibm_mount` | string | Yes | Vault IBM secrets engine mount path |
| `role_name` | string | Yes | Vault IBM secrets engine role name |
| `iam_endpoint` | string | No | IBM Cloud IAM endpoint (default: `https://iam.cloud.ibm.com`) |
| `ttl` | duration | No | Requested lease TTL for the dynamic API key |
| `access_key_id` | string | COS mode | IBM COS HMAC access key ID (static, from spec config) |
| `secret_access_key` | string | COS mode | IBM COS HMAC secret access key (static, from spec config) |

### Credential Source Config (IBM)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | IBM Cloud API key |
| `account_id` | string | No | IBM Cloud account ID (discovered from API key if omitted) |
| `iam_endpoint` | string | No | IBM Cloud IAM endpoint (default: `https://iam.cloud.ibm.com`) |
| `activation_delay` | duration | No | Wait period for API key propagation during rotation (default: `2m`) |

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

### IBM Source (iam_with_cos)

| Aspect | Details |
|--------|---------|
| **IAM Token** | Dynamically minted from the source API key with ~1h TTL. Cached with 30s refresh buffer. |
| **COS HMAC Keys** | Static — stored on the credential spec. Rotate manually via IBM Cloud Console. |
| **Source API Key Rotation** | Automatic — the IBM driver supports source API key rotation via the IAM Identity Services API. |

### Vault Dynamic IBM (dynamic_ibm)

| Aspect | Details |
|--------|---------|
| **API Key** | Dynamically generated by Vault IBM secrets engine with automatic lease revocation. |
| **IAM Token** | Exchanged from the dynamic API key. TTL = min(vault_lease, iam_token_expiry). |
| **COS HMAC Keys** | Static — stored on the credential spec. |
