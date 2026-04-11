# OVH Provider E2E Tests

End-to-end Terraform tests for the Warden OVH gateway. These tests validate that Warden correctly proxies requests to OVHcloud APIs with automatic credential injection (Bearer token for REST API, SigV4 re-signing for S3 Object Storage).

## Cost

All tests use **free or near-free** resources only:
- Cloud Project read operations (info, regions, instances, volumes) — **free**
- Object Storage buckets with tiny objects — **free** (billed per GB stored, destroyed on cleanup)
- Direct HTTP data sources — **free** (read-only API calls)
- **No** compute instances, databases, load balancers, or reserved IPs

## Test Suite

| File | Tests | Provider | What's Tested | Cost |
|------|-------|----------|---------------|------|
| `test-01-cloud-project.tf` | 1-4 | ovh + http | Cloud Project read, regions, account info, users | Free |
| `test-02-object-storage.tf` | 5-9 | aws (S3) | Buckets, versioning, objects, CORS | ~Free |
| `test-03-direct-api.tf` | 10-13 | http | Direct HTTP calls to various OVH APIs | Free |
| `test-04-edge-cases.tf` | 14-20 | http + aws (S3) | Auth failures, 404s, special chars, S3 edge cases | ~Free |

### Provider Strategy

- **`ovh`** — for standard OVH API operations (Bearer token path). The OVH Terraform provider's `access_token` mode sends a standard `Authorization: Bearer` header. Warden intercepts it, authenticates the JWT, and replaces it with the real OVH API token.
- **`http`** — for read-only API calls and edge case tests where raw HTTP control is needed.
- **`hashicorp/aws`** — for S3 Object Storage operations (SigV4 path). The AWS provider performs real SigV4 signing using the JWT as both `access_key` and `secret_key`. Warden detects the `AWS4-HMAC-SHA256` header, verifies the signature, re-signs with real OVH S3 credentials, and forwards to `s3.{region}.io.cloud.ovh.net`.

## Prerequisites

1. **Warden server running** with the OVH provider mounted
2. **OVHcloud account** with a Public Cloud project
3. **OVH credentials** — API token + S3 access key/secret key (stored as `ovh_keys` credential type)
4. **JWT auth configured** with a role bound to an OVH credential spec
5. **Terraform >= 1.10** installed

### OVH API Permissions

The API token (`api_token`) must have the following OVHcloud API permissions (`{serviceName}` is your Public Cloud project ID, i.e. the `ovh_service_name` variable):

| API Route | Method | Used By | Purpose |
|-----------|--------|---------|---------|
| `GET /me` | GET | Tests 3, 14, 15 | Account info, auth edge cases |
| `GET /cloud/project/{serviceName}` | GET | Test 1 | Cloud Project details |
| `GET /cloud/project/{serviceName}/region` | GET | Test 2 | Region listing |
| `GET /cloud/project/{serviceName}/user` | GET | Test 4 | Cloud Project users |
| `GET /cloud/project/{serviceName}/instance` | GET | Tests 10, 17 | Instance listing |
| `GET /cloud/project/{serviceName}/volume` | GET | Test 11 | Volume listing |
| `GET /cloud/project/{serviceName}/network/private` | GET | Test 12 | Network listing |
| `GET /cloud/project/{serviceName}/storage` | GET | Test 18 | Storage containers |
| `GET /domain` | GET | Test 13 | Domain listing |

The S3 credentials (`access_key` + `secret_key`) must have **Object Storage read/write** permission on the target project for tests 5-9, 19-20.

When creating the OAuth2 service account in [OVHcloud IAM](https://www.ovh.com/auth/), grant it:
- **Public Cloud** — `publicCloudProject:apiovh:GET` on your project (covers tests 1-4, 10-12, 17-18)
- **Account** — `account:apiovh:GET` (covers test 3)
- **Domain** — `domain:apiovh:GET` (covers test 13)

All permissions are **read-only**. No write operations are performed on the OVH REST API — only Object Storage (S3) tests create/destroy resources.

### OVH Credential Setup

The OVH provider uses `ovh_keys` credentials with three fields:

| Field | Purpose | How to Obtain |
|-------|---------|---------------|
| `api_token` | Bearer token for REST API | See [Creating an OAuth2 token](#creating-an-oauth2-api-token) below |
| `access_key` | S3 access key for Object Storage | See [Creating S3 credentials](#creating-s3-credentials) below |
| `secret_key` | S3 secret key for Object Storage | Generated alongside access_key |

#### Creating an OAuth2 API Token

You need legacy API keys first, then use them to create an OAuth2 service account.

**Step 1: Create API keys**

Go to the createToken page for your region and log in with your OVHcloud account:
- EU: https://eu.api.ovh.com/createToken/
- CA: https://ca.api.ovh.com/createToken/
- US: https://api.us.ovhcloud.com/createToken/

Set the permissions to `GET`, `POST`, `PUT`, `DELETE` on `/*` (all APIs), or restrict to `/me/api/oauth2/client` if you only need service account management. You receive an **Application Key**, **Application Secret**, and **Consumer Key**.

**Step 2: Create a service account**

Use the API keys from step 1 to create an OAuth2 service account via the [OVHcloud API console](https://eu.api.ovh.com/console/#/me/api/oauth2/client~POST) (`POST /me/api/oauth2/client`):

```json
{
  "flow": "CLIENT_CREDENTIALS",
  "callbackUrls": [],
  "name": "warden-e2e-test",
  "description": "Warden e2e test service account"
}
```

The response contains `clientId` and `clientSecret`. **Save both immediately** — the secret cannot be retrieved later.

**Step 3: Assign an access policy**

In the [OVHcloud Control Panel](https://www.ovh.com/manager/) > **My account** > **Access policies**, create a policy granting the read-only permissions listed in [OVH API Permissions](#ovh-api-permissions) and attach it to the service account's URN.

**Step 4: Generate a bearer token**

```bash
export OVH_API_TOKEN=$(curl -s -X POST https://www.ovh.com/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<your-client-id>&client_secret=<your-client-secret>" \
  | jq -r '.access_token')
```

The token is valid for **1 hour**. For regional endpoints, use the matching token URL:
- EU: `https://www.ovh.com/auth/oauth2/token`
- CA: `https://ca.ovh.com/auth/oauth2/token`
- US: `https://us.ovhcloud.com/auth/oauth2/token`

#### Creating S3 Credentials

**Option A: Via OpenStack CLI**

```bash
# Install the OpenStack CLI if needed
pip install python-openstackclient

# Source your OpenStack RC file (download from OVH Control Panel > Public Cloud > Users & Roles)
source openrc.sh

# Create S3 credentials
openstack ec2 credentials create
```

The output contains `access` (access_key) and `secret` (secret_key).

**Option B: Via OVH Control Panel**

1. Go to [OVH Control Panel](https://www.ovh.com/manager/) > **Public Cloud** > your project > **Object Storage** > **S3 Users**
2. Click **Create a user** (or use an existing OpenStack user)
3. Click **View credentials** or **Generate S3 credentials**
4. Note the `Access Key` and `Secret Key`

## Setup

### 1. Start the identity provider (Hydra)

From the repo root:

```bash
docker compose -f deploy/docker-compose.quickstart.yml up -d
```

### 2. Start Warden (dev mode)

```bash
warden server --dev --dev-root-token=root
```

### 3. Configure Warden

```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="root"

# Enable JWT auth
warden auth enable --type=jwt
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create role
warden write auth/jwt/role/ovh-user \
    token_policies="ovh-access" \
    user_claim=sub \
    cred_spec_name=ovh-ops

# Enable OVH provider
warden provider enable --type=ovh

# Configure provider
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

# Create credential source
warden cred source create ovh-src \
  --type=local

# Create credential spec with OVH keys
warden cred spec create ovh-ops \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=static_keys \
  --config access_key=<your-s3-access-key> \
  --config secret_key=<your-s3-secret-key> \
  --config api_token=<your-api-bearer-token>

# Create policy
warden policy write ovh-access - <<EOF
path "ovh/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

### 4. Get a JWT token

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

### 5. Run tests

```bash
cd provider/ovh/e2e_test

export TF_VAR_access_token="${JWT_TOKEN}"
export TF_VAR_ovh_service_name="your-cloud-project-id"

terraform init
terraform apply -auto-approve
```

### 6. Cleanup

```bash
# Destroy OVH resources
terraform destroy -auto-approve

# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop Hydra
docker compose -f deploy/docker-compose.quickstart.yml down -v
```

## What's Verified

### Standard API (Bearer token injection) — via ovh + http
- Tests 1-2: Cloud Project operations (project details, region listing) via native OVH provider
- Tests 3-4: Account info and Cloud Project users via direct HTTP
- Tests 10-13: Direct HTTP calls to Instance, Volume, Network, and Domain APIs

### S3 Object Storage (SigV4 re-signing) — via hashicorp/aws
- Tests 5-6: Bucket operations (create, versioning)
- Tests 7-8: Object upload (PUT with SigV4 signing, JSON + text)
- Test 9: Bucket with CORS configuration
- Test 19: Bucket with dots and hyphens in name
- Test 20: Object with deep nested key path

The AWS provider performs real SigV4 signing. Warden auto-detects this via the `Authorization: AWS4-HMAC-SHA256` header, verifies the client signature, re-signs with real OVH S3 credentials, and forwards to `s3.{region}.io.cloud.ovh.net`.

### Edge Cases
- Test 14: Unauthenticated request (expect 401/403)
- Test 15: Invalid JWT token (expect 401/403)
- Test 16: Non-existent resource (expect 404 forwarded)
- Test 17: Query parameters with region filter
- Test 18: Deep nested API path (Cloud Project storage)

## Customization

Override defaults via variables:

```bash
# Use a different Warden endpoint
export TF_VAR_warden_address="http://localhost:8400/v1/ovh/role/my-role/gateway"

# Use a different S3 region
export TF_VAR_ovh_region="bhs"
```

## Supported S3 Regions

| Region | Location | S3 Endpoint |
|--------|----------|-------------|
| `gra` | Gravelines, France | `s3.gra.io.cloud.ovh.net` |
| `bhs` | Beauharnois, Canada | `s3.bhs.io.cloud.ovh.net` |
| `sbg` | Strasbourg, France | `s3.sbg.io.cloud.ovh.net` |
| `de` | Frankfurt, Germany | `s3.de.io.cloud.ovh.net` |
| `uk` | London, United Kingdom | `s3.uk.io.cloud.ovh.net` |
| `waw` | Warsaw, Poland | `s3.waw.io.cloud.ovh.net` |
