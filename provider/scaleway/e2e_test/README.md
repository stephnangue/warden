# Scaleway Provider E2E Tests

End-to-end Terraform tests for the Warden Scaleway gateway. These tests validate that Warden correctly proxies requests to Scaleway APIs with automatic credential injection (X-Auth-Token for standard API, SigV4 re-signing for S3 Object Storage).

## Cost

All tests use **free or near-free** resources only:
- Security groups, IAM applications, IAM policies, IAM API keys — **free**
- Object Storage buckets with tiny objects — **free** (billed per GB stored, destroyed on cleanup)
- Direct HTTP data sources — **free** (read-only API calls)
- **No** compute instances, databases, load balancers, or reserved IPs

## Test Suite

| File | Tests | Provider | What's Tested | Cost |
|------|-------|----------|---------------|------|
| `test-01-instances.tf` | 1-3 | restapi + http | Security group CRUD, image listing | Free |
| `test-02-object-storage.tf` | 4-8 | aws (S3) | Buckets, versioning, lifecycle, objects, CORS | ~Free |
| `test-03-iam.tf` | 9-13 | restapi + http | IAM application, policy, API key CRUD | Free |
| `test-04-direct-api.tf` | 14-17 | http | Direct HTTP calls to various Scaleway APIs | Free |
| `test-05-edge-cases.tf` | 18-25 | http + aws (S3) | Auth failures, 404s, special chars, S3 edge cases | ~Free |

### Provider Strategy

The native Scaleway Terraform provider validates that `secret_key` is a UUID, which conflicts with JWT-based transparent auth. Instead, this test suite uses:

- **`restapi` + `http`** — for standard Scaleway API operations (X-Auth-Token path). The JWT is passed via `Authorization: Bearer` header.
- **`hashicorp/aws`** — for S3 Object Storage operations (SigV4 path). The AWS provider performs real SigV4 signing using the JWT as both `access_key` and `secret_key`. Warden detects the `AWS4-HMAC-SHA256` header, verifies the signature, re-signs with real Scaleway credentials, and forwards to `s3.{region}.scw.cloud`.

## Prerequisites

1. **Warden server running** with the Scaleway provider mounted
2. **Scaleway account** with two IAM applications configured (see below)
3. **JWT auth configured** with a role bound to a Scaleway credential spec
4. **Terraform >= 1.10** installed

### Scaleway IAM Setup

Create two IAM applications in [Scaleway Console > IAM > Applications](https://console.scaleway.com/iam/applications):

**Application 1: `warden-management`** — manages API key lifecycle

Create a policy with:

| Scope | Permission Set |
|-------|---------------|
| Organization | `IAMManager` |

Create an API key for this application. The `access_key` and `secret_key` go into the credential source config (`management_access_key` and `management_secret_key`).

**Application 2: `warden-workload`** — grants access to Scaleway resources

Dynamic API keys are minted for this application by the credential spec. Create a policy with:

| Scope | Permission Set | Used By |
|-------|---------------|---------|
| Project | `InstancesFullAccess` | Tests 1-3, 14, 18-21 |
| Project | `ObjectStorageFullAccess` | Tests 4-8, 24-25 |
| Project | `KubernetesReadOnly` | Test 22 |
| Project | `ContainerRegistryReadOnly` | Test 17 |
| Project | `DomainsDNSReadOnly` | Test 23 |
| Organization | `IAMManager` | Tests 9-12 |
| Organization | `ProjectReadOnly` | Test 16 |

Note the application ID of `warden-workload` — it goes into the credential spec config as `application_id`.

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
warden write auth/jwt/role/scaleway-user \
    token_policies="scaleway-access" \
    user_claim=sub \
    cred_spec_name=scaleway-ops

# Enable Scaleway provider
warden provider enable --type=scaleway

# Configure provider
warden write scaleway/config <<EOF
{
  "scaleway_url": "https://api.scaleway.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

# Create credential source with management app keys (Application 1)
warden cred source create scaleway-src \
  --type=scaleway \
  --rotation-period=24h \
  --config=management_secret_key=<warden-management-secret-key> \
  --config=management_access_key=<warden-management-access-key>

# Create credential spec pointing to workload app (Application 2)
warden cred spec create scaleway-ops \
  --source scaleway-src \
  --config mint_method=dynamic_keys \
  --config application_id=<warden-workload-application-id> \
  --config default_project_id=<your-project-id> \
  --config ttl=1h

# Create policy
warden policy write scaleway-access - <<EOF
path "scaleway/role/+/gateway*" {
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
cd provider/scaleway/e2e_test

export TF_VAR_access_token="${JWT_TOKEN}"
export TF_VAR_scaleway_project_id="your-project-id"
export TF_VAR_scaleway_organization_id="your-organization-id"

terraform init
terraform apply -auto-approve
```

### 6. Cleanup

```bash
# Destroy Scaleway resources
terraform destroy -auto-approve

# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop Hydra
docker compose -f deploy/docker-compose.quickstart.yml down -v
```

## What's Verified

### Standard API (X-Auth-Token injection) — via restapi + http
- Tests 1-3: Instance operations (image listing, security group CRUD)
- Tests 9-13: IAM operations (application, policy, API key CRUD)
- Tests 14-17: Direct HTTP calls to Instance, IAM, Account, and Registry APIs

### S3 Object Storage (SigV4 re-signing) — via hashicorp/aws
- Tests 4-6: Bucket operations (create, versioning, lifecycle)
- Test 7: Object upload (PUT with SigV4 signing)
- Test 8: Bucket with CORS configuration
- Test 24: Bucket with dots and hyphens in name
- Test 25: Object with deep nested key path

The AWS provider performs real SigV4 signing. Warden auto-detects this via the `Authorization: AWS4-HMAC-SHA256` header, verifies the client signature, re-signs with real Scaleway credentials, and forwards to `s3.{region}.scw.cloud`.

### Edge Cases
- Test 18: Unauthenticated request (expect 401/403)
- Test 19: Invalid JWT token (expect 401/403)
- Test 20: Non-existent resource (expect 404 forwarded)
- Test 21: Query parameters with URL-encoded characters
- Test 22: Deep nested API path (K8s clusters)
- Test 23: Different API product (DNS zones)

## Customization

Override defaults via variables:

```bash
# Use a different Warden endpoint
export TF_VAR_warden_address="http://localhost:8400/v1/scaleway/role/my-role/gateway"

# Use a different region/zone
export TF_VAR_scaleway_region="nl-ams"
export TF_VAR_scaleway_zone="nl-ams-1"
```
