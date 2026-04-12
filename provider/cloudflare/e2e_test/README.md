# Cloudflare Provider E2E Tests

End-to-end Terraform tests for the Warden Cloudflare gateway. These tests validate that Warden correctly proxies requests to Cloudflare APIs with automatic credential injection (Bearer token for REST API, SigV4 re-signing for R2 Object Storage).

## Cost

All tests use **free or near-free** resources only:
- Cloudflare REST API read operations (zones, accounts, user, DNS records) — **free**
- R2 Object Storage buckets with tiny objects — **free** (first 10 GB stored free, destroyed on cleanup)
- Direct HTTP data sources — **free** (read-only API calls)
- **No** Workers, Pages, load balancers, or paid add-ons

## Test Suite

| File | Tests | Provider | What's Tested | Cost |
|------|-------|----------|---------------|------|
| `test-01-api.tf` | 1-6 | http | Zones, token verify, user, accounts, query params, DNS records | Free |
| `test-02-r2-object-storage.tf` | 7-11 | aws (S3) | Buckets, objects (JSON + text), CORS, lifecycle | ~Free |
| `test-03-edge-cases.tf` | 12-18 | http + aws (S3) | Auth failures, 404s, query encoding, R2 edge cases | ~Free |

### Provider Strategy

- **`http`** — for REST API operations (Bearer token injection). Cloudflare's Terraform provider does not support custom endpoints, so we use raw HTTP data sources. Warden intercepts the `Authorization: Bearer` header, authenticates the JWT, and replaces it with the real Cloudflare API token.
- **`hashicorp/aws`** — for R2 Object Storage operations (SigV4 path). The AWS provider performs real SigV4 signing using the JWT as both `access_key` and `secret_key`. Warden detects the `AWS4-HMAC-SHA256` header, verifies the signature, re-signs with real Cloudflare R2 credentials, and forwards to `<account_id>.r2.cloudflarestorage.com`.

## Prerequisites

1. **Warden server running** with the Cloudflare provider mounted
2. **Cloudflare account** with:
   - An API token with Zone Read permissions (from My Profile > API Tokens)
   - R2 API credentials (access key ID + secret access key) from R2 > Manage R2 API Tokens
3. **Cloudflare credentials** stored as `cloudflare_keys` credential type in Warden
4. **JWT auth configured** with a role bound to the Cloudflare credential spec
5. **Terraform >= 1.10** installed

### Cloudflare API Token Permissions

The API token (`api_token`) needs the following permissions for the test suite:

| Permission | Level | Used By | Purpose |
|------------|-------|---------|---------|
| Zone Read | All zones | Tests 1, 5, 6, 14 | List zones, DNS records |
| User Details Read | User | Tests 2, 3 | Token verify, user details |
| Account Read | All accounts | Test 4 | List accounts |
| API Tokens Read | User | Test 16 | List tokens |

The R2 credentials (`access_key_id` + `secret_access_key`) must have **Object Read & Write** permission for tests 7-11, 17-18.

All REST API permissions are **read-only**. No write operations are performed on the Cloudflare REST API — only R2 (S3) tests create/destroy resources.

### Cloudflare Credential Setup

The Cloudflare provider uses `cloudflare_keys` credentials. You can configure all three fields for dual-mode, or just the fields for the mode you need:

| Field | Purpose | How to Obtain |
|-------|---------|---------------|
| `api_token` | Bearer token for REST API | Cloudflare Dashboard > My Profile > API Tokens > Create Token |
| `access_key_id` | R2 access key for Object Storage | Cloudflare Dashboard > R2 > Manage R2 API Tokens |
| `secret_access_key` | R2 secret key for Object Storage | Generated alongside access_key_id |

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
warden write auth/jwt/role/cloudflare-user \
    token_policies="cloudflare-access" \
    user_claim=sub \
    cred_spec_name=cloudflare-ops

# Enable Cloudflare provider
warden provider enable --type=cloudflare

# Configure provider (account_id required for R2)
warden write cloudflare/config <<EOF
{
  "cloudflare_url": "https://api.cloudflare.com/client/v4",
  "account_id": "<your-cloudflare-account-id>",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

# Create credential source
warden cred source create cloudflare-src \
  --type=local

# Create credential spec with Cloudflare keys (dual-mode)
warden cred spec create cloudflare-ops \
  --source cloudflare-src \
  --type=cloudflare_keys \
  --config mint_method=static_keys \
  --config access_key_id=<your-r2-access-key-id> \
  --config secret_access_key=<your-r2-secret-access-key> \
  --config api_token=<your-cloudflare-api-token>

# Create policy
warden policy write cloudflare-access - <<EOF
path "cloudflare/role/+/gateway*" {
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
cd provider/cloudflare/e2e_test

export TF_VAR_access_token="${JWT_TOKEN}"

terraform init
terraform apply -auto-approve
```

### 6. Cleanup

```bash
# Destroy R2 resources
terraform destroy -auto-approve

# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop Hydra
docker compose -f deploy/docker-compose.quickstart.yml down -v
```

## What's Verified

### Standard API (Bearer token injection) — via http
- Tests 1, 5: Zone listing (basic and with query parameters)
- Test 2: API token verification
- Test 3: User details
- Test 4: Account listing
- Test 6: DNS records for a zone (nested path)
- Test 16: User tokens (deep API path)

### R2 Object Storage (SigV4 re-signing) — via hashicorp/aws
- Test 7: Bucket creation (CreateBucket via SigV4)
- Tests 8-9: Object upload (PutObject with SigV4 signing, JSON + text)
- Test 10: Bucket with CORS configuration
- Test 11: Bucket with lifecycle rules
- Test 17: Bucket with dots and hyphens in name
- Test 18: Object with deep nested key path

The AWS provider performs real SigV4 signing with region `auto`. Warden auto-detects this via the `Authorization: AWS4-HMAC-SHA256` header, verifies the client signature, re-signs with real Cloudflare R2 credentials, and forwards to `<account_id>.r2.cloudflarestorage.com`.

### Edge Cases
- Test 12: Unauthenticated request (expect 401/403)
- Test 13: Invalid JWT token (expect 401/403)
- Test 14: Non-existent resource (expect 404/403 forwarded)
- Test 15: Query parameters with pagination and ordering

## R2 Jurisdictions

R2 supports jurisdiction-restricted buckets. To test a specific jurisdiction, update the provider config:

```bash
warden write cloudflare/config <<EOF
{
  "cloudflare_url": "https://api.cloudflare.com/client/v4",
  "account_id": "<your-cloudflare-account-id>",
  "r2_jurisdiction": "eu",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

| Jurisdiction | R2 Endpoint |
|-------------|-------------|
| Default | `<account_id>.r2.cloudflarestorage.com` |
| EU | `<account_id>.eu.r2.cloudflarestorage.com` |
| FedRAMP | `<account_id>.fedramp.r2.cloudflarestorage.com` |

## Customization

Override defaults via variables:

```bash
# Use a different Warden endpoint
export TF_VAR_warden_address="http://localhost:8400/v1/cloudflare/role/my-role/gateway"
```
