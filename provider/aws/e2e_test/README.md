# Warden AWS Provider End-to-End Tests

This directory contains Terraform-based end-to-end tests for the Warden AWS provider. These tests validate that AWS API requests are correctly proxied through Warden with proper signature handling.

## Test Suites

| Directory | Service | Protocol | Tests |
|-----------|---------|----------|-------|
| `tests_aws_s3/` | S3 | REST (dedicated processor) | Buckets, objects, access points, replication |
| `tests_aws_ec2/` | EC2 | Query | Instances, networking, storage, scaling |
| `tests_aws_dynamodb/` | DynamoDB | JSON-RPC | Tables, indexes, streams, global tables |
| `tests_aws_lambda/` | Lambda | REST | Functions, versions, layers, event sources |
| `tests_aws_sqs/` | SQS | Query | Standard/FIFO queues, DLQ, encryption |
| `tests_aws_sns/` | SNS | Query | Topics, subscriptions, policies |
| `tests_aws_iam/` | IAM | Query (global) | Roles, policies, users, OIDC/SAML |
| `tests_aws_cloudwatch/` | CloudWatch | JSON-RPC | Logs, metrics, alarms, dashboards |
| `tests_aws_secrets/` | Secrets Manager / SSM | JSON-RPC / Query | Secrets, parameters, versioning |

## Prerequisites

- Warden server running locally
- HashiCorp Vault running (for credential sourcing)
- Hydra OAuth2 server running (for JWT authentication)
- Terraform >= 1.0
- AWS CLI configured

## Setup

### 1. Start Warden Server

```bash
./warden server --config=warden.local.hcl
```

### 2. Configure Warden Namespaces and Authentication

```bash
# Create namespaces
./warden namespace create PROD
./warden namespace create SEC -n PROD

# Create policy for AWS streaming
./warden -n PROD/SEC policy write aws-streaming - <<EOF
path "aws/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF

# Configure Vault as credential source
./warden -n PROD/SEC cred source create vault \
  --type hvault \
  --config vault_address=http://127.0.0.1:8200 \
  --config auth_method=approle \
  --config role_id=c0ae884e-b55e-1736-3710-bb1d88d76182 \
  --config secret_id=e0b8f9b8-6b32-5478-9a73-196e50734c2f \
  --config approle_mount=warden_approle

# Create credential specifications
./warden -n PROD/SEC cred spec create aws_local \
  --type aws_access_keys \
  --source local \
  --config access_key_id=test \
  --config secret_access_key=test

./warden -n PROD/SEC cred spec create aws_static \
  --type aws_access_keys \
  --source vault \
  --config mint_method=kv2_static \
  --config kv2_mount=kv_static_secret \
  --config secret_path=aws/prod

./warden -n PROD/SEC cred spec create aws_dynamic \
  --type aws_access_keys \
  --source vault \
  --config mint_method=dynamic_aws \
  --config aws_mount=aws \
  --config role_name=terraform \
  --config ttl=900s \
  --config role_session_name=warden \
  --config role_arn=arn:aws:iam::905418489750:role/terraform-role-warden \
  --min-ttl 600s \
  --max-ttl 8h

# Enable JWT authentication
./warden -n PROD/SEC auth enable --type=jwt --description="jwt test auth method"
./warden -n PROD/SEC write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create JWT roles
./warden -n PROD/SEC write auth/jwt/role/aws-streamer \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_local \
    token_ttl=1h

./warden -n PROD/SEC write auth/jwt/role/aws-kv \
    token_type=aws_access_keys \
    token_policies="aws-streaming" \
    user_claim=sub \
    cred_spec_name=aws_static \
    token_ttl=1h

# Enable AWS provider
./warden -n PROD/SEC provider enable --type=aws --description="aws provider"
./warden -n PROD/SEC write aws/config proxy_domains="localhost,warden"
```

### 3. Set Environment Variables

```bash
# Get JWT token from Hydra
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=service-client-1&client_secret=service-secret-1-change-this&scope=api:read api:write' \
  | jq -r '.access_token')

# Login to Warden and extract credentials
LOGIN_OUTPUT=$(./warden -n PROD/SEC login --method=jwt --token=$JWT --role=aws-kv)
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')

# Point AWS SDK to Warden proxy
export AWS_ENDPOINT_URL=http://localhost:8400/v1/PROD/SEC/aws/gateway
```

## Running Tests

Each test suite is independent and can be run separately:

```bash
# Run S3 tests
cd tests_aws_s3
terraform init
terraform apply

# Run EC2 tests
cd tests_aws_ec2
terraform init
terraform apply

# Run all tests (from e2e_test directory)
for dir in tests_aws_*/; do
  echo "Running tests in $dir"
  cd "$dir"
  terraform init
  terraform apply -auto-approve
  cd ..
done
```

## Cleanup

```bash
# Destroy resources for a specific test suite
cd tests_aws_s3
terraform destroy

# Destroy all test resources
for dir in tests_aws_*/; do
  cd "$dir"
  terraform destroy -auto-approve
  cd ..
done
```

## Test Structure

Each test suite follows this structure:
- `main.tf` - Provider configuration, random suffix, common data sources
- `test-XX-*.tf` - Individual test files (each is independent, only requires main.tf)

Test files are numbered and categorized:
- `test-01-*` to `test-02-*` - Basic functionality
- `test-03-*` to `test-05-*` - Advanced features
- `test-06-*` to `test-07-*` - Edge cases and error scenarios

## Notes

- All test files are independent and only depend on `main.tf`
- Resources use random suffixes to avoid naming conflicts
- Tests validate AWS signature handling through the Warden proxy
- IAM tests use `us-east-1` signing region (global service)
