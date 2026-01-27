#!/bin/sh
set -e

echo "Waiting for Vault to be ready..."
sleep 5

echo ""
echo "Enabling KV v2 secrets engine..."
vault secrets enable -path=kv_warden_storage -version=2 kv || echo "KV already enabled"
vault secrets enable -path=kv_static_secret -version=2 kv || echo "KV already enabled"

sleep 2

echo ""
echo "Configuring AppRole Authentication..."

# Enable AppRole auth method at custom path
vault auth enable -path=warden_approle approle || echo "AppRole already enabled"

# Create the warden_root policy
echo "Creating warden_root policy..."
vault policy write warden_root - <<EOF
# KV v2 access for warden storage
path "kv_warden_storage/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv_warden_storage/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv_warden_storage/metadata/*" {
  capabilities = ["list", "read"]
}

path "kv_warden_storage/delete/*" {
  capabilities = ["update"]
}

path "kv_warden_storage/undelete/*" {
  capabilities = ["update"]
}

path "kv_warden_storage/destroy/*" {
  capabilities = ["update"]
}

# KV v2 access for testing the fetching of static secrets
path "kv_static_secret/*" {
  capabilities = ["read", "list"]
}

# Database secrets engine access
path "database/creds/*" {
  capabilities = ["read"]
}

path "database/roles/*" {
  capabilities = ["read"]
}

# AWS secrets engine access
path "aws/creds/*" {
  capabilities = ["read", "create", "update"]
}

path "aws/roles/*" {
  capabilities = ["read"]
}

# allow creating tokens with any role
path "auth/token/create/*" {
  capabilities = ["create", "update"]
}

# allow revoking tokens via accessor (for cleanup)
path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}
EOF

echo ""
echo "=========================================="
echo "Creating Token Roles for Warden"
echo "=========================================="

# Create policy for secrets-reader tokens (read-only access to secrets)
echo "Creating secrets-reader policy..."
vault policy write secrets-reader - <<EOF
# Read-only access to KV secrets
path "kv_static_secret/*" {
  capabilities = ["read", "list"]
}

path "kv_static_secret/data/*" {
  capabilities = ["read", "list"]
}

path "kv_static_secret/metadata/*" {
  capabilities = ["list", "read"]
}
EOF

# Create policy for database-user tokens (database credential access)
echo "Creating database-user policy..."
vault policy write database-user - <<EOF
# Database secrets engine - read credentials only
path "database/creds/*" {
  capabilities = ["read"]
}

path "database/roles/*" {
  capabilities = ["read", "list"]
}
EOF

# Create policy for aws-user tokens (AWS credential access)
echo "Creating aws-user policy..."
vault policy write aws-user - <<EOF
# AWS secrets engine - read credentials only
path "aws/creds/*" {
  capabilities = ["read", "create", "update"]
}

path "aws/roles/*" {
  capabilities = ["read", "list"]
}
EOF

# Create policy for full-access tokens (admin-like access)
echo "Creating full-access policy..."
vault policy write full-access - <<EOF
# Full access to all secret engines
path "kv_static_secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv_static_secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

path "aws/creds/*" {
  capabilities = ["read", "create", "update"]
}

# System health and info
path "sys/health" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read", "list"]
}
EOF

# Create policy for terraform-admin tokens (full Vault administration)
echo "Creating terraform-admin policy..."
vault policy write terraform-admin - <<EOF
# Full admin access for Terraform to configure Vault

path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

sleep 1

# Token Role 1: secrets-reader - Short-lived read-only tokens for secrets
echo "Creating token role 'secrets-reader'..."
vault write auth/token/roles/secrets-reader \
    allowed_policies="secrets-reader" \
    disallowed_policies="root" \
    orphan=true \
    token_period=1h \
    renewable=true \
    token_explicit_max_ttl=24h \
    token_type="service"

# Token Role 2: database-user - Tokens for database credential access
echo "Creating token role 'database-user'..."
vault write auth/token/roles/database-user \
    allowed_policies="database-user" \
    disallowed_policies="root" \
    orphan=true \
    token_period=30m \
    renewable=true \
    token_explicit_max_ttl=8h \
    token_type="service"

# Token Role 3: aws-user - Tokens for AWS credential access
echo "Creating token role 'aws-user'..."
vault write auth/token/roles/aws-user \
    allowed_policies="aws-user" \
    disallowed_policies="root" \
    orphan=true \
    token_period=1h \
    renewable=true \
    token_explicit_max_ttl=12h \
    token_type="service"

# Token Role 4: full-access - Longer-lived tokens with broader access
echo "Creating token role 'full-access'..."
vault write auth/token/roles/full-access \
    allowed_policies="full-access,secrets-reader,database-user,aws-user" \
    disallowed_policies="root" \
    orphan=true \
    token_period=4h \
    renewable=true \
    token_explicit_max_ttl=48h \
    token_type="service"

# Token Role 5: short-lived - Very short TTL for testing
echo "Creating token role 'short-lived'..."
vault write auth/token/roles/short-lived \
    allowed_policies="secrets-reader" \
    disallowed_policies="root" \
    orphan=true \
    token_ttl=5m \
    token_max_ttl=15m \
    renewable=false \
    token_type="service"

# Token Role 6: terraform-admin - Full admin for Terraform Vault configuration
echo "Creating token role 'terraform-admin'..."
vault write auth/token/roles/terraform-admin \
    allowed_policies="terraform-admin" \
    disallowed_policies="root" \
    orphan=true \
    token_period=4h \
    renewable=true \
    token_explicit_max_ttl=24h \
    token_type="service"

# Token Role 6: ephemeral-admin - Full admin for Terraform Vault configuration
echo "Creating token role 'ephemeral-admin'..."
vault write auth/token/roles/ephemeral-admin \
    allowed_policies="terraform-admin" \
    disallowed_policies="root" \
    orphan=true \
    token_ttl=5m \
    token_max_ttl=15m \
    renewable=false \
    token_type="service"
    
sleep 1

# Verify token roles
echo ""
echo "Verifying token roles..."
vault read auth/token/roles/secrets-reader
vault read auth/token/roles/database-user
vault read auth/token/roles/aws-user
vault read auth/token/roles/full-access
vault read auth/token/roles/short-lived
vault read auth/token/roles/terraform-admin

echo ""
echo "✓ Token roles configured successfully!"

# Switch back to root token
export VAULT_TOKEN=root

# Set the database static credential
echo "Setting database static creds..."
vault kv put -mount=kv_static_secret database/mysql/prod username=root password=rootpassword database=myapp

# Set the aws static credential
echo "Setting aws static creds..."
vault kv put -mount=kv_static_secret aws/prod access_key_id=test secret_access_key=test

sleep 1

# Create AppRole role with specific settings
echo "Creating AppRole role 'warden_root_role'..."
vault write auth/warden_approle/role/warden_root_role \
    token_policies="default,warden_root" \
    token_ttl=3600 \
    token_period=3600 \
    token_type="service" \
    bind_secret_id=true

sleep 1

# Set custom role_id
echo "Setting custom role_id..."
vault write auth/warden_approle/role/warden_root_role/role-id \
    role_id="c0ae884e-b55e-1736-3710-bb1d88d76182"

sleep 1

# Create custom secret_id
echo "Creating custom secret_id..."
vault write -f auth/warden_approle/role/warden_root_role/custom-secret-id \
    secret_id="e0b8f9b8-6b32-5478-9a73-196e50734c2f"

echo ""
echo "Verifying AppRole configuration..."
vault read auth/warden_approle/role/warden_root_role

# Test AppRole login
echo ""
echo "Testing AppRole login..."
WARDEN_TOKEN=$(vault write -field=token auth/warden_approle/login \
    role_id="c0ae884e-b55e-1736-3710-bb1d88d76182" \
    secret_id="e0b8f9b8-6b32-5478-9a73-196e50734c2f")

echo "AppRole login successful! Token: ${WARDEN_TOKEN:0:20}..."

echo ""
echo "=========================================="
echo "Creating Terraform AppRole"
echo "=========================================="

# Create AppRole role for Terraform with terraform-admin policy
echo "Creating AppRole role 'terraform_role'..."
vault write auth/warden_approle/role/terraform_role \
    token_policies="default,terraform-admin" \
    token_ttl=3600 \
    token_period=3600 \
    token_type="service" \
    bind_secret_id=true

sleep 1

# Set custom role_id for terraform
echo "Setting custom role_id for terraform..."
vault write auth/warden_approle/role/terraform_role/role-id \
    role_id="tf-role-id-1234-5678-90ab-cdef12345678"

sleep 1

# Create custom secret_id for terraform
echo "Creating custom secret_id for terraform..."
vault write -f auth/warden_approle/role/terraform_role/custom-secret-id \
    secret_id="tf-secret-id-abcd-efgh-ijkl-mnop12345678"

echo ""
echo "Verifying Terraform AppRole configuration..."
vault read auth/warden_approle/role/terraform_role

# Test Terraform AppRole login
echo ""
echo "Testing Terraform AppRole login..."
TERRAFORM_TOKEN=$(vault write -field=token auth/warden_approle/login \
    role_id="tf-role-id-1234-5678-90ab-cdef12345678" \
    secret_id="tf-secret-id-abcd-efgh-ijkl-mnop12345678")

echo "Terraform AppRole login successful! Token: ${TERRAFORM_TOKEN:0:20}..."

# Test KV access with AppRole token
echo ""
echo "Testing KV access with AppRole token..."
VAULT_TOKEN=$WARDEN_TOKEN vault kv put kv_warden_storage/test key=value
VAULT_TOKEN=$WARDEN_TOKEN vault kv get kv_warden_storage/test

# Test token creation with AppRole token
echo ""
echo "Testing token creation with warden_root token..."
echo "Creating test token using secrets-reader role..."
TEST_TOKEN=$(VAULT_TOKEN=$WARDEN_TOKEN vault write -force -field=token auth/token/create/secrets-reader)
echo "Created token: ${TEST_TOKEN:0:20}..."

# Verify the created token has correct policies
echo "Verifying created token policies..."
VAULT_TOKEN=$TEST_TOKEN vault token lookup | grep -A5 policies

# Clean up test token (use root token for cleanup since warden_root doesn't have revoke permission)
echo "Revoking test token..."
vault token revoke $TEST_TOKEN

# Switch back to root token for database configuration
echo ""
echo "Switching back to root token for database configuration..."
export VAULT_TOKEN=root

echo ""
echo "=========================================="
echo "Configuring MySQL Database Secrets Engine"
echo "=========================================="

# Enable database secrets engine
echo "Enabling database secrets engine..."
vault secrets enable -path=database database 2>&1 || echo "Database secrets engine already enabled"

sleep 3

# Wait for MySQL to be fully ready
echo "Waiting for MySQL server to be ready..."
max_attempts=30
attempt=0
until nc -z mysql-server 3306 || [ $attempt -eq $max_attempts ]; do
    echo "Waiting for MySQL (attempt $((attempt+1))/$max_attempts)..."
    sleep 2
    attempt=$((attempt+1))
done

if [ $attempt -eq $max_attempts ]; then
    echo "ERROR: MySQL server did not become ready in time"
    exit 1
fi

echo "MySQL server is ready!"

# Configure MySQL connection with better error handling
# Note: vaultadmin privileges (CREATE USER, GRANT OPTION) are granted via
# /docker-entrypoint-initdb.d/01-grant-vault-privileges.sql on MySQL container initialization
echo "Configuring MySQL database connection..."
vault write database/config/myapp \
    plugin_name=mysql-database-plugin \
    connection_url="{{username}}:{{password}}@tcp(mysql-server:3306)/?tls=skip-verify" \
    allowed_roles="my-role" \
    username="vaultadmin" \
    password="vaultpassword" \
    || {
        echo "ERROR: Failed to configure database connection"
        echo "Checking database secrets engine status..."
        vault secrets list -detailed | grep database || true
        exit 1
    }

echo "Database connection configured successfully!"

sleep 2

# Verify the configuration
echo "Verifying database configuration..."
vault read database/config/myapp || {
    echo "ERROR: Failed to read database configuration"
    exit 1
}

sleep 2

# Create a role for dynamic credentials
echo "Creating database role 'my-role'..."
vault write database/roles/my-role \
    db_name=myapp \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT ALL PRIVILEGES ON myapp.* TO '{{name}}'@'%';" \
    default_ttl="300s" \
    max_ttl="24h" \
    || {
        echo "ERROR: Failed to create database role"
        exit 1
    }

echo "Database role created successfully!"

sleep 2

# Verify the role
echo "Verifying database role..."
vault read database/roles/my-role || {
    echo "ERROR: Failed to read database role"
    exit 1
}

echo ""
echo "=============================="
echo "Configuring AWS Secrets Engine"
echo "=============================="

# Enable aws secrets engine
echo "Enabling aws secrets engine..."
vault secrets enable -path=aws aws 2>&1 || echo "AWS secrets engine already enabled"

sleep 1

echo "Configuring aws root user.."
vault write aws/config/root \
    access_key=test \
    secret_key=test \
    region=us-east-1

echo "Creating terraform role.."
vault write aws/roles/terraform \
    role_arns=arn:aws:iam::905418489750:role/terraform-role-warden \
    credential_type=assumed_role

echo ""
echo "=========================================="
echo "Vault configuration completed successfully!"
echo "=========================================="

echo ""
echo "✓ All tests passed!"