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
EOF

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
VAULT_TOKEN=$(vault write -field=token auth/warden_approle/login \
    role_id="c0ae884e-b55e-1736-3710-bb1d88d76182" \
    secret_id="e0b8f9b8-6b32-5478-9a73-196e50734c2f")

echo "AppRole login successful! Token: ${VAULT_TOKEN:0:20}..."

# Test KV access with AppRole token
echo ""
echo "Testing KV access with AppRole token..."
VAULT_TOKEN=$VAULT_TOKEN vault kv put kv_warden_storage/test key=value
VAULT_TOKEN=$VAULT_TOKEN vault kv get kv_warden_storage/test

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

# Test MySQL connection manually first
echo "Testing MySQL connection..."
if command -v mysql >/dev/null 2>&1; then
    mysql -h mysql-server -u vaultadmin -pvaultpassword -e "SELECT 1;" 2>&1 || echo "MySQL direct connection test failed"
else
    echo "mysql client not available, skipping direct connection test"
fi

sleep 2

# Configure MySQL connection with better error handling
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

# Test dynamic credential generation
echo ""
echo "Testing dynamic credential generation..."
vault read database/creds/my-role || {
    echo "ERROR: Failed to generate dynamic credentials"
    echo "This might be a database connection or permissions issue"
    exit 1
}

echo ""
echo "✓ All tests passed!"