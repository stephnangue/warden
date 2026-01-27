# test-01-kv-secrets.tf
# Tests 1-20: KV Secrets Engine (v1 and v2)
# Tests: basic secrets, JSON secrets, versioning, metadata, paths

################################################################################
# KV v2 Secrets Engine Mount
################################################################################

resource "vault_mount" "kv_v2" {
  path        = "${local.name_prefix}-kv-v2"
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 secrets engine for Warden testing"
}

resource "vault_mount" "kv_v1" {
  path        = "${local.name_prefix}-kv-v1"
  type        = "kv"
  options     = { version = "1" }
  description = "KV v1 secrets engine for Warden testing"
}

################################################################################
# Test 1: Basic KV v2 Secret (plaintext)
################################################################################
resource "vault_kv_secret_v2" "basic" {
  mount = vault_mount.kv_v2.path
  name  = "basic"

  data_json = jsonencode({
    value = "my-secret-value"
  })
}

################################################################################
# Test 2: KV v2 Secret with JSON structure
################################################################################
resource "vault_kv_secret_v2" "json_secret" {
  mount = vault_mount.kv_v2.path
  name  = "database/credentials"

  data_json = jsonencode({
    username = "admin"
    password = "super-secret-password"
    host     = "db.example.com"
    port     = 5432
    database = "mydb"
    ssl_mode = "require"
  })
}

################################################################################
# Test 3: KV v2 Secret with deep path hierarchy
################################################################################
resource "vault_kv_secret_v2" "hierarchical" {
  mount = vault_mount.kv_v2.path
  name  = "apps/production/api-gateway/config"

  data_json = jsonencode({
    api_key    = "sk-prod-1234567890"
    api_secret = "secret-abcdef1234567890"
    endpoint   = "https://api.example.com/v1"
    rate_limit = 1000
  })
}

################################################################################
# Test 4: KV v2 Secret with custom metadata
################################################################################
resource "vault_kv_secret_v2" "with_metadata" {
  mount = vault_mount.kv_v2.path
  name  = "service/config"

  custom_metadata {
    max_versions         = 10
    cas_required         = false
    delete_version_after = 30
    data = {
      owner       = "platform-team"
      environment = "production"
      created_by  = "terraform"
    }
  }

  data_json = jsonencode({
    key1 = "value1"
    key2 = "value2"
  })
}

################################################################################
# Test 5: KV v2 Secret with CAS (Check-And-Set)
################################################################################
resource "vault_kv_secret_v2" "cas_enabled" {
  mount               = vault_mount.kv_v2.path
  name                = "cas-protected"
  cas                 = 0
  delete_all_versions = false

  data_json = jsonencode({
    protected_value = "cas-protected-secret"
  })
}

################################################################################
# Test 6: Multiple secrets in same path
################################################################################
resource "vault_kv_secret_v2" "multi_1" {
  mount = vault_mount.kv_v2.path
  name  = "multi/secret-1"

  data_json = jsonencode({
    service = "service-a"
    key     = "key-1"
  })
}

resource "vault_kv_secret_v2" "multi_2" {
  mount = vault_mount.kv_v2.path
  name  = "multi/secret-2"

  data_json = jsonencode({
    service = "service-b"
    key     = "key-2"
  })
}

resource "vault_kv_secret_v2" "multi_3" {
  mount = vault_mount.kv_v2.path
  name  = "multi/secret-3"

  data_json = jsonencode({
    service = "service-c"
    key     = "key-3"
  })
}

################################################################################
# Test 7: KV v1 Secret (basic)
################################################################################
resource "vault_kv_secret" "v1_basic" {
  path = "${vault_mount.kv_v1.path}/basic"

  data_json = jsonencode({
    username = "v1-user"
    password = "v1-password"
  })
}

################################################################################
# Test 8: KV v1 Secret with deep path
################################################################################
resource "vault_kv_secret" "v1_hierarchical" {
  path = "${vault_mount.kv_v1.path}/apps/legacy/config"

  data_json = jsonencode({
    connection_string = "Server=myserver;Database=mydb;User=admin;Password=secret;"
    timeout           = 30
  })
}

################################################################################
# Test 9: OAuth credentials pattern
################################################################################
resource "vault_kv_secret_v2" "oauth" {
  mount = vault_mount.kv_v2.path
  name  = "oauth/github"

  data_json = jsonencode({
    client_id     = "github-client-id-12345"
    client_secret = "github-client-secret-67890"
    token_url     = "https://github.com/login/oauth/access_token"
    authorize_url = "https://github.com/login/oauth/authorize"
    scope         = "read:user,repo"
  })
}

################################################################################
# Test 10: AWS credentials pattern
################################################################################
resource "vault_kv_secret_v2" "aws_creds" {
  mount = vault_mount.kv_v2.path
  name  = "cloud/aws/production"

  data_json = jsonencode({
    access_key_id     = "AKIAIOSFODNN7EXAMPLE"
    secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    region            = "us-east-1"
    account_id        = "123456789012"
  })
}

################################################################################
# Test 11: TLS Certificate pattern
################################################################################
resource "vault_kv_secret_v2" "tls_cert" {
  mount = vault_mount.kv_v2.path
  name  = "certs/api-gateway"

  data_json = jsonencode({
    certificate = <<-EOT
      -----BEGIN CERTIFICATE-----
      MIIBkTCB+wIJAKHBfpegMIIBkTCB+wIJAKHBfpegEXAMPLE
      -----END CERTIFICATE-----
    EOT
    private_key = <<-EOT
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwEXAMPLE
      -----END PRIVATE KEY-----
    EOT
    ca_bundle = <<-EOT
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUEXAMPLE
      -----END CERTIFICATE-----
    EOT
  })
}

################################################################################
# Test 12: Database connection string pattern
################################################################################
resource "vault_kv_secret_v2" "db_connection" {
  mount = vault_mount.kv_v2.path
  name  = "database/mysql/production"

  data_json = jsonencode({
    host     = "mysql.prod.internal"
    port     = 3306
    username = "app_user"
    password = "super-secure-db-password"
    database = "production_db"
    params = {
      charset         = "utf8mb4"
      parseTime       = "true"
      loc             = "UTC"
      maxAllowedPacket = "16777216"
    }
  })
}

################################################################################
# Test 13: Redis configuration pattern
################################################################################
resource "vault_kv_secret_v2" "redis" {
  mount = vault_mount.kv_v2.path
  name  = "cache/redis/cluster"

  data_json = jsonencode({
    nodes = [
      "redis-1.cache.internal:6379",
      "redis-2.cache.internal:6379",
      "redis-3.cache.internal:6379"
    ]
    password     = "redis-cluster-password"
    database     = 0
    max_retries  = 3
    read_timeout = "3s"
    cluster_mode = true
  })
}

################################################################################
# Test 14: API Keys for multiple services
################################################################################
resource "vault_kv_secret_v2" "api_keys" {
  mount = vault_mount.kv_v2.path
  name  = "integrations/api-keys"

  data_json = jsonencode({
    stripe = {
      publishable_key = "pk_live_1234567890"
      secret_key      = "sk_live_abcdefghij"
      webhook_secret  = "whsec_1234567890"
    }
    sendgrid = {
      api_key = "SG.1234567890.abcdefghij"
    }
    twilio = {
      account_sid = "ACabcdefghij1234567890"
      auth_token  = "1234567890abcdefghij"
    }
  })
}

################################################################################
# Test 15: Environment-specific configurations
################################################################################
resource "vault_kv_secret_v2" "env_dev" {
  mount = vault_mount.kv_v2.path
  name  = "environments/development/config"

  data_json = jsonencode({
    debug             = true
    log_level         = "debug"
    feature_flags     = ["feature_a", "feature_b", "experimental"]
    mock_external_api = true
  })
}

resource "vault_kv_secret_v2" "env_staging" {
  mount = vault_mount.kv_v2.path
  name  = "environments/staging/config"

  data_json = jsonencode({
    debug         = false
    log_level     = "info"
    feature_flags = ["feature_a", "feature_b"]
  })
}

resource "vault_kv_secret_v2" "env_prod" {
  mount = vault_mount.kv_v2.path
  name  = "environments/production/config"

  data_json = jsonencode({
    debug         = false
    log_level     = "warn"
    feature_flags = ["feature_a"]
  })
}

################################################################################
# Test 16: Secret with special characters in name
################################################################################
resource "vault_kv_secret_v2" "special_name" {
  mount = vault_mount.kv_v2.path
  name  = "special_chars-test.secret"

  data_json = jsonencode({
    value = "special-name-secret"
  })
}

################################################################################
# Test 17: Secret with special characters in values
################################################################################
resource "vault_kv_secret_v2" "special_values" {
  mount = vault_mount.kv_v2.path
  name  = "special-values"

  data_json = jsonencode({
    password_special = "P@ssw0rd!#$%^&*()"
    json_string      = "{\"nested\": \"json\"}"
    unicode          = "日本語テスト"
    newlines         = "line1\nline2\nline3"
    tabs             = "col1\tcol2\tcol3"
  })
}

################################################################################
# Test 18: Large secret value
################################################################################
resource "vault_kv_secret_v2" "large_value" {
  mount = vault_mount.kv_v2.path
  name  = "large-secret"

  data_json = jsonencode({
    # Generate a large value (about 10KB)
    large_data = join("", [for i in range(200) : "line-${i}-with-some-data-padding-to-make-it-larger-"])
  })
}

################################################################################
# Test 19: Empty values in secret
################################################################################
resource "vault_kv_secret_v2" "empty_values" {
  mount = vault_mount.kv_v2.path
  name  = "empty-values"

  data_json = jsonencode({
    non_empty    = "has-value"
    empty_string = ""
    null_value   = null
  })
}

################################################################################
# Test 20: Boolean and numeric values
################################################################################
resource "vault_kv_secret_v2" "typed_values" {
  mount = vault_mount.kv_v2.path
  name  = "typed-values"

  data_json = jsonencode({
    string_val  = "hello"
    int_val     = 42
    float_val   = 3.14159
    bool_true   = true
    bool_false  = false
    array_val   = ["a", "b", "c"]
    nested_obj = {
      inner_key = "inner_value"
    }
  })
}

################################################################################
# Outputs
################################################################################

output "kv_v2_mount_path" {
  value       = vault_mount.kv_v2.path
  description = "KV v2 secrets engine mount path"
}

output "kv_v1_mount_path" {
  value       = vault_mount.kv_v1.path
  description = "KV v1 secrets engine mount path"
}

output "kv_secret_paths" {
  value = {
    basic        = vault_kv_secret_v2.basic.path
    json         = vault_kv_secret_v2.json_secret.path
    hierarchical = vault_kv_secret_v2.hierarchical.path
    oauth        = vault_kv_secret_v2.oauth.path
    aws_creds    = vault_kv_secret_v2.aws_creds.path
    tls_cert     = vault_kv_secret_v2.tls_cert.path
  }
  description = "KV v2 secret paths"
}

