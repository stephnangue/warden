# test-09-edge-cases.tf
# Tests 116-130: Edge Cases and Special Scenarios
# Tests: boundary conditions, error handling, unusual configurations

################################################################################
# Additional KV Mount for Edge Cases
################################################################################
resource "vault_mount" "kv_edge" {
  path        = "${local.name_prefix}-kv-edge"
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 for edge case testing"
}

################################################################################
# Test 116: Secret with very long path
################################################################################
resource "vault_kv_secret_v2" "very_long_path" {
  mount = vault_mount.kv_edge.path
  name  = "level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/deep-secret"

  data_json = jsonencode({
    value = "deep-nested-secret-value"
  })
}

################################################################################
# Test 117: Secret with maximum metadata
################################################################################
resource "vault_kv_secret_v2" "max_metadata" {
  mount = vault_mount.kv_edge.path
  name  = "max-metadata"

  custom_metadata {
    max_versions         = 100
    cas_required         = true
    delete_version_after = 876000000
    data = {
      key1  = "value1"
      key2  = "value2"
      key3  = "value3"
      key4  = "value4"
      key5  = "value5"
      key6  = "value6"
      key7  = "value7"
      key8  = "value8"
      key9  = "value9"
      key10 = "value10"
    }
  }

  data_json = jsonencode({
    secret = "secret-with-max-metadata"
  })
}

################################################################################
# Test 118: Secret with unicode characters in path and value
################################################################################
resource "vault_kv_secret_v2" "unicode" {
  mount = vault_mount.kv_edge.path
  name  = "unicode-test"

  data_json = jsonencode({
    japanese = "日本語テスト"
    chinese  = "中文测试"
    korean   = "한국어 테스트"
    arabic   = "اختبار عربي"
    emoji    = "🔐🔑🛡️"
    mixed    = "Test-テスト-测试-🔐"
  })
}

################################################################################
# Test 119: Secret with base64 encoded binary
################################################################################
resource "vault_kv_secret_v2" "binary_encoded" {
  mount = vault_mount.kv_edge.path
  name  = "binary-encoded"

  data_json = jsonencode({
    # Simulated binary data (like an encryption key or certificate)
    binary_key = base64encode("this-is-simulated-binary-data-for-testing-purposes-with-various-bytes")
    format     = "base64"
  })
}

################################################################################
# Test 120: Secret with extremely long value
################################################################################
resource "vault_kv_secret_v2" "very_long_value" {
  mount = vault_mount.kv_edge.path
  name  = "very-long-value"

  data_json = jsonencode({
    # Generate approximately 50KB of data
    large_data = join("", [for i in range(1000) : "line-${i}-${md5(tostring(i))}-padding-data-"])
  })
}

################################################################################
# Test 121: Policy with complex path patterns
################################################################################
resource "vault_policy" "complex_patterns" {
  name = "${local.name_prefix}-complex-patterns"

  policy = <<-EOT
    # Glob patterns
    path "${vault_mount.kv_edge.path}/data/apps/*/config" {
      capabilities = ["read"]
    }

    # Plus pattern (single segment)
    path "${vault_mount.kv_edge.path}/data/teams/+/secrets" {
      capabilities = ["read", "list"]
    }

    # Multiple wildcards
    path "${vault_mount.kv_edge.path}/data/env/*/app/*/config" {
      capabilities = ["read"]
    }

    # Segment parameters with identity
    path "${vault_mount.kv_edge.path}/data/users/{{identity.entity.name}}/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # Complex nested pattern
    path "${vault_mount.kv_edge.path}/+/+/+/secrets" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Test 122: Token role with all constraints
################################################################################
resource "vault_token_auth_backend_role" "fully_constrained" {
  role_name = "${local.name_prefix}-fully-constrained"

  allowed_policies = [
    vault_policy.readonly.name,
    vault_policy.minimal.name,
  ]
  disallowed_policies = ["root", vault_policy.admin.name]

  orphan = true

  token_max_ttl          = 600 # 10 minutes
  token_explicit_max_ttl = 900 # 15 minutes
  renewable              = true
  token_type             = "service"
  token_num_uses         = 3 # Only 3 uses
  token_bound_cidrs      = ["127.0.0.1/32", "10.0.0.0/8"]

  path_suffix = "constrained"
}

################################################################################
# Test 123: AppRole with extreme constraints
################################################################################
resource "vault_approle_auth_backend_role" "extreme_constraints" {
  backend   = vault_auth_backend.approle.path
  role_name = "extreme-constraints"

  token_policies = [
    vault_policy.minimal.name,
  ]

  # Secret ID constraints - very restrictive
  secret_id_num_uses = 1   # One-time use
  secret_id_ttl      = 300 # 5 minutes

  # Token constraints - very restrictive
  token_ttl      = 60      # 1 minute
  token_max_ttl  = 120     # 2 minutes
  token_num_uses = 0       # Unlimited uses (batch tokens cannot have limited use count)
  token_type     = "batch" # Batch tokens (not stored)

  # Network constraints
  secret_id_bound_cidrs = ["127.0.0.1/32"]
  token_bound_cidrs     = ["127.0.0.1/32"]
}

################################################################################
# Test 124: Multiple secrets with same prefix (list test)
################################################################################
resource "vault_kv_secret_v2" "list_test_1" {
  mount     = vault_mount.kv_edge.path
  name      = "list-test/secret-001"
  data_json = jsonencode({ id = "001" })
}

resource "vault_kv_secret_v2" "list_test_2" {
  mount     = vault_mount.kv_edge.path
  name      = "list-test/secret-002"
  data_json = jsonencode({ id = "002" })
}

resource "vault_kv_secret_v2" "list_test_3" {
  mount     = vault_mount.kv_edge.path
  name      = "list-test/secret-003"
  data_json = jsonencode({ id = "003" })
}

resource "vault_kv_secret_v2" "list_test_nested_1" {
  mount     = vault_mount.kv_edge.path
  name      = "list-test/nested/secret-001"
  data_json = jsonencode({ id = "nested-001" })
}

resource "vault_kv_secret_v2" "list_test_nested_2" {
  mount     = vault_mount.kv_edge.path
  name      = "list-test/nested/secret-002"
  data_json = jsonencode({ id = "nested-002" })
}

################################################################################
# Test 125: Secret with special JSON structures
################################################################################
resource "vault_kv_secret_v2" "special_json" {
  mount = vault_mount.kv_edge.path
  name  = "special-json"

  data_json = jsonencode({
    array_empty  = []
    array_nested = [[1, 2], [3, 4], [5, 6]]
    object_empty = {}
    object_nested = {
      level1 = {
        level2 = {
          level3 = {
            value = "deep"
          }
        }
      }
    }
    mixed_array = [
      "string",
      123,
      true,
      null,
      { key = "value" },
      [1, 2, 3]
    ]
    numeric_keys = {
      "1" = "one"
      "2" = "two"
      "3" = "three"
    }
  })
}

################################################################################
# Test 126: Policy with template functions
################################################################################
resource "vault_policy" "templated" {
  name = "${local.name_prefix}-templated"

  policy = <<-EOT
    # Time-based access (example)
    path "${vault_mount.kv_edge.path}/data/time-restricted/*" {
      capabilities = ["read"]
    }

    # Identity-based path with entity metadata
    path "${vault_mount.kv_edge.path}/data/users/{{identity.entity.metadata.department}}/*" {
      capabilities = ["read", "list"]
    }

    # Group-based access
    path "${vault_mount.kv_edge.path}/data/groups/{{identity.groups.names}}/*" {
      capabilities = ["read", "list"]
    }

    # Allow access to own entity
    path "identity/entity/id/{{identity.entity.id}}" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Test 127: Transit key with all options enabled
################################################################################
resource "vault_transit_secret_backend_key" "all_options" {
  backend = vault_mount.transit.path
  name    = "all-options-key"
  type    = "aes256-gcm96"

  deletion_allowed       = true
  exportable             = true
  allow_plaintext_backup = true
  min_decryption_version = 1
  min_encryption_version = 1
  auto_rotate_period     = 3600 # Rotate every hour for testing
}

################################################################################
# Test 128: Database role with complex SQL statements
################################################################################
resource "vault_database_secret_backend_role" "complex_sql" {
  backend = vault_mount.database.path
  name    = "complex-sql-role"
  db_name = vault_database_secret_backend_connection.postgresql.name

  creation_statements = [
    # Create role with specific attributes
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT 10;",
    # Grant schema usage
    "GRANT USAGE ON SCHEMA public TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA app TO \"{{name}}\";",
    # Grant table permissions with column restrictions
    "GRANT SELECT (id, name, created_at) ON public.users TO \"{{name}}\";",
    "GRANT SELECT, INSERT, UPDATE ON app.orders TO \"{{name}}\";",
    # Grant sequence usage
    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO \"{{name}}\";",
    # Set default search path
    "ALTER ROLE \"{{name}}\" SET search_path TO app, public;",
    # Set role-specific parameters
    "ALTER ROLE \"{{name}}\" SET statement_timeout TO '30s';",
  ]

  revocation_statements = [
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
    "DROP OWNED BY \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  renew_statements = [
    "ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}';",
  ]

  default_ttl = 600
  max_ttl     = 3600
}

################################################################################
# Test 129: AWS role with session tags and external ID
################################################################################
resource "vault_aws_secret_backend_role" "complex_assume" {
  backend = vault_aws_secret_backend.aws.path
  name    = "complex-assume-role"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/ComplexRole"]

  # External ID for cross-account access
  external_id = "warden-external-id-${random_id.suffix.hex}"

  # Session tags
  session_tags = {
    "warden:session"     = "true"
    "warden:environment" = "test"
    "warden:purpose"     = "e2e-testing"
    "warden:timestamp"   = "{{now | unix}}"
  }

  default_sts_ttl = 3600
  max_sts_ttl     = 14400
}

################################################################################
# Tests 130-139: Paths containing "role" and "gateway" keywords
# Tests: Warden transparent mode path parsing with confusing path segments
################################################################################

################################################################################
# Test 130: PKI mount named "role-pki" (contains "role" keyword)
################################################################################
resource "vault_mount" "pki_role" {
  path        = "${local.name_prefix}-role-pki"
  type        = "pki"
  description = "PKI mount with 'role' in name - tests transparent mode path parsing"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000
}

resource "vault_pki_secret_backend_root_cert" "role_pki_root" {
  backend     = vault_mount.pki_role.path
  type        = "internal"
  common_name = "Role PKI Test CA"
  ttl         = "315360000"
  issuer_name = "role-ca"
}

################################################################################
# Test 131: PKI mount named "gateway-pki" (contains "gateway" keyword)
################################################################################
resource "vault_mount" "pki_gateway" {
  path        = "${local.name_prefix}-gateway-pki"
  type        = "pki"
  description = "PKI mount with 'gateway' in name - tests transparent mode path parsing"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000
}

resource "vault_pki_secret_backend_root_cert" "gateway_pki_root" {
  backend     = vault_mount.pki_gateway.path
  type        = "internal"
  common_name = "Gateway PKI Test CA"
  ttl         = "315360000"
  issuer_name = "gateway-ca"
}

################################################################################
# Test 132: PKI mount named "role-gateway" (contains both keywords)
################################################################################
resource "vault_mount" "pki_role_gateway" {
  path        = "${local.name_prefix}-role-gateway-pki"
  type        = "pki"
  description = "PKI mount with both 'role' and 'gateway' in name"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000
}

resource "vault_pki_secret_backend_root_cert" "role_gateway_pki_root" {
  backend     = vault_mount.pki_role_gateway.path
  type        = "internal"
  common_name = "Role Gateway PKI Test CA"
  ttl         = "315360000"
  issuer_name = "role-gateway-ca"
}

################################################################################
# Test 133: KV mount named "role-secrets" (contains "role" keyword)
################################################################################
resource "vault_mount" "kv_role" {
  path        = "${local.name_prefix}-role-secrets"
  type        = "kv"
  options     = { version = "2" }
  description = "KV mount with 'role' in name"
}

resource "vault_kv_secret_v2" "role_secret" {
  mount = vault_mount.kv_role.path
  name  = "test-secret"

  data_json = jsonencode({
    value = "secret-in-role-named-mount"
  })
}

################################################################################
# Test 134: KV mount named "gateway-config" (contains "gateway" keyword)
################################################################################
resource "vault_mount" "kv_gateway" {
  path        = "${local.name_prefix}-gateway-config"
  type        = "kv"
  options     = { version = "2" }
  description = "KV mount with 'gateway' in name"
}

resource "vault_kv_secret_v2" "gateway_secret" {
  mount = vault_mount.kv_gateway.path
  name  = "test-secret"

  data_json = jsonencode({
    value = "secret-in-gateway-named-mount"
  })
}

################################################################################
# Test 135: Secret path containing "role" keyword
################################################################################
resource "vault_kv_secret_v2" "path_with_role" {
  mount = vault_mount.kv_edge.path
  name  = "apps/role-manager/config"

  data_json = jsonencode({
    value = "secret-with-role-in-path"
  })
}

################################################################################
# Test 136: Secret path containing "gateway" keyword
################################################################################
resource "vault_kv_secret_v2" "path_with_gateway" {
  mount = vault_mount.kv_edge.path
  name  = "apps/gateway-service/config"

  data_json = jsonencode({
    value = "secret-with-gateway-in-path"
  })
}

################################################################################
# Test 137: Secret path containing both "role" and "gateway" keywords
################################################################################
resource "vault_kv_secret_v2" "path_with_both_keywords" {
  mount = vault_mount.kv_edge.path
  name  = "role-config/gateway-settings/main"

  data_json = jsonencode({
    value = "secret-with-both-keywords-in-path"
  })
}

################################################################################
# Test 138: PKI role for issuing certs (tests unauthenticated paths)
################################################################################
resource "vault_pki_secret_backend_role" "role_pki_server" {
  backend = vault_mount.pki_role.path
  name    = "server-role"

  ttl     = "86400"
  max_ttl = "2592000"

  allow_any_name = true
  server_flag    = true
  client_flag    = false
  key_type       = "rsa"
  key_bits       = 2048
}

resource "vault_pki_secret_backend_role" "gateway_pki_server" {
  backend = vault_mount.pki_gateway.path
  name    = "gateway-server-role"

  ttl     = "86400"
  max_ttl = "2592000"

  allow_any_name = true
  server_flag    = true
  client_flag    = false
  key_type       = "rsa"
  key_bits       = 2048
}

################################################################################
# Test 139: Data sources for verification
################################################################################

# Verify policy exists
data "vault_policy_document" "verify_readonly" {
  rule {
    path         = "${vault_mount.kv_edge.path}/data/*"
    capabilities = ["read", "list"]
  }
}

# Verify auth method configuration
data "vault_auth_backend" "verify_approle" {
  path = vault_auth_backend.approle.path
}

################################################################################
# Outputs
################################################################################

output "edge_case_mounts" {
  value = {
    kv_edge     = vault_mount.kv_edge.path
    pki_role    = vault_mount.pki_role.path
    pki_gateway = vault_mount.pki_gateway.path
    pki_role_gw = vault_mount.pki_role_gateway.path
    kv_role     = vault_mount.kv_role.path
    kv_gateway  = vault_mount.kv_gateway.path
  }
  description = "Edge case mount paths"
}

output "edge_case_secrets" {
  value = {
    very_long_path    = vault_kv_secret_v2.very_long_path.path
    max_metadata      = vault_kv_secret_v2.max_metadata.path
    unicode           = vault_kv_secret_v2.unicode.path
    binary_encoded    = vault_kv_secret_v2.binary_encoded.path
    very_long_value   = vault_kv_secret_v2.very_long_value.path
    special_json      = vault_kv_secret_v2.special_json.path
    role_secret       = vault_kv_secret_v2.role_secret.path
    gateway_secret    = vault_kv_secret_v2.gateway_secret.path
    path_with_role    = vault_kv_secret_v2.path_with_role.path
    path_with_gateway = vault_kv_secret_v2.path_with_gateway.path
    path_with_both    = vault_kv_secret_v2.path_with_both_keywords.path
  }
  description = "Edge case secret paths"
}

output "edge_case_list_secrets" {
  value = [
    vault_kv_secret_v2.list_test_1.path,
    vault_kv_secret_v2.list_test_2.path,
    vault_kv_secret_v2.list_test_3.path,
    vault_kv_secret_v2.list_test_nested_1.path,
    vault_kv_secret_v2.list_test_nested_2.path,
  ]
  description = "List test secret paths"
}

output "edge_case_policies" {
  value = {
    complex_patterns = vault_policy.complex_patterns.name
    templated        = vault_policy.templated.name
  }
  description = "Edge case policy names"
}

output "edge_case_token_roles" {
  value = {
    fully_constrained = vault_token_auth_backend_role.fully_constrained.role_name
  }
  description = "Edge case token role names"
}

output "edge_case_approle_roles" {
  value = {
    extreme_constraints = vault_approle_auth_backend_role.extreme_constraints.role_name
  }
  description = "Edge case AppRole role names"
}

output "verification_results" {
  value = {
    approle_accessor = data.vault_auth_backend.verify_approle.accessor
  }
  description = "Verification test results"
}

################################################################################
# Keyword Path PKI Outputs (for unauthenticated path testing)
################################################################################

output "keyword_pki_mounts" {
  value = {
    role_pki         = vault_mount.pki_role.path
    gateway_pki      = vault_mount.pki_gateway.path
    role_gateway_pki = vault_mount.pki_role_gateway.path
  }
  description = "PKI mounts with 'role' and 'gateway' keywords in path"
}

output "keyword_pki_issuers" {
  value = {
    role_ca         = vault_pki_secret_backend_root_cert.role_pki_root.issuer_id
    gateway_ca      = vault_pki_secret_backend_root_cert.gateway_pki_root.issuer_id
    role_gateway_ca = vault_pki_secret_backend_root_cert.role_gateway_pki_root.issuer_id
  }
  description = "PKI issuer IDs for unauthenticated path testing"
}

output "keyword_pki_unauthenticated_paths" {
  value = {
    # These paths should be accessible without authentication in transparent mode
    role_pki_ca_pem        = "${vault_mount.pki_role.path}/ca/pem"
    role_pki_issuer_pem    = "${vault_mount.pki_role.path}/issuer/${vault_pki_secret_backend_root_cert.role_pki_root.issuer_id}/pem"
    gateway_pki_ca_pem     = "${vault_mount.pki_gateway.path}/ca/pem"
    gateway_pki_issuer_pem = "${vault_mount.pki_gateway.path}/issuer/${vault_pki_secret_backend_root_cert.gateway_pki_root.issuer_id}/pem"
    role_gw_pki_ca_pem     = "${vault_mount.pki_role_gateway.path}/ca/pem"
    role_gw_pki_issuer_pem = "${vault_mount.pki_role_gateway.path}/issuer/${vault_pki_secret_backend_root_cert.role_gateway_pki_root.issuer_id}/pem"
  }
  description = "Unauthenticated PKI paths with 'role' and 'gateway' keywords"
}

output "keyword_pki_roles" {
  value = {
    role_pki_server    = vault_pki_secret_backend_role.role_pki_server.name
    gateway_pki_server = vault_pki_secret_backend_role.gateway_pki_server.name
  }
  description = "PKI roles for certificate issuance"
}
