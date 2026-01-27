# test-04-token-roles.tf
# Tests 51-60: Vault Token Roles and Token Creation
# Tests: token roles, token creation, token management

################################################################################
# Test 51: Token Role - Secrets Reader
################################################################################
resource "vault_token_auth_backend_role" "secrets_reader" {
  role_name = "${local.name_prefix}-secrets-reader"

  allowed_policies = [
    vault_policy.readonly.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 3600  # 1 hour
  renewable              = true
  token_explicit_max_ttl = 86400 # 24 hours
  token_type             = "service"
}

################################################################################
# Test 52: Token Role - Database User
################################################################################
resource "vault_token_auth_backend_role" "database_user" {
  role_name = "${local.name_prefix}-database-user"

  allowed_policies = [
    vault_policy.db_reader.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 1800  # 30 minutes
  renewable              = true
  token_explicit_max_ttl = 28800 # 8 hours
  token_type             = "service"
}

################################################################################
# Test 53: Token Role - AWS User
################################################################################
resource "vault_token_auth_backend_role" "aws_user" {
  role_name = "${local.name_prefix}-aws-user"

  allowed_policies = [
    vault_policy.aws_reader.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 3600  # 1 hour
  renewable              = true
  token_explicit_max_ttl = 43200 # 12 hours
  token_type             = "service"
}

################################################################################
# Test 54: Token Role - Full Access
################################################################################
resource "vault_token_auth_backend_role" "full_access" {
  role_name = "${local.name_prefix}-full-access"

  allowed_policies = [
    vault_policy.full_access.name,
    vault_policy.readonly.name,
    vault_policy.db_reader.name,
    vault_policy.aws_reader.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 14400  # 4 hours
  renewable              = true
  token_explicit_max_ttl = 172800 # 48 hours
  token_type             = "service"
}

################################################################################
# Test 55: Token Role - Very Short TTL (for testing expiration)
################################################################################
resource "vault_token_auth_backend_role" "very_short" {
  role_name = "${local.name_prefix}-very-short"

  allowed_policies = [
    vault_policy.minimal.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_ttl     = 60   # 1 minute
  token_max_ttl = 300  # 5 minutes
  renewable     = true
  token_type    = "service"
}

################################################################################
# Test 56: Token Role - Non-renewable
################################################################################
resource "vault_token_auth_backend_role" "non_renewable" {
  role_name = "${local.name_prefix}-non-renewable"

  allowed_policies = [
    vault_policy.readonly.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_ttl     = 3600  # 1 hour
  token_max_ttl = 3600  # 1 hour (same as TTL since not renewable)
  renewable     = false
  token_type    = "service"
}

################################################################################
# Test 57: Token Role - Limited Uses
################################################################################
resource "vault_token_auth_backend_role" "limited_uses" {
  role_name = "${local.name_prefix}-limited-uses"

  allowed_policies = [
    vault_policy.readonly.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period   = 3600
  renewable      = true
  token_num_uses = 5 # Only 5 uses allowed
  token_type     = "service"
}

################################################################################
# Test 58: Token Role - CIDR Bound
################################################################################
resource "vault_token_auth_backend_role" "cidr_bound" {
  role_name = "${local.name_prefix}-cidr-bound"

  allowed_policies = [
    vault_policy.service_account.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period      = 3600
  renewable         = true
  token_type        = "service"
  token_bound_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

################################################################################
# Test 59: Token Role - Terraform Admin
################################################################################
resource "vault_token_auth_backend_role" "terraform_admin" {
  role_name = "${local.name_prefix}-terraform-admin"

  allowed_policies = [
    vault_policy.admin.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 14400 # 4 hours
  renewable              = true
  token_explicit_max_ttl = 86400 # 24 hours
  token_type             = "service"
}

################################################################################
# Test 60: Token Role - Transit User
################################################################################
resource "vault_token_auth_backend_role" "transit_user" {
  role_name = "${local.name_prefix}-transit-user"

  allowed_policies = [
    vault_policy.transit_user.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 7200  # 2 hours
  renewable              = true
  token_explicit_max_ttl = 28800 # 8 hours
  token_type             = "service"
}

################################################################################
# Token Creation Tests (using vault_token resource)
################################################################################

# Test: Create token with secrets-reader role
resource "vault_token" "test_secrets_reader" {
  role_name = vault_token_auth_backend_role.secrets_reader.role_name
  policies  = [vault_policy.readonly.name]

  renewable = true
  ttl       = "1h"

  metadata = {
    created_by = "terraform"
    purpose    = "warden-testing"
    test_name  = "secrets-reader-token"
  }
}

# Test: Create token with database-user role
resource "vault_token" "test_database_user" {
  role_name = vault_token_auth_backend_role.database_user.role_name
  policies  = [vault_policy.db_reader.name]

  renewable = true
  ttl       = "30m"

  metadata = {
    created_by = "terraform"
    purpose    = "warden-testing"
    test_name  = "database-user-token"
  }
}

# Test: Create short-lived token
resource "vault_token" "test_short_lived" {
  role_name = vault_token_auth_backend_role.very_short.role_name
  policies  = [vault_policy.minimal.name]

  renewable = true
  ttl       = "1m"

  metadata = {
    created_by = "terraform"
    purpose    = "warden-testing"
    test_name  = "short-lived-token"
  }
}

# Test: Create non-renewable token
resource "vault_token" "test_non_renewable" {
  role_name = vault_token_auth_backend_role.non_renewable.role_name
  policies  = [vault_policy.readonly.name]

  renewable = false
  ttl       = "1h"

  metadata = {
    created_by = "terraform"
    purpose    = "warden-testing"
    test_name  = "non-renewable-token"
  }
}

################################################################################
# Outputs
################################################################################

output "token_role_names" {
  value = {
    secrets_reader = vault_token_auth_backend_role.secrets_reader.role_name
    database_user  = vault_token_auth_backend_role.database_user.role_name
    aws_user       = vault_token_auth_backend_role.aws_user.role_name
    full_access    = vault_token_auth_backend_role.full_access.role_name
    very_short     = vault_token_auth_backend_role.very_short.role_name
    non_renewable  = vault_token_auth_backend_role.non_renewable.role_name
    limited_uses   = vault_token_auth_backend_role.limited_uses.role_name
    cidr_bound     = vault_token_auth_backend_role.cidr_bound.role_name
    terraform_admin = vault_token_auth_backend_role.terraform_admin.role_name
    transit_user   = vault_token_auth_backend_role.transit_user.role_name
  }
  description = "Token role names for Warden credential specs"
}

output "test_tokens" {
  value = {
    secrets_reader = {
      lease_duration = vault_token.test_secrets_reader.lease_duration
      renewable    = vault_token.test_secrets_reader.renewable
    }
    database_user = {
      lease_duration = vault_token.test_database_user.lease_duration
      renewable    = vault_token.test_database_user.renewable
    }
    short_lived = {
      lease_duration = vault_token.test_short_lived.lease_duration
      renewable    = vault_token.test_short_lived.renewable
    }
  }
  description = "Test token info (no actual tokens exposed)"
}

output "test_token_values" {
  value = {
    secrets_reader = vault_token.test_secrets_reader.client_token
    database_user  = vault_token.test_database_user.client_token
    short_lived    = vault_token.test_short_lived.client_token
    non_renewable  = vault_token.test_non_renewable.client_token
  }
  sensitive   = true
  description = "Test token values (sensitive)"
}
