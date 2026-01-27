# test-03-auth-methods.tf
# Tests 36-50: Vault Authentication Methods
# Tests: AppRole, UserPass, JWT/OIDC, Kubernetes, Token

################################################################################
# Test 36: AppRole Auth Method
################################################################################
resource "vault_auth_backend" "approle" {
  type        = "approle"
  path        = "${local.name_prefix}-approle"
  description = "AppRole auth for Warden testing"

  tune {
    default_lease_ttl  = "1h"
    max_lease_ttl      = "24h"
    listing_visibility = "unauth"
  }
}

################################################################################
# Test 37: AppRole Role - Basic
################################################################################
resource "vault_approle_auth_backend_role" "basic" {
  backend   = vault_auth_backend.approle.path
  role_name = "basic-role"

  token_policies = [
    vault_policy.readonly.name,
  ]

  token_ttl     = 3600
  token_max_ttl = 86400
}

################################################################################
# Test 38: AppRole Role - With Secret ID constraints
################################################################################
resource "vault_approle_auth_backend_role" "constrained" {
  backend   = vault_auth_backend.approle.path
  role_name = "constrained-role"

  token_policies = [
    vault_policy.service_account.name,
  ]

  # Secret ID constraints
  secret_id_num_uses = 10
  secret_id_ttl      = 3600

  # Token constraints
  token_ttl         = 1800
  token_max_ttl     = 7200
  token_num_uses    = 0
  token_type        = "service"
  token_bound_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

################################################################################
# Test 39: AppRole Role - CICD use case
################################################################################
resource "vault_approle_auth_backend_role" "cicd" {
  backend   = vault_auth_backend.approle.path
  role_name = "cicd-role"

  token_policies = [
    vault_policy.cicd.name,
  ]

  # CICD usually needs unlimited secret_id uses
  secret_id_num_uses = 0
  secret_id_ttl      = 86400

  # Short-lived tokens for CI jobs
  token_ttl     = 900  # 15 minutes
  token_max_ttl = 3600 # 1 hour
  token_type    = "batch"

  # Bind to CI runner IPs (example)
  secret_id_bound_cidrs = ["10.0.0.0/8"]
}

################################################################################
# Test 40: AppRole with Role ID and Secret ID
################################################################################
resource "vault_approle_auth_backend_role" "full_config" {
  backend   = vault_auth_backend.approle.path
  role_name = "full-config-role"

  token_policies = [
    vault_policy.full_access.name,
  ]

  role_id             = "custom-role-id-${random_id.suffix.hex}"
  bind_secret_id      = true
  secret_id_num_uses  = 100
  secret_id_ttl       = 86400
  token_ttl           = 3600
  token_max_ttl       = 86400
  token_period        = 3600
  token_explicit_max_ttl = 0
}

resource "vault_approle_auth_backend_role_secret_id" "full_config" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.full_config.role_name

  metadata = jsonencode({
    created_by = "terraform"
    purpose    = "warden-testing"
  })
}

################################################################################
# Test 41: UserPass Auth Method
################################################################################
resource "vault_auth_backend" "userpass" {
  type        = "userpass"
  path        = "${local.name_prefix}-userpass"
  description = "UserPass auth for Warden testing"

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "12h"
  }
}

################################################################################
# Test 42: UserPass User - Basic
################################################################################
resource "vault_generic_endpoint" "user_basic" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/${vault_auth_backend.userpass.path}/users/testuser"
  ignore_absent_fields = true

  data_json = jsonencode({
    password       = "testpassword123"
    token_policies = [vault_policy.readonly.name]
    token_ttl      = 3600
  })
}

################################################################################
# Test 43: UserPass User - Admin
################################################################################
resource "vault_generic_endpoint" "user_admin" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/${vault_auth_backend.userpass.path}/users/adminuser"
  ignore_absent_fields = true

  data_json = jsonencode({
    password       = "adminpassword456"
    token_policies = [vault_policy.admin.name]
    token_ttl      = 7200
    token_max_ttl  = 86400
  })
}

################################################################################
# Test 44: UserPass User - Developer
################################################################################
resource "vault_generic_endpoint" "user_developer" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/${vault_auth_backend.userpass.path}/users/developer"
  ignore_absent_fields = true

  data_json = jsonencode({
    password       = "devpassword789"
    token_policies = [vault_policy.developer.name]
    token_ttl      = 14400
    token_bound_cidrs = ["10.0.0.0/8"]
  })
}

################################################################################
# Test 45: JWT Auth Method (mock configuration)
################################################################################
resource "vault_jwt_auth_backend" "jwt" {
  path        = "${local.name_prefix}-jwt"
  description = "JWT auth for Warden testing"

  # Mock OIDC discovery URL (won't work in real tests without actual IdP)
  # In real usage, this would point to your OIDC provider
  oidc_discovery_url = "https://accounts.google.com"

  default_role = "default"

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "24h"
  }
}

################################################################################
# Test 46: JWT Auth Role
################################################################################
resource "vault_jwt_auth_backend_role" "default" {
  backend   = vault_jwt_auth_backend.jwt.path
  role_name = "default"
  role_type = "jwt"

  token_policies = [
    vault_policy.readonly.name,
  ]

  bound_audiences = ["vault"]
  user_claim      = "sub"
  groups_claim    = "groups"

  token_ttl     = 3600
  token_max_ttl = 86400
}

################################################################################
# Test 47: JWT Auth Role - GitHub Actions
################################################################################
resource "vault_jwt_auth_backend_role" "github_actions" {
  backend   = vault_jwt_auth_backend.jwt.path
  role_name = "github-actions"
  role_type = "jwt"

  token_policies = [
    vault_policy.cicd.name,
  ]

  bound_audiences = ["https://github.com/my-org"]
  user_claim      = "actor"

  # Bound claims for GitHub Actions
  bound_claims = {
    repository = "my-org/my-repo"
    ref        = "refs/heads/main"
  }

  token_ttl     = 900  # 15 minutes
  token_max_ttl = 3600 # 1 hour
}

################################################################################
# Test 48: Token Auth Backend Role
################################################################################
resource "vault_token_auth_backend_role" "service" {
  role_name = "${local.name_prefix}-service-token"

  allowed_policies = [
    vault_policy.service_account.name,
    vault_policy.readonly.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_period           = 3600
  renewable              = true
  token_explicit_max_ttl = 86400
  token_type             = "service"

  path_suffix = "service"
}

################################################################################
# Test 49: Token Auth Backend Role - Batch tokens
################################################################################
resource "vault_token_auth_backend_role" "batch" {
  role_name = "${local.name_prefix}-batch-token"

  allowed_policies = [
    vault_policy.cicd.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_ttl     = 900  # 15 minutes
  token_max_ttl = 3600 # 1 hour
  renewable     = false
  token_type    = "batch"
}

################################################################################
# Test 50: Token Auth Backend Role - Short-lived
################################################################################
resource "vault_token_auth_backend_role" "short_lived" {
  role_name = "${local.name_prefix}-short-lived"

  allowed_policies = [
    vault_policy.minimal.name,
  ]
  disallowed_policies = ["root"]

  orphan = true

  token_ttl     = 300  # 5 minutes
  token_max_ttl = 900  # 15 minutes
  renewable     = true
  token_type    = "service"

  token_num_uses = 10 # Limited uses
}

################################################################################
# Outputs
################################################################################

output "auth_methods" {
  value = {
    approle = {
      path     = vault_auth_backend.approle.path
      accessor = vault_auth_backend.approle.accessor
    }
    userpass = {
      path     = vault_auth_backend.userpass.path
      accessor = vault_auth_backend.userpass.accessor
    }
    jwt = {
      path     = vault_jwt_auth_backend.jwt.path
      accessor = vault_jwt_auth_backend.jwt.accessor
    }
  }
  description = "Auth method details"
}

output "approle_roles" {
  value = {
    basic       = vault_approle_auth_backend_role.basic.role_name
    constrained = vault_approle_auth_backend_role.constrained.role_name
    cicd        = vault_approle_auth_backend_role.cicd.role_name
    full_config = vault_approle_auth_backend_role.full_config.role_name
  }
  description = "AppRole role names"
}

output "approle_credentials" {
  value = {
    full_config_role_id   = vault_approle_auth_backend_role.full_config.role_id
    full_config_secret_id = vault_approle_auth_backend_role_secret_id.full_config.secret_id
  }
  sensitive   = true
  description = "AppRole credentials for testing"
}

output "token_roles" {
  value = {
    service     = vault_token_auth_backend_role.service.role_name
    batch       = vault_token_auth_backend_role.batch.role_name
    short_lived = vault_token_auth_backend_role.short_lived.role_name
  }
  description = "Token role names"
}
