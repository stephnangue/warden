# test-02-policies.tf
# Tests 21-35: Vault Policies
# Tests: ACL policies, policy attachments, capability-based access

################################################################################
# Test 21: Basic read-only policy
################################################################################
resource "vault_policy" "readonly" {
  name = "${local.name_prefix}-readonly"

  policy = <<-EOT
    # Read-only access to KV secrets
    path "${vault_mount.kv_v2.path}/data/*" {
      capabilities = ["read", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/*" {
      capabilities = ["read", "list"]
    }
  EOT
}

################################################################################
# Test 22: Full access policy for specific path
################################################################################
resource "vault_policy" "full_access" {
  name = "${local.name_prefix}-full-access"

  policy = <<-EOT
    # Full access to specific KV path
    path "${vault_mount.kv_v2.path}/data/apps/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/apps/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "${vault_mount.kv_v2.path}/delete/apps/*" {
      capabilities = ["update"]
    }

    path "${vault_mount.kv_v2.path}/undelete/apps/*" {
      capabilities = ["update"]
    }

    path "${vault_mount.kv_v2.path}/destroy/apps/*" {
      capabilities = ["update"]
    }
  EOT
}

################################################################################
# Test 23: Database secrets reader policy
################################################################################
resource "vault_policy" "db_reader" {
  name = "${local.name_prefix}-db-reader"

  policy = <<-EOT
    # Read database credentials
    path "database/creds/*" {
      capabilities = ["read"]
    }

    # List available database roles
    path "database/roles" {
      capabilities = ["list"]
    }

    path "database/roles/*" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Test 24: AWS secrets reader policy
################################################################################
resource "vault_policy" "aws_reader" {
  name = "${local.name_prefix}-aws-reader"

  policy = <<-EOT
    # Read AWS credentials
    path "aws/creds/*" {
      capabilities = ["read"]
    }

    # List available AWS roles
    path "aws/roles" {
      capabilities = ["list"]
    }

    path "aws/roles/*" {
      capabilities = ["read"]
    }

    # Renew/revoke leases
    path "sys/leases/renew" {
      capabilities = ["update"]
    }
  EOT
}

################################################################################
# Test 25: Transit encrypt/decrypt policy
################################################################################
resource "vault_policy" "transit_user" {
  name = "${local.name_prefix}-transit-user"

  policy = <<-EOT
    # Encrypt data
    path "transit/encrypt/*" {
      capabilities = ["update"]
    }

    # Decrypt data
    path "transit/decrypt/*" {
      capabilities = ["update"]
    }

    # Generate data keys
    path "transit/datakey/*" {
      capabilities = ["update"]
    }

    # List keys (but not read key material)
    path "transit/keys" {
      capabilities = ["list"]
    }
  EOT
}

################################################################################
# Test 26: PKI certificates policy
################################################################################
resource "vault_policy" "pki_user" {
  name = "${local.name_prefix}-pki-user"

  policy = <<-EOT
    # Issue certificates
    path "pki/issue/*" {
      capabilities = ["create", "update"]
    }

    # Sign CSRs
    path "pki/sign/*" {
      capabilities = ["create", "update"]
    }

    # List roles
    path "pki/roles" {
      capabilities = ["list"]
    }

    path "pki/roles/*" {
      capabilities = ["read"]
    }

    # Read CA certificate
    path "pki/cert/ca" {
      capabilities = ["read"]
    }

    # Revoke certificates
    path "pki/revoke" {
      capabilities = ["update"]
    }
  EOT
}

################################################################################
# Test 27: Admin policy with sudo capability
################################################################################
resource "vault_policy" "admin" {
  name = "${local.name_prefix}-admin"

  policy = <<-EOT
    # Full access to secrets engines
    path "sys/mounts/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "sys/mounts" {
      capabilities = ["read", "list"]
    }

    # Manage policies
    path "sys/policies/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "sys/policies/acl/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # Manage auth methods
    path "sys/auth/*" {
      capabilities = ["create", "read", "update", "delete", "list", "sudo"]
    }

    path "sys/auth" {
      capabilities = ["read", "list"]
    }

    # Manage token roles
    path "auth/token/roles/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # Create tokens
    path "auth/token/create/*" {
      capabilities = ["create", "update"]
    }

    # Lookup tokens
    path "auth/token/lookup" {
      capabilities = ["update"]
    }

    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }

    # Revoke tokens
    path "auth/token/revoke" {
      capabilities = ["update"]
    }

    path "auth/token/revoke-accessor" {
      capabilities = ["update"]
    }

    # System health and status
    path "sys/health" {
      capabilities = ["read", "sudo"]
    }

    path "sys/leader" {
      capabilities = ["read"]
    }

    # Lease management
    path "sys/leases/*" {
      capabilities = ["create", "read", "update", "delete", "list", "sudo"]
    }
  EOT
}

################################################################################
# Test 28: Service account policy (microservice pattern)
################################################################################
resource "vault_policy" "service_account" {
  name = "${local.name_prefix}-service-account"

  policy = <<-EOT
    # Read own service secrets
    path "${vault_mount.kv_v2.path}/data/services/{{identity.entity.name}}/*" {
      capabilities = ["read", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/services/{{identity.entity.name}}/*" {
      capabilities = ["read", "list"]
    }

    # Read shared configuration
    path "${vault_mount.kv_v2.path}/data/shared/config" {
      capabilities = ["read"]
    }

    # Get database credentials
    path "database/creds/{{identity.entity.name}}" {
      capabilities = ["read"]
    }

    # Renew own token
    path "auth/token/renew-self" {
      capabilities = ["update"]
    }

    # Lookup own token
    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Test 29: Developer policy (limited admin)
################################################################################
resource "vault_policy" "developer" {
  name = "${local.name_prefix}-developer"

  policy = <<-EOT
    # Read and write to development secrets
    path "${vault_mount.kv_v2.path}/data/environments/development/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/environments/development/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # Read-only access to staging
    path "${vault_mount.kv_v2.path}/data/environments/staging/*" {
      capabilities = ["read", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/environments/staging/*" {
      capabilities = ["read", "list"]
    }

    # No access to production (implicitly denied)

    # Use transit for encryption
    path "transit/encrypt/dev-*" {
      capabilities = ["update"]
    }

    path "transit/decrypt/dev-*" {
      capabilities = ["update"]
    }
  EOT
}

################################################################################
# Test 30: CI/CD pipeline policy
################################################################################
resource "vault_policy" "cicd" {
  name = "${local.name_prefix}-cicd"

  policy = <<-EOT
    # Read deployment secrets
    path "${vault_mount.kv_v2.path}/data/deployments/*" {
      capabilities = ["read", "list"]
    }

    # Read environment-specific configs
    path "${vault_mount.kv_v2.path}/data/environments/+/deploy-config" {
      capabilities = ["read"]
    }

    # Get cloud credentials for deployment
    path "aws/creds/deployer" {
      capabilities = ["read"]
    }

    # Create short-lived tokens for deployed services
    path "auth/token/create/service-token" {
      capabilities = ["create", "update"]
    }

    # Lookup created tokens
    path "auth/token/lookup" {
      capabilities = ["update"]
    }
  EOT
}

################################################################################
# Test 31: Policy with denied paths
################################################################################
resource "vault_policy" "restricted" {
  name = "${local.name_prefix}-restricted"

  policy = <<-EOT
    # Explicitly deny access to production secrets
    path "${vault_mount.kv_v2.path}/data/environments/production/*" {
      capabilities = ["deny"]
    }

    # Allow everything else in environments
    path "${vault_mount.kv_v2.path}/data/environments/*" {
      capabilities = ["read", "list"]
    }

    path "${vault_mount.kv_v2.path}/metadata/environments/*" {
      capabilities = ["read", "list"]
    }
  EOT
}

################################################################################
# Test 32: Policy with required parameters
################################################################################
resource "vault_policy" "parameterized" {
  name = "${local.name_prefix}-parameterized"

  policy = <<-EOT
    # Only allow specific TTL values for tokens
    path "auth/token/create" {
      capabilities = ["create", "update"]
      required_parameters = ["ttl"]
      allowed_parameters = {
        "ttl" = ["1h", "2h", "4h"]
        "policies" = []
      }
    }

    # Restrict database credential TTLs
    path "database/creds/*" {
      capabilities = ["read"]
      allowed_parameters = {
        "ttl" = ["15m", "30m", "1h"]
      }
    }
  EOT
}

################################################################################
# Test 33: Namespace-aware policy (Enterprise feature, but valid HCL)
################################################################################
resource "vault_policy" "namespace_aware" {
  name = "${local.name_prefix}-namespace-aware"

  policy = <<-EOT
    # Access secrets in current namespace
    path "${vault_mount.kv_v2.path}/data/*" {
      capabilities = ["read", "list"]
    }

    # Access child namespace secrets (Enterprise)
    path "+/${vault_mount.kv_v2.path}/data/shared/*" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Test 34: Audit-focused policy
################################################################################
resource "vault_policy" "auditor" {
  name = "${local.name_prefix}-auditor"

  policy = <<-EOT
    # Read-only access to system information
    path "sys/health" {
      capabilities = ["read"]
    }

    path "sys/host-info" {
      capabilities = ["read"]
    }

    path "sys/leader" {
      capabilities = ["read"]
    }

    path "sys/seal-status" {
      capabilities = ["read"]
    }

    # List mounts and auth methods
    path "sys/mounts" {
      capabilities = ["read"]
    }

    path "sys/auth" {
      capabilities = ["read"]
    }

    # List policies
    path "sys/policies/acl" {
      capabilities = ["list"]
    }

    path "sys/policies/acl/*" {
      capabilities = ["read"]
    }

    # Read audit device config
    path "sys/audit" {
      capabilities = ["read"]
    }

    # List leases (no revoke)
    path "sys/leases/lookup/*" {
      capabilities = ["list"]
    }
  EOT
}

################################################################################
# Test 35: Minimal token policy
################################################################################
resource "vault_policy" "minimal" {
  name = "${local.name_prefix}-minimal"

  policy = <<-EOT
    # Only allow self-lookup and renewal
    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }

    path "auth/token/renew-self" {
      capabilities = ["update"]
    }

    # Read single secret
    path "${vault_mount.kv_v2.path}/data/public/info" {
      capabilities = ["read"]
    }
  EOT
}

################################################################################
# Outputs
################################################################################

output "policy_names" {
  value = {
    readonly        = vault_policy.readonly.name
    full_access     = vault_policy.full_access.name
    db_reader       = vault_policy.db_reader.name
    aws_reader      = vault_policy.aws_reader.name
    transit_user    = vault_policy.transit_user.name
    pki_user        = vault_policy.pki_user.name
    admin           = vault_policy.admin.name
    service_account = vault_policy.service_account.name
    developer       = vault_policy.developer.name
    cicd            = vault_policy.cicd.name
    restricted      = vault_policy.restricted.name
    auditor         = vault_policy.auditor.name
    minimal         = vault_policy.minimal.name
  }
  description = "Policy names created"
}
