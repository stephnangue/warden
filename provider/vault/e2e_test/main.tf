# main.tf - HashiCorp Vault Test Suite for Warden Vault Gateway Provider
# Tests Vault operations through Warden's Vault proxy/gateway

terraform {
  required_version = ">= 1.10"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.5"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9"
    }
  }
}

# Configure Vault provider
# When testing through Warden, set VAULT_ADDR to Warden's gateway endpoint
# e.g., VAULT_ADDR=http://localhost:5000/v1/vault/gateway
provider "vault" {
  # Skip child token creation - use the token directly
  skip_child_token = true

  # Skip TLS verification for dev/test environments
  skip_tls_verify = true
}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "warden-vault-test-${random_id.suffix.hex}"

  # Common tags for all resources
  common_metadata = {
    project    = "warden-vault-tests"
    managed_by = "terraform"
    test_suite = "vault-gateway"
  }
}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "Name prefix used for all resources"
}

output "test_timestamp" {
  value       = timestamp()
  description = "Timestamp when tests were run"
}
