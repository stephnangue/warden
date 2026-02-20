# main.tf - GitHub Provider Test Suite for Warden GitHub Gateway
# Tests GitHub API operations through Warden's GitHub proxy/gateway
#
# Usage:
#   1. Start Warden server with GitHub provider mounted
#   2. Register a GitHub credential source and spec
#   3. Obtain a Warden access token (JWT for transparent mode)
#   4. Run:
#        export TF_VAR_access_token="<your-jwt-token>"
#        export TF_VAR_github_owner="<your-github-username-or-org>"
#        terraform init && terraform apply

terraform {
  required_version = ">= 1.10"

  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = ">= 1.20"
    }
    http = {
      source  = "hashicorp/http"
      version = ">= 3.0"
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

################################################################################
# Variables
################################################################################

variable "warden_address" {
  type        = string
  description = "Warden GitHub gateway endpoint URL"
  default     = "http://localhost:8400/v1/PROD/DEV/github/role/github-pat/gateway"
}

variable "access_token" {
  type        = string
  description = "JWT token for Warden authentication (transparent mode)"
  sensitive   = true
}

variable "github_owner" {
  type        = string
  description = "GitHub owner (user or organization) for repository operations"
}

################################################################################
# Providers
################################################################################

# GitHub REST API via Warden gateway
provider "restapi" {
  uri                  = var.warden_address
  write_returns_object = true
  create_method        = "POST"
  update_method        = "PATCH"
  destroy_method       = "DELETE"
  id_attribute         = "name"

  headers = {
    Content-Type  = "application/json"
    Accept        = "application/vnd.github+json"
    Authorization = "Bearer ${var.access_token}"
  }
}

################################################################################
# Random suffix for unique naming
################################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

################################################################################
# Locals
################################################################################

locals {
  name_prefix = "warden-gh-test-${random_id.suffix.hex}"

  # Base path for repository operations
  repos_base = "/repos/${var.github_owner}"

  # Common headers for data "http" requests
  common_headers = {
    Accept        = "application/vnd.github+json"
    Authorization = "Bearer ${var.access_token}"
  }
}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "Name prefix used for all test resources"
}

output "test_timestamp" {
  value       = timestamp()
  description = "Timestamp when tests were run"
}

output "warden_gateway_url" {
  value       = var.warden_address
  description = "Warden GitHub gateway URL used for testing"
}
