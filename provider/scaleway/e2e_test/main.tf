# main.tf - Scaleway Provider Test Suite for Warden Scaleway Gateway
# Tests Scaleway API operations through Warden's Scaleway proxy/gateway
#
# Uses three provider types:
# - restapi: CRUD operations on Scaleway standard API (X-Auth-Token injection)
# - http: read-only API calls and edge case tests
# - aws (S3 only): Object Storage operations via SigV4 signing
#
# The native Scaleway Terraform provider cannot be used because it validates
# that secret_key is a UUID, which conflicts with JWT-based transparent auth.
# The AWS provider is used for S3 because it performs SigV4 signing which is
# how Warden detects and proxies Object Storage requests.
#
# Prerequisites:
#   1. Hydra running (deploy/docker-compose.quickstart.yml)
#   2. Warden server running with Scaleway provider mounted
#   3. Scaleway credential source and spec configured
#   4. JWT auth configured with a role bound to the credential spec
#
# Usage:
#   export TF_VAR_access_token="<your-jwt-token>"
#   export TF_VAR_scaleway_project_id="<your-project-id>"
#   terraform init && terraform apply

terraform {
  required_version = ">= 1.10"

  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = ">= 1.20"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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
  description = "Warden Scaleway gateway endpoint URL"
  default     = "http://localhost:8400/v1/scaleway/role/scaleway-user/gateway"
}

variable "access_token" {
  type        = string
  description = "JWT token for Warden authentication (transparent mode)"
  sensitive   = true
}

variable "scaleway_project_id" {
  type        = string
  description = "Scaleway project ID for resource creation"
}

variable "scaleway_region" {
  type        = string
  description = "Scaleway region for resources"
  default     = "fr-par"
}

variable "scaleway_zone" {
  type        = string
  description = "Scaleway zone for zonal resources"
  default     = "fr-par-1"
}

variable "scaleway_organization_id" {
  type        = string
  description = "Scaleway organization ID (required for IAM operations)"
}

################################################################################
# Providers
################################################################################

# Scaleway standard API via Warden gateway (for CRUD operations)
# Warden authenticates via the Authorization: Bearer header, then injects
# the real X-Auth-Token for the upstream Scaleway API.
provider "restapi" {
  uri                  = var.warden_address
  write_returns_object = true
  create_method        = "POST"
  update_method        = "PATCH"
  destroy_method       = "DELETE"
  id_attribute         = "id"

  headers = {
    Content-Type  = "application/json"
    Accept        = "application/json"
    Authorization = "Bearer ${var.access_token}"
  }
}

# AWS provider for S3 Object Storage operations (SigV4 signing)
# Pointed at Warden's gateway — Warden detects the SigV4 Authorization header,
# verifies the client signature, re-signs with real Scaleway credentials, and
# forwards to s3.{region}.scw.cloud.
# The JWT is used as both access_key and secret_key (Warden transparent auth).
provider "aws" {
  region     = var.scaleway_region
  access_key = var.access_token
  secret_key = var.access_token

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true

  endpoints {
    s3 = var.warden_address
  }

  s3_use_path_style = true
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
  name_prefix = "warden-scw-test-${random_id.suffix.hex}"

  # Common headers for http data source requests
  common_headers = {
    Accept        = "application/json"
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
  description = "Warden Scaleway gateway URL used for testing"
}
