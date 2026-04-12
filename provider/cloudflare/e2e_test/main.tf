# main.tf - Cloudflare Provider Test Suite for Warden Cloudflare Gateway
# Tests Cloudflare API and R2 Object Storage operations through Warden's gateway
#
# Uses two provider types:
# - http: read-only API calls and edge case tests (Bearer token injection)
# - aws (S3 only): R2 Object Storage operations via SigV4 signing
#
# Cloudflare does not have a native Terraform provider that supports custom
# endpoints, so we use the http data source for REST API tests and the AWS
# provider for R2 (S3-compatible) operations.
#
# Prerequisites:
#   1. Hydra running (deploy/docker-compose.quickstart.yml)
#   2. Warden server running with Cloudflare provider mounted
#   3. Cloudflare credential source and spec configured (cloudflare_keys type)
#   4. JWT auth configured with a role bound to the credential spec
#
# Usage:
#   export TF_VAR_access_token="<your-jwt-token>"
#   terraform init && terraform apply

terraform {
  required_version = ">= 1.10"

  required_providers {
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
  }
}

################################################################################
# Variables
################################################################################

variable "warden_address" {
  type        = string
  description = "Warden Cloudflare gateway endpoint URL"
  default     = "http://localhost:8400/v1/cloudflare/role/cloudflare-user/gateway"
}

variable "access_token" {
  type        = string
  description = "JWT token for Warden authentication (transparent mode)"
  sensitive   = true
}

################################################################################
# Providers
################################################################################

# AWS provider for R2 Object Storage operations (SigV4 signing)
# Pointed at Warden's gateway — Warden detects the SigV4 Authorization header,
# verifies the client signature, re-signs with real Cloudflare R2 credentials,
# and forwards to <account_id>.r2.cloudflarestorage.com.
# The JWT is used as both access_key and secret_key (Warden transparent auth).
# R2 always uses region "auto" for SigV4 signing.
provider "aws" {
  region     = "auto"
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
  name_prefix = "warden-cf-test-${random_id.suffix.hex}"

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
  description = "Warden Cloudflare gateway URL used for testing"
}
