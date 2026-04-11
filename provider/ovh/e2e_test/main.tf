# main.tf - OVH Provider Test Suite for Warden OVH Gateway
# Tests OVH API operations through Warden's OVH proxy/gateway
#
# Uses three provider types:
# - ovh: CRUD operations on OVH REST API (Bearer token injection via access_token)
# - http: read-only API calls and edge case tests
# - aws (S3 only): Object Storage operations via SigV4 signing
#
# The native OVH Terraform provider supports access_token (Bearer) authentication
# and custom endpoints, making it compatible with Warden's transparent auth.
# The AWS provider is used for S3 because OVH Object Storage is S3-compatible
# and Warden detects SigV4 signatures to proxy Object Storage requests.
#
# Prerequisites:
#   1. Hydra running (deploy/docker-compose.quickstart.yml)
#   2. Warden server running with OVH provider mounted
#   3. OVH credential source and spec configured (ovh_keys type)
#   4. JWT auth configured with a role bound to the credential spec
#
# Usage:
#   export TF_VAR_access_token="<your-jwt-token>"
#   export TF_VAR_ovh_service_name="<your-cloud-project-id>"
#   terraform init && terraform apply

terraform {
  required_version = ">= 1.10"

  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = ">= 1.0"
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
  }
}

################################################################################
# Variables
################################################################################

variable "warden_address" {
  type        = string
  description = "Warden OVH gateway endpoint URL"
  default     = "http://localhost:8400/v1/ovh/role/ovh-user/gateway"
}

variable "access_token" {
  type        = string
  description = "JWT token for Warden authentication (transparent mode)"
  sensitive   = true
}

variable "ovh_service_name" {
  type        = string
  description = "OVH Public Cloud project ID (service name)"
}

variable "ovh_region" {
  type        = string
  description = "OVH region for S3 Object Storage"
  default     = "gra"
}

################################################################################
# Providers
################################################################################

# OVH REST API via Warden gateway (for CRUD operations)
# With access_token mode, the OVH SDK sends a standard
# Authorization: Bearer header — Warden intercepts it, authenticates the JWT,
# and replaces it with the real OVH API token.
provider "ovh" {
  endpoint     = var.warden_address
  access_token = var.access_token
}

# AWS provider for S3 Object Storage operations (SigV4 signing)
# Pointed at Warden's gateway — Warden detects the SigV4 Authorization header,
# verifies the client signature, re-signs with real OVH S3 credentials, and
# forwards to s3.{region}.io.cloud.ovh.net.
# The JWT is used as both access_key and secret_key (Warden transparent auth).
provider "aws" {
  region     = var.ovh_region
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
  name_prefix = "warden-ovh-test-${random_id.suffix.hex}"

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
  description = "Warden OVH gateway URL used for testing"
}
