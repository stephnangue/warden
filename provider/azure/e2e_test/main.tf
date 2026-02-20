# main.tf - Azure Test Suite for Warden Azure Gateway Provider
# Tests Azure operations through Warden's Azure proxy/gateway
#
# Usage:
#   1. Start Warden server with Azure provider mounted
#   2. Register an Azure credential source and spec
#   3. Obtain a Warden access token
#   4. Run:
#        export TF_VAR_access_token="<your-access-token>"
#        export TF_VAR_subscription_id="<your-azure-subscription-id>"
#        terraform init && terraform apply

terraform {
  required_version = ">= 1.10"

  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = ">= 1.20"
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
  description = "Warden gateway base URL"
  default     = "http://localhost:8400/v1/PROD/DEV/azure/role/azure-ops/gateway"
}

variable "access_token" {
  type        = string
  description = "Warden access token for authentication"
  sensitive   = true
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID"
}

variable "location" {
  type        = string
  description = "Azure region for resource deployment"
  default     = "eastus"
}

variable "keyvault_name" {
  type        = string
  description = "Name of an existing Key Vault (for data-plane tests)"
  default     = ""
}

variable "storage_account_name" {
  type        = string
  description = "Name of an existing storage account (for blob tests)"
  default     = ""
}

variable "tenant_id" {
  type        = string
  description = "Azure AD tenant ID (used for Key Vault access policies)"
  default     = ""
}

variable "object_id" {
  type        = string
  description = "Azure AD object ID of the service principal (for Key Vault access policies)"
  default     = ""
}

################################################################################
# Providers
################################################################################

# Azure Resource Manager (management.azure.com)
provider "restapi" {
  uri                  = "${var.warden_address}/management.azure.com"
  write_returns_object = false
  create_method        = "PUT"
  update_method        = "PUT"
  destroy_method       = "DELETE"
  id_attribute         = "name"

  headers = {
    Content-Type   = "application/json"
    Authorization = "Bearer ${var.access_token}"
  }
}

# Microsoft Graph API (graph.microsoft.com)
provider "restapi" {
  alias                = "graph"
  uri                  = "${var.warden_address}/graph.microsoft.com"
  write_returns_object = true
  id_attribute         = "id"

  headers = {
    Content-Type   = "application/json"
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
  name_prefix = "warden-azure-test-${random_id.suffix.hex}"
  arm_base    = "/subscriptions/${var.subscription_id}"

  common_tags = {
    Project     = "warden-azure-tests"
    ManagedBy   = "terraform"
    TestSuite   = "azure-gateway"
    Environment = "test"
  }

  warden_gateway = "${var.warden_address}"
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

output "warden_gateway_url" {
  value       = local.warden_gateway
  description = "Warden Azure gateway base URL"
}
