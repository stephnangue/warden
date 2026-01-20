# main.tf - CloudWatch Test Suite for Warden AWS Proxy
# Tests CloudWatch and CloudWatch Logs through the generic processor
# CloudWatch uses JSON-RPC protocol with X-Amz-Target headers

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "warden-cloudwatch-tests"
      ManagedBy   = "terraform"
      TestSuite   = "cloudwatch"
    }
  }
}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "warden-cw-test-${random_id.suffix.hex}"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "Name prefix used for all resources"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID"
}

output "region" {
  value       = data.aws_region.current.name
  description = "AWS Region"
}
