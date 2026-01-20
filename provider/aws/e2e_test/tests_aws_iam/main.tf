# main.tf - IAM Test Suite for Warden AWS Proxy
# Tests IAM service through the generic processor
# IAM is a global service - always routes to iam.amazonaws.com with us-east-1 signing

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
      Project     = "warden-iam-tests"
      ManagedBy   = "terraform"
      TestSuite   = "iam"
    }
  }
}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "warden-iam-test-${random_id.suffix.hex}"
}

# Data sources
data "aws_caller_identity" "current" {}
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

output "partition" {
  value       = data.aws_partition.current.partition
  description = "AWS Partition"
}
