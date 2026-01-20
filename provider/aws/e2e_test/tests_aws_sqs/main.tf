# main.tf
# Main configuration for SQS Comprehensive Test Suite

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # S3 Backend Configuration
  backend "s3" {
    bucket = "bucket-tutorial-us-east-1-905418489750"
    key    = "sqs-tests/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {}
  }
}

# Secondary provider for cross-region tests
provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"

  default_tags {
    tags = {}
  }
}

variable "test_prefix" {
  description = "Prefix for test resources"
  type        = string
  default     = "warden-sqs-test"
}

# Generate random suffix for unique names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "${var.test_prefix}-${random_id.suffix.hex}"
}

# Get current AWS account identity
data "aws_caller_identity" "current" {}

# Get current region
data "aws_region" "current" {}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "The name prefix used for all SQS resources"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID"
}

output "region" {
  value       = data.aws_region.current.name
  description = "AWS Region"
}
