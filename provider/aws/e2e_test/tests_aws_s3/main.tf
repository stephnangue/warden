# main.tf
# Main configuration for S3 Comprehensive Test Suite

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
    key    = "ec2-tests/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {}
  }
}

# Secondary provider for cross-region replication tests
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
  default     = "warden-s3-test"
}

variable "test_content" {
  description = "Test content for S3 objects"
  type        = string
  default     = "Hello from Warden S3 proxy!"
}

# Generate random suffix for unique bucket names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_prefix = "${var.test_prefix}-${random_id.suffix.hex}"
}

# Get current AWS account identity
data "aws_caller_identity" "current" {}

# Get current region
data "aws_region" "current" {}

################################################################################
# Outputs
################################################################################

output "bucket_prefix" {
  value       = local.bucket_prefix
  description = "The bucket prefix used for all S3 resources"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID"
}

output "region" {
  value       = data.aws_region.current.name
  description = "AWS Region"
}
