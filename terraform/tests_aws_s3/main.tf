# main.tf
# Main configuration for S3 Comprehensive Test Suite

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  
  # Prevent automatic tag management to avoid tag listing issues
  default_tags {
    tags = {}
  }
}

# Secondary provider for cross-region replication
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
  description = "Test content for objects"
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
