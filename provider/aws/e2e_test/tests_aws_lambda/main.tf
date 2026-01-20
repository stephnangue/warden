# main.tf
# Main configuration for Lambda Comprehensive Test Suite

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
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # S3 Backend Configuration
  backend "s3" {
    bucket = "bucket-tutorial-us-east-1-905418489750"
    key    = "lambda-tests/terraform.tfstate"
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
  default     = "warden-lambda-test"
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
# Base IAM Role for Lambda functions
################################################################################
resource "aws_iam_role" "lambda_basic" {
  name = "${local.name_prefix}-lambda-basic"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Lambda Basic Role"
    Description = "Basic execution role for Lambda functions"
  }
}

# Basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_basic.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC execution policy for VPC-enabled functions
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_basic.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

################################################################################
# VPC for Lambda functions
################################################################################
resource "aws_vpc" "lambda" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_subnet" "lambda_1" {
  vpc_id            = aws_vpc.lambda.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "${local.name_prefix}-subnet-1"
  }
}

resource "aws_subnet" "lambda_2" {
  vpc_id            = aws_vpc.lambda.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "${local.name_prefix}-subnet-2"
  }
}

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Security group for Lambda functions"
  vpc_id      = aws_vpc.lambda.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-lambda-sg"
  }
}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "The name prefix used for all Lambda resources"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID"
}

output "region" {
  value       = data.aws_region.current.name
  description = "AWS Region"
}

output "lambda_role_arn" {
  value       = aws_iam_role.lambda_basic.arn
  description = "Basic Lambda execution role ARN"
}

output "vpc_id" {
  value       = aws_vpc.lambda.id
  description = "VPC ID for Lambda functions"
}

output "subnet_ids" {
  value       = [aws_subnet.lambda_1.id, aws_subnet.lambda_2.id]
  description = "Subnet IDs for Lambda functions"
}

output "security_group_id" {
  value       = aws_security_group.lambda.id
  description = "Security group ID for Lambda functions"
}
