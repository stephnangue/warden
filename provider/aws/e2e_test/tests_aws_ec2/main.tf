# main.tf
# Main configuration for EC2 Comprehensive Test Suite

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

variable "test_prefix" {
  description = "Prefix for test resources"
  type        = string
  default     = "warden-ec2-test"
}

# Generate random suffix for unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "${var.test_prefix}-${random_id.suffix.hex}"
}

# Get current AWS account identity
data "aws_caller_identity" "current" {}

# Get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Amazon Linux 2023 AMI - x86_64
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Amazon Linux 2023 AMI - ARM64
data "aws_ami" "amazon_linux_2023_arm" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

################################################################################
# Shared VPC Infrastructure
# These resources are shared across all EC2 test files
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name       = "${local.name_prefix}-vpc"
    TestNumber = "VPC"
  }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name       = "${local.name_prefix}-subnet-main"
    TestNumber = "Subnet-1"
  }
}

resource "aws_subnet" "secondary" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name       = "${local.name_prefix}-subnet-secondary"
    TestNumber = "Subnet-2"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-igw"
    TestNumber = "IGW"
  }
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name       = "${local.name_prefix}-rt"
    TestNumber = "RouteTable"
  }
}

resource "aws_route_table_association" "main" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.main.id
}

resource "aws_route_table_association" "secondary" {
  subnet_id      = aws_subnet.secondary.id
  route_table_id = aws_route_table.main.id
}

################################################################################
# Shared Security Group
# Basic security group used across multiple test files
################################################################################

resource "aws_security_group" "basic" {
  name        = "${local.name_prefix}-sg-basic"
  description = "Basic security group for EC2 tests"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name       = "${local.name_prefix}-sg-basic"
    TestNumber = "SG-Basic"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.basic.id
  description       = "SSH access"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.basic.id
  description       = "HTTP access"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all_outbound" {
  security_group_id = aws_security_group.basic.id
  description       = "Allow all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

################################################################################
# Outputs
################################################################################

output "name_prefix" {
  value       = local.name_prefix
  description = "The name prefix used for all resources"
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID"
}

output "ami_x86_64" {
  value       = data.aws_ami.amazon_linux_2023.id
  description = "Amazon Linux 2023 x86_64 AMI ID"
}

output "ami_arm64" {
  value       = data.aws_ami.amazon_linux_2023_arm.id
  description = "Amazon Linux 2023 ARM64 AMI ID"
}

output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID"
}

output "subnet_ids" {
  value = {
    main      = aws_subnet.main.id
    secondary = aws_subnet.secondary.id
  }
  description = "Subnet IDs"
}

output "basic_security_group_id" {
  value       = aws_security_group.basic.id
  description = "Basic security group ID"
}
