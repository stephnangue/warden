# Test: EC2 Instances with Different Architectures
# Features: x86_64 and ARM64 (Graviton) architectures

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_ami" "amazon_linux_2023_x86" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_ami" "amazon_linux_2023_arm" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

resource "aws_instance" "x86_instance" {
  ami           = data.aws_ami.amazon_linux_2023_x86.id
  instance_type = "t2.micro" # x86_64 based

  tags = {
    Name         = "ec2-test-x86"
    Architecture = "x86_64"
  }
}

resource "aws_instance" "arm_instance" {
  ami           = data.aws_ami.amazon_linux_2023_arm.id
  instance_type = "t4g.micro" # ARM64 Graviton based (cheaper than x86)

  tags = {
    Name         = "ec2-test-arm"
    Architecture = "arm64"
  }
}

output "x86_instance_id" {
  value = aws_instance.x86_instance.id
}

output "arm_instance_id" {
  value = aws_instance.arm_instance.id
}
