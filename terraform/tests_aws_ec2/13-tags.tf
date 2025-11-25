# Test: EC2 Instance with Extensive Tagging
# Features: Multiple tags, volume tags

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

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "with_tags" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name        = "ec2-test-tags"
    Environment = "test"
    Project     = "ec2-testing"
    Owner       = "terraform"
    CostCenter  = "engineering"
    Application = "test-suite"
  }

  volume_tags = {
    Name        = "ec2-test-volume"
    Environment = "test"
    VolumeType  = "root"
  }
}

output "instance_id" {
  value = aws_instance.with_tags.id
}

output "instance_tags" {
  value = aws_instance.with_tags.tags
}
