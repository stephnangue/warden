# Test: EC2 Instance with Metadata Options
# Features: IMDSv2, metadata options configuration

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

resource "aws_instance" "with_metadata_options" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name        = "ec2-test-metadata"
    Environment = "test"
  }
}

output "instance_id" {
  value = aws_instance.with_metadata_options.id
}

output "metadata_options" {
  value = aws_instance.with_metadata_options.metadata_options
}
