# Test: EC2 Instance with Nitro Enclaves
# Features: AWS Nitro Enclaves enabled

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

resource "aws_instance" "with_enclave" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro" # Nitro-based instance required

  enclave_options {
    enabled = true
  }

  tags = {
    Name = "ec2-test-enclave"
  }
}

output "instance_id" {
  value = aws_instance.with_enclave.id
}

output "enclave_enabled" {
  value = aws_instance.with_enclave.enclave_options
}
