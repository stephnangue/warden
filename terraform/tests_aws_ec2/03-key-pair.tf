# Test: EC2 Instance with Key Pair
# Features: SSH key pair creation and assignment

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
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

resource "tls_private_key" "test_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "test_key" {
  key_name   = "ec2-test-key"
  public_key = tls_private_key.test_key.public_key_openssh
}

resource "aws_instance" "with_key" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  key_name      = aws_key_pair.test_key.key_name

  tags = {
    Name = "ec2-test-with-key"
  }
}

output "private_key_pem" {
  value     = tls_private_key.test_key.private_key_pem
  sensitive = true
}

output "instance_id" {
  value = aws_instance.with_key.id
}
