# Test: Basic EC2 Instance
# Features: Launch a simple EC2 instance with minimal configuration

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

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "basic" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name        = "ec2-test-basic"
    Environment = "test"
  }
}

output "instance_id" {
  value = aws_instance.basic.id
}

output "public_ip" {
  value = aws_instance.basic.public_ip
}
