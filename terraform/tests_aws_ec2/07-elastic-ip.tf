# Test: EC2 Instance with Elastic IP
# Features: Elastic IP allocation and association

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

resource "aws_instance" "with_eip" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-eip"
  }
}

resource "aws_eip" "test_eip" {
  domain   = "vpc"
  instance = aws_instance.with_eip.id

  tags = {
    Name = "ec2-test-eip"
  }
}

output "instance_id" {
  value = aws_instance.with_eip.id
}

output "elastic_ip" {
  value = aws_eip.test_eip.public_ip
}

output "eip_allocation_id" {
  value = aws_eip.test_eip.id
}
