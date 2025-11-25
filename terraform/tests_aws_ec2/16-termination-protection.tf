# Test: EC2 Instance with Termination Protection
# Features: Disable API termination, stop protection

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

resource "aws_instance" "with_protection" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  disable_api_termination = true
  disable_api_stop        = false

  tags = {
    Name = "ec2-test-termination-protection"
  }
}

output "instance_id" {
  value = aws_instance.with_protection.id
}

output "termination_protection" {
  value = aws_instance.with_protection.disable_api_termination
}
