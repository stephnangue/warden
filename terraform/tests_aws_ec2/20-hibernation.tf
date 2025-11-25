# Test: EC2 Instance with Hibernation
# Features: Hibernation enabled

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

resource "aws_instance" "with_hibernation" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"

  hibernation = true

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true # Hibernation requires encrypted root volume
  }

  tags = {
    Name = "ec2-test-hibernation"
  }
}

output "instance_id" {
  value = aws_instance.with_hibernation.id
}

output "hibernation_enabled" {
  value = aws_instance.with_hibernation.hibernation
}
