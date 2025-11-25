# Test: EC2 Instance with EBS Optimization
# Features: EBS optimized instance

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

resource "aws_instance" "ebs_optimized" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro" # t3 instances are EBS optimized by default
  ebs_optimized = true

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name = "ec2-test-ebs-optimized"
  }
}

output "instance_id" {
  value = aws_instance.ebs_optimized.id
}

output "ebs_optimized" {
  value = aws_instance.ebs_optimized.ebs_optimized
}
