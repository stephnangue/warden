# Test: EC2 Instance Tenancy Options
# Features: Dedicated vs shared tenancy

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

resource "aws_instance" "default_tenancy" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  tenancy       = "default"

  tags = {
    Name    = "ec2-test-default-tenancy"
    Tenancy = "default"
  }
}

# Note: Dedicated tenancy is much more expensive
# Uncomment only if you need to test it
# resource "aws_instance" "dedicated_tenancy" {
#   ami           = data.aws_ami.amazon_linux_2023.id
#   instance_type = "t2.micro"
#   tenancy       = "dedicated"
#
#   tags = {
#     Name    = "ec2-test-dedicated-tenancy"
#     Tenancy = "dedicated"
#   }
# }

output "default_instance_id" {
  value = aws_instance.default_tenancy.id
}

output "default_tenancy" {
  value = aws_instance.default_tenancy.tenancy
}
