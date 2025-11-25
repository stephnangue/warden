# Test: EC2 Instance with Instance Store (Ephemeral Storage)
# Features: Instance store volumes (ephemeral)

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

# Note: Most cheap instance types don't have instance store
# c5d.large is one of the cheapest with instance store (~$0.096/hr)
# Uncomment to test, but be aware of the cost

# resource "aws_instance" "with_instance_store" {
#   ami           = data.aws_ami.amazon_linux_2023.id
#   instance_type = "c5d.large" # Has NVMe instance store
#
#   ephemeral_block_device {
#     device_name  = "/dev/sdc"
#     virtual_name = "ephemeral0"
#   }
#
#   tags = {
#     Name = "ec2-test-instance-store"
#   }
# }

# For testing purposes, create a regular instance
resource "aws_instance" "test_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-no-instance-store"
    Note = "Instance store requires larger instance types like c5d.large"
  }
}

output "instance_id" {
  value = aws_instance.test_instance.id
}

# output "instance_store_instance_id" {
#   value = aws_instance.with_instance_store.id
# }
