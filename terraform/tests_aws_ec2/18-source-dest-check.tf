# Test: EC2 Instance with Source/Dest Check Disabled
# Features: Disable source/destination check (for NAT instances)

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

resource "aws_vpc" "test_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "ec2-test-vpc-srcdes"
  }
}

resource "aws_subnet" "test_subnet" {
  vpc_id            = aws_vpc.test_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "ec2-test-subnet-srcdest"
  }
}

resource "aws_instance" "nat_instance" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.test_subnet.id
  source_dest_check      = false

  tags = {
    Name = "ec2-test-nat-instance"
  }
}

output "instance_id" {
  value = aws_instance.nat_instance.id
}

output "source_dest_check" {
  value = aws_instance.nat_instance.source_dest_check
}
