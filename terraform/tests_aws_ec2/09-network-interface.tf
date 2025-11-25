# Test: EC2 Instance with Network Interface
# Features: Elastic network interface (ENI), multiple private IPs

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
    Name = "ec2-test-eni-vpc"
  }
}

resource "aws_subnet" "test_subnet" {
  vpc_id            = aws_vpc.test_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "ec2-test-eni-subnet"
  }
}

resource "aws_network_interface" "test_eni" {
  subnet_id = aws_subnet.test_subnet.id
  private_ips = [
    "10.0.1.10",
    "10.0.1.11"
  ]

  tags = {
    Name = "ec2-test-eni"
  }
}

resource "aws_instance" "with_eni" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  network_interface {
    network_interface_id = aws_network_interface.test_eni.id
    device_index         = 0
  }

  tags = {
    Name = "ec2-test-with-eni"
  }
}

output "instance_id" {
  value = aws_instance.with_eni.id
}

output "eni_id" {
  value = aws_network_interface.test_eni.id
}

output "private_ips" {
  value = aws_network_interface.test_eni.private_ips
}
