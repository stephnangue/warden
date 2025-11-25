# Test: EC2 Instance Connect Endpoint
# Features: EC2 Instance Connect endpoint for secure SSH access

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
    Name = "ec2-test-eice-vpc"
  }
}

resource "aws_subnet" "test_subnet" {
  vpc_id            = aws_vpc.test_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "ec2-test-eice-subnet"
  }
}

resource "aws_security_group" "eice_sg" {
  name        = "ec2-test-eice-sg"
  description = "Security group for EC2 Instance Connect Endpoint"
  vpc_id      = aws_vpc.test_vpc.id

  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = {
    Name = "ec2-test-eice-sg"
  }
}

resource "aws_security_group" "instance_sg" {
  name        = "ec2-test-instance-sg"
  description = "Allow SSH from EICE"
  vpc_id      = aws_vpc.test_vpc.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.eice_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ec2-test-instance-sg"
  }
}

resource "aws_ec2_instance_connect_endpoint" "test_eice" {
  subnet_id          = aws_subnet.test_subnet.id
  security_group_ids = [aws_security_group.eice_sg.id]

  tags = {
    Name = "ec2-test-eice"
  }
}

resource "aws_instance" "with_eice" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.test_subnet.id
  vpc_security_group_ids = [aws_security_group.instance_sg.id]

  tags = {
    Name = "ec2-test-with-eice"
  }
}

output "eice_id" {
  value = aws_ec2_instance_connect_endpoint.test_eice.id
}

output "instance_id" {
  value = aws_instance.with_eice.id
}
