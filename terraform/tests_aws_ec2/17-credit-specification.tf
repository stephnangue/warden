# Test: EC2 Instance with Credit Specification
# Features: T2/T3 unlimited mode for burstable instances

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

resource "aws_instance" "unlimited_credits" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  credit_specification {
    cpu_credits = "unlimited"
  }

  tags = {
    Name = "ec2-test-unlimited-credits"
  }
}

resource "aws_instance" "standard_credits" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  credit_specification {
    cpu_credits = "standard"
  }

  tags = {
    Name = "ec2-test-standard-credits"
  }
}

output "unlimited_instance_id" {
  value = aws_instance.unlimited_credits.id
}

output "standard_instance_id" {
  value = aws_instance.standard_credits.id
}
