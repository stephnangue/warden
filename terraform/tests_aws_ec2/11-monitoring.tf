# Test: EC2 Instance with Enhanced Monitoring
# Features: Detailed monitoring enabled

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

resource "aws_instance" "with_monitoring" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  monitoring    = true

  tags = {
    Name = "ec2-test-monitoring"
  }
}

output "instance_id" {
  value = aws_instance.with_monitoring.id
}

output "monitoring_enabled" {
  value = aws_instance.with_monitoring.monitoring
}
