# Test: EC2 Spot Instance
# Features: Spot instance request (cheaper than on-demand)

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

resource "aws_spot_instance_request" "test_spot" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  spot_type            = "one-time"
  wait_for_fulfillment = true

  tags = {
    Name = "ec2-test-spot-request"
  }
}

output "spot_request_id" {
  value = aws_spot_instance_request.test_spot.id
}

output "spot_instance_id" {
  value = aws_spot_instance_request.test_spot.spot_instance_id
}

output "spot_price" {
  value = aws_spot_instance_request.test_spot.spot_price
}
