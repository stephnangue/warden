# Test: EC2 Capacity Reservation
# Features: On-demand capacity reservation

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

resource "aws_ec2_capacity_reservation" "test_reservation" {
  instance_type     = "t2.micro"
  instance_platform = "Linux/UNIX"
  availability_zone = "us-east-1a"
  instance_count    = 1

  tags = {
    Name = "ec2-test-capacity-reservation"
  }
}

resource "aws_instance" "with_reservation" {
  ami               = data.aws_ami.amazon_linux_2023.id
  instance_type     = "t2.micro"
  availability_zone = "us-east-1a"

  capacity_reservation_specification {
    capacity_reservation_target {
      capacity_reservation_id = aws_ec2_capacity_reservation.test_reservation.id
    }
  }

  tags = {
    Name = "ec2-test-with-reservation"
  }
}

output "capacity_reservation_id" {
  value = aws_ec2_capacity_reservation.test_reservation.id
}

output "instance_id" {
  value = aws_instance.with_reservation.id
}
