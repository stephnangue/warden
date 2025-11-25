# Test: EC2 Instance Lifecycle
# Features: Lifecycle hooks, prevent destroy, create before destroy

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

resource "aws_instance" "with_lifecycle" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-lifecycle"
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      user_data,
      tags["LastUpdated"]
    ]
  }
}

resource "aws_instance" "with_prevent_destroy" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-prevent-destroy"
  }

  # Uncomment to enable prevention
  # lifecycle {
  #   prevent_destroy = true
  # }
}

output "lifecycle_instance_id" {
  value = aws_instance.with_lifecycle.id
}

output "prevent_destroy_instance_id" {
  value = aws_instance.with_prevent_destroy.id
}
