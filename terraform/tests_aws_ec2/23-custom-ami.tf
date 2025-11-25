# Test: EC2 AMI Creation from Instance
# Features: AMI creation, instance from custom AMI

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

resource "aws_instance" "source_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  user_data = <<-EOF
              #!/bin/bash
              echo "Source instance for AMI" > /tmp/source-marker.txt
              EOF

  tags = {
    Name = "ec2-test-ami-source"
  }
}

resource "aws_ami_from_instance" "custom_ami" {
  name               = "ec2-test-custom-ami"
  source_instance_id = aws_instance.source_instance.id
  snapshot_without_reboot = true

  tags = {
    Name = "ec2-test-custom-ami"
  }
}

resource "aws_instance" "from_custom_ami" {
  ami           = aws_ami_from_instance.custom_ami.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-from-custom-ami"
  }
}

output "source_instance_id" {
  value = aws_instance.source_instance.id
}

output "custom_ami_id" {
  value = aws_ami_from_instance.custom_ami.id
}

output "new_instance_id" {
  value = aws_instance.from_custom_ami.id
}
