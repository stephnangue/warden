# Test: EC2 Instance with EBS Volumes
# Features: EBS volume creation, attachment, root block device configuration

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

resource "aws_instance" "with_ebs" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  ebs_block_device {
    device_name           = "/dev/sdf"
    volume_size           = 8
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name = "ec2-test-ebs"
  }
}

resource "aws_ebs_volume" "additional" {
  availability_zone = aws_instance.with_ebs.availability_zone
  size              = 8
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "ec2-test-additional-volume"
  }
}

resource "aws_volume_attachment" "additional" {
  device_name = "/dev/sdg"
  volume_id   = aws_ebs_volume.additional.id
  instance_id = aws_instance.with_ebs.id
}

output "instance_id" {
  value = aws_instance.with_ebs.id
}

output "volume_id" {
  value = aws_ebs_volume.additional.id
}
