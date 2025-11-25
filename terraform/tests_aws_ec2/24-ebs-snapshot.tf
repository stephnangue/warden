# Test: EC2 EBS Snapshot Management
# Features: EBS snapshots, volume from snapshot

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

resource "aws_instance" "test_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "ec2-test-snapshot"
  }
}

resource "aws_ebs_volume" "test_volume" {
  availability_zone = aws_instance.test_instance.availability_zone
  size              = 8
  type              = "gp3"

  tags = {
    Name = "ec2-test-volume-for-snapshot"
  }
}

resource "aws_volume_attachment" "test_attachment" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.test_volume.id
  instance_id = aws_instance.test_instance.id
}

resource "aws_ebs_snapshot" "test_snapshot" {
  volume_id = aws_ebs_volume.test_volume.id

  tags = {
    Name = "ec2-test-snapshot"
  }
}

resource "aws_ebs_volume" "from_snapshot" {
  availability_zone = aws_instance.test_instance.availability_zone
  snapshot_id       = aws_ebs_snapshot.test_snapshot.id

  tags = {
    Name = "ec2-test-volume-from-snapshot"
  }
}

output "instance_id" {
  value = aws_instance.test_instance.id
}

output "snapshot_id" {
  value = aws_ebs_snapshot.test_snapshot.id
}

output "restored_volume_id" {
  value = aws_ebs_volume.from_snapshot.id
}
