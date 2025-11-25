# Test: EC2 Instance with IAM Role
# Features: IAM role, instance profile, assume role policy

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

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ec2_role" {
  name               = "ec2-test-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Name = "ec2-test-role"
  }
}

data "aws_iam_policy_document" "s3_read_only" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "s3_policy" {
  name   = "s3-read-only"
  role   = aws_iam_role.ec2_role.id
  policy = data.aws_iam_policy_document.s3_read_only.json
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-test-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_instance" "with_iam_role" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  tags = {
    Name = "ec2-test-iam-role"
  }
}

output "instance_id" {
  value = aws_instance.with_iam_role.id
}

output "role_arn" {
  value = aws_iam_role.ec2_role.arn
}
