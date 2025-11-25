# Test: EC2 Data Lifecycle Manager (DLM)
# Features: Automated EBS snapshot lifecycle policy

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

data "aws_iam_policy_document" "dlm_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "dlm_lifecycle_role" {
  name               = "ec2-test-dlm-lifecycle-role"
  assume_role_policy = data.aws_iam_policy_document.dlm_assume_role.json
}

resource "aws_iam_role_policy_attachment" "dlm_lifecycle" {
  role       = aws_iam_role.dlm_lifecycle_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_instance" "test_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tags = {
    Name       = "ec2-test-dlm"
    Backup     = "daily"
  }
}

resource "aws_dlm_lifecycle_policy" "snapshot_policy" {
  description        = "Daily snapshot policy"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "Daily snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }

      retain_rule {
        count = 7
      }

      tags_to_add = {
        SnapshotType = "DailyBackup"
      }

      copy_tags = true
    }

    target_tags = {
      Backup = "daily"
    }
  }

  tags = {
    Name = "ec2-test-snapshot-policy"
  }
}

output "instance_id" {
  value = aws_instance.test_instance.id
}

output "dlm_policy_id" {
  value = aws_dlm_lifecycle_policy.snapshot_policy.id
}
