# Test: EC2 Fleet
# Features: EC2 Fleet with spot and on-demand mix

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

resource "aws_ec2_fleet" "test_fleet" {
  launch_template_config {
    launch_template_specification {
      launch_template_id = aws_launch_template.fleet_template.id
      version            = "$Latest"
    }

    override {
      instance_type = "t2.micro"
      max_price     = "0.05"
    }

    override {
      instance_type = "t3.micro"
      max_price     = "0.05"
    }
  }

  target_capacity_specification {
    default_target_capacity_type = "spot"
    total_target_capacity        = 2
    spot_target_capacity         = 2
  }

  spot_options {
    allocation_strategy = "lowest-price"
    instance_interruption_behavior = "terminate"
  }

  type = "maintain"

  tags = {
    Name = "ec2-test-fleet"
  }
}

resource "aws_launch_template" "fleet_template" {
  name          = "ec2-test-fleet-template"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ec2-test-fleet-instance"
    }
  }
}

output "fleet_id" {
  value = aws_ec2_fleet.test_fleet.id
}

output "launch_template_id" {
  value = aws_launch_template.fleet_template.id
}
