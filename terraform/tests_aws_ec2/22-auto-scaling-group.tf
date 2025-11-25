# Test: EC2 Auto Scaling Group
# Features: Auto scaling group with launch template

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

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_launch_template" "asg_template" {
  name_prefix   = "ec2-test-asg-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ec2-test-asg-instance"
    }
  }
}

resource "aws_autoscaling_group" "test_asg" {
  name                = "ec2-test-asg"
  desired_capacity    = 1
  max_size            = 2
  min_size            = 1
  availability_zones  = [data.aws_availability_zones.available.names[0]]

  launch_template {
    id      = aws_launch_template.asg_template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "ec2-test-asg"
    propagate_at_launch = true
  }
}

output "asg_name" {
  value = aws_autoscaling_group.test_asg.name
}

output "launch_template_id" {
  value = aws_launch_template.asg_template.id
}
