# Test: EC2 Instance with Launch Template
# Features: Launch template with versioning

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

resource "aws_launch_template" "test_template" {
  name          = "ec2-test-launch-template"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ec2-test-from-template"
    }
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              echo "Launched from template" > /tmp/launch-info.txt
              EOF
  )
}

resource "aws_instance" "from_template" {
  launch_template {
    id      = aws_launch_template.test_template.id
    version = "$Latest"
  }
}

output "launch_template_id" {
  value = aws_launch_template.test_template.id
}

output "instance_id" {
  value = aws_instance.from_template.id
}
