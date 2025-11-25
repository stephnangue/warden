# Test: EC2 Instance with Multiple Security Groups
# Features: Multiple security group associations

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # S3 Backend Configuration
  backend "s3" {
    bucket         = "bucket-tutorial-us-east-1-905418489750"
    key            = "ec2-multiple-sg/terraform.tfstate"
    region         = "us-east-1"
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

resource "aws_instance" "with_user_data" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Hello from EC2 User Data</h1>" > /var/www/html/index.html
              EOF

  user_data_replace_on_change = true

  tags = {
    Name = "ec2-test-user-data"
  }
}

output "instance_id" {
  value = aws_instance.with_user_data.id
}

output "public_ip" {
  value = aws_instance.with_user_data.public_ip
}

