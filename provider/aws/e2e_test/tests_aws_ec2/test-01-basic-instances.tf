# test-01-basic-instances.tf
# Tests: Basic EC2 instances, instance options, monitoring, metadata, tags, architectures
# Consolidates: 01-basic-instance, 11-monitoring, 12-metadata-options, 13-tags, 14-architectures,
#               16-termination-protection, 17-credit-specification, 18-source-dest-check,
#               19-ebs-optimized, 20-hibernation, 04-user-data

################################################################################
# Test 1: Basic EC2 Instance - minimal configuration
################################################################################
resource "aws_instance" "basic" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-basic"
    TestNumber = "01"
  }
}

################################################################################
# Test 2: Instance with detailed monitoring enabled
################################################################################
resource "aws_instance" "with_monitoring" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]
  monitoring             = true

  tags = {
    Name       = "${local.name_prefix}-monitoring"
    TestNumber = "02"
  }
}

################################################################################
# Test 3: Instance with IMDSv2 metadata options
################################################################################
resource "aws_instance" "with_metadata_options" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name       = "${local.name_prefix}-metadata"
    TestNumber = "03"
  }
}

################################################################################
# Test 4: Instance with multiple tags
################################################################################
resource "aws_instance" "with_tags" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name        = "${local.name_prefix}-tags"
    TestNumber  = "04"
    Department  = "Engineering"
    CostCenter  = "12345"
    Owner       = "test-team"
    Application = "warden-test"
  }
}

################################################################################
# Test 5: ARM64 architecture instance - Graviton
################################################################################
resource "aws_instance" "arm64" {
  ami                    = data.aws_ami.amazon_linux_2023_arm.id
  instance_type          = "t4g.micro" # Graviton2
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name         = "${local.name_prefix}-arm64"
    TestNumber   = "05"
    Architecture = "arm64"
  }
}

################################################################################
# Test 6: Instance with termination protection
################################################################################
resource "aws_instance" "termination_protection" {
  ami                     = data.aws_ami.amazon_linux_2023.id
  instance_type           = "t2.micro"
  subnet_id               = aws_subnet.main.id
  vpc_security_group_ids  = [aws_security_group.basic.id]
  disable_api_termination = true

  tags = {
    Name       = "${local.name_prefix}-termination-protection"
    TestNumber = "06"
  }

  lifecycle {
    ignore_changes = [disable_api_termination]
  }
}

################################################################################
# Test 7: T2/T3 instance with credit specification - unlimited
################################################################################
resource "aws_instance" "credit_unlimited" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  credit_specification {
    cpu_credits = "unlimited"
  }

  tags = {
    Name       = "${local.name_prefix}-credit-unlimited"
    TestNumber = "07"
  }
}

################################################################################
# Test 8: T2/T3 instance with credit specification - standard
################################################################################
resource "aws_instance" "credit_standard" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  credit_specification {
    cpu_credits = "standard"
  }

  tags = {
    Name       = "${local.name_prefix}-credit-standard"
    TestNumber = "08"
  }
}

################################################################################
# Test 9: Instance with source/destination check disabled - for NAT
################################################################################
resource "aws_instance" "source_dest_check_disabled" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  source_dest_check      = false
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  tags = {
    Name       = "${local.name_prefix}-source-dest-disabled"
    TestNumber = "09"
  }
}

################################################################################
# Test 10: EBS-optimized instance
################################################################################
resource "aws_instance" "ebs_optimized" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t3.micro" # t3 is EBS-optimized by default
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]
  ebs_optimized          = true

  tags = {
    Name       = "${local.name_prefix}-ebs-optimized"
    TestNumber = "10"
  }
}

################################################################################
# Test 11: Instance with user data script
################################################################################
resource "aws_instance" "with_user_data" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "Hello from Warden EC2 test" > /tmp/warden-test.txt
    yum update -y
    echo "User data script completed" >> /tmp/warden-test.txt
  EOF
  )

  user_data_replace_on_change = true

  tags = {
    Name       = "${local.name_prefix}-user-data"
    TestNumber = "11"
  }
}

################################################################################
# Test 12: Instance with user data base64
################################################################################
resource "aws_instance" "with_user_data_base64" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.basic.id]

  user_data_base64 = base64encode(<<-EOF
    #!/bin/bash
    echo "Base64 user data test" > /tmp/base64-test.txt
  EOF
  )

  tags = {
    Name       = "${local.name_prefix}-user-data-base64"
    TestNumber = "12"
  }
}

################################################################################
# Outputs
################################################################################

output "basic_instances" {
  value = {
    basic                    = aws_instance.basic.id
    monitoring               = aws_instance.with_monitoring.id
    metadata_options         = aws_instance.with_metadata_options.id
    with_tags                = aws_instance.with_tags.id
    arm64                    = aws_instance.arm64.id
    termination_protection   = aws_instance.termination_protection.id
    credit_unlimited         = aws_instance.credit_unlimited.id
    credit_standard          = aws_instance.credit_standard.id
    source_dest_check        = aws_instance.source_dest_check_disabled.id
    ebs_optimized            = aws_instance.ebs_optimized.id
    user_data                = aws_instance.with_user_data.id
    user_data_base64         = aws_instance.with_user_data_base64.id
  }
  description = "Basic instance IDs"
}
