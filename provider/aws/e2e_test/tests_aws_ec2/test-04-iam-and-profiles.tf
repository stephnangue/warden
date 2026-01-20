# test-04-iam-and-profiles.tf
# Tests: IAM roles, instance profiles, policies
# Consolidates: 06-iam-role, 03-key-pair

################################################################################
# Test 39: IAM Role for EC2
################################################################################

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ec2_basic" {
  name               = "${local.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name       = "${local.name_prefix}-ec2-role"
    TestNumber = "39"
  }
}

################################################################################
# Test 40: IAM Policy - S3 Read Only
################################################################################

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

resource "aws_iam_role_policy" "s3_read_only" {
  name   = "s3-read-only"
  role   = aws_iam_role.ec2_basic.id
  policy = data.aws_iam_policy_document.s3_read_only.json
}

################################################################################
# Test 41: IAM Instance Profile
################################################################################

resource "aws_iam_instance_profile" "ec2_basic" {
  name = "${local.name_prefix}-ec2-profile"
  role = aws_iam_role.ec2_basic.name

  tags = {
    Name       = "${local.name_prefix}-ec2-profile"
    TestNumber = "41"
  }
}

################################################################################
# Test 42: Instance with IAM Role
################################################################################

resource "aws_instance" "with_iam_role" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_basic.name

  tags = {
    Name       = "${local.name_prefix}-with-iam-role"
    TestNumber = "42"
  }
}

################################################################################
# Test 43: IAM Role with multiple policies
################################################################################

resource "aws_iam_role" "ec2_multi_policy" {
  name               = "${local.name_prefix}-ec2-multi-policy"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name       = "${local.name_prefix}-ec2-multi-policy"
    TestNumber = "43"
  }
}

data "aws_iam_policy_document" "cloudwatch_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name   = "cloudwatch-logs"
  role   = aws_iam_role.ec2_multi_policy.id
  policy = data.aws_iam_policy_document.cloudwatch_logs.json
}

data "aws_iam_policy_document" "ssm_managed" {
  statement {
    effect = "Allow"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ssm_managed" {
  name   = "ssm-managed"
  role   = aws_iam_role.ec2_multi_policy.id
  policy = data.aws_iam_policy_document.ssm_managed.json
}

resource "aws_iam_instance_profile" "ec2_multi_policy" {
  name = "${local.name_prefix}-ec2-multi-policy"
  role = aws_iam_role.ec2_multi_policy.name

  tags = {
    Name       = "${local.name_prefix}-ec2-multi-policy"
    TestNumber = "43"
  }
}

resource "aws_instance" "with_multi_policy" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_multi_policy.name

  tags = {
    Name       = "${local.name_prefix}-with-multi-policy"
    TestNumber = "43"
  }
}

################################################################################
# Test 44: IAM Role with AWS managed policies
################################################################################

resource "aws_iam_role" "ec2_ssm" {
  name               = "${local.name_prefix}-ec2-ssm"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name       = "${local.name_prefix}-ec2-ssm"
    TestNumber = "44"
  }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "${local.name_prefix}-ec2-ssm"
  role = aws_iam_role.ec2_ssm.name

  tags = {
    Name       = "${local.name_prefix}-ec2-ssm"
    TestNumber = "44"
  }
}

resource "aws_instance" "with_ssm" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_ssm.name

  tags = {
    Name       = "${local.name_prefix}-with-ssm"
    TestNumber = "44"
  }
}

################################################################################
# Test 45: Key Pair
################################################################################

resource "aws_key_pair" "test" {
  key_name   = "${local.name_prefix}-key"
  # Valid OpenSSH RSA 2048-bit public key for testing
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0ROuzNcd+k4GR/96NI7dvf9OuolJXfL7/VvypHYdylBWXKr39DGyoH5iNlKTimSTLemTWrAHVZurtDOdp61Ea/m1Ka/dejDQShZK7kFy6fTj8F2fTPCEas02zjhrmrcwN/lLe3x0p0LXCj/Z2SJ9EqqPizt2zT4nJBSFwm5EJ6d5p+ZZIVGKvKrxewsUEE9crKar6Aa6xmn0ymA5DKUf3rOqHXHr0GMNo0fXXbIbAiB8xyC37wNvVGNTrrSuFRZ9ZcEcVoCg/0DbJvzqFxRkNvHwwAy7jdfTngxSl0AZw6UY9QOIkeKjJUf2O+ElxCNJE/TC9Fz6OLc7QbzLaJLbf warden-test"

  tags = {
    Name       = "${local.name_prefix}-key"
    TestNumber = "45"
  }
}

################################################################################
# Test 46: Instance with Key Pair
################################################################################

resource "aws_instance" "with_key_pair" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  key_name      = aws_key_pair.test.key_name

  tags = {
    Name       = "${local.name_prefix}-with-key-pair"
    TestNumber = "46"
  }
}

################################################################################
# Outputs
################################################################################

output "iam_roles" {
  value = {
    ec2_basic        = aws_iam_role.ec2_basic.arn
    ec2_multi_policy = aws_iam_role.ec2_multi_policy.arn
    ec2_ssm          = aws_iam_role.ec2_ssm.arn
  }
  description = "IAM role ARNs"
}

output "instance_profiles" {
  value = {
    ec2_basic        = aws_iam_instance_profile.ec2_basic.arn
    ec2_multi_policy = aws_iam_instance_profile.ec2_multi_policy.arn
    ec2_ssm          = aws_iam_instance_profile.ec2_ssm.arn
  }
  description = "Instance profile ARNs"
}

output "iam_instances" {
  value = {
    with_iam_role    = aws_instance.with_iam_role.id
    with_multi_policy = aws_instance.with_multi_policy.id
    with_ssm         = aws_instance.with_ssm.id
    with_key_pair    = aws_instance.with_key_pair.id
  }
  description = "IAM test instance IDs"
}

output "key_pair" {
  value       = aws_key_pair.test.key_name
  description = "Key pair name"
}
