# test-01-roles.tf
# Tests 1-10: IAM Role configurations
# Tests: basic roles, trust policies, inline policies, managed policies

################################################################################
# Test 1: Basic IAM Role with EC2 trust
################################################################################
resource "aws_iam_role" "basic_ec2" {
  name = "${local.name_prefix}-basic-ec2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Basic EC2 Role"
    TestNumber  = "01"
    Description = "Basic role with EC2 trust policy"
  }
}

################################################################################
# Test 2: IAM Role with Lambda trust
################################################################################
resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Lambda Role"
    TestNumber  = "02"
    Description = "Role for Lambda functions"
  }
}

################################################################################
# Test 3: IAM Role with multiple service principals
################################################################################
resource "aws_iam_role" "multi_service" {
  name = "${local.name_prefix}-multi-svc"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com",
            "lambda.amazonaws.com",
            "ecs-tasks.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = {
    Name        = "Multi Service Role"
    TestNumber  = "03"
    Description = "Role with multiple service principals"
  }
}

################################################################################
# Test 4: IAM Role with inline policy
################################################################################
resource "aws_iam_role" "with_inline" {
  name = "${local.name_prefix}-inline"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  inline_policy {
    name = "s3-read-access"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["s3:GetObject", "s3:ListBucket"]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }

  tags = {
    Name        = "Inline Policy Role"
    TestNumber  = "04"
    Description = "Role with inline policy"
  }
}

################################################################################
# Test 5: IAM Role with managed policy attachment
################################################################################
resource "aws_iam_role" "with_managed" {
  name = "${local.name_prefix}-managed"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonS3ReadOnlyAccess"
  ]

  tags = {
    Name        = "Managed Policy Role"
    TestNumber  = "05"
    Description = "Role with AWS managed policy"
  }
}

################################################################################
# Test 6: IAM Role with path
################################################################################
resource "aws_iam_role" "with_path" {
  name = "${local.name_prefix}-pathed"
  path = "/warden/test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Pathed Role"
    TestNumber  = "06"
    Description = "Role with custom path"
  }
}

################################################################################
# Test 7: IAM Role with max session duration
################################################################################
resource "aws_iam_role" "max_session" {
  name                 = "${local.name_prefix}-max-session"
  max_session_duration = 43200 # 12 hours

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Max Session Role"
    TestNumber  = "07"
    Description = "Role with max session duration"
  }
}

################################################################################
# Test 8: IAM Role with permissions boundary
################################################################################
resource "aws_iam_role" "with_boundary" {
  name = "${local.name_prefix}-boundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  permissions_boundary = "arn:${data.aws_partition.current.partition}:iam::aws:policy/PowerUserAccess"

  tags = {
    Name        = "Boundary Role"
    TestNumber  = "08"
    Description = "Role with permissions boundary"
  }
}

################################################################################
# Test 9: IAM Role with description
################################################################################
resource "aws_iam_role" "with_description" {
  name        = "${local.name_prefix}-described"
  description = "This role is used for Warden IAM testing purposes"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Described Role"
    TestNumber  = "09"
    Description = "Role with description field"
  }
}

################################################################################
# Test 10: IAM Role with condition in trust policy
################################################################################
resource "aws_iam_role" "with_condition" {
  name = "${local.name_prefix}-condition"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name        = "Condition Role"
    TestNumber  = "10"
    Description = "Role with condition in trust policy"
  }
}

################################################################################
# Outputs
################################################################################

output "role_arns" {
  value = {
    basic_ec2     = aws_iam_role.basic_ec2.arn
    lambda        = aws_iam_role.lambda.arn
    multi_service = aws_iam_role.multi_service.arn
    with_inline   = aws_iam_role.with_inline.arn
    with_managed  = aws_iam_role.with_managed.arn
    with_path     = aws_iam_role.with_path.arn
    max_session   = aws_iam_role.max_session.arn
    with_boundary = aws_iam_role.with_boundary.arn
    with_desc     = aws_iam_role.with_description.arn
    with_cond     = aws_iam_role.with_condition.arn
  }
  description = "IAM Role ARNs"
}

output "role_names" {
  value = {
    basic_ec2     = aws_iam_role.basic_ec2.name
    lambda        = aws_iam_role.lambda.name
    multi_service = aws_iam_role.multi_service.name
  }
  description = "IAM Role names"
}
