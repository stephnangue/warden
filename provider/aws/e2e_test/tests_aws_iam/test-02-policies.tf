# test-02-policies.tf
# Tests 11-20: IAM Policy configurations
# Tests: customer managed policies, policy documents, policy attachments

################################################################################
# Test 11: Basic customer managed policy
################################################################################
resource "aws_iam_policy" "basic" {
  name        = "${local.name_prefix}-basic"
  description = "Basic customer managed policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3List"
        Action   = "s3:ListAllMyBuckets"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "Basic Policy"
    TestNumber  = "11"
    Description = "Basic customer managed policy"
  }
}

################################################################################
# Test 12: Policy with multiple statements
################################################################################
resource "aws_iam_policy" "multi_statement" {
  name        = "${local.name_prefix}-multi-stmt"
  description = "Policy with multiple statements"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3Read"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid      = "AllowEC2Describe"
        Action   = ["ec2:Describe*"]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid      = "AllowCloudWatchLogs"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "Multi Statement Policy"
    TestNumber  = "12"
    Description = "Policy with multiple statements"
  }
}

################################################################################
# Test 13: Policy with path
################################################################################
resource "aws_iam_policy" "with_path" {
  name        = "${local.name_prefix}-pathed"
  path        = "/warden/test/"
  description = "Policy with custom path"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "ec2:DescribeInstances"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "Pathed Policy"
    TestNumber  = "13"
    Description = "Policy with custom path"
  }
}

################################################################################
# Test 14: Policy with resource constraints
################################################################################
resource "aws_iam_policy" "resource_constrained" {
  name        = "${local.name_prefix}-res-constrained"
  description = "Policy with specific resource ARNs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificBucket"
        Action = ["s3:GetObject", "s3:PutObject"]
        Effect = "Allow"
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::example-bucket/*",
          "arn:${data.aws_partition.current.partition}:s3:::example-bucket"
        ]
      }
    ]
  })

  tags = {
    Name        = "Resource Constrained Policy"
    TestNumber  = "14"
    Description = "Policy with specific resource ARNs"
  }
}

################################################################################
# Test 15: Policy with conditions
################################################################################
resource "aws_iam_policy" "with_conditions" {
  name        = "${local.name_prefix}-conditions"
  description = "Policy with condition blocks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3WithMFA"
        Action   = ["s3:DeleteObject", "s3:DeleteBucket"]
        Effect   = "Allow"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
      {
        Sid      = "AllowFromVPC"
        Action   = "s3:GetObject"
        Effect   = "Allow"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = "vpc-12345678"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "Conditions Policy"
    TestNumber  = "15"
    Description = "Policy with condition blocks"
  }
}

################################################################################
# Test 16: Policy with deny statement
################################################################################
resource "aws_iam_policy" "with_deny" {
  name        = "${local.name_prefix}-deny"
  description = "Policy with deny statement"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAll"
        Action   = "s3:*"
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid      = "DenyDelete"
        Action   = ["s3:DeleteBucket", "s3:DeleteObject"]
        Effect   = "Deny"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "Deny Policy"
    TestNumber  = "16"
    Description = "Policy with deny statement"
  }
}

################################################################################
# Test 17: Policy with NotAction
################################################################################
resource "aws_iam_policy" "not_action" {
  name        = "${local.name_prefix}-not-action"
  description = "Policy using NotAction"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAllExceptS3"
        NotAction = "s3:*"
        Effect    = "Deny"
        Resource  = "*"
      }
    ]
  })

  tags = {
    Name        = "NotAction Policy"
    TestNumber  = "17"
    Description = "Policy using NotAction"
  }
}

################################################################################
# Test 18: Policy with NotResource
################################################################################
resource "aws_iam_policy" "not_resource" {
  name        = "${local.name_prefix}-not-resource"
  description = "Policy using NotResource"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid         = "AllowAllExceptProd"
        Action      = "s3:*"
        Effect      = "Allow"
        NotResource = "arn:${data.aws_partition.current.partition}:s3:::production-*"
      }
    ]
  })

  tags = {
    Name        = "NotResource Policy"
    TestNumber  = "18"
    Description = "Policy using NotResource"
  }
}

################################################################################
# Test 19: Policy attachment to role
################################################################################
resource "aws_iam_role" "for_attachment" {
  name = "${local.name_prefix}-for-attach"

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
    Name        = "Role for Attachment"
    TestNumber  = "19"
    Description = "Role for policy attachment test"
  }
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.for_attachment.name
  policy_arn = aws_iam_policy.basic.arn
}

################################################################################
# Test 20: Multiple policy attachments
################################################################################
resource "aws_iam_role" "multi_attach" {
  name = "${local.name_prefix}-multi-attach"

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
    Name        = "Multi Attach Role"
    TestNumber  = "20"
    Description = "Role with multiple policy attachments"
  }
}

resource "aws_iam_role_policy_attachment" "multi_1" {
  role       = aws_iam_role.multi_attach.name
  policy_arn = aws_iam_policy.basic.arn
}

resource "aws_iam_role_policy_attachment" "multi_2" {
  role       = aws_iam_role.multi_attach.name
  policy_arn = aws_iam_policy.multi_statement.arn
}

resource "aws_iam_role_policy_attachment" "multi_3" {
  role       = aws_iam_role.multi_attach.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

################################################################################
# Outputs
################################################################################

output "policy_arns" {
  value = {
    basic              = aws_iam_policy.basic.arn
    multi_statement    = aws_iam_policy.multi_statement.arn
    with_path          = aws_iam_policy.with_path.arn
    resource_constrained = aws_iam_policy.resource_constrained.arn
    with_conditions    = aws_iam_policy.with_conditions.arn
    with_deny          = aws_iam_policy.with_deny.arn
    not_action         = aws_iam_policy.not_action.arn
    not_resource       = aws_iam_policy.not_resource.arn
  }
  description = "IAM Policy ARNs"
}

output "policy_names" {
  value = {
    basic           = aws_iam_policy.basic.name
    multi_statement = aws_iam_policy.multi_statement.name
    with_path       = aws_iam_policy.with_path.name
  }
  description = "IAM Policy names"
}
