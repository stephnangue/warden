# test-06-service-linked.tf
# Tests 41-45: Service-Linked Roles and Edge Cases
# Tests: service-linked roles, role name edge cases, special characters

################################################################################
# Test 41: Data source for existing service-linked role
################################################################################
# Service-linked roles are created by AWS services, we can query them
data "aws_iam_role" "autoscaling_slr" {
  name = "AWSServiceRoleForAutoScaling"
}

################################################################################
# Test 42: Role with special characters in name (allowed: +=,.@-_)
################################################################################
resource "aws_iam_role" "special_chars" {
  name = "${local.name_prefix}-role_with.special+chars"

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
    Name        = "Special Chars Role"
    TestNumber  = "42"
    Description = "Role with special characters in name"
  }
}

################################################################################
# Test 43: Role at max name length (64 characters)
################################################################################
resource "aws_iam_role" "max_length" {
  # Max length is 64 chars, prefix is ~24 chars, so we add ~40 more
  name = "${local.name_prefix}-maxlen1234567890123456789012345678901"

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
    Name        = "Max Length Role"
    TestNumber  = "43"
    Description = "Role with maximum name length"
  }
}

################################################################################
# Test 44: Policy at max size (6144 bytes for inline)
################################################################################
resource "aws_iam_role" "large_policy" {
  name = "${local.name_prefix}-large-policy"

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

  # Large inline policy with many statements
  inline_policy {
    name = "large-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        for i in range(50) : {
          Sid      = "Statement${i}"
          Action   = "s3:GetObject"
          Effect   = "Allow"
          Resource = "arn:${data.aws_partition.current.partition}:s3:::bucket-${i}/*"
        }
      ]
    })
  }

  tags = {
    Name        = "Large Policy Role"
    TestNumber  = "44"
    Description = "Role with large inline policy"
  }
}

################################################################################
# Test 45: Multiple inline policies on same role
################################################################################
resource "aws_iam_role" "multi_inline" {
  name = "${local.name_prefix}-multi-inline"

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
    name = "s3-policy"
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

  inline_policy {
    name = "ec2-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }

  inline_policy {
    name = "cloudwatch-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }

  tags = {
    Name        = "Multi Inline Role"
    TestNumber  = "45"
    Description = "Role with multiple inline policies"
  }
}

################################################################################
# Outputs
################################################################################

output "service_linked_role" {
  value = {
    autoscaling_arn = data.aws_iam_role.autoscaling_slr.arn
  }
  description = "Service-linked role ARNs"
}

output "edge_case_roles" {
  value = {
    special_chars = aws_iam_role.special_chars.arn
    max_length    = aws_iam_role.max_length.arn
    large_policy  = aws_iam_role.large_policy.arn
    multi_inline  = aws_iam_role.multi_inline.arn
  }
  description = "Edge case role ARNs"
}
