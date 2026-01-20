# test-04-users-groups.tf
# Tests 27-35: IAM Users and Groups
# Tests: users, groups, group membership, user policies

################################################################################
# Test 27: Basic IAM User
################################################################################
resource "aws_iam_user" "basic" {
  name = "${local.name_prefix}-basic-user"

  tags = {
    Name        = "Basic User"
    TestNumber  = "27"
    Description = "Basic IAM user"
  }
}

################################################################################
# Test 28: IAM User with path
################################################################################
resource "aws_iam_user" "with_path" {
  name = "${local.name_prefix}-pathed-user"
  path = "/warden/test/"

  tags = {
    Name        = "Pathed User"
    TestNumber  = "28"
    Description = "IAM user with custom path"
  }
}

################################################################################
# Test 29: IAM User with permissions boundary
################################################################################
resource "aws_iam_user" "with_boundary" {
  name                 = "${local.name_prefix}-boundary-user"
  permissions_boundary = "arn:${data.aws_partition.current.partition}:iam::aws:policy/PowerUserAccess"

  tags = {
    Name        = "Boundary User"
    TestNumber  = "29"
    Description = "IAM user with permissions boundary"
  }
}

################################################################################
# Test 30: IAM User with inline policy
################################################################################
resource "aws_iam_user" "with_inline" {
  name = "${local.name_prefix}-inline-user"

  tags = {
    Name        = "Inline User"
    TestNumber  = "30"
    Description = "IAM user with inline policy"
  }
}

resource "aws_iam_user_policy" "inline" {
  name = "s3-access"
  user = aws_iam_user.with_inline.name

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

################################################################################
# Test 31: IAM User with managed policy
################################################################################
resource "aws_iam_user" "with_managed" {
  name = "${local.name_prefix}-managed-user"

  tags = {
    Name        = "Managed User"
    TestNumber  = "31"
    Description = "IAM user with managed policy"
  }
}

resource "aws_iam_user_policy_attachment" "managed" {
  user       = aws_iam_user.with_managed.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

################################################################################
# Test 32: Basic IAM Group
################################################################################
resource "aws_iam_group" "basic" {
  name = "${local.name_prefix}-basic-group"
}

################################################################################
# Test 33: IAM Group with path
################################################################################
resource "aws_iam_group" "with_path" {
  name = "${local.name_prefix}-pathed-group"
  path = "/warden/test/"
}

################################################################################
# Test 34: IAM Group with policy
################################################################################
resource "aws_iam_group" "with_policy" {
  name = "${local.name_prefix}-policy-group"
}

resource "aws_iam_group_policy" "group_inline" {
  name  = "group-s3-access"
  group = aws_iam_group.with_policy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:GetObject", "s3:PutObject"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "group_managed" {
  group      = aws_iam_group.with_policy.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

################################################################################
# Test 35: Group membership
################################################################################
resource "aws_iam_user" "for_group" {
  name = "${local.name_prefix}-group-member"

  tags = {
    Name        = "Group Member User"
    TestNumber  = "35"
    Description = "IAM user for group membership test"
  }
}

resource "aws_iam_group_membership" "test" {
  name = "${local.name_prefix}-membership"

  users = [
    aws_iam_user.basic.name,
    aws_iam_user.for_group.name,
  ]

  group = aws_iam_group.basic.name
}

################################################################################
# Outputs
################################################################################

output "user_arns" {
  value = {
    basic         = aws_iam_user.basic.arn
    with_path     = aws_iam_user.with_path.arn
    with_boundary = aws_iam_user.with_boundary.arn
    with_inline   = aws_iam_user.with_inline.arn
    with_managed  = aws_iam_user.with_managed.arn
    for_group     = aws_iam_user.for_group.arn
  }
  description = "IAM User ARNs"
}

output "group_arns" {
  value = {
    basic       = aws_iam_group.basic.arn
    with_path   = aws_iam_group.with_path.arn
    with_policy = aws_iam_group.with_policy.arn
  }
  description = "IAM Group ARNs"
}
