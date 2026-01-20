# test-03-instance-profiles.tf
# Tests 21-26: IAM Instance Profile configurations
# Tests: basic profiles, role associations

################################################################################
# Roles for Instance Profiles (defined locally for independence)
################################################################################

resource "aws_iam_role" "basic_ec2_03" {
  name = "${local.name_prefix}-basic-ec2-03"

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
    Name        = "Basic EC2 Role for Profile"
    TestNumber  = "21"
    Description = "Basic role for instance profile"
  }
}

resource "aws_iam_role" "with_inline_03" {
  name = "${local.name_prefix}-inline-03"

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
    Name        = "Inline Policy Role for Profile"
    TestNumber  = "23"
    Description = "Role with inline policy for profile"
  }
}

resource "aws_iam_role" "with_managed_03" {
  name = "${local.name_prefix}-managed-03"

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
    Name        = "Managed Policy Role for Profile"
    TestNumber  = "24"
    Description = "Role with managed policy for profile"
  }
}

resource "aws_iam_role" "multi_service_03" {
  name = "${local.name_prefix}-multi-svc-03"

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
    Name        = "Multi Service Role for Profile"
    TestNumber  = "25"
    Description = "Role with multiple service principals for profile"
  }
}

resource "aws_iam_role" "with_boundary_03" {
  name = "${local.name_prefix}-boundary-03"

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
    Name        = "Boundary Role for Profile"
    TestNumber  = "26"
    Description = "Role with permissions boundary for profile"
  }
}

################################################################################
# Test 21: Basic instance profile
################################################################################
resource "aws_iam_instance_profile" "basic" {
  name = "${local.name_prefix}-basic"
  role = aws_iam_role.basic_ec2_03.name

  tags = {
    Name        = "Basic Instance Profile"
    TestNumber  = "21"
    Description = "Basic instance profile"
  }
}

################################################################################
# Test 22: Instance profile with path
################################################################################
resource "aws_iam_role" "for_profile_path" {
  name = "${local.name_prefix}-for-profile-path"
  path = "/warden/profiles/"

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
    Name        = "Role for Profile Path"
    TestNumber  = "22"
    Description = "Role for pathed profile test"
  }
}

resource "aws_iam_instance_profile" "with_path" {
  name = "${local.name_prefix}-pathed"
  path = "/warden/profiles/"
  role = aws_iam_role.for_profile_path.name

  tags = {
    Name        = "Pathed Instance Profile"
    TestNumber  = "22"
    Description = "Instance profile with custom path"
  }
}

################################################################################
# Test 23: Instance profile with inline policy role
################################################################################
resource "aws_iam_instance_profile" "inline_role" {
  name = "${local.name_prefix}-inline-role"
  role = aws_iam_role.with_inline_03.name

  tags = {
    Name        = "Inline Role Profile"
    TestNumber  = "23"
    Description = "Instance profile with inline policy role"
  }
}

################################################################################
# Test 24: Instance profile with managed policy role
################################################################################
resource "aws_iam_instance_profile" "managed_role" {
  name = "${local.name_prefix}-managed-role"
  role = aws_iam_role.with_managed_03.name

  tags = {
    Name        = "Managed Role Profile"
    TestNumber  = "24"
    Description = "Instance profile with managed policy role"
  }
}

################################################################################
# Test 25: Instance profile for Lambda-capable role (edge case)
################################################################################
resource "aws_iam_instance_profile" "lambda_role" {
  name = "${local.name_prefix}-lambda-role"
  role = aws_iam_role.multi_service_03.name

  tags = {
    Name        = "Lambda Role Profile"
    TestNumber  = "25"
    Description = "Instance profile with multi-service role"
  }
}

################################################################################
# Test 26: Instance profile with boundary role
################################################################################
resource "aws_iam_instance_profile" "boundary_role" {
  name = "${local.name_prefix}-boundary-role"
  role = aws_iam_role.with_boundary_03.name

  tags = {
    Name        = "Boundary Role Profile"
    TestNumber  = "26"
    Description = "Instance profile with permissions boundary role"
  }
}

################################################################################
# Outputs
################################################################################

output "instance_profile_arns" {
  value = {
    basic        = aws_iam_instance_profile.basic.arn
    with_path    = aws_iam_instance_profile.with_path.arn
    inline_role  = aws_iam_instance_profile.inline_role.arn
    managed_role = aws_iam_instance_profile.managed_role.arn
    lambda_role  = aws_iam_instance_profile.lambda_role.arn
    boundary     = aws_iam_instance_profile.boundary_role.arn
  }
  description = "Instance Profile ARNs"
}

output "instance_profile_names" {
  value = {
    basic     = aws_iam_instance_profile.basic.name
    with_path = aws_iam_instance_profile.with_path.name
  }
  description = "Instance Profile names"
}
