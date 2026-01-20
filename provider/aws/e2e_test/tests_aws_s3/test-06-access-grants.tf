# test-06-access-grants.tf
# Test 33: S3 Access Grants
################################################################################
# Access Grants IAM Role
################################################################################

resource "aws_iam_role" "access_grants" {
  name = "${local.bucket_prefix}-access-grants-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "access-grants.s3.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name       = "Access Grants Role"
    TestNumber = "33"
  }
}

# IAM Policy for Access Grants Role
resource "aws_iam_role_policy" "access_grants" {
  name = "${local.bucket_prefix}-access-grants-policy"
  role = aws_iam_role.access_grants.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "${aws_s3_bucket.access_grants.arn}",
          "${aws_s3_bucket.access_grants.arn}/*"
        ]
      }
    ]
  })
}

################################################################################
# Test 33: S3 Access Grants Instance
################################################################################

resource "aws_s3control_access_grants_instance" "main" {
  # Access grants instance is account-level, not bucket-level
  tags = {
    Name        = "Access Grants Instance"
    TestNumber  = "33"
    Description = "Tests S3 Access Grants"
  }
}

resource "aws_s3_bucket" "access_grants" {
  bucket        = "${local.bucket_prefix}-access-grants"
  force_destroy = true

  tags = {
    Name        = "Access Grants Bucket"
    TestNumber  = "33"
    Description = "Bucket for Access Grants testing"
  }
}

# Access Grants Location
resource "aws_s3control_access_grants_location" "main" {
  iam_role_arn   = aws_iam_role.access_grants.arn
  location_scope = "s3://${aws_s3_bucket.access_grants.id}/*" # Use s3:// format

  tags = {
    Name       = "Access Grants Location"
    TestNumber = "33"
  }
  
  depends_on = [
    aws_iam_role_policy.access_grants,
    aws_s3control_access_grants_instance.main
  ]
}

# Example Access Grant
resource "aws_s3control_access_grant" "example" {
  access_grants_location_id = aws_s3control_access_grants_location.main.access_grants_location_id
  
  permission = "READ" # Options: READ, WRITE, READWRITE
  
  access_grants_location_configuration {
    s3_sub_prefix = "data/*" # Optional: restrict to specific prefix
  }
  
  grantee {
    grantee_type       = "IAM"
    grantee_identifier = data.aws_caller_identity.current.arn
  }

  tags = {
    Name       = "Example Access Grant"
    TestNumber = "33"
  }
}

################################################################################
# Outputs
################################################################################

output "access_grants_instance_arn" {
  value       = aws_s3control_access_grants_instance.main.access_grants_instance_arn
  description = "ARN of the Access Grants Instance"
}

output "access_grants_location_id" {
  value       = aws_s3control_access_grants_location.main.access_grants_location_id
  description = "ID of the Access Grants Location"
}

output "access_grant_arn" {
  value       = aws_s3control_access_grant.example.access_grant_arn
  description = "ARN of the example Access Grant"
}
