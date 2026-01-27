# test-08-aws.tf
# Tests 106-115: AWS Secrets Engine
# Tests: IAM user credentials, STS assumed role, federation tokens

################################################################################
# AWS Secrets Engine Mount
################################################################################
resource "vault_aws_secret_backend" "aws" {
  path        = "${local.name_prefix}-aws"
  description = "AWS secrets engine for Warden testing"

  # Root credentials for the AWS secrets engine
  # In real usage, these would be IAM user credentials with appropriate permissions
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"

  default_lease_ttl_seconds = 3600  # 1 hour
  max_lease_ttl_seconds     = 86400 # 24 hours
}

################################################################################
# Test 106: IAM User Role (generates IAM user + access keys)
################################################################################
resource "vault_aws_secret_backend_role" "iam_user" {
  backend = vault_aws_secret_backend.aws.path
  name    = "iam-user-role"

  credential_type = "iam_user"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ]
      }
    ]
  })

}

################################################################################
# Test 107: Assumed Role (STS AssumeRole)
################################################################################
resource "vault_aws_secret_backend_role" "assumed_role" {
  backend = vault_aws_secret_backend.aws.path
  name    = "assumed-role"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/VaultAssumedRole"]

  default_sts_ttl = 900   # 15 minutes
  max_sts_ttl     = 3600  # 1 hour
}

################################################################################
# Test 108: Federation Token
################################################################################
resource "vault_aws_secret_backend_role" "federation_token" {
  backend = vault_aws_secret_backend.aws.path
  name    = "federation-token"

  credential_type = "federation_token"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*"
        ]
        Resource = "*"
      }
    ]
  })

  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 43200 # 12 hours
}

################################################################################
# Test 109: S3 Read-only Role
################################################################################
resource "vault_aws_secret_backend_role" "s3_readonly" {
  backend = vault_aws_secret_backend.aws.path
  name    = "s3-readonly"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/S3ReadOnlyRole"]

  default_sts_ttl = 1800 # 30 minutes
  max_sts_ttl     = 7200 # 2 hours
}

################################################################################
# Test 110: S3 Full Access Role
################################################################################
resource "vault_aws_secret_backend_role" "s3_fullaccess" {
  backend = vault_aws_secret_backend.aws.path
  name    = "s3-fullaccess"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/S3FullAccessRole"]

  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 14400 # 4 hours
}

################################################################################
# Test 111: EC2 Admin Role
################################################################################
resource "vault_aws_secret_backend_role" "ec2_admin" {
  backend = vault_aws_secret_backend.aws.path
  name    = "ec2-admin"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/EC2AdminRole"]

  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 14400 # 4 hours
}

################################################################################
# Test 112: Lambda Deploy Role
################################################################################
resource "vault_aws_secret_backend_role" "lambda_deploy" {
  backend = vault_aws_secret_backend.aws.path
  name    = "lambda-deploy"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/LambdaDeployRole"]

  default_sts_ttl = 1800 # 30 minutes
  max_sts_ttl     = 3600 # 1 hour
}

################################################################################
# Test 113: Terraform Role (broad permissions)
################################################################################
resource "vault_aws_secret_backend_role" "terraform" {
  backend = vault_aws_secret_backend.aws.path
  name    = "terraform"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/TerraformRole"]

  # Longer TTL for Terraform operations
  default_sts_ttl = 7200  # 2 hours
  max_sts_ttl     = 28800 # 8 hours
}

################################################################################
# Test 114: Read-only Audit Role
################################################################################
resource "vault_aws_secret_backend_role" "audit_readonly" {
  backend = vault_aws_secret_backend.aws.path
  name    = "audit-readonly"

  credential_type = "federation_token"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "cloudtrail:LookupEvents",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "iam:Get*",
          "iam:List*",
          "organizations:Describe*",
          "organizations:List*"
        ]
        Resource = "*"
      }
    ]
  })

  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 14400 # 4 hours
}

################################################################################
# Test 115: Session Tags Role (for ABAC)
################################################################################
resource "vault_aws_secret_backend_role" "session_tags" {
  backend = vault_aws_secret_backend.aws.path
  name    = "session-tags"

  credential_type = "assumed_role"
  role_arns       = ["arn:aws:iam::123456789012:role/SessionTagsRole"]

  # Session tags for attribute-based access control
  session_tags = {
    "Project"     = "Warden"
    "Environment" = "Test"
    "Team"        = "Platform"
  }

  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 14400 # 4 hours
}

################################################################################
# Outputs
################################################################################

output "aws_mount_path" {
  value       = vault_aws_secret_backend.aws.path
  description = "AWS secrets engine mount path"
}

output "aws_roles" {
  value = {
    iam_user         = vault_aws_secret_backend_role.iam_user.name
    assumed_role     = vault_aws_secret_backend_role.assumed_role.name
    federation_token = vault_aws_secret_backend_role.federation_token.name
    s3_readonly      = vault_aws_secret_backend_role.s3_readonly.name
    s3_fullaccess    = vault_aws_secret_backend_role.s3_fullaccess.name
    ec2_admin        = vault_aws_secret_backend_role.ec2_admin.name
    lambda_deploy    = vault_aws_secret_backend_role.lambda_deploy.name
    terraform        = vault_aws_secret_backend_role.terraform.name
    audit_readonly   = vault_aws_secret_backend_role.audit_readonly.name
    session_tags     = vault_aws_secret_backend_role.session_tags.name
  }
  description = "AWS role names for dynamic credentials"
}

output "aws_role_types" {
  value = {
    iam_user = {
      name            = vault_aws_secret_backend_role.iam_user.name
      credential_type = vault_aws_secret_backend_role.iam_user.credential_type
    }
    assumed_role = {
      name            = vault_aws_secret_backend_role.assumed_role.name
      credential_type = vault_aws_secret_backend_role.assumed_role.credential_type
    }
    federation_token = {
      name            = vault_aws_secret_backend_role.federation_token.name
      credential_type = vault_aws_secret_backend_role.federation_token.credential_type
    }
  }
  description = "AWS role credential types"
}

output "aws_role_ttls" {
  value = {
    iam_user = {
      default_sts_ttl = vault_aws_secret_backend_role.iam_user.default_sts_ttl
      max_sts_ttl     = vault_aws_secret_backend_role.iam_user.max_sts_ttl
    }
    assumed_role = {
      default_sts_ttl = vault_aws_secret_backend_role.assumed_role.default_sts_ttl
      max_sts_ttl     = vault_aws_secret_backend_role.assumed_role.max_sts_ttl
    }
    terraform = {
      default_sts_ttl = vault_aws_secret_backend_role.terraform.default_sts_ttl
      max_sts_ttl     = vault_aws_secret_backend_role.terraform.max_sts_ttl
    }
  }
  description = "AWS role TTL configurations"
}
