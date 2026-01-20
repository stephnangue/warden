# test-05-oidc-saml.tf
# Tests 36-40: OIDC Identity Providers and AssumeRole configurations
# Tests: OIDC providers, web identity trust, external ID

################################################################################
# Test 36: OIDC Identity Provider (GitHub Actions)
################################################################################
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]

  tags = {
    Name        = "GitHub OIDC Provider"
    TestNumber  = "36"
    Description = "OIDC provider for GitHub Actions"
  }
}

################################################################################
# Test 37: Role with OIDC trust (GitHub Actions)
################################################################################
resource "aws_iam_role" "github_actions" {
  name = "${local.name_prefix}-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:example-org/*"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "GitHub Actions Role"
    TestNumber  = "37"
    Description = "Role for GitHub Actions OIDC"
  }
}

################################################################################
# Test 38: Role with cross-account trust
################################################################################
resource "aws_iam_role" "cross_account" {
  name = "${local.name_prefix}-cross-account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "warden-test-external-id"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "Cross Account Role"
    TestNumber  = "38"
    Description = "Role with cross-account trust and external ID"
  }
}

################################################################################
# Test 39: Role with MFA requirement
################################################################################
resource "aws_iam_role" "mfa_required" {
  name = "${local.name_prefix}-mfa-required"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "MFA Required Role"
    TestNumber  = "39"
    Description = "Role requiring MFA for assumption"
  }
}

################################################################################
# Test 40: Role with session tags
################################################################################
resource "aws_iam_role" "session_tags" {
  name = "${local.name_prefix}-session-tags"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
      }
    ]
  })

  tags = {
    Name        = "Session Tags Role"
    TestNumber  = "40"
    Description = "Role allowing session tags"
  }
}

################################################################################
# Outputs
################################################################################

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.github.arn
  description = "GitHub OIDC Provider ARN"
}

output "federated_role_arns" {
  value = {
    github_actions = aws_iam_role.github_actions.arn
    cross_account  = aws_iam_role.cross_account.arn
    mfa_required   = aws_iam_role.mfa_required.arn
    session_tags   = aws_iam_role.session_tags.arn
  }
  description = "Federated/special role ARNs"
}
