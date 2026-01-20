# test-01-log-groups.tf
# Tests 1-10: CloudWatch Log Groups
# Tests: basic log groups, retention, KMS encryption, tags

################################################################################
# Test 1: Basic Log Group
################################################################################
resource "aws_cloudwatch_log_group" "basic" {
  name = "/${local.name_prefix}/basic"

  tags = {
    Name        = "Basic Log Group"
    TestNumber  = "01"
    Description = "Basic log group creation"
  }
}

################################################################################
# Test 2: Log Group with retention
################################################################################
resource "aws_cloudwatch_log_group" "with_retention" {
  name              = "/${local.name_prefix}/retention"
  retention_in_days = 7

  tags = {
    Name        = "Retention Log Group"
    TestNumber  = "02"
    Description = "Log group with 7-day retention"
  }
}

################################################################################
# Test 3: Log Group with 30-day retention
################################################################################
resource "aws_cloudwatch_log_group" "retention_30" {
  name              = "/${local.name_prefix}/retention-30"
  retention_in_days = 30

  tags = {
    Name        = "30-Day Retention Log Group"
    TestNumber  = "03"
    Description = "Log group with 30-day retention"
  }
}

################################################################################
# Test 4: Log Group with 1-year retention
################################################################################
resource "aws_cloudwatch_log_group" "retention_365" {
  name              = "/${local.name_prefix}/retention-365"
  retention_in_days = 365

  tags = {
    Name        = "1-Year Retention Log Group"
    TestNumber  = "04"
    Description = "Log group with 1-year retention"
  }
}

################################################################################
# Test 5: Log Group with KMS encryption
################################################################################
resource "aws_kms_key" "logs" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "CloudWatch Logs KMS Key"
    TestNumber  = "05"
    Description = "KMS key for log encryption"
  }
}

resource "aws_cloudwatch_log_group" "encrypted" {
  name              = "/${local.name_prefix}/encrypted"
  kms_key_id        = aws_kms_key.logs.arn
  retention_in_days = 14

  tags = {
    Name        = "Encrypted Log Group"
    TestNumber  = "05"
    Description = "Log group with KMS encryption"
  }
}

################################################################################
# Test 6: Log Group with log class STANDARD
################################################################################
resource "aws_cloudwatch_log_group" "standard_class" {
  name      = "/${local.name_prefix}/standard-class"
  log_group_class = "STANDARD"

  tags = {
    Name        = "Standard Class Log Group"
    TestNumber  = "06"
    Description = "Log group with STANDARD class"
  }
}

################################################################################
# Test 7: Log Group with log class INFREQUENT_ACCESS
################################################################################
resource "aws_cloudwatch_log_group" "infrequent_access" {
  name            = "/${local.name_prefix}/infrequent-access"
  log_group_class = "INFREQUENT_ACCESS"

  tags = {
    Name        = "Infrequent Access Log Group"
    TestNumber  = "07"
    Description = "Log group with INFREQUENT_ACCESS class"
  }
}

################################################################################
# Test 8: Log Group with deep path
################################################################################
resource "aws_cloudwatch_log_group" "deep_path" {
  name = "/${local.name_prefix}/level1/level2/level3/deep"

  tags = {
    Name        = "Deep Path Log Group"
    TestNumber  = "08"
    Description = "Log group with deeply nested path"
  }
}

################################################################################
# Test 9: Log Group for Lambda (common pattern)
################################################################################
resource "aws_cloudwatch_log_group" "lambda_pattern" {
  name              = "/aws/lambda/${local.name_prefix}-function"
  retention_in_days = 14

  tags = {
    Name        = "Lambda Pattern Log Group"
    TestNumber  = "09"
    Description = "Log group following Lambda naming pattern"
  }
}

################################################################################
# Test 10: Log Group for API Gateway (common pattern)
################################################################################
resource "aws_cloudwatch_log_group" "apigw_pattern" {
  name              = "/aws/api-gateway/${local.name_prefix}-api"
  retention_in_days = 30

  tags = {
    Name        = "API Gateway Pattern Log Group"
    TestNumber  = "10"
    Description = "Log group following API Gateway naming pattern"
  }
}

################################################################################
# Outputs
################################################################################

output "log_group_names" {
  value = {
    basic             = aws_cloudwatch_log_group.basic.name
    with_retention    = aws_cloudwatch_log_group.with_retention.name
    retention_30      = aws_cloudwatch_log_group.retention_30.name
    retention_365     = aws_cloudwatch_log_group.retention_365.name
    encrypted         = aws_cloudwatch_log_group.encrypted.name
    standard_class    = aws_cloudwatch_log_group.standard_class.name
    infrequent_access = aws_cloudwatch_log_group.infrequent_access.name
    deep_path         = aws_cloudwatch_log_group.deep_path.name
    lambda_pattern    = aws_cloudwatch_log_group.lambda_pattern.name
    apigw_pattern     = aws_cloudwatch_log_group.apigw_pattern.name
  }
  description = "CloudWatch Log Group names"
}

output "log_group_arns" {
  value = {
    basic     = aws_cloudwatch_log_group.basic.arn
    encrypted = aws_cloudwatch_log_group.encrypted.arn
  }
  description = "CloudWatch Log Group ARNs"
}

output "kms_key_arn" {
  value       = aws_kms_key.logs.arn
  description = "KMS key ARN for log encryption"
}
