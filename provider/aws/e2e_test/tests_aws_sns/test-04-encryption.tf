# test-04-encryption.tf
# Tests 25-30: Topic encryption configurations
# Tests: SSE-KMS, custom keys

################################################################################
# Test 25: Topic with AWS managed KMS key
################################################################################
resource "aws_sns_topic" "kms_aws" {
  name              = "${local.name_prefix}-kms-aws"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name        = "KMS AWS Key Topic"
    TestNumber  = "25"
    Description = "Topic with AWS managed KMS encryption"
  }
}

################################################################################
# Test 26: Custom KMS key for SNS
################################################################################
resource "aws_kms_key" "sns" {
  description             = "KMS key for SNS encryption tests"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow SNS Service"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "SNS KMS Key"
    TestNumber  = "26"
    Description = "Custom KMS key for SNS"
  }
}

resource "aws_kms_alias" "sns" {
  name          = "alias/${local.name_prefix}-sns-key"
  target_key_id = aws_kms_key.sns.key_id
}

################################################################################
# Test 27: Topic with custom KMS key
################################################################################
resource "aws_sns_topic" "kms_custom" {
  name              = "${local.name_prefix}-kms-custom"
  kms_master_key_id = aws_kms_key.sns.arn

  tags = {
    Name        = "KMS Custom Key Topic"
    TestNumber  = "27"
    Description = "Topic with custom KMS encryption"
  }
}

################################################################################
# Test 28: Topic with KMS key alias
################################################################################
resource "aws_sns_topic" "kms_alias" {
  name              = "${local.name_prefix}-kms-alias"
  kms_master_key_id = aws_kms_alias.sns.name

  tags = {
    Name        = "KMS Alias Topic"
    TestNumber  = "28"
    Description = "Topic with KMS key alias"
  }
}

################################################################################
# Test 29: FIFO Topic with KMS encryption
################################################################################
resource "aws_sns_topic" "fifo_kms" {
  name              = "${local.name_prefix}-fifo-kms.fifo"
  fifo_topic        = true
  kms_master_key_id = aws_kms_key.sns.arn

  tags = {
    Name        = "FIFO KMS Topic"
    TestNumber  = "29"
    Description = "FIFO topic with KMS encryption"
  }
}

################################################################################
# Test 30: Encrypted topic with encrypted SQS subscription
################################################################################
resource "aws_sns_topic" "encrypted_chain" {
  name              = "${local.name_prefix}-encrypted-chain"
  kms_master_key_id = aws_kms_key.sns.arn

  tags = {
    Name        = "Encrypted Chain Topic"
    TestNumber  = "30"
    Description = "Encrypted topic for encrypted SQS"
  }
}

resource "aws_sqs_queue" "encrypted_target" {
  name              = "${local.name_prefix}-encrypted-target"
  kms_master_key_id = aws_kms_key.sns.arn

  tags = {
    Name        = "Encrypted Target Queue"
    TestNumber  = "30"
    Description = "Encrypted SQS for encrypted SNS"
  }
}

resource "aws_sqs_queue_policy" "encrypted_target" {
  queue_url = aws_sqs_queue.encrypted_target.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNS"
        Effect    = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.encrypted_target.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.encrypted_chain.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "encrypted" {
  topic_arn = aws_sns_topic.encrypted_chain.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.encrypted_target.arn
}

################################################################################
# Outputs
################################################################################

output "encrypted_topics" {
  value = {
    kms_aws     = aws_sns_topic.kms_aws.name
    kms_custom  = aws_sns_topic.kms_custom.name
    kms_alias   = aws_sns_topic.kms_alias.name
    fifo_kms    = aws_sns_topic.fifo_kms.name
    chain       = aws_sns_topic.encrypted_chain.name
  }
  description = "Encrypted topic names"
}

output "encrypted_topic_arns" {
  value = {
    kms_custom = aws_sns_topic.kms_custom.arn
    fifo_kms   = aws_sns_topic.fifo_kms.arn
    chain      = aws_sns_topic.encrypted_chain.arn
  }
  description = "Encrypted topic ARNs"
}

output "kms_resources" {
  value = {
    key_id    = aws_kms_key.sns.key_id
    key_arn   = aws_kms_key.sns.arn
    key_alias = aws_kms_alias.sns.name
  }
  description = "KMS key resources"
}
