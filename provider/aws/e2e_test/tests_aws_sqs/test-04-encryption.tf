# test-04-encryption.tf
# Tests 29-35: Queue encryption configurations
# Tests: SSE-SQS, SSE-KMS, custom KMS keys

################################################################################
# Test 29: Queue with SSE-SQS encryption
################################################################################
resource "aws_sqs_queue" "sse_sqs" {
  name              = "${local.name_prefix}-sse-sqs"
  sqs_managed_sse_enabled = true

  tags = {
    Name        = "SSE-SQS Queue"
    TestNumber  = "29"
    Description = "Queue with SQS-managed encryption"
  }
}

################################################################################
# Test 30: Queue with SSE-KMS (AWS managed key)
################################################################################
resource "aws_sqs_queue" "sse_kms_aws" {
  name                    = "${local.name_prefix}-sse-kms-aws"
  kms_master_key_id       = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name        = "SSE-KMS AWS Key Queue"
    TestNumber  = "30"
    Description = "Queue with AWS managed KMS encryption"
  }
}

################################################################################
# Test 31: Custom KMS key for SQS
################################################################################
resource "aws_kms_key" "sqs" {
  description             = "KMS key for SQS encryption tests"
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
        Sid    = "Allow SQS Service"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
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
    Name        = "SQS KMS Key"
    TestNumber  = "31"
    Description = "Custom KMS key for SQS"
  }
}

resource "aws_kms_alias" "sqs" {
  name          = "alias/${local.name_prefix}-sqs-key"
  target_key_id = aws_kms_key.sqs.key_id
}

################################################################################
# Test 32: Queue with custom KMS key
################################################################################
resource "aws_sqs_queue" "sse_kms_custom" {
  name              = "${local.name_prefix}-sse-kms-custom"
  kms_master_key_id = aws_kms_key.sqs.arn
  kms_data_key_reuse_period_seconds = 600

  tags = {
    Name        = "SSE-KMS Custom Key Queue"
    TestNumber  = "32"
    Description = "Queue with custom KMS encryption"
  }
}

################################################################################
# Test 33: Queue with KMS key alias
################################################################################
resource "aws_sqs_queue" "sse_kms_alias" {
  name              = "${local.name_prefix}-sse-kms-alias"
  kms_master_key_id = aws_kms_alias.sqs.name
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name        = "SSE-KMS Alias Queue"
    TestNumber  = "33"
    Description = "Queue with KMS key alias"
  }
}

################################################################################
# Test 34: FIFO Queue with SSE-SQS
################################################################################
resource "aws_sqs_queue" "fifo_sse_sqs" {
  name                    = "${local.name_prefix}-fifo-sse-sqs.fifo"
  fifo_queue              = true
  sqs_managed_sse_enabled = true

  tags = {
    Name        = "FIFO SSE-SQS Queue"
    TestNumber  = "34"
    Description = "FIFO queue with SQS-managed encryption"
  }
}

################################################################################
# Test 35: FIFO Queue with custom KMS key
################################################################################
resource "aws_sqs_queue" "fifo_sse_kms" {
  name              = "${local.name_prefix}-fifo-sse-kms.fifo"
  fifo_queue        = true
  kms_master_key_id = aws_kms_key.sqs.arn
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name        = "FIFO SSE-KMS Queue"
    TestNumber  = "35"
    Description = "FIFO queue with custom KMS encryption"
  }
}

################################################################################
# Outputs
################################################################################

output "encrypted_queues" {
  value = {
    sse_sqs        = aws_sqs_queue.sse_sqs.name
    sse_kms_aws    = aws_sqs_queue.sse_kms_aws.name
    sse_kms_custom = aws_sqs_queue.sse_kms_custom.name
    sse_kms_alias  = aws_sqs_queue.sse_kms_alias.name
    fifo_sse_sqs   = aws_sqs_queue.fifo_sse_sqs.name
    fifo_sse_kms   = aws_sqs_queue.fifo_sse_kms.name
  }
  description = "Encrypted queue names"
}

output "encrypted_queue_urls" {
  value = {
    sse_sqs        = aws_sqs_queue.sse_sqs.url
    sse_kms_custom = aws_sqs_queue.sse_kms_custom.url
    fifo_sse_kms   = aws_sqs_queue.fifo_sse_kms.url
  }
  description = "Encrypted queue URLs"
}

output "kms_resources" {
  value = {
    key_id    = aws_kms_key.sqs.key_id
    key_arn   = aws_kms_key.sqs.arn
    key_alias = aws_kms_alias.sqs.name
  }
  description = "KMS key resources"
}
