# test-05-policies.tf
# Tests 36-42: Queue policies and access control
# Tests: resource policies, cross-account access, service principals

################################################################################
# Test 36: Queue with basic policy
################################################################################
resource "aws_sqs_queue" "with_policy" {
  name = "${local.name_prefix}-with-policy"

  tags = {
    Name        = "Queue with Policy"
    TestNumber  = "36"
    Description = "Queue with basic resource policy"
  }
}

resource "aws_sqs_queue_policy" "basic" {
  queue_url = aws_sqs_queue.with_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.with_policy.arn
      }
    ]
  })
}

################################################################################
# Test 37: Queue with SNS publish permission
################################################################################
resource "aws_sqs_queue" "sns_publish" {
  name = "${local.name_prefix}-sns-publish"

  tags = {
    Name        = "SNS Publish Queue"
    TestNumber  = "37"
    Description = "Queue allowing SNS to publish"
  }
}

resource "aws_sns_topic" "for_sqs" {
  name = "${local.name_prefix}-for-sqs"

  tags = {
    Name        = "SNS for SQS"
    TestNumber  = "37"
    Description = "SNS topic for SQS testing"
  }
}

resource "aws_sqs_queue_policy" "sns_publish" {
  queue_url = aws_sqs_queue.sns_publish.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSPublish"
        Effect    = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.sns_publish.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.for_sqs.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "sqs" {
  topic_arn = aws_sns_topic.for_sqs.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.sns_publish.arn
}

################################################################################
# Test 38: Queue with S3 event notification permission
################################################################################
resource "aws_sqs_queue" "s3_events" {
  name = "${local.name_prefix}-s3-events"

  tags = {
    Name        = "S3 Events Queue"
    TestNumber  = "38"
    Description = "Queue for S3 event notifications"
  }
}

resource "aws_sqs_queue_policy" "s3_events" {
  queue_url = aws_sqs_queue.s3_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3Events"
        Effect    = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.s3_events.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

################################################################################
# Test 39: Queue with EventBridge permission
################################################################################
resource "aws_sqs_queue" "eventbridge" {
  name = "${local.name_prefix}-eventbridge"

  tags = {
    Name        = "EventBridge Queue"
    TestNumber  = "39"
    Description = "Queue for EventBridge events"
  }
}

resource "aws_sqs_queue_policy" "eventbridge" {
  queue_url = aws_sqs_queue.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.eventbridge.arn
      }
    ]
  })
}

################################################################################
# Test 40: Queue with multiple statements
################################################################################
resource "aws_sqs_queue" "multi_policy" {
  name = "${local.name_prefix}-multi-policy"

  tags = {
    Name        = "Multi Policy Queue"
    TestNumber  = "40"
    Description = "Queue with multiple policy statements"
  }
}

resource "aws_sqs_queue_policy" "multi" {
  queue_url = aws_sqs_queue.multi_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = ["sqs:SendMessage", "sqs:ReceiveMessage"]
        Resource  = aws_sqs_queue.multi_policy.arn
      },
      {
        Sid       = "AllowSNS"
        Effect    = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.multi_policy.arn
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.multi_policy.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

################################################################################
# Test 41: Queue with deny policy
################################################################################
resource "aws_sqs_queue" "deny_policy" {
  name = "${local.name_prefix}-deny-policy"

  tags = {
    Name        = "Deny Policy Queue"
    TestNumber  = "41"
    Description = "Queue with deny policy"
  }
}

resource "aws_sqs_queue_policy" "deny" {
  queue_url = aws_sqs_queue.deny_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOwner"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.deny_policy.arn
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.deny_policy.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

################################################################################
# Test 42: FIFO Queue with policy
################################################################################
resource "aws_sqs_queue" "fifo_with_policy" {
  name       = "${local.name_prefix}-fifo-policy.fifo"
  fifo_queue = true

  tags = {
    Name        = "FIFO with Policy"
    TestNumber  = "42"
    Description = "FIFO queue with resource policy"
  }
}

resource "aws_sqs_queue_policy" "fifo" {
  queue_url = aws_sqs_queue.fifo_with_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.fifo_with_policy.arn
      }
    ]
  })
}

################################################################################
# Outputs
################################################################################

output "policy_queues" {
  value = {
    with_policy     = aws_sqs_queue.with_policy.name
    sns_publish     = aws_sqs_queue.sns_publish.name
    s3_events       = aws_sqs_queue.s3_events.name
    eventbridge     = aws_sqs_queue.eventbridge.name
    multi_policy    = aws_sqs_queue.multi_policy.name
    deny_policy     = aws_sqs_queue.deny_policy.name
    fifo_with_policy = aws_sqs_queue.fifo_with_policy.name
  }
  description = "Policy queue names"
}

output "policy_queue_urls" {
  value = {
    with_policy  = aws_sqs_queue.with_policy.url
    sns_publish  = aws_sqs_queue.sns_publish.url
    eventbridge  = aws_sqs_queue.eventbridge.url
  }
  description = "Policy queue URLs"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.for_sqs.arn
  description = "SNS topic ARN for SQS subscription"
}
