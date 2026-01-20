# test-05-policies.tf
# Tests 31-38: Topic policies and access control
# Tests: resource policies, cross-service access

################################################################################
# Test 31: Topic with basic policy
################################################################################
resource "aws_sns_topic" "with_policy" {
  name = "${local.name_prefix}-with-policy"

  tags = {
    Name        = "Topic with Policy"
    TestNumber  = "31"
    Description = "Topic with basic resource policy"
  }
}

resource "aws_sns_topic_policy" "basic" {
  arn = aws_sns_topic.with_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes"]
        Resource  = aws_sns_topic.with_policy.arn
      }
    ]
  })
}

################################################################################
# Test 32: Topic with S3 publish permission
################################################################################
resource "aws_sns_topic" "s3_publish" {
  name = "${local.name_prefix}-s3-publish"

  tags = {
    Name        = "S3 Publish Topic"
    TestNumber  = "32"
    Description = "Topic allowing S3 to publish"
  }
}

resource "aws_sns_topic_policy" "s3_publish" {
  arn = aws_sns_topic.s3_publish.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3Publish"
        Effect    = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.s3_publish.arn
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
# Test 33: Topic with EventBridge permission
################################################################################
resource "aws_sns_topic" "eventbridge" {
  name = "${local.name_prefix}-eventbridge"

  tags = {
    Name        = "EventBridge Topic"
    TestNumber  = "33"
    Description = "Topic for EventBridge events"
  }
}

resource "aws_sns_topic_policy" "eventbridge" {
  arn = aws_sns_topic.eventbridge.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.eventbridge.arn
      }
    ]
  })
}

################################################################################
# Test 34: Topic with CloudWatch Alarms permission
################################################################################
resource "aws_sns_topic" "cloudwatch" {
  name = "${local.name_prefix}-cloudwatch"

  tags = {
    Name        = "CloudWatch Topic"
    TestNumber  = "34"
    Description = "Topic for CloudWatch Alarms"
  }
}

resource "aws_sns_topic_policy" "cloudwatch" {
  arn = aws_sns_topic.cloudwatch.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatch"
        Effect    = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.cloudwatch.arn
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
# Test 35: Topic with multiple statements
################################################################################
resource "aws_sns_topic" "multi_policy" {
  name = "${local.name_prefix}-multi-policy"

  tags = {
    Name        = "Multi Policy Topic"
    TestNumber  = "35"
    Description = "Topic with multiple policy statements"
  }
}

resource "aws_sns_topic_policy" "multi" {
  arn = aws_sns_topic.multi_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOwner"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:DeleteTopic", "sns:ListSubscriptionsByTopic"]
        Resource  = aws_sns_topic.multi_policy.arn
      },
      {
        Sid       = "AllowS3"
        Effect    = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.multi_policy.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "AllowCloudWatch"
        Effect    = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.multi_policy.arn
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.multi_policy.arn
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
# Test 36: Topic with deny policy
################################################################################
resource "aws_sns_topic" "deny_policy" {
  name = "${local.name_prefix}-deny-policy"

  tags = {
    Name        = "Deny Policy Topic"
    TestNumber  = "36"
    Description = "Topic with deny policy"
  }
}

resource "aws_sns_topic_policy" "deny" {
  arn = aws_sns_topic.deny_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOwner"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:DeleteTopic", "sns:ListSubscriptionsByTopic"]
        Resource  = aws_sns_topic.deny_policy.arn
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.deny_policy.arn
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
# Test 37: FIFO Topic with policy
################################################################################
resource "aws_sns_topic" "fifo_policy" {
  name       = "${local.name_prefix}-fifo-policy.fifo"
  fifo_topic = true

  tags = {
    Name        = "FIFO Policy Topic"
    TestNumber  = "37"
    Description = "FIFO topic with resource policy"
  }
}

resource "aws_sns_topic_policy" "fifo" {
  arn = aws_sns_topic.fifo_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:DeleteTopic", "sns:ListSubscriptionsByTopic"]
        Resource  = aws_sns_topic.fifo_policy.arn
      }
    ]
  })
}

################################################################################
# Test 38: Topic with Lambda permission
################################################################################
resource "aws_sns_topic" "lambda_permission" {
  name = "${local.name_prefix}-lambda-permission"

  tags = {
    Name        = "Lambda Permission Topic"
    TestNumber  = "38"
    Description = "Topic with Lambda publish permission"
  }
}

resource "aws_sns_topic_policy" "lambda" {
  arn = aws_sns_topic.lambda_permission.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambda"
        Effect    = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.lambda_permission.arn
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
# Outputs
################################################################################

output "policy_topics" {
  value = {
    with_policy       = aws_sns_topic.with_policy.name
    s3_publish        = aws_sns_topic.s3_publish.name
    eventbridge       = aws_sns_topic.eventbridge.name
    cloudwatch        = aws_sns_topic.cloudwatch.name
    multi_policy      = aws_sns_topic.multi_policy.name
    deny_policy       = aws_sns_topic.deny_policy.name
    fifo_policy       = aws_sns_topic.fifo_policy.name
    lambda_permission = aws_sns_topic.lambda_permission.name
  }
  description = "Policy topic names"
}

output "policy_topic_arns" {
  value = {
    with_policy  = aws_sns_topic.with_policy.arn
    multi_policy = aws_sns_topic.multi_policy.arn
    fifo_policy  = aws_sns_topic.fifo_policy.arn
  }
  description = "Policy topic ARNs"
}
