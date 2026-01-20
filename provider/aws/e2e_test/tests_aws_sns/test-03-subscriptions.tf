# test-03-subscriptions.tf
# Tests 19-30: SNS Subscriptions
# Tests: SQS, Lambda, Email, HTTP endpoints

################################################################################
# Test 19: SQS Subscription
################################################################################
resource "aws_sns_topic" "for_sqs" {
  name = "${local.name_prefix}-for-sqs"

  tags = {
    Name        = "Topic for SQS"
    TestNumber  = "19"
    Description = "Topic for SQS subscription test"
  }
}

resource "aws_sqs_queue" "sns_target" {
  name = "${local.name_prefix}-sns-target"

  tags = {
    Name        = "SNS Target Queue"
    TestNumber  = "19"
    Description = "SQS queue for SNS subscription"
  }
}

resource "aws_sqs_queue_policy" "sns_target" {
  queue_url = aws_sqs_queue.sns_target.id

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
        Resource  = aws_sqs_queue.sns_target.arn
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
  endpoint  = aws_sqs_queue.sns_target.arn
}

################################################################################
# Test 20: SQS Subscription with raw message delivery
################################################################################
resource "aws_sns_topic" "raw_delivery" {
  name = "${local.name_prefix}-raw-delivery"

  tags = {
    Name        = "Raw Delivery Topic"
    TestNumber  = "20"
    Description = "Topic for raw message delivery test"
  }
}

resource "aws_sqs_queue" "raw_target" {
  name = "${local.name_prefix}-raw-target"

  tags = {
    Name        = "Raw Target Queue"
    TestNumber  = "20"
    Description = "SQS queue for raw message delivery"
  }
}

resource "aws_sqs_queue_policy" "raw_target" {
  queue_url = aws_sqs_queue.raw_target.id

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
        Resource  = aws_sqs_queue.raw_target.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.raw_delivery.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "raw_sqs" {
  topic_arn            = aws_sns_topic.raw_delivery.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.raw_target.arn
  raw_message_delivery = true
}

################################################################################
# Test 21: SQS Subscription with filter policy
################################################################################
resource "aws_sns_topic" "filtered" {
  name = "${local.name_prefix}-filtered"

  tags = {
    Name        = "Filtered Topic"
    TestNumber  = "21"
    Description = "Topic for filter policy test"
  }
}

resource "aws_sqs_queue" "filtered_target" {
  name = "${local.name_prefix}-filtered-target"

  tags = {
    Name        = "Filtered Target Queue"
    TestNumber  = "21"
    Description = "SQS queue for filtered messages"
  }
}

resource "aws_sqs_queue_policy" "filtered_target" {
  queue_url = aws_sqs_queue.filtered_target.id

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
        Resource  = aws_sqs_queue.filtered_target.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.filtered.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "filtered_sqs" {
  topic_arn = aws_sns_topic.filtered.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.filtered_target.arn

  filter_policy = jsonencode({
    event_type = ["order_placed", "order_cancelled"]
    store_id   = [{ numeric = [">=", 100] }]
  })
}

################################################################################
# Test 22: SQS Subscription with filter policy scope
################################################################################
resource "aws_sns_topic" "filter_scope" {
  name = "${local.name_prefix}-filter-scope"

  tags = {
    Name        = "Filter Scope Topic"
    TestNumber  = "22"
    Description = "Topic for filter policy scope test"
  }
}

resource "aws_sqs_queue" "filter_scope_target" {
  name = "${local.name_prefix}-filter-scope-target"

  tags = {
    Name        = "Filter Scope Target Queue"
    TestNumber  = "22"
    Description = "SQS queue for filter scope"
  }
}

resource "aws_sqs_queue_policy" "filter_scope_target" {
  queue_url = aws_sqs_queue.filter_scope_target.id

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
        Resource  = aws_sqs_queue.filter_scope_target.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.filter_scope.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "filter_scope_sqs" {
  topic_arn           = aws_sns_topic.filter_scope.arn
  protocol            = "sqs"
  endpoint            = aws_sqs_queue.filter_scope_target.arn
  filter_policy_scope = "MessageBody"

  filter_policy = jsonencode({
    customer_type = ["premium"]
  })
}

################################################################################
# Test 23: FIFO Topic to FIFO Queue subscription
################################################################################
resource "aws_sns_topic" "fifo_sub" {
  name                        = "${local.name_prefix}-fifo-sub.fifo"
  fifo_topic                  = true
  content_based_deduplication = true

  tags = {
    Name        = "FIFO Sub Topic"
    TestNumber  = "23"
    Description = "FIFO topic for FIFO subscription test"
  }
}

resource "aws_sqs_queue" "fifo_target" {
  name                        = "${local.name_prefix}-fifo-target.fifo"
  fifo_queue                  = true
  content_based_deduplication = true

  tags = {
    Name        = "FIFO Target Queue"
    TestNumber  = "23"
    Description = "FIFO queue for FIFO topic subscription"
  }
}

resource "aws_sqs_queue_policy" "fifo_target" {
  queue_url = aws_sqs_queue.fifo_target.id

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
        Resource  = aws_sqs_queue.fifo_target.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.fifo_sub.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "fifo" {
  topic_arn = aws_sns_topic.fifo_sub.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.fifo_target.arn
}

################################################################################
# Test 24: Multiple subscriptions to same topic
################################################################################
resource "aws_sns_topic" "multi_sub" {
  name = "${local.name_prefix}-multi-sub"

  tags = {
    Name        = "Multi Sub Topic"
    TestNumber  = "24"
    Description = "Topic with multiple subscriptions"
  }
}

resource "aws_sqs_queue" "multi_target_1" {
  name = "${local.name_prefix}-multi-target-1"
  tags = { Name = "Multi Target 1", TestNumber = "24" }
}

resource "aws_sqs_queue" "multi_target_2" {
  name = "${local.name_prefix}-multi-target-2"
  tags = { Name = "Multi Target 2", TestNumber = "24" }
}

resource "aws_sqs_queue" "multi_target_3" {
  name = "${local.name_prefix}-multi-target-3"
  tags = { Name = "Multi Target 3", TestNumber = "24" }
}

resource "aws_sqs_queue_policy" "multi_target_1" {
  queue_url = aws_sqs_queue.multi_target_1.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNS"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.multi_target_1.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.multi_sub.arn } }
    }]
  })
}

resource "aws_sqs_queue_policy" "multi_target_2" {
  queue_url = aws_sqs_queue.multi_target_2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNS"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.multi_target_2.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.multi_sub.arn } }
    }]
  })
}

resource "aws_sqs_queue_policy" "multi_target_3" {
  queue_url = aws_sqs_queue.multi_target_3.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNS"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.multi_target_3.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.multi_sub.arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "multi_1" {
  topic_arn = aws_sns_topic.multi_sub.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.multi_target_1.arn
}

resource "aws_sns_topic_subscription" "multi_2" {
  topic_arn = aws_sns_topic.multi_sub.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.multi_target_2.arn
}

resource "aws_sns_topic_subscription" "multi_3" {
  topic_arn = aws_sns_topic.multi_sub.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.multi_target_3.arn
}

################################################################################
# Outputs
################################################################################

output "subscription_topics" {
  value = {
    for_sqs      = aws_sns_topic.for_sqs.name
    raw_delivery = aws_sns_topic.raw_delivery.name
    filtered     = aws_sns_topic.filtered.name
    filter_scope = aws_sns_topic.filter_scope.name
    fifo_sub     = aws_sns_topic.fifo_sub.name
    multi_sub    = aws_sns_topic.multi_sub.name
  }
  description = "Subscription topic names"
}

output "subscription_arns" {
  value = {
    sqs        = aws_sns_topic_subscription.sqs.arn
    raw_sqs    = aws_sns_topic_subscription.raw_sqs.arn
    filtered   = aws_sns_topic_subscription.filtered_sqs.arn
    fifo       = aws_sns_topic_subscription.fifo.arn
  }
  description = "Subscription ARNs"
}

output "target_queues" {
  value = {
    sns_target     = aws_sqs_queue.sns_target.url
    raw_target     = aws_sqs_queue.raw_target.url
    filtered       = aws_sqs_queue.filtered_target.url
    fifo_target    = aws_sqs_queue.fifo_target.url
  }
  description = "Target queue URLs"
}
