# test-06-subscriptions.tf
# Tests 38-42: CloudWatch Logs Subscription Filters
# Tests: Lambda destinations, Kinesis destinations, filter patterns

################################################################################
# IAM Role for Kinesis subscription
################################################################################
resource "aws_iam_role" "logs_kinesis" {
  name = "${local.name_prefix}-logs-kinesis"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "Logs Kinesis Role"
    TestNumber  = "38"
    Description = "IAM role for logs to Kinesis"
  }
}

resource "aws_iam_role_policy" "logs_kinesis" {
  name = "kinesis-put"
  role = aws_iam_role.logs_kinesis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kinesis:PutRecord",
          "kinesis:PutRecords"
        ]
        Effect   = "Allow"
        Resource = aws_kinesis_stream.logs_target.arn
      }
    ]
  })
}

################################################################################
# Kinesis Stream for subscription target
################################################################################
resource "aws_kinesis_stream" "logs_target" {
  name             = "${local.name_prefix}-logs-target"
  shard_count      = 1
  retention_period = 24

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  tags = {
    Name        = "Logs Target Stream"
    TestNumber  = "38"
    Description = "Kinesis stream for log subscription"
  }
}

################################################################################
# Test 38: Log Group for subscription tests
################################################################################
resource "aws_cloudwatch_log_group" "for_subscription" {
  name = "/${local.name_prefix}/subscription"

  tags = {
    Name        = "Subscription Log Group"
    TestNumber  = "38"
    Description = "Log group for subscription filter tests"
  }
}

################################################################################
# Test 39: Subscription Filter to Kinesis
################################################################################
resource "aws_cloudwatch_log_subscription_filter" "kinesis" {
  name            = "${local.name_prefix}-kinesis-sub"
  log_group_name  = aws_cloudwatch_log_group.for_subscription.name
  filter_pattern  = "ERROR"
  destination_arn = aws_kinesis_stream.logs_target.arn
  role_arn        = aws_iam_role.logs_kinesis.arn
}

################################################################################
# Test 40: Subscription Filter with JSON pattern
################################################################################
resource "aws_cloudwatch_log_group" "json_sub" {
  name = "/${local.name_prefix}/json-subscription"

  tags = {
    Name        = "JSON Subscription Log Group"
    TestNumber  = "40"
    Description = "Log group for JSON subscription filter"
  }
}

resource "aws_cloudwatch_log_subscription_filter" "json" {
  name            = "${local.name_prefix}-json-sub"
  log_group_name  = aws_cloudwatch_log_group.json_sub.name
  filter_pattern  = "{ $.level = \"ERROR\" }"
  destination_arn = aws_kinesis_stream.logs_target.arn
  role_arn        = aws_iam_role.logs_kinesis.arn
}

################################################################################
# Test 41: Subscription Filter with no pattern (all logs)
################################################################################
resource "aws_cloudwatch_log_group" "all_logs_sub" {
  name = "/${local.name_prefix}/all-logs-subscription"

  tags = {
    Name        = "All Logs Subscription Log Group"
    TestNumber  = "41"
    Description = "Log group for all-logs subscription filter"
  }
}

resource "aws_cloudwatch_log_subscription_filter" "all_logs" {
  name            = "${local.name_prefix}-all-sub"
  log_group_name  = aws_cloudwatch_log_group.all_logs_sub.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_stream.logs_target.arn
  role_arn        = aws_iam_role.logs_kinesis.arn
}

################################################################################
# Test 42: Query Definition
################################################################################
resource "aws_cloudwatch_query_definition" "basic" {
  name = "${local.name_prefix}/errors"

  log_group_names = [
    aws_cloudwatch_log_group.for_subscription.name
  ]

  query_string = <<-EOF
    fields @timestamp, @message
    | filter @message like /ERROR/
    | sort @timestamp desc
    | limit 100
  EOF
}

resource "aws_cloudwatch_query_definition" "with_stats" {
  name = "${local.name_prefix}/error-stats"

  log_group_names = [
    aws_cloudwatch_log_group.for_subscription.name,
    aws_cloudwatch_log_group.json_sub.name
  ]

  query_string = <<-EOF
    fields @timestamp, @message
    | filter @message like /ERROR/
    | stats count(*) as errorCount by bin(1h)
  EOF
}

################################################################################
# Outputs
################################################################################

output "subscription_filter_names" {
  value = {
    kinesis  = aws_cloudwatch_log_subscription_filter.kinesis.name
    json     = aws_cloudwatch_log_subscription_filter.json.name
    all_logs = aws_cloudwatch_log_subscription_filter.all_logs.name
  }
  description = "CloudWatch Logs Subscription Filter names"
}

output "kinesis_stream_arn" {
  value       = aws_kinesis_stream.logs_target.arn
  description = "Kinesis stream ARN for log subscription"
}

output "query_definition_ids" {
  value = {
    basic      = aws_cloudwatch_query_definition.basic.query_definition_id
    with_stats = aws_cloudwatch_query_definition.with_stats.query_definition_id
  }
  description = "CloudWatch Logs Query Definition IDs"
}
