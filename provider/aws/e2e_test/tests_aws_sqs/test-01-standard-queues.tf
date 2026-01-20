# test-01-standard-queues.tf
# Tests 1-10: Standard SQS Queue configurations
# Tests: basic queues, visibility timeout, message retention, delay

################################################################################
# Test 1: Basic Standard Queue
################################################################################
resource "aws_sqs_queue" "basic" {
  name = "${local.name_prefix}-basic"

  tags = {
    Name        = "Basic Queue"
    TestNumber  = "01"
    Description = "Tests basic standard queue creation"
  }
}

################################################################################
# Test 2: Queue with custom visibility timeout
################################################################################
resource "aws_sqs_queue" "visibility_timeout" {
  name                       = "${local.name_prefix}-visibility"
  visibility_timeout_seconds = 120

  tags = {
    Name        = "Visibility Timeout Queue"
    TestNumber  = "02"
    Description = "Tests queue with custom visibility timeout"
  }
}

################################################################################
# Test 3: Queue with maximum visibility timeout (12 hours)
################################################################################
resource "aws_sqs_queue" "max_visibility" {
  name                       = "${local.name_prefix}-max-visibility"
  visibility_timeout_seconds = 43200

  tags = {
    Name        = "Max Visibility Queue"
    TestNumber  = "03"
    Description = "Tests queue with maximum visibility timeout"
  }
}

################################################################################
# Test 4: Queue with custom message retention
################################################################################
resource "aws_sqs_queue" "retention" {
  name                      = "${local.name_prefix}-retention"
  message_retention_seconds = 604800 # 7 days

  tags = {
    Name        = "Retention Queue"
    TestNumber  = "04"
    Description = "Tests queue with custom message retention"
  }
}

################################################################################
# Test 5: Queue with maximum retention (14 days)
################################################################################
resource "aws_sqs_queue" "max_retention" {
  name                      = "${local.name_prefix}-max-retention"
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name        = "Max Retention Queue"
    TestNumber  = "05"
    Description = "Tests queue with maximum message retention"
  }
}

################################################################################
# Test 6: Queue with minimum retention (1 minute)
################################################################################
resource "aws_sqs_queue" "min_retention" {
  name                      = "${local.name_prefix}-min-retention"
  message_retention_seconds = 60

  tags = {
    Name        = "Min Retention Queue"
    TestNumber  = "06"
    Description = "Tests queue with minimum message retention"
  }
}

################################################################################
# Test 7: Queue with delay seconds
################################################################################
resource "aws_sqs_queue" "delay" {
  name          = "${local.name_prefix}-delay"
  delay_seconds = 30

  tags = {
    Name        = "Delay Queue"
    TestNumber  = "07"
    Description = "Tests queue with delivery delay"
  }
}

################################################################################
# Test 8: Queue with maximum delay (15 minutes)
################################################################################
resource "aws_sqs_queue" "max_delay" {
  name          = "${local.name_prefix}-max-delay"
  delay_seconds = 900

  tags = {
    Name        = "Max Delay Queue"
    TestNumber  = "08"
    Description = "Tests queue with maximum delivery delay"
  }
}

################################################################################
# Test 9: Queue with custom max message size
################################################################################
resource "aws_sqs_queue" "message_size" {
  name                = "${local.name_prefix}-message-size"
  max_message_size    = 131072 # 128 KB

  tags = {
    Name        = "Message Size Queue"
    TestNumber  = "09"
    Description = "Tests queue with custom max message size"
  }
}

################################################################################
# Test 10: Queue with maximum message size (256 KB)
################################################################################
resource "aws_sqs_queue" "max_message_size" {
  name             = "${local.name_prefix}-max-msg-size"
  max_message_size = 262144 # 256 KB

  tags = {
    Name        = "Max Message Size Queue"
    TestNumber  = "10"
    Description = "Tests queue with maximum message size"
  }
}

################################################################################
# Outputs
################################################################################

output "standard_queues" {
  value = {
    basic            = aws_sqs_queue.basic.name
    visibility       = aws_sqs_queue.visibility_timeout.name
    max_visibility   = aws_sqs_queue.max_visibility.name
    retention        = aws_sqs_queue.retention.name
    max_retention    = aws_sqs_queue.max_retention.name
    min_retention    = aws_sqs_queue.min_retention.name
    delay            = aws_sqs_queue.delay.name
    max_delay        = aws_sqs_queue.max_delay.name
    message_size     = aws_sqs_queue.message_size.name
    max_message_size = aws_sqs_queue.max_message_size.name
  }
  description = "Standard queue names"
}

output "standard_queue_urls" {
  value = {
    basic            = aws_sqs_queue.basic.url
    visibility       = aws_sqs_queue.visibility_timeout.url
    max_visibility   = aws_sqs_queue.max_visibility.url
    retention        = aws_sqs_queue.retention.url
    max_retention    = aws_sqs_queue.max_retention.url
    min_retention    = aws_sqs_queue.min_retention.url
    delay            = aws_sqs_queue.delay.url
    max_delay        = aws_sqs_queue.max_delay.url
    message_size     = aws_sqs_queue.message_size.url
    max_message_size = aws_sqs_queue.max_message_size.url
  }
  description = "Standard queue URLs - these contain region and account ID"
}

output "standard_queue_arns" {
  value = {
    basic    = aws_sqs_queue.basic.arn
    delay    = aws_sqs_queue.delay.arn
    retention = aws_sqs_queue.retention.arn
  }
  description = "Standard queue ARNs"
}
