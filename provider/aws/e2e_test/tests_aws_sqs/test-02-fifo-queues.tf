# test-02-fifo-queues.tf
# Tests 11-20: FIFO Queue configurations
# Tests: basic FIFO, deduplication, high throughput, content-based dedup

################################################################################
# Test 11: Basic FIFO Queue
################################################################################
resource "aws_sqs_queue" "fifo_basic" {
  name       = "${local.name_prefix}-basic.fifo"
  fifo_queue = true

  tags = {
    Name        = "Basic FIFO Queue"
    TestNumber  = "11"
    Description = "Tests basic FIFO queue creation"
  }
}

################################################################################
# Test 12: FIFO Queue with content-based deduplication
################################################################################
resource "aws_sqs_queue" "fifo_content_dedup" {
  name                        = "${local.name_prefix}-content-dedup.fifo"
  fifo_queue                  = true
  content_based_deduplication = true

  tags = {
    Name        = "Content Dedup FIFO Queue"
    TestNumber  = "12"
    Description = "Tests FIFO queue with content-based deduplication"
  }
}

################################################################################
# Test 13: FIFO Queue without content-based deduplication
################################################################################
resource "aws_sqs_queue" "fifo_no_content_dedup" {
  name                        = "${local.name_prefix}-no-content-dedup.fifo"
  fifo_queue                  = true
  content_based_deduplication = false

  tags = {
    Name        = "No Content Dedup FIFO Queue"
    TestNumber  = "13"
    Description = "Tests FIFO queue without content-based deduplication"
  }
}

################################################################################
# Test 14: FIFO Queue with high throughput mode
################################################################################
resource "aws_sqs_queue" "fifo_high_throughput" {
  name                        = "${local.name_prefix}-high-throughput.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  deduplication_scope         = "messageGroup"
  fifo_throughput_limit       = "perMessageGroupId"

  tags = {
    Name        = "High Throughput FIFO Queue"
    TestNumber  = "14"
    Description = "Tests FIFO queue with high throughput mode"
  }
}

################################################################################
# Test 15: FIFO Queue with queue-level deduplication
################################################################################
resource "aws_sqs_queue" "fifo_queue_dedup" {
  name                        = "${local.name_prefix}-queue-dedup.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  deduplication_scope         = "queue"
  fifo_throughput_limit       = "perQueue"

  tags = {
    Name        = "Queue Dedup FIFO Queue"
    TestNumber  = "15"
    Description = "Tests FIFO queue with queue-level deduplication"
  }
}

################################################################################
# Test 16: FIFO Queue with custom visibility timeout
################################################################################
resource "aws_sqs_queue" "fifo_visibility" {
  name                       = "${local.name_prefix}-visibility.fifo"
  fifo_queue                 = true
  visibility_timeout_seconds = 300

  tags = {
    Name        = "Visibility FIFO Queue"
    TestNumber  = "16"
    Description = "Tests FIFO queue with custom visibility timeout"
  }
}

################################################################################
# Test 17: FIFO Queue with delay
################################################################################
resource "aws_sqs_queue" "fifo_delay" {
  name          = "${local.name_prefix}-delay.fifo"
  fifo_queue    = true
  delay_seconds = 60

  tags = {
    Name        = "Delay FIFO Queue"
    TestNumber  = "17"
    Description = "Tests FIFO queue with delivery delay"
  }
}

################################################################################
# Test 18: FIFO Queue with custom retention
################################################################################
resource "aws_sqs_queue" "fifo_retention" {
  name                      = "${local.name_prefix}-retention.fifo"
  fifo_queue                = true
  message_retention_seconds = 259200 # 3 days

  tags = {
    Name        = "Retention FIFO Queue"
    TestNumber  = "18"
    Description = "Tests FIFO queue with custom retention"
  }
}

################################################################################
# Test 19: FIFO Queue with all custom settings
################################################################################
resource "aws_sqs_queue" "fifo_custom" {
  name                        = "${local.name_prefix}-custom.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  visibility_timeout_seconds  = 600
  message_retention_seconds   = 86400
  delay_seconds               = 15
  max_message_size            = 65536

  tags = {
    Name        = "Custom FIFO Queue"
    TestNumber  = "19"
    Description = "Tests FIFO queue with all custom settings"
  }
}

################################################################################
# Test 20: FIFO Queue with long name
################################################################################
resource "aws_sqs_queue" "fifo_long_name" {
  name       = "${local.name_prefix}-this-is-a-longer-queue-name.fifo"
  fifo_queue = true

  tags = {
    Name        = "Long Name FIFO Queue"
    TestNumber  = "20"
    Description = "Tests FIFO queue with longer name"
  }
}

################################################################################
# Outputs
################################################################################

output "fifo_queues" {
  value = {
    basic           = aws_sqs_queue.fifo_basic.name
    content_dedup   = aws_sqs_queue.fifo_content_dedup.name
    no_content_dedup = aws_sqs_queue.fifo_no_content_dedup.name
    high_throughput = aws_sqs_queue.fifo_high_throughput.name
    queue_dedup     = aws_sqs_queue.fifo_queue_dedup.name
    visibility      = aws_sqs_queue.fifo_visibility.name
    delay           = aws_sqs_queue.fifo_delay.name
    retention       = aws_sqs_queue.fifo_retention.name
    custom          = aws_sqs_queue.fifo_custom.name
    long_name       = aws_sqs_queue.fifo_long_name.name
  }
  description = "FIFO queue names"
}

output "fifo_queue_urls" {
  value = {
    basic           = aws_sqs_queue.fifo_basic.url
    content_dedup   = aws_sqs_queue.fifo_content_dedup.url
    high_throughput = aws_sqs_queue.fifo_high_throughput.url
    custom          = aws_sqs_queue.fifo_custom.url
  }
  description = "FIFO queue URLs"
}

output "fifo_queue_arns" {
  value = {
    basic           = aws_sqs_queue.fifo_basic.arn
    high_throughput = aws_sqs_queue.fifo_high_throughput.arn
    custom          = aws_sqs_queue.fifo_custom.arn
  }
  description = "FIFO queue ARNs"
}
