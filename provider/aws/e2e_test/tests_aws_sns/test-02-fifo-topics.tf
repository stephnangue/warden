# test-02-fifo-topics.tf
# Tests 11-18: FIFO Topic configurations
# Tests: basic FIFO, content-based deduplication

################################################################################
# Test 11: Basic FIFO Topic
################################################################################
resource "aws_sns_topic" "fifo_basic" {
  name       = "${local.name_prefix}-basic.fifo"
  fifo_topic = true

  tags = {
    Name        = "Basic FIFO Topic"
    TestNumber  = "11"
    Description = "Tests basic FIFO topic creation"
  }
}

################################################################################
# Test 12: FIFO Topic with content-based deduplication
################################################################################
resource "aws_sns_topic" "fifo_content_dedup" {
  name                        = "${local.name_prefix}-content-dedup.fifo"
  fifo_topic                  = true
  content_based_deduplication = true

  tags = {
    Name        = "Content Dedup FIFO Topic"
    TestNumber  = "12"
    Description = "Tests FIFO topic with content-based deduplication"
  }
}

################################################################################
# Test 13: FIFO Topic without content-based deduplication
################################################################################
resource "aws_sns_topic" "fifo_no_content_dedup" {
  name                        = "${local.name_prefix}-no-content-dedup.fifo"
  fifo_topic                  = true
  content_based_deduplication = false

  tags = {
    Name        = "No Content Dedup FIFO Topic"
    TestNumber  = "13"
    Description = "Tests FIFO topic without content-based deduplication"
  }
}

################################################################################
# Test 14: FIFO Topic with display name
################################################################################
resource "aws_sns_topic" "fifo_display_name" {
  name         = "${local.name_prefix}-display.fifo"
  fifo_topic   = true
  display_name = "FIFO Display Name"

  tags = {
    Name        = "FIFO Display Name Topic"
    TestNumber  = "14"
    Description = "Tests FIFO topic with display name"
  }
}

################################################################################
# Test 15: FIFO Topic with long name
################################################################################
resource "aws_sns_topic" "fifo_long_name" {
  name       = "${local.name_prefix}-this-is-a-longer-fifo-name.fifo"
  fifo_topic = true

  tags = {
    Name        = "Long Name FIFO Topic"
    TestNumber  = "15"
    Description = "Tests FIFO topic with longer name"
  }
}

################################################################################
# Test 16: FIFO Topic with numbers in name
################################################################################
resource "aws_sns_topic" "fifo_numbers" {
  name       = "${local.name_prefix}-123456.fifo"
  fifo_topic = true

  tags = {
    Name        = "Numbers FIFO Topic"
    TestNumber  = "16"
    Description = "Tests FIFO topic with numbers in name"
  }
}

################################################################################
# Test 17: FIFO Topic with underscores
################################################################################
resource "aws_sns_topic" "fifo_underscore" {
  name       = "${local.name_prefix}_underscore.fifo"
  fifo_topic = true

  tags = {
    Name        = "Underscore FIFO Topic"
    TestNumber  = "17"
    Description = "Tests FIFO topic with underscores"
  }
}

################################################################################
# Test 18: FIFO Topic for SQS subscription
################################################################################
resource "aws_sns_topic" "fifo_for_sqs" {
  name                        = "${local.name_prefix}-for-sqs.fifo"
  fifo_topic                  = true
  content_based_deduplication = true

  tags = {
    Name        = "FIFO for SQS Topic"
    TestNumber  = "18"
    Description = "Tests FIFO topic for SQS subscription"
  }
}

################################################################################
# Outputs
################################################################################

output "fifo_topics" {
  value = {
    basic           = aws_sns_topic.fifo_basic.name
    content_dedup   = aws_sns_topic.fifo_content_dedup.name
    no_content_dedup = aws_sns_topic.fifo_no_content_dedup.name
    display_name    = aws_sns_topic.fifo_display_name.name
    long_name       = aws_sns_topic.fifo_long_name.name
    numbers         = aws_sns_topic.fifo_numbers.name
    underscore      = aws_sns_topic.fifo_underscore.name
    for_sqs         = aws_sns_topic.fifo_for_sqs.name
  }
  description = "FIFO topic names"
}

output "fifo_topic_arns" {
  value = {
    basic         = aws_sns_topic.fifo_basic.arn
    content_dedup = aws_sns_topic.fifo_content_dedup.arn
    for_sqs       = aws_sns_topic.fifo_for_sqs.arn
  }
  description = "FIFO topic ARNs"
}
