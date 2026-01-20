# test-06-edge-cases.tf
# Tests 43-50: SQS Edge Cases
# Tests: special characters, long polling, batch operations, URL parsing

################################################################################
# Test 43: Queue with special characters in tags
################################################################################
resource "aws_sqs_queue" "special_tags" {
  name = "${local.name_prefix}-special-tags"

  tags = {
    Name        = "Special Tags Queue"
    TestNumber  = "43"
    Description = "Tests queue with special tag values"
    Environment = "test-environment"
    CostCenter  = "12345-ABCDE"
    Project     = "warden/sqs/tests"
    Version     = "1.0.0"
  }
}

################################################################################
# Test 44: Queue with long polling enabled
################################################################################
resource "aws_sqs_queue" "long_polling" {
  name                      = "${local.name_prefix}-long-polling"
  receive_wait_time_seconds = 20

  tags = {
    Name        = "Long Polling Queue"
    TestNumber  = "44"
    Description = "Tests queue with long polling maximum"
  }
}

################################################################################
# Test 45: Queue with short polling
################################################################################
resource "aws_sqs_queue" "short_polling" {
  name                      = "${local.name_prefix}-short-polling"
  receive_wait_time_seconds = 0

  tags = {
    Name        = "Short Polling Queue"
    TestNumber  = "45"
    Description = "Tests queue with short polling"
  }
}

################################################################################
# Test 46: Queue with all settings at minimum
################################################################################
resource "aws_sqs_queue" "all_min" {
  name                       = "${local.name_prefix}-all-min"
  visibility_timeout_seconds = 0
  message_retention_seconds  = 60
  delay_seconds              = 0
  max_message_size           = 1024
  receive_wait_time_seconds  = 0

  tags = {
    Name        = "All Minimum Queue"
    TestNumber  = "46"
    Description = "Tests queue with all minimum settings"
  }
}

################################################################################
# Test 47: Queue with all settings at maximum
################################################################################
resource "aws_sqs_queue" "all_max" {
  name                       = "${local.name_prefix}-all-max"
  visibility_timeout_seconds = 43200
  message_retention_seconds  = 1209600
  delay_seconds              = 900
  max_message_size           = 262144
  receive_wait_time_seconds  = 20

  tags = {
    Name        = "All Maximum Queue"
    TestNumber  = "47"
    Description = "Tests queue with all maximum settings"
  }
}

################################################################################
# Test 48: Queue with numbers in name
################################################################################
resource "aws_sqs_queue" "numbers_name" {
  name = "${local.name_prefix}-123456789"

  tags = {
    Name        = "Numbers Name Queue"
    TestNumber  = "48"
    Description = "Tests queue with numbers in name"
  }
}

################################################################################
# Test 49: Queue with underscores in name
################################################################################
resource "aws_sqs_queue" "underscore_name" {
  name = "${local.name_prefix}_underscore_queue"

  tags = {
    Name        = "Underscore Name Queue"
    TestNumber  = "49"
    Description = "Tests queue with underscores in name"
  }
}

################################################################################
# Test 50: Queue for URL parsing test (contains region and account)
################################################################################
resource "aws_sqs_queue" "url_test" {
  name = "${local.name_prefix}-url-test"

  tags = {
    Name        = "URL Test Queue"
    TestNumber  = "50"
    Description = "Tests queue URL parsing with region and account ID"
  }
}

################################################################################
# Outputs
################################################################################

output "edge_case_queues" {
  value = {
    special_tags    = aws_sqs_queue.special_tags.name
    long_polling    = aws_sqs_queue.long_polling.name
    short_polling   = aws_sqs_queue.short_polling.name
    all_min         = aws_sqs_queue.all_min.name
    all_max         = aws_sqs_queue.all_max.name
    numbers_name    = aws_sqs_queue.numbers_name.name
    underscore_name = aws_sqs_queue.underscore_name.name
    url_test        = aws_sqs_queue.url_test.name
  }
  description = "Edge case queue names"
}

output "edge_case_queue_urls" {
  value = {
    special_tags    = aws_sqs_queue.special_tags.url
    long_polling    = aws_sqs_queue.long_polling.url
    all_min         = aws_sqs_queue.all_min.url
    all_max         = aws_sqs_queue.all_max.url
    numbers_name    = aws_sqs_queue.numbers_name.url
    underscore_name = aws_sqs_queue.underscore_name.url
    url_test        = aws_sqs_queue.url_test.url
  }
  description = "Edge case queue URLs - contain region and account ID"
}

output "url_parsing_test" {
  value = {
    queue_url    = aws_sqs_queue.url_test.url
    queue_arn    = aws_sqs_queue.url_test.arn
    queue_name   = aws_sqs_queue.url_test.name
    region       = data.aws_region.current.name
    account_id   = data.aws_caller_identity.current.account_id
  }
  description = "URL parsing test data"
}
