# test-01-standard-topics.tf
# Tests 1-10: Standard SNS Topic configurations
# Tests: basic topics, display names, delivery policies

################################################################################
# Test 1: Basic Standard Topic
################################################################################
resource "aws_sns_topic" "basic" {
  name = "${local.name_prefix}-basic"

  tags = {
    Name        = "Basic Topic"
    TestNumber  = "01"
    Description = "Tests basic standard topic creation"
  }
}

################################################################################
# Test 2: Topic with display name
################################################################################
resource "aws_sns_topic" "display_name" {
  name         = "${local.name_prefix}-display-name"
  display_name = "Warden Test Topic"

  tags = {
    Name        = "Display Name Topic"
    TestNumber  = "02"
    Description = "Tests topic with display name"
  }
}

################################################################################
# Test 3: Topic with delivery policy
################################################################################
resource "aws_sns_topic" "delivery_policy" {
  name = "${local.name_prefix}-delivery-policy"

  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 20
        maxDelayTarget     = 20
        numRetries         = 3
        numMaxDelayRetries = 0
        numNoDelayRetries  = 0
        numMinDelayRetries = 0
        backoffFunction    = "linear"
      }
      disableSubscriptionOverrides = false
    }
  })

  tags = {
    Name        = "Delivery Policy Topic"
    TestNumber  = "03"
    Description = "Tests topic with custom delivery policy"
  }
}

################################################################################
# Test 4: Topic with aggressive retry policy
################################################################################
resource "aws_sns_topic" "aggressive_retry" {
  name = "${local.name_prefix}-aggressive-retry"

  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 1
        maxDelayTarget     = 60
        numRetries         = 10
        numMaxDelayRetries = 3
        numNoDelayRetries  = 2
        numMinDelayRetries = 2
        backoffFunction    = "exponential"
      }
      disableSubscriptionOverrides = false
    }
  })

  tags = {
    Name        = "Aggressive Retry Topic"
    TestNumber  = "04"
    Description = "Tests topic with aggressive retry policy"
  }
}

################################################################################
# Test 5: Topic with subscription overrides disabled
################################################################################
resource "aws_sns_topic" "no_overrides" {
  name = "${local.name_prefix}-no-overrides"

  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 20
        maxDelayTarget     = 20
        numRetries         = 3
        backoffFunction    = "linear"
      }
      disableSubscriptionOverrides = true
    }
  })

  tags = {
    Name        = "No Overrides Topic"
    TestNumber  = "05"
    Description = "Tests topic with subscription overrides disabled"
  }
}

################################################################################
# Test 6: Topic with long name
################################################################################
resource "aws_sns_topic" "long_name" {
  name = "${local.name_prefix}-this-is-a-longer-topic-name-for-testing"

  tags = {
    Name        = "Long Name Topic"
    TestNumber  = "06"
    Description = "Tests topic with longer name"
  }
}

################################################################################
# Test 7: Topic with numbers in name
################################################################################
resource "aws_sns_topic" "numbers_name" {
  name = "${local.name_prefix}-123456789"

  tags = {
    Name        = "Numbers Name Topic"
    TestNumber  = "07"
    Description = "Tests topic with numbers in name"
  }
}

################################################################################
# Test 8: Topic with underscores
################################################################################
resource "aws_sns_topic" "underscore_name" {
  name = "${local.name_prefix}_underscore_topic"

  tags = {
    Name        = "Underscore Name Topic"
    TestNumber  = "08"
    Description = "Tests topic with underscores in name"
  }
}

################################################################################
# Test 9: Topic with special tags
################################################################################
resource "aws_sns_topic" "special_tags" {
  name = "${local.name_prefix}-special-tags"

  tags = {
    Name        = "Special Tags Topic"
    TestNumber  = "09"
    Description = "Tests topic with various tag values"
  }
}

################################################################################
# Test 10: Topic with content-based deduplication (for later FIFO comparison)
################################################################################
resource "aws_sns_topic" "for_comparison" {
  name = "${local.name_prefix}-for-comparison"

  tags = {
    Name        = "Comparison Topic"
    TestNumber  = "10"
    Description = "Standard topic for FIFO comparison"
  }
}

################################################################################
# Outputs
################################################################################

output "standard_topics" {
  value = {
    basic            = aws_sns_topic.basic.name
    display_name     = aws_sns_topic.display_name.name
    delivery_policy  = aws_sns_topic.delivery_policy.name
    aggressive_retry = aws_sns_topic.aggressive_retry.name
    no_overrides     = aws_sns_topic.no_overrides.name
    long_name        = aws_sns_topic.long_name.name
    numbers_name     = aws_sns_topic.numbers_name.name
    underscore_name  = aws_sns_topic.underscore_name.name
    special_tags     = aws_sns_topic.special_tags.name
    for_comparison   = aws_sns_topic.for_comparison.name
  }
  description = "Standard topic names"
}

output "standard_topic_arns" {
  value = {
    basic            = aws_sns_topic.basic.arn
    display_name     = aws_sns_topic.display_name.arn
    delivery_policy  = aws_sns_topic.delivery_policy.arn
    aggressive_retry = aws_sns_topic.aggressive_retry.arn
  }
  description = "Standard topic ARNs"
}
