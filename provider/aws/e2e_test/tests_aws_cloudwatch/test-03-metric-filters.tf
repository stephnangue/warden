# test-03-metric-filters.tf
# Tests 16-22: CloudWatch Metric Filters
# Tests: basic filters, patterns, metric transformations

################################################################################
# Test 16: Basic Metric Filter
################################################################################
resource "aws_cloudwatch_log_group" "for_filters" {
  name = "/${local.name_prefix}/filters"

  tags = {
    Name        = "Log Group for Filters"
    TestNumber  = "16"
    Description = "Log group for metric filter tests"
  }
}

resource "aws_cloudwatch_log_metric_filter" "basic" {
  name           = "${local.name_prefix}-basic-filter"
  pattern        = "ERROR"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name      = "ErrorCount"
    namespace = "${local.name_prefix}/Errors"
    value     = "1"
  }
}

################################################################################
# Test 17: Metric Filter with JSON pattern
################################################################################
resource "aws_cloudwatch_log_metric_filter" "json_pattern" {
  name           = "${local.name_prefix}-json-filter"
  pattern        = "{ $.level = \"ERROR\" }"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name      = "JSONErrorCount"
    namespace = "${local.name_prefix}/Errors"
    value     = "1"
  }
}

################################################################################
# Test 18: Metric Filter with numeric extraction
################################################################################
resource "aws_cloudwatch_log_metric_filter" "numeric" {
  name           = "${local.name_prefix}-numeric-filter"
  pattern        = "{ $.latency = * }"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name      = "Latency"
    namespace = "${local.name_prefix}/Performance"
    value     = "$.latency"
  }
}

################################################################################
# Test 19: Metric Filter with dimensions
################################################################################
resource "aws_cloudwatch_log_metric_filter" "with_dimensions" {
  name           = "${local.name_prefix}-dimension-filter"
  pattern        = "{ $.statusCode = * }"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name       = "RequestCount"
    namespace  = "${local.name_prefix}/Requests"
    value      = "1"
    dimensions = {
      StatusCode = "$.statusCode"
    }
  }
}

################################################################################
# Test 20: Metric Filter with default value
################################################################################
resource "aws_cloudwatch_log_metric_filter" "with_default" {
  name           = "${local.name_prefix}-default-filter"
  pattern        = "{ $.duration = * }"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name          = "Duration"
    namespace     = "${local.name_prefix}/Performance"
    value         = "$.duration"
    default_value = "0"
  }
}

################################################################################
# Test 21: Metric Filter with complex pattern
################################################################################
resource "aws_cloudwatch_log_metric_filter" "complex" {
  name           = "${local.name_prefix}-complex-filter"
  pattern        = "[timestamp, requestid, level=ERROR, message]"
  log_group_name = aws_cloudwatch_log_group.for_filters.name

  metric_transformation {
    name      = "ComplexErrorCount"
    namespace = "${local.name_prefix}/Errors"
    value     = "1"
  }
}

################################################################################
# Test 22: Multiple filters on same log group
################################################################################
resource "aws_cloudwatch_log_group" "multi_filter" {
  name = "/${local.name_prefix}/multi-filter"

  tags = {
    Name        = "Multi Filter Log Group"
    TestNumber  = "22"
    Description = "Log group with multiple metric filters"
  }
}

resource "aws_cloudwatch_log_metric_filter" "multi_error" {
  name           = "${local.name_prefix}-multi-error"
  pattern        = "ERROR"
  log_group_name = aws_cloudwatch_log_group.multi_filter.name

  metric_transformation {
    name      = "MultiErrorCount"
    namespace = "${local.name_prefix}/MultiMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "multi_warn" {
  name           = "${local.name_prefix}-multi-warn"
  pattern        = "WARN"
  log_group_name = aws_cloudwatch_log_group.multi_filter.name

  metric_transformation {
    name      = "MultiWarnCount"
    namespace = "${local.name_prefix}/MultiMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "multi_info" {
  name           = "${local.name_prefix}-multi-info"
  pattern        = "INFO"
  log_group_name = aws_cloudwatch_log_group.multi_filter.name

  metric_transformation {
    name      = "MultiInfoCount"
    namespace = "${local.name_prefix}/MultiMetrics"
    value     = "1"
  }
}

################################################################################
# Outputs
################################################################################

output "metric_filter_names" {
  value = {
    basic           = aws_cloudwatch_log_metric_filter.basic.name
    json_pattern    = aws_cloudwatch_log_metric_filter.json_pattern.name
    numeric         = aws_cloudwatch_log_metric_filter.numeric.name
    with_dimensions = aws_cloudwatch_log_metric_filter.with_dimensions.name
    with_default    = aws_cloudwatch_log_metric_filter.with_default.name
    complex         = aws_cloudwatch_log_metric_filter.complex.name
  }
  description = "CloudWatch Metric Filter names"
}
