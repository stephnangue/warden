# test-02-log-streams.tf
# Tests 11-15: CloudWatch Log Streams
# Tests: basic streams, naming patterns

################################################################################
# Test 11: Basic Log Stream
################################################################################
resource "aws_cloudwatch_log_group" "for_streams" {
  name = "/${local.name_prefix}/streams"

  tags = {
    Name        = "Log Group for Streams"
    TestNumber  = "11"
    Description = "Log group for stream tests"
  }
}

resource "aws_cloudwatch_log_stream" "basic" {
  name           = "basic-stream"
  log_group_name = aws_cloudwatch_log_group.for_streams.name
}

################################################################################
# Test 12: Log Stream with date-based name
################################################################################
resource "aws_cloudwatch_log_stream" "date_based" {
  name           = "2024/01/19/stream"
  log_group_name = aws_cloudwatch_log_group.for_streams.name
}

################################################################################
# Test 13: Log Stream with instance ID pattern
################################################################################
resource "aws_cloudwatch_log_stream" "instance_pattern" {
  name           = "i-1234567890abcdef0"
  log_group_name = aws_cloudwatch_log_group.for_streams.name
}

################################################################################
# Test 14: Log Stream with container ID pattern
################################################################################
resource "aws_cloudwatch_log_stream" "container_pattern" {
  name           = "ecs/service/abc123def456"
  log_group_name = aws_cloudwatch_log_group.for_streams.name
}

################################################################################
# Test 15: Multiple streams in same group
################################################################################
resource "aws_cloudwatch_log_group" "multi_stream" {
  name = "/${local.name_prefix}/multi-stream"

  tags = {
    Name        = "Multi Stream Log Group"
    TestNumber  = "15"
    Description = "Log group with multiple streams"
  }
}

resource "aws_cloudwatch_log_stream" "multi_1" {
  name           = "stream-1"
  log_group_name = aws_cloudwatch_log_group.multi_stream.name
}

resource "aws_cloudwatch_log_stream" "multi_2" {
  name           = "stream-2"
  log_group_name = aws_cloudwatch_log_group.multi_stream.name
}

resource "aws_cloudwatch_log_stream" "multi_3" {
  name           = "stream-3"
  log_group_name = aws_cloudwatch_log_group.multi_stream.name
}

################################################################################
# Outputs
################################################################################

output "log_stream_names" {
  value = {
    basic             = aws_cloudwatch_log_stream.basic.name
    date_based        = aws_cloudwatch_log_stream.date_based.name
    instance_pattern  = aws_cloudwatch_log_stream.instance_pattern.name
    container_pattern = aws_cloudwatch_log_stream.container_pattern.name
    multi_1           = aws_cloudwatch_log_stream.multi_1.name
    multi_2           = aws_cloudwatch_log_stream.multi_2.name
    multi_3           = aws_cloudwatch_log_stream.multi_3.name
  }
  description = "CloudWatch Log Stream names"
}
