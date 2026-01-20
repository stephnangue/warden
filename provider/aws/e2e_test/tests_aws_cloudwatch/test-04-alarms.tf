# test-04-alarms.tf
# Tests 23-32: CloudWatch Alarms
# Tests: metric alarms, comparison operators, actions, composite alarms

################################################################################
# SNS Topic for alarm actions
################################################################################
resource "aws_sns_topic" "alarm_actions" {
  name = "${local.name_prefix}-alarm-actions"

  tags = {
    Name        = "Alarm Actions Topic"
    TestNumber  = "23"
    Description = "SNS topic for alarm actions"
  }
}

################################################################################
# Test 23: Basic Metric Alarm
################################################################################
resource "aws_cloudwatch_metric_alarm" "basic" {
  alarm_name          = "${local.name_prefix}-basic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Basic CPU utilization alarm"

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Basic Alarm"
    TestNumber  = "23"
    Description = "Basic metric alarm"
  }
}

################################################################################
# Test 24: Alarm with actions
################################################################################
resource "aws_cloudwatch_metric_alarm" "with_actions" {
  alarm_name          = "${local.name_prefix}-with-actions"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 90
  alarm_description   = "Alarm with SNS actions"

  alarm_actions = [aws_sns_topic.alarm_actions.arn]
  ok_actions    = [aws_sns_topic.alarm_actions.arn]

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Alarm with Actions"
    TestNumber  = "24"
    Description = "Alarm with alarm and ok actions"
  }
}

################################################################################
# Test 25: Alarm with LessThan comparison
################################################################################
resource "aws_cloudwatch_metric_alarm" "less_than" {
  alarm_name          = "${local.name_prefix}-less-than"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alarm for low healthy host count"

  dimensions = {
    LoadBalancerName = "my-load-balancer"
  }

  tags = {
    Name        = "Less Than Alarm"
    TestNumber  = "25"
    Description = "Alarm with LessThan comparison"
  }
}

################################################################################
# Test 26: Alarm with missing data treatment
################################################################################
resource "aws_cloudwatch_metric_alarm" "missing_data" {
  alarm_name                = "${local.name_prefix}-missing-data"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = 2
  metric_name               = "Errors"
  namespace                 = "AWS/Lambda"
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 5
  alarm_description         = "Alarm treating missing data as not breaching"
  treat_missing_data        = "notBreaching"

  dimensions = {
    FunctionName = "my-function"
  }

  tags = {
    Name        = "Missing Data Alarm"
    TestNumber  = "26"
    Description = "Alarm with missing data treatment"
  }
}

################################################################################
# Test 27: Alarm with extended statistic (percentile)
################################################################################
resource "aws_cloudwatch_metric_alarm" "percentile" {
  alarm_name          = "${local.name_prefix}-percentile"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  extended_statistic  = "p99"
  threshold           = 5000
  alarm_description   = "Alarm on p99 latency"

  dimensions = {
    FunctionName = "my-function"
  }

  tags = {
    Name        = "Percentile Alarm"
    TestNumber  = "27"
    Description = "Alarm with extended statistic"
  }
}

################################################################################
# Test 28: Alarm with datapoints to alarm
################################################################################
resource "aws_cloudwatch_metric_alarm" "datapoints" {
  alarm_name          = "${local.name_prefix}-datapoints"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Alarm with 3 of 5 datapoints"

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Datapoints Alarm"
    TestNumber  = "28"
    Description = "Alarm with datapoints to alarm"
  }
}

################################################################################
# Test 29: Alarm with anomaly detection
################################################################################
resource "aws_cloudwatch_metric_alarm" "anomaly" {
  alarm_name          = "${local.name_prefix}-anomaly"
  comparison_operator = "LessThanLowerOrGreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "e1"
  alarm_description   = "Alarm based on anomaly detection"

  metric_query {
    id          = "m1"
    return_data = true

    metric {
      metric_name = "CPUUtilization"
      namespace   = "AWS/EC2"
      period      = 300
      stat        = "Average"

      dimensions = {
        InstanceId = "i-1234567890abcdef0"
      }
    }
  }

  metric_query {
    id          = "e1"
    expression  = "ANOMALY_DETECTION_BAND(m1, 2)"
    label       = "CPUUtilization (expected)"
    return_data = true
  }

  tags = {
    Name        = "Anomaly Alarm"
    TestNumber  = "29"
    Description = "Alarm with anomaly detection"
  }
}

################################################################################
# Test 30: Alarm with math expression
################################################################################
resource "aws_cloudwatch_metric_alarm" "math_expression" {
  alarm_name          = "${local.name_prefix}-math"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 100
  alarm_description   = "Alarm using metric math"

  metric_query {
    id          = "m1"
    return_data = false

    metric {
      metric_name = "Invocations"
      namespace   = "AWS/Lambda"
      period      = 60
      stat        = "Sum"

      dimensions = {
        FunctionName = "my-function"
      }
    }
  }

  metric_query {
    id          = "m2"
    return_data = false

    metric {
      metric_name = "Errors"
      namespace   = "AWS/Lambda"
      period      = 60
      stat        = "Sum"

      dimensions = {
        FunctionName = "my-function"
      }
    }
  }

  metric_query {
    id          = "e1"
    expression  = "m2/m1*100"
    label       = "Error Rate"
    return_data = true
  }

  tags = {
    Name        = "Math Expression Alarm"
    TestNumber  = "30"
    Description = "Alarm with metric math expression"
  }
}

################################################################################
# Test 31: Composite Alarm
################################################################################
resource "aws_cloudwatch_metric_alarm" "composite_child_1" {
  alarm_name          = "${local.name_prefix}-comp-child-1"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Child alarm 1 for composite"

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Composite Child 1"
    TestNumber  = "31"
    Description = "Child alarm for composite"
  }
}

resource "aws_cloudwatch_metric_alarm" "composite_child_2" {
  alarm_name          = "${local.name_prefix}-comp-child-2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NetworkIn"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 1000000
  alarm_description   = "Child alarm 2 for composite"

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Composite Child 2"
    TestNumber  = "31"
    Description = "Child alarm for composite"
  }
}

resource "aws_cloudwatch_composite_alarm" "composite" {
  alarm_name        = "${local.name_prefix}-composite"
  alarm_description = "Composite alarm combining CPU and Network"

  alarm_rule = "ALARM(${aws_cloudwatch_metric_alarm.composite_child_1.alarm_name}) AND ALARM(${aws_cloudwatch_metric_alarm.composite_child_2.alarm_name})"

  alarm_actions = [aws_sns_topic.alarm_actions.arn]

  tags = {
    Name        = "Composite Alarm"
    TestNumber  = "31"
    Description = "Composite alarm with AND logic"
  }
}

################################################################################
# Test 32: Composite Alarm with OR logic
################################################################################
resource "aws_cloudwatch_composite_alarm" "composite_or" {
  alarm_name        = "${local.name_prefix}-composite-or"
  alarm_description = "Composite alarm with OR logic"

  alarm_rule = "ALARM(${aws_cloudwatch_metric_alarm.composite_child_1.alarm_name}) OR ALARM(${aws_cloudwatch_metric_alarm.composite_child_2.alarm_name})"

  tags = {
    Name        = "Composite OR Alarm"
    TestNumber  = "32"
    Description = "Composite alarm with OR logic"
  }
}

################################################################################
# Outputs
################################################################################

output "alarm_names" {
  value = {
    basic           = aws_cloudwatch_metric_alarm.basic.alarm_name
    with_actions    = aws_cloudwatch_metric_alarm.with_actions.alarm_name
    less_than       = aws_cloudwatch_metric_alarm.less_than.alarm_name
    missing_data    = aws_cloudwatch_metric_alarm.missing_data.alarm_name
    percentile      = aws_cloudwatch_metric_alarm.percentile.alarm_name
    datapoints      = aws_cloudwatch_metric_alarm.datapoints.alarm_name
    anomaly         = aws_cloudwatch_metric_alarm.anomaly.alarm_name
    math_expression = aws_cloudwatch_metric_alarm.math_expression.alarm_name
  }
  description = "CloudWatch Alarm names"
}

output "composite_alarm_names" {
  value = {
    composite    = aws_cloudwatch_composite_alarm.composite.alarm_name
    composite_or = aws_cloudwatch_composite_alarm.composite_or.alarm_name
  }
  description = "CloudWatch Composite Alarm names"
}

output "alarm_actions_topic_arn" {
  value       = aws_sns_topic.alarm_actions.arn
  description = "SNS topic ARN for alarm actions"
}
