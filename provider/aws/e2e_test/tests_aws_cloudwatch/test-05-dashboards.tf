# test-05-dashboards.tf
# Tests 33-37: CloudWatch Dashboards
# Tests: basic dashboards, widgets, cross-account

################################################################################
# Local resources for dashboard tests (independence)
################################################################################
resource "aws_cloudwatch_log_group" "dashboard_logs" {
  name = "/${local.name_prefix}/dashboard-logs"

  tags = {
    Name        = "Dashboard Log Group"
    TestNumber  = "37"
    Description = "Log group for dashboard log widget"
  }
}

resource "aws_cloudwatch_metric_alarm" "dashboard_alarm" {
  alarm_name          = "${local.name_prefix}-dashboard-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm for dashboard widget"

  dimensions = {
    InstanceId = "i-1234567890abcdef0"
  }

  tags = {
    Name        = "Dashboard Alarm"
    TestNumber  = "36"
    Description = "Alarm for dashboard widget test"
  }
}

################################################################################
# Test 33: Basic Dashboard
################################################################################
resource "aws_cloudwatch_dashboard" "basic" {
  dashboard_name = "${local.name_prefix}-basic"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2

        properties = {
          markdown = "# Basic Dashboard\nThis is a test dashboard for Warden"
        }
      }
    ]
  })
}

################################################################################
# Test 34: Dashboard with metric widget
################################################################################
resource "aws_cloudwatch_dashboard" "metric_widget" {
  dashboard_name = "${local.name_prefix}-metric"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "i-1234567890abcdef0"]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "EC2 CPU Utilization"
        }
      }
    ]
  })
}

################################################################################
# Test 35: Dashboard with multiple widgets
################################################################################
resource "aws_cloudwatch_dashboard" "multi_widget" {
  dashboard_name = "${local.name_prefix}-multi"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "## Multi-Widget Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "i-1234567890abcdef0"]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "CPU"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 1
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "NetworkIn", "InstanceId", "i-1234567890abcdef0"],
            [".", "NetworkOut", ".", "."]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Network"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 1
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "DiskReadOps", "InstanceId", "i-1234567890abcdef0"],
            [".", "DiskWriteOps", ".", "."]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Disk I/O"
        }
      }
    ]
  })
}

################################################################################
# Test 36: Dashboard with alarm widget
################################################################################
resource "aws_cloudwatch_dashboard" "alarm_widget" {
  dashboard_name = "${local.name_prefix}-alarm"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "alarm"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          alarms = [
            aws_cloudwatch_metric_alarm.dashboard_alarm.arn
          ]
          title = "Alarm Status"
        }
      }
    ]
  })
}

################################################################################
# Test 37: Dashboard with log widget
################################################################################
resource "aws_cloudwatch_dashboard" "log_widget" {
  dashboard_name = "${local.name_prefix}-logs"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "log"
        x      = 0
        y      = 0
        width  = 24
        height = 6

        properties = {
          query  = "SOURCE '${aws_cloudwatch_log_group.dashboard_logs.name}' | fields @timestamp, @message | sort @timestamp desc | limit 100"
          region = data.aws_region.current.name
          title  = "Recent Logs"
        }
      }
    ]
  })
}

################################################################################
# Outputs
################################################################################

output "dashboard_names" {
  value = {
    basic        = aws_cloudwatch_dashboard.basic.dashboard_name
    metric       = aws_cloudwatch_dashboard.metric_widget.dashboard_name
    multi_widget = aws_cloudwatch_dashboard.multi_widget.dashboard_name
    alarm        = aws_cloudwatch_dashboard.alarm_widget.dashboard_name
    log          = aws_cloudwatch_dashboard.log_widget.dashboard_name
  }
  description = "CloudWatch Dashboard names"
}
