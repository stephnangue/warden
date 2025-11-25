# test-07-event-notifications.tf
# Tests 34-37: Event notifications (SNS, SQS, Lambda, EventBridge)
################################################################################
# Lambda Execution IAM Role
################################################################################

resource "aws_iam_role" "lambda_s3" {
  name = "${local.bucket_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name       = "Lambda S3 Role"
    TestNumber = "36"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_s3.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

################################################################################
# Test 34: SNS Event Notification
################################################################################

# SNS Topic for S3 notifications
resource "aws_sns_topic" "s3_notifications" {
  name = "${local.bucket_prefix}-notifications"

  tags = {
    Name       = "S3 Event Notifications Topic"
    TestNumber = "34"
  }
}

resource "aws_sns_topic_policy" "s3_notifications" {
  arn = aws_sns_topic.s3_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = "SNS:Publish"
        Resource = aws_sns_topic.s3_notifications.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.sns_notifications.arn
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket" "sns_notifications" {
  bucket        = "${local.bucket_prefix}-sns-notif"
  force_destroy = true

  tags = {
    Name        = "SNS Notifications Bucket"
    TestNumber  = "34"
    Description = "Tests SNS event notifications"
  }
}

resource "aws_s3_bucket_notification" "sns" {
  bucket = aws_s3_bucket.sns_notifications.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*"]
    filter_prefix = "uploads/"
  }

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectRemoved:*"]
  }
}

################################################################################
# Test 35: SQS Event Notification
################################################################################

# SQS Queue for S3 notifications
resource "aws_sqs_queue" "s3_notifications" {
  name = "${local.bucket_prefix}-notifications"

  tags = {
    Name       = "S3 Event Notifications Queue"
    TestNumber = "35"
  }
}

resource "aws_sqs_queue_policy" "s3_notifications" {
  queue_url = aws_sqs_queue.s3_notifications.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = "SQS:SendMessage"
        Resource = aws_sqs_queue.s3_notifications.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.sqs_notifications.arn
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket" "sqs_notifications" {
  bucket        = "${local.bucket_prefix}-sqs-notif"
  force_destroy = true

  tags = {
    Name        = "SQS Notifications Bucket"
    TestNumber  = "35"
    Description = "Tests SQS event notifications"
  }
}

resource "aws_s3_bucket_notification" "sqs" {
  bucket = aws_s3_bucket.sqs_notifications.id

  queue {
    queue_arn = aws_sqs_queue.s3_notifications.arn
    events    = ["s3:ObjectCreated:Put"]
    filter_prefix = "documents/"
    filter_suffix = ".pdf"
  }

  queue {
    queue_arn = aws_sqs_queue.s3_notifications.arn
    events    = ["s3:ObjectCreated:Post", "s3:ObjectCreated:Copy"]
  }
}

################################################################################
# Test 36: Lambda Event Notification
################################################################################

# Create Lambda deployment package using archive_file
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"

  source {
    content  = <<-EOF
def handler(event, context):
    """Process S3 events"""
    print("S3 event received:", event)
    
    # Extract bucket and object information
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        event_name = record['eventName']
        print(f"Event: {event_name}, Bucket: {bucket}, Key: {key}")
    
    return {
        'statusCode': 200,
        'body': 'S3 event processed successfully'
    }
EOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "s3_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${local.bucket_prefix}-s3-processor"
  role             = aws_iam_role.lambda_s3.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  tags = {
    Name       = "S3 Event Processor"
    TestNumber = "36"
  }
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.lambda_notifications.arn
}

resource "aws_s3_bucket" "lambda_notifications" {
  bucket        = "${local.bucket_prefix}-lambda-notif"
  force_destroy = true

  tags = {
    Name        = "Lambda Notifications Bucket"
    TestNumber  = "36"
    Description = "Tests Lambda event notifications"
  }
}

resource "aws_s3_bucket_notification" "lambda" {
  bucket = aws_s3_bucket.lambda_notifications.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.s3_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "process/"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.s3_processor.arn
    events              = ["s3:ObjectRemoved:Delete"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}

################################################################################
# Test 37: EventBridge Notification
################################################################################

resource "aws_s3_bucket" "eventbridge_notifications" {
  bucket        = "${local.bucket_prefix}-eventbridge"
  force_destroy = true

  tags = {
    Name        = "EventBridge Notifications Bucket"
    TestNumber  = "37"
    Description = "Tests EventBridge event notifications"
  }
}

resource "aws_s3_bucket_notification" "eventbridge" {
  bucket      = aws_s3_bucket.eventbridge_notifications.id
  eventbridge = true
}

# EventBridge rule for S3 events
resource "aws_cloudwatch_event_rule" "s3_events" {
  name        = "${local.bucket_prefix}-s3-events"
  description = "Capture S3 events via EventBridge"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [aws_s3_bucket.eventbridge_notifications.id]
      }
    }
  })

  tags = {
    Name       = "S3 EventBridge Rule"
    TestNumber = "37"
  }
}
