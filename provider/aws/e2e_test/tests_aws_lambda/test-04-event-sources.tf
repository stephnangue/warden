# test-04-event-sources.tf
# Tests 35-45: Lambda Event Sources and Triggers
# Tests: SQS, SNS, S3, CloudWatch Events, API Gateway

################################################################################
# Lambda function code package
################################################################################

# Node.js function code
data "archive_file" "nodejs" {
  type        = "zip"
  output_path = "${path.module}/nodejs_function_04.zip"

  source {
    content  = <<-EOF
      exports.handler = async (event, context) => {
        console.log('Event:', JSON.stringify(event, null, 2));
        console.log('Context:', JSON.stringify(context, null, 2));
        return {
          statusCode: 200,
          body: JSON.stringify({
            message: 'Hello from Node.js Lambda',
            event: event,
            requestId: context.awsRequestId
          })
        };
      };
    EOF
    filename = "index.js"
  }
}

################################################################################
# Function for event source testing
################################################################################
resource "aws_lambda_function" "event_processor" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-event-processor"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  timeout          = 30

  tags = {
    Name        = "Event Processor Function"
    TestNumber  = "35-45"
    Description = "Function for testing event sources"
  }
}

################################################################################
# Test 35: SQS Event Source
################################################################################
resource "aws_sqs_queue" "lambda_trigger" {
  name                       = "${local.name_prefix}-trigger-queue"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400

  tags = {
    Name        = "Lambda Trigger Queue"
    TestNumber  = "35"
    Description = "SQS queue for Lambda trigger testing"
  }
}

# IAM policy for SQS access
resource "aws_iam_role_policy" "sqs_access" {
  name = "${local.name_prefix}-sqs-access"
  role = aws_iam_role.lambda_basic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.lambda_trigger.arn
      }
    ]
  })
}

resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn = aws_sqs_queue.lambda_trigger.arn
  function_name    = aws_lambda_function.event_processor.arn
  batch_size       = 10
  enabled          = true

  depends_on = [aws_iam_role_policy.sqs_access]
}

################################################################################
# Test 36: SQS FIFO Queue Event Source
################################################################################
resource "aws_sqs_queue" "fifo_trigger" {
  name                        = "${local.name_prefix}-trigger-queue.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  visibility_timeout_seconds  = 60

  tags = {
    Name        = "Lambda FIFO Trigger Queue"
    TestNumber  = "36"
    Description = "SQS FIFO queue for Lambda trigger testing"
  }
}

resource "aws_lambda_function" "fifo_processor" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-fifo-processor"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  timeout          = 30

  tags = {
    Name        = "FIFO Processor Function"
    TestNumber  = "36"
    Description = "Function for FIFO queue processing"
  }
}

resource "aws_iam_role_policy" "fifo_sqs_access" {
  name = "${local.name_prefix}-fifo-sqs-access"
  role = aws_iam_role.lambda_basic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.fifo_trigger.arn
      }
    ]
  })
}

resource "aws_lambda_event_source_mapping" "fifo_sqs" {
  event_source_arn = aws_sqs_queue.fifo_trigger.arn
  function_name    = aws_lambda_function.fifo_processor.arn
  batch_size       = 10
  enabled          = true

  depends_on = [aws_iam_role_policy.fifo_sqs_access]
}

################################################################################
# Test 37: SNS Trigger
################################################################################
resource "aws_sns_topic" "lambda_trigger" {
  name = "${local.name_prefix}-trigger-topic"

  tags = {
    Name        = "Lambda Trigger Topic"
    TestNumber  = "37"
    Description = "SNS topic for Lambda trigger testing"
  }
}

resource "aws_lambda_function" "sns_processor" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-sns-processor"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "SNS Processor Function"
    TestNumber  = "37"
    Description = "Function triggered by SNS"
  }
}

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_processor.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.lambda_trigger.arn
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.lambda_trigger.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_processor.arn
}

################################################################################
# Test 38: S3 Trigger
################################################################################
resource "aws_s3_bucket" "lambda_trigger" {
  bucket        = "${local.name_prefix}-trigger-bucket"
  force_destroy = true

  tags = {
    Name        = "Lambda Trigger Bucket"
    TestNumber  = "38"
    Description = "S3 bucket for Lambda trigger testing"
  }
}

resource "aws_lambda_function" "s3_processor" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-s3-processor"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "S3 Processor Function"
    TestNumber  = "38"
    Description = "Function triggered by S3 events"
  }
}

resource "aws_lambda_permission" "s3" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.lambda_trigger.arn
}

resource "aws_s3_bucket_notification" "lambda" {
  bucket = aws_s3_bucket.lambda_trigger.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.s3_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "uploads/"
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.s3]
}

################################################################################
# Test 39: CloudWatch Events / EventBridge Rule
################################################################################
resource "aws_lambda_function" "scheduled" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-scheduled"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Scheduled Function"
    TestNumber  = "39"
    Description = "Function triggered by schedule"
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name_prefix}-schedule"
  description         = "Trigger Lambda every 5 minutes"
  schedule_expression = "rate(5 minutes)"
  state               = "DISABLED" # Disabled to avoid costs

  tags = {
    Name        = "Lambda Schedule Rule"
    TestNumber  = "39"
    Description = "EventBridge rule for scheduled Lambda"
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "lambda"
  arn       = aws_lambda_function.scheduled.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scheduled.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

################################################################################
# Test 40: API Gateway HTTP API Integration
################################################################################
resource "aws_lambda_function" "api_handler" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-api-handler"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "API Handler Function"
    TestNumber  = "40"
    Description = "Function for API Gateway integration"
  }
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${local.name_prefix}-http-api"
  protocol_type = "HTTP"

  tags = {
    Name        = "Lambda HTTP API"
    TestNumber  = "40"
    Description = "HTTP API for Lambda integration"
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_handler.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

################################################################################
# Test 41: CloudWatch Log Subscription
################################################################################
resource "aws_cloudwatch_log_group" "source" {
  name              = "/aws/lambda/${local.name_prefix}-log-source"
  retention_in_days = 1

  tags = {
    Name        = "Source Log Group"
    TestNumber  = "41"
    Description = "Log group to trigger Lambda"
  }
}

resource "aws_lambda_function" "log_processor" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-log-processor"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Log Processor Function"
    TestNumber  = "41"
    Description = "Function triggered by CloudWatch Logs"
  }
}

resource "aws_lambda_permission" "logs" {
  statement_id  = "AllowCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_processor.function_name
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.source.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "lambda" {
  name            = "${local.name_prefix}-log-filter"
  log_group_name  = aws_cloudwatch_log_group.source.name
  filter_pattern  = "ERROR"
  destination_arn = aws_lambda_function.log_processor.arn

  depends_on = [aws_lambda_permission.logs]
}

################################################################################
# Outputs
################################################################################

output "event_source_functions" {
  value = {
    event_processor = aws_lambda_function.event_processor.function_name
    fifo_processor  = aws_lambda_function.fifo_processor.function_name
    sns_processor   = aws_lambda_function.sns_processor.function_name
    s3_processor    = aws_lambda_function.s3_processor.function_name
    scheduled       = aws_lambda_function.scheduled.function_name
    api_handler     = aws_lambda_function.api_handler.function_name
    log_processor   = aws_lambda_function.log_processor.function_name
  }
  description = "Event source function names"
}

output "event_sources" {
  value = {
    sqs_queue      = aws_sqs_queue.lambda_trigger.url
    fifo_queue     = aws_sqs_queue.fifo_trigger.url
    sns_topic      = aws_sns_topic.lambda_trigger.arn
    s3_bucket      = aws_s3_bucket.lambda_trigger.bucket
    schedule_rule  = aws_cloudwatch_event_rule.schedule.name
    http_api       = aws_apigatewayv2_api.http.api_endpoint
    log_group      = aws_cloudwatch_log_group.source.name
  }
  description = "Event source resources"
}

output "api_endpoint" {
  value       = aws_apigatewayv2_stage.default.invoke_url
  description = "HTTP API endpoint URL"
}
