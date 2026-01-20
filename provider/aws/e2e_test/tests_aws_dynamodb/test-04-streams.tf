# test-04-streams.tf
# Tests 37-42: DynamoDB Streams
# Tests: Stream specifications, Lambda triggers, Kinesis Data Streams

################################################################################
# Test 37: Table with DynamoDB Streams - KEYS_ONLY
################################################################################
resource "aws_dynamodb_table" "stream_keys_only" {
  name             = "${local.table_prefix}-stream-keys"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  range_key        = "sk"
  stream_enabled   = true
  stream_view_type = "KEYS_ONLY"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Name        = "Stream KEYS_ONLY"
    TestNumber  = "37"
    Description = "Tests DynamoDB Stream with KEYS_ONLY view"
  }
}

################################################################################
# Test 38: Table with DynamoDB Streams - NEW_IMAGE
################################################################################
resource "aws_dynamodb_table" "stream_new_image" {
  name             = "${local.table_prefix}-stream-new"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Stream NEW_IMAGE"
    TestNumber  = "38"
    Description = "Tests DynamoDB Stream with NEW_IMAGE view"
  }
}

################################################################################
# Test 39: Table with DynamoDB Streams - OLD_IMAGE
################################################################################
resource "aws_dynamodb_table" "stream_old_image" {
  name             = "${local.table_prefix}-stream-old"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "OLD_IMAGE"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Stream OLD_IMAGE"
    TestNumber  = "39"
    Description = "Tests DynamoDB Stream with OLD_IMAGE view"
  }
}

################################################################################
# Test 40: Table with DynamoDB Streams - NEW_AND_OLD_IMAGES
################################################################################
resource "aws_dynamodb_table" "stream_both_images" {
  name             = "${local.table_prefix}-stream-both"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  range_key        = "sk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Name        = "Stream NEW_AND_OLD_IMAGES"
    TestNumber  = "40"
    Description = "Tests DynamoDB Stream with NEW_AND_OLD_IMAGES view"
  }
}

################################################################################
# Test 41: Table with Kinesis Data Stream integration
################################################################################
resource "aws_kinesis_stream" "dynamodb_stream" {
  name             = "${local.table_prefix}-kinesis-stream"
  shard_count      = 1
  retention_period = 24

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  tags = {
    Name        = "DynamoDB Kinesis Stream"
    TestNumber  = "41"
    Description = "Kinesis stream for DynamoDB integration"
  }
}

resource "aws_dynamodb_table" "kinesis_stream" {
  name         = "${local.table_prefix}-kinesis-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Kinesis Stream Table"
    TestNumber  = "41"
    Description = "Tests DynamoDB with Kinesis Data Streams"
  }
}

resource "aws_dynamodb_kinesis_streaming_destination" "main" {
  stream_arn = aws_kinesis_stream.dynamodb_stream.arn
  table_name = aws_dynamodb_table.kinesis_stream.name
}

################################################################################
# Test 42: Stream with Lambda trigger (IAM role and function)
################################################################################

# IAM role for Lambda
resource "aws_iam_role" "lambda_dynamodb" {
  name = "${local.table_prefix}-lambda-ddb-role"

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
    Name        = "Lambda DynamoDB Role"
    TestNumber  = "42"
    Description = "IAM role for Lambda DynamoDB stream trigger"
  }
}

# IAM policy for Lambda to read DynamoDB streams
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.table_prefix}-lambda-ddb-policy"
  role = aws_iam_role.lambda_dynamodb.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams"
        ]
        Resource = "${aws_dynamodb_table.stream_lambda.arn}/stream/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# DynamoDB table with stream for Lambda trigger
resource "aws_dynamodb_table" "stream_lambda" {
  name             = "${local.table_prefix}-stream-lambda"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Stream with Lambda Trigger"
    TestNumber  = "42"
    Description = "Tests DynamoDB Stream with Lambda trigger"
  }
}

# Lambda function for stream processing
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"

  source {
    content  = <<-EOF
      exports.handler = async (event) => {
        console.log('DynamoDB Stream Event:', JSON.stringify(event, null, 2));
        for (const record of event.Records) {
          console.log('Event ID:', record.eventID);
          console.log('Event Name:', record.eventName);
          console.log('DynamoDB Record:', JSON.stringify(record.dynamodb, null, 2));
        }
        return { statusCode: 200, body: 'Processed ' + event.Records.length + ' records' };
      };
    EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "stream_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${local.table_prefix}-stream-processor"
  role             = aws_iam_role.lambda_dynamodb.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "nodejs18.x"
  timeout          = 30

  tags = {
    Name        = "DynamoDB Stream Processor"
    TestNumber  = "42"
    Description = "Lambda function for processing DynamoDB streams"
  }
}

# Lambda event source mapping
resource "aws_lambda_event_source_mapping" "dynamodb_stream" {
  event_source_arn  = aws_dynamodb_table.stream_lambda.stream_arn
  function_name     = aws_lambda_function.stream_processor.arn
  starting_position = "LATEST"
  batch_size        = 100

  depends_on = [aws_iam_role_policy.lambda_dynamodb]
}

################################################################################
# Test items to trigger streams
################################################################################
resource "aws_dynamodb_table_item" "stream_test_item" {
  table_name = aws_dynamodb_table.stream_lambda.name
  hash_key   = aws_dynamodb_table.stream_lambda.hash_key

  item = jsonencode({
    pk = { S = "STREAM#TEST#001" }
    message = { S = "This item triggers the stream" }
    created_at = { S = timestamp() }
  })

  depends_on = [aws_lambda_event_source_mapping.dynamodb_stream]

  lifecycle {
    ignore_changes = [item]
  }
}

################################################################################
# Outputs
################################################################################

output "stream_tables" {
  value = {
    keys_only   = aws_dynamodb_table.stream_keys_only.name
    new_image   = aws_dynamodb_table.stream_new_image.name
    old_image   = aws_dynamodb_table.stream_old_image.name
    both_images = aws_dynamodb_table.stream_both_images.name
    kinesis     = aws_dynamodb_table.kinesis_stream.name
    lambda      = aws_dynamodb_table.stream_lambda.name
  }
  description = "Stream test table names"
}

output "stream_arns" {
  value = {
    keys_only   = aws_dynamodb_table.stream_keys_only.stream_arn
    new_image   = aws_dynamodb_table.stream_new_image.stream_arn
    old_image   = aws_dynamodb_table.stream_old_image.stream_arn
    both_images = aws_dynamodb_table.stream_both_images.stream_arn
    lambda      = aws_dynamodb_table.stream_lambda.stream_arn
  }
  description = "DynamoDB Stream ARNs"
}

output "kinesis_stream_arn" {
  value       = aws_kinesis_stream.dynamodb_stream.arn
  description = "Kinesis Data Stream ARN"
}

output "lambda_function_arn" {
  value       = aws_lambda_function.stream_processor.arn
  description = "Stream processor Lambda ARN"
}
