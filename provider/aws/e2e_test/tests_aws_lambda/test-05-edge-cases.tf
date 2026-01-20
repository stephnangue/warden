# test-05-edge-cases.tf
# Tests 42-55: Lambda Edge Cases
# Tests: ARN with colons, special characters, cross-account, dead letter queues

################################################################################
# Lambda function code package
################################################################################

# Node.js function code
data "archive_file" "nodejs" {
  type        = "zip"
  output_path = "${path.module}/nodejs_function_05.zip"

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
# Test 42: Function with long name - max 64 characters
################################################################################
resource "aws_lambda_function" "long_name" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-this-is-a-very-long-function-name"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Long Name Function"
    TestNumber  = "42"
    Description = "Tests function with long name"
  }
}

################################################################################
# Test 43: Function with special characters in environment variables
################################################################################
resource "aws_lambda_function" "special_env" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-special-env"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  environment {
    variables = {
      # Special characters that might break signing
      URL_WITH_QUERY    = "https://api.example.com/path?key=value&other=123"
      JSON_CONFIG       = "{\"key\": \"value\", \"nested\": {\"a\": 1}}"
      PATH_WITH_SLASHES = "/opt/app/config/settings.json"
      CONN_STRING       = "postgresql://user:pass@host:5432/db?sslmode=require"
      SPECIAL_CHARS     = "test@#$%^&*special"
      UNICODE_VALUE     = "Hello World"
      BASE64_DATA       = "SGVsbG8gV29ybGQh"
    }
  }

  tags = {
    Name        = "Special Env Function"
    TestNumber  = "43"
    Description = "Tests function with special environment variables"
  }
}

################################################################################
# Test 44: Function with dead letter queue
################################################################################
resource "aws_sqs_queue" "dlq" {
  name = "${local.name_prefix}-dlq"

  tags = {
    Name        = "Lambda DLQ"
    TestNumber  = "44"
    Description = "Dead letter queue for Lambda"
  }
}

resource "aws_iam_role_policy" "dlq_access" {
  name = "${local.name_prefix}-dlq-access"
  role = aws_iam_role.lambda_basic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.dlq.arn
      }
    ]
  })
}

resource "aws_lambda_function" "with_dlq" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-dlq"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tags = {
    Name        = "DLQ Function"
    TestNumber  = "44"
    Description = "Tests function with dead letter queue"
  }

  depends_on = [aws_iam_role_policy.dlq_access]
}

################################################################################
# Test 45: Function with SNS dead letter topic
################################################################################
resource "aws_sns_topic" "dlq_topic" {
  name = "${local.name_prefix}-dlq-topic"

  tags = {
    Name        = "Lambda DLQ Topic"
    TestNumber  = "45"
    Description = "Dead letter SNS topic for Lambda"
  }
}

resource "aws_iam_role_policy" "sns_dlq_access" {
  name = "${local.name_prefix}-sns-dlq-access"
  role = aws_iam_role.lambda_basic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.dlq_topic.arn
      }
    ]
  })
}

resource "aws_lambda_function" "with_sns_dlq" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-sns-dlq"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  dead_letter_config {
    target_arn = aws_sns_topic.dlq_topic.arn
  }

  tags = {
    Name        = "SNS DLQ Function"
    TestNumber  = "45"
    Description = "Tests function with SNS dead letter topic"
  }

  depends_on = [aws_iam_role_policy.sns_dlq_access]
}

################################################################################
# Test 46: Function with tracing enabled - X-Ray
################################################################################
resource "aws_iam_role_policy_attachment" "xray" {
  role       = aws_iam_role.lambda_basic.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_lambda_function" "with_tracing" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-tracing"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name        = "Tracing Function"
    TestNumber  = "46"
    Description = "Tests function with X-Ray tracing"
  }

  depends_on = [aws_iam_role_policy_attachment.xray]
}

################################################################################
# Test 47: Function with passthrough tracing
################################################################################
resource "aws_lambda_function" "passthrough_tracing" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-passthrough-trace"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tracing_config {
    mode = "PassThrough"
  }

  tags = {
    Name        = "Passthrough Tracing Function"
    TestNumber  = "47"
    Description = "Tests function with passthrough tracing"
  }
}

################################################################################
# Test 48: Function with ephemeral storage
################################################################################
resource "aws_lambda_function" "ephemeral_storage" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-ephemeral-storage"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  ephemeral_storage {
    size = 1024 # 1GB - max is 10240 MB
  }

  tags = {
    Name        = "Ephemeral Storage Function"
    TestNumber  = "48"
    Description = "Tests function with custom ephemeral storage"
  }
}

################################################################################
# Test 49: Function with maximum ephemeral storage
################################################################################
resource "aws_lambda_function" "max_ephemeral" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-max-ephemeral"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  ephemeral_storage {
    size = 10240 # Maximum 10GB
  }

  tags = {
    Name        = "Max Ephemeral Storage Function"
    TestNumber  = "49"
    Description = "Tests function with maximum ephemeral storage"
  }
}

################################################################################
# Test 50: Function with code signing config
################################################################################
resource "aws_signer_signing_profile" "lambda" {
  name_prefix = replace(local.name_prefix, "-", "")
  platform_id = "AWSLambda-SHA384-ECDSA"

  tags = {
    Name        = "Lambda Signing Profile"
    TestNumber  = "50"
    Description = "Signing profile for Lambda"
  }
}

resource "aws_lambda_code_signing_config" "main" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }

  description = "Code signing config for Lambda functions"
}

################################################################################
# Test 51: Function invoked by alias ARN - tests colon in path
################################################################################
# This tests the edge case where Lambda is invoked via alias ARN
# ARN format: arn:aws:lambda:region:account:function:name:alias
# The colons in the ARN can break signature verification if not handled properly

resource "aws_lambda_function" "alias_invoke_test" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-alias-invoke"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Alias Invoke Test"
    TestNumber  = "51"
    Description = "Tests invocation via alias ARN with colons"
  }
}

resource "aws_lambda_alias" "invoke_test" {
  name             = "test-alias"
  description      = "Alias for invoke testing"
  function_name    = aws_lambda_function.alias_invoke_test.function_name
  function_version = aws_lambda_function.alias_invoke_test.version
}

################################################################################
# Test 52: Function with file system config - EFS
################################################################################
resource "aws_efs_file_system" "lambda" {
  creation_token = "${local.name_prefix}-efs"
  encrypted      = true

  tags = {
    Name        = "Lambda EFS"
    TestNumber  = "52"
    Description = "EFS for Lambda function"
  }
}

resource "aws_efs_mount_target" "lambda_1" {
  file_system_id  = aws_efs_file_system.lambda.id
  subnet_id       = aws_subnet.lambda_1.id
  security_groups = [aws_security_group.lambda.id]
}

resource "aws_efs_mount_target" "lambda_2" {
  file_system_id  = aws_efs_file_system.lambda.id
  subnet_id       = aws_subnet.lambda_2.id
  security_groups = [aws_security_group.lambda.id]
}

resource "aws_efs_access_point" "lambda" {
  file_system_id = aws_efs_file_system.lambda.id

  root_directory {
    path = "/lambda"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }

  posix_user {
    gid = 1000
    uid = 1000
  }

  tags = {
    Name        = "Lambda EFS Access Point"
    TestNumber  = "52"
    Description = "EFS access point for Lambda"
  }
}

resource "aws_iam_role_policy" "efs_access" {
  name = "${local.name_prefix}-efs-access"
  role = aws_iam_role.lambda_basic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientRootAccess"
        ]
        Resource = aws_efs_file_system.lambda.arn
      }
    ]
  })
}

resource "aws_lambda_function" "with_efs" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-efs"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  vpc_config {
    subnet_ids         = [aws_subnet.lambda_1.id, aws_subnet.lambda_2.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  file_system_config {
    arn              = aws_efs_access_point.lambda.arn
    local_mount_path = "/mnt/efs"
  }

  tags = {
    Name        = "EFS Function"
    TestNumber  = "52"
    Description = "Tests function with EFS file system"
  }

  depends_on = [
    aws_efs_mount_target.lambda_1,
    aws_efs_mount_target.lambda_2,
    aws_iam_role_policy.efs_access
  ]
}

################################################################################
# Test 53: Function with SnapStart - Java runtime would be needed
# Skipping as it requires Java runtime and larger deployment package
################################################################################

################################################################################
# Test 54: Resource-based policy with specific conditions
################################################################################
resource "aws_lambda_function" "with_policy" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-policy"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Policy Function"
    TestNumber  = "54"
    Description = "Tests function with resource-based policy"
  }
}

resource "aws_lambda_permission" "allow_account" {
  statement_id  = "AllowAccountInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.with_policy.function_name
  principal     = data.aws_caller_identity.current.account_id
}

resource "aws_lambda_permission" "allow_with_condition" {
  statement_id  = "AllowWithCondition"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.with_policy.function_name
  principal     = "events.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}

################################################################################
# Test 55: Function invocation data - to test invoke API
################################################################################
# This creates a function specifically designed for testing the Invoke API
# which is an important edge case for signature verification

data "archive_file" "echo_function" {
  type        = "zip"
  output_path = "${path.module}/echo_function.zip"

  source {
    content  = <<-EOF
      exports.handler = async (event, context) => {
        // Echo back the event for testing
        return {
          statusCode: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Request-Id': context.awsRequestId,
            'X-Function-Name': context.functionName
          },
          body: JSON.stringify({
            message: 'Echo response',
            receivedEvent: event,
            context: {
              functionName: context.functionName,
              functionVersion: context.functionVersion,
              invokedFunctionArn: context.invokedFunctionArn,
              memoryLimitInMB: context.memoryLimitInMB,
              awsRequestId: context.awsRequestId
            }
          })
        };
      };
    EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "echo" {
  filename         = data.archive_file.echo_function.output_path
  function_name    = "${local.name_prefix}-echo"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.echo_function.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Echo Function"
    TestNumber  = "55"
    Description = "Function for testing Lambda Invoke API"
  }
}

################################################################################
# Outputs
################################################################################

output "edge_case_functions" {
  value = {
    long_name          = aws_lambda_function.long_name.function_name
    special_env        = aws_lambda_function.special_env.function_name
    with_dlq           = aws_lambda_function.with_dlq.function_name
    with_sns_dlq       = aws_lambda_function.with_sns_dlq.function_name
    with_tracing       = aws_lambda_function.with_tracing.function_name
    passthrough_trace  = aws_lambda_function.passthrough_tracing.function_name
    ephemeral_storage  = aws_lambda_function.ephemeral_storage.function_name
    max_ephemeral      = aws_lambda_function.max_ephemeral.function_name
    alias_invoke_test  = aws_lambda_function.alias_invoke_test.function_name
    with_efs           = aws_lambda_function.with_efs.function_name
    with_policy        = aws_lambda_function.with_policy.function_name
    echo               = aws_lambda_function.echo.function_name
  }
  description = "Edge case function names"
}

output "alias_arn_with_colons" {
  value       = aws_lambda_alias.invoke_test.arn
  description = "Alias ARN containing colons - edge case for signing"
}

output "qualified_arns" {
  value = {
    # These ARNs contain colons after the function name
    alias_arn   = aws_lambda_alias.invoke_test.arn
    version_arn = aws_lambda_function.alias_invoke_test.qualified_arn
  }
  description = "Qualified ARNs with colons for testing"
}

output "dlq_resources" {
  value = {
    sqs_dlq   = aws_sqs_queue.dlq.arn
    sns_dlq   = aws_sns_topic.dlq_topic.arn
  }
  description = "Dead letter queue resources"
}

output "efs_resources" {
  value = {
    file_system_id  = aws_efs_file_system.lambda.id
    access_point_id = aws_efs_access_point.lambda.id
  }
  description = "EFS resources"
}

output "code_signing_config" {
  value       = aws_lambda_code_signing_config.main.arn
  description = "Code signing config ARN"
}

output "echo_function_arn" {
  value       = aws_lambda_function.echo.arn
  description = "Echo function ARN for invoke testing"
}
