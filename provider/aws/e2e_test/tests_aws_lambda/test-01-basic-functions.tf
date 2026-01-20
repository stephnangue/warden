# test-01-basic-functions.tf
# Tests 1-15: Basic Lambda function configurations
# Tests: runtimes, memory, timeout, environment variables, architectures

################################################################################
# Lambda function code packages
################################################################################

# Node.js function code
data "archive_file" "nodejs" {
  type        = "zip"
  output_path = "${path.module}/nodejs_function.zip"

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

# Python function code
data "archive_file" "python" {
  type        = "zip"
  output_path = "${path.module}/python_function.zip"

  source {
    content  = <<-EOF
import json

def handler(event, context):
    print(f"Event: {json.dumps(event)}")
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Hello from Python Lambda',
            'event': event,
            'requestId': context.aws_request_id
        })
    }
    EOF
    filename = "lambda_function.py"
  }
}

################################################################################
# Test 1: Basic Node.js 18.x function
################################################################################
resource "aws_lambda_function" "nodejs_18" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-nodejs-18"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Node.js 18 Function"
    TestNumber  = "01"
    Description = "Tests basic Node.js 18 Lambda function"
  }
}

################################################################################
# Test 2: Node.js 20.x function
################################################################################
resource "aws_lambda_function" "nodejs_20" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-nodejs-20"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs20.x"

  tags = {
    Name        = "Node.js 20 Function"
    TestNumber  = "02"
    Description = "Tests basic Node.js 20 Lambda function"
  }
}

################################################################################
# Test 3: Python 3.11 function
################################################################################
resource "aws_lambda_function" "python_311" {
  filename         = data.archive_file.python.output_path
  function_name    = "${local.name_prefix}-python-311"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "lambda_function.handler"
  source_code_hash = data.archive_file.python.output_base64sha256
  runtime          = "python3.11"

  tags = {
    Name        = "Python 3.11 Function"
    TestNumber  = "03"
    Description = "Tests basic Python 3.11 Lambda function"
  }
}

################################################################################
# Test 4: Python 3.12 function
################################################################################
resource "aws_lambda_function" "python_312" {
  filename         = data.archive_file.python.output_path
  function_name    = "${local.name_prefix}-python-312"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "lambda_function.handler"
  source_code_hash = data.archive_file.python.output_base64sha256
  runtime          = "python3.12"

  tags = {
    Name        = "Python 3.12 Function"
    TestNumber  = "04"
    Description = "Tests basic Python 3.12 Lambda function"
  }
}

################################################################################
# Test 5: Function with custom memory - 128 MB minimum
################################################################################
resource "aws_lambda_function" "memory_128" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-memory-128"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  memory_size      = 128

  tags = {
    Name        = "Memory 128MB Function"
    TestNumber  = "05"
    Description = "Tests Lambda with 128MB memory minimum"
  }
}

################################################################################
# Test 6: Function with high memory - 1024 MB
################################################################################
resource "aws_lambda_function" "memory_1024" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-memory-1024"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  memory_size      = 1024

  tags = {
    Name        = "Memory 1024MB Function"
    TestNumber  = "06"
    Description = "Tests Lambda with 1024MB memory"
  }
}

################################################################################
# Test 7: Function with high memory - 3008 MB (default account limit)
################################################################################
resource "aws_lambda_function" "memory_max" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-memory-max"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  memory_size      = 3008  # Default account limit - request increase for 10240

  tags = {
    Name        = "Memory Max Function"
    TestNumber  = "07"
    Description = "Tests Lambda with 3008MB memory"
  }
}

################################################################################
# Test 8: Function with custom timeout - 3 seconds minimum
################################################################################
resource "aws_lambda_function" "timeout_3" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-timeout-3"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  timeout          = 3

  tags = {
    Name        = "Timeout 3s Function"
    TestNumber  = "08"
    Description = "Tests Lambda with 3 second timeout"
  }
}

################################################################################
# Test 9: Function with maximum timeout - 900 seconds
################################################################################
resource "aws_lambda_function" "timeout_max" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-timeout-max"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  timeout          = 900

  tags = {
    Name        = "Timeout Max Function"
    TestNumber  = "09"
    Description = "Tests Lambda with 900 second timeout maximum"
  }
}

################################################################################
# Test 10: Function with environment variables
################################################################################
resource "aws_lambda_function" "with_env_vars" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-env-vars"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  environment {
    variables = {
      APP_ENV          = "test"
      LOG_LEVEL        = "debug"
      DATABASE_HOST    = "localhost"
      API_KEY          = "test-api-key-12345"
      FEATURE_FLAG     = "enabled"
      MAX_CONNECTIONS  = "100"
    }
  }

  tags = {
    Name        = "Environment Variables Function"
    TestNumber  = "10"
    Description = "Tests Lambda with environment variables"
  }
}

################################################################################
# Test 11: Function with x86_64 architecture
################################################################################
resource "aws_lambda_function" "x86_64" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-x86-64"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  architectures    = ["x86_64"]

  tags = {
    Name        = "x86_64 Architecture Function"
    TestNumber  = "11"
    Description = "Tests Lambda with x86_64 architecture"
  }
}

################################################################################
# Test 12: Function with arm64 architecture - Graviton2
################################################################################
resource "aws_lambda_function" "arm64" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-arm64"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  architectures    = ["arm64"]

  tags = {
    Name        = "arm64 Architecture Function"
    TestNumber  = "12"
    Description = "Tests Lambda with arm64 Graviton2 architecture"
  }
}

################################################################################
# Test 13: Function in VPC
################################################################################
resource "aws_lambda_function" "in_vpc" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-in-vpc"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  vpc_config {
    subnet_ids         = [aws_subnet.lambda_1.id, aws_subnet.lambda_2.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = {
    Name        = "VPC Function"
    TestNumber  = "13"
    Description = "Tests Lambda deployed in VPC"
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_vpc]
}

################################################################################
# Test 14: Function with description
################################################################################
resource "aws_lambda_function" "with_description" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-description"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  description      = "This is a test Lambda function with a detailed description for testing purposes"

  tags = {
    Name        = "Description Function"
    TestNumber  = "14"
    Description = "Tests Lambda with function description"
  }
}

################################################################################
# Test 15: Function with reserved concurrency
# Note: Commented out - requires sufficient unreserved account concurrency
################################################################################
# resource "aws_lambda_function" "reserved_concurrency" {
#   filename                       = data.archive_file.nodejs.output_path
#   function_name                  = "${local.name_prefix}-reserved-concurrency"
#   role                           = aws_iam_role.lambda_basic.arn
#   handler                        = "index.handler"
#   source_code_hash               = data.archive_file.nodejs.output_base64sha256
#   runtime                        = "nodejs18.x"
#   reserved_concurrent_executions = 5
#
#   tags = {
#     Name        = "Reserved Concurrency Function"
#     TestNumber  = "15"
#     Description = "Tests Lambda with reserved concurrency"
#   }
# }

################################################################################
# Outputs
################################################################################

output "basic_functions" {
  value = {
    nodejs_18            = aws_lambda_function.nodejs_18.function_name
    nodejs_20            = aws_lambda_function.nodejs_20.function_name
    python_311           = aws_lambda_function.python_311.function_name
    python_312           = aws_lambda_function.python_312.function_name
    memory_128           = aws_lambda_function.memory_128.function_name
    memory_1024          = aws_lambda_function.memory_1024.function_name
    memory_max           = aws_lambda_function.memory_max.function_name
    timeout_3            = aws_lambda_function.timeout_3.function_name
    timeout_max          = aws_lambda_function.timeout_max.function_name
    with_env_vars        = aws_lambda_function.with_env_vars.function_name
    x86_64               = aws_lambda_function.x86_64.function_name
    arm64                = aws_lambda_function.arm64.function_name
    in_vpc               = aws_lambda_function.in_vpc.function_name
    with_description     = aws_lambda_function.with_description.function_name
    # reserved_concurrency commented out - requires sufficient account concurrency
  }
  description = "Basic function names"
}

output "basic_function_arns" {
  value = {
    nodejs_18  = aws_lambda_function.nodejs_18.arn
    nodejs_20  = aws_lambda_function.nodejs_20.arn
    python_311 = aws_lambda_function.python_311.arn
    python_312 = aws_lambda_function.python_312.arn
  }
  description = "Basic function ARNs"
}
