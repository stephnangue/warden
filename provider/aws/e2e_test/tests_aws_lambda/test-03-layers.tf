# test-03-layers.tf
# Tests 26-32: Lambda Layers
# Tests: layer creation, versions, compatibility, functions with layers

################################################################################
# Lambda function code package
################################################################################

# Node.js function code (for functions that use layers)
data "archive_file" "nodejs" {
  type        = "zip"
  output_path = "${path.module}/nodejs_function_03.zip"

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
# Layer code packages
################################################################################

# Node.js utility layer
data "archive_file" "nodejs_layer" {
  type        = "zip"
  output_path = "${path.module}/nodejs_layer.zip"

  source {
    content  = <<-EOF
      // Utility functions
      module.exports.formatDate = (date) => {
        return date.toISOString();
      };

      module.exports.generateId = () => {
        return Math.random().toString(36).substring(2, 15);
      };

      module.exports.logger = {
        info: (msg) => console.log('[INFO] ' + msg),
        error: (msg) => console.error('[ERROR] ' + msg),
        debug: (msg) => console.log('[DEBUG] ' + msg)
      };
    EOF
    filename = "nodejs/node_modules/utils/index.js"
  }
}

# Python utility layer
data "archive_file" "python_layer" {
  type        = "zip"
  output_path = "${path.module}/python_layer.zip"

  source {
    content  = <<-EOF
import json
from datetime import datetime

def format_date(dt):
    return dt.isoformat()

def generate_id():
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

class Logger:
    @staticmethod
    def info(msg):
        print("[INFO] " + str(msg))

    @staticmethod
    def error(msg):
        print("[ERROR] " + str(msg))

    @staticmethod
    def debug(msg):
        print("[DEBUG] " + str(msg))
    EOF
    filename = "python/utils.py"
  }
}

################################################################################
# Test 26: Basic Node.js layer
################################################################################
resource "aws_lambda_layer_version" "nodejs_utils" {
  filename            = data.archive_file.nodejs_layer.output_path
  layer_name          = "${local.name_prefix}-nodejs-utils"
  compatible_runtimes = ["nodejs18.x", "nodejs20.x"]
  description         = "Node.js utility functions layer"
  source_code_hash    = data.archive_file.nodejs_layer.output_base64sha256
}

################################################################################
# Test 27: Basic Python layer
################################################################################
resource "aws_lambda_layer_version" "python_utils" {
  filename            = data.archive_file.python_layer.output_path
  layer_name          = "${local.name_prefix}-python-utils"
  compatible_runtimes = ["python3.11", "python3.12"]
  description         = "Python utility functions layer"
  source_code_hash    = data.archive_file.python_layer.output_base64sha256
}

################################################################################
# Test 28: Layer with single runtime compatibility
################################################################################
resource "aws_lambda_layer_version" "single_runtime" {
  filename            = data.archive_file.nodejs_layer.output_path
  layer_name          = "${local.name_prefix}-single-runtime"
  compatible_runtimes = ["nodejs18.x"]
  description         = "Layer compatible with only Node.js 18"
  source_code_hash    = data.archive_file.nodejs_layer.output_base64sha256
}

################################################################################
# Test 29: Layer with x86_64 architecture
################################################################################
resource "aws_lambda_layer_version" "x86_layer" {
  filename                 = data.archive_file.nodejs_layer.output_path
  layer_name               = "${local.name_prefix}-x86-layer"
  compatible_runtimes      = ["nodejs18.x", "nodejs20.x"]
  compatible_architectures = ["x86_64"]
  description              = "Layer for x86_64 architecture"
  source_code_hash         = data.archive_file.nodejs_layer.output_base64sha256
}

################################################################################
# Test 30: Layer with arm64 architecture
################################################################################
resource "aws_lambda_layer_version" "arm_layer" {
  filename                 = data.archive_file.nodejs_layer.output_path
  layer_name               = "${local.name_prefix}-arm-layer"
  compatible_runtimes      = ["nodejs18.x", "nodejs20.x"]
  compatible_architectures = ["arm64"]
  description              = "Layer for arm64 architecture"
  source_code_hash         = data.archive_file.nodejs_layer.output_base64sha256
}

################################################################################
# Test 31: Layer with both architectures
################################################################################
resource "aws_lambda_layer_version" "multi_arch_layer" {
  filename                 = data.archive_file.nodejs_layer.output_path
  layer_name               = "${local.name_prefix}-multi-arch-layer"
  compatible_runtimes      = ["nodejs18.x", "nodejs20.x"]
  compatible_architectures = ["x86_64", "arm64"]
  description              = "Layer for both architectures"
  source_code_hash         = data.archive_file.nodejs_layer.output_base64sha256
}

################################################################################
# Test 32: Function using single layer
################################################################################
resource "aws_lambda_function" "with_single_layer" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-single-layer"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  layers           = [aws_lambda_layer_version.nodejs_utils.arn]

  tags = {
    Name        = "Single Layer Function"
    TestNumber  = "32"
    Description = "Function using single layer"
  }
}

################################################################################
# Test 33: Function using multiple layers - max 5
################################################################################
resource "aws_lambda_layer_version" "layer_1" {
  filename            = data.archive_file.nodejs_layer.output_path
  layer_name          = "${local.name_prefix}-layer-1"
  compatible_runtimes = ["nodejs18.x"]
  description         = "Additional layer 1"
  source_code_hash    = data.archive_file.nodejs_layer.output_base64sha256
}

resource "aws_lambda_layer_version" "layer_2" {
  filename            = data.archive_file.nodejs_layer.output_path
  layer_name          = "${local.name_prefix}-layer-2"
  compatible_runtimes = ["nodejs18.x"]
  description         = "Additional layer 2"
  source_code_hash    = data.archive_file.nodejs_layer.output_base64sha256
}

resource "aws_lambda_layer_version" "layer_3" {
  filename            = data.archive_file.nodejs_layer.output_path
  layer_name          = "${local.name_prefix}-layer-3"
  compatible_runtimes = ["nodejs18.x"]
  description         = "Additional layer 3"
  source_code_hash    = data.archive_file.nodejs_layer.output_base64sha256
}

resource "aws_lambda_function" "with_multiple_layers" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-multi-layer"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  layers = [
    aws_lambda_layer_version.nodejs_utils.arn,
    aws_lambda_layer_version.layer_1.arn,
    aws_lambda_layer_version.layer_2.arn,
    aws_lambda_layer_version.layer_3.arn
  ]

  tags = {
    Name        = "Multiple Layers Function"
    TestNumber  = "33"
    Description = "Function using multiple layers"
  }
}

################################################################################
# Test 34: Layer permission - allow specific account
################################################################################
resource "aws_lambda_layer_version_permission" "same_account" {
  layer_name     = aws_lambda_layer_version.nodejs_utils.layer_name
  version_number = aws_lambda_layer_version.nodejs_utils.version
  principal      = data.aws_caller_identity.current.account_id
  action         = "lambda:GetLayerVersion"
  statement_id   = "allow-same-account"
}

################################################################################
# Outputs
################################################################################

output "layers" {
  value = {
    nodejs_utils    = aws_lambda_layer_version.nodejs_utils.layer_name
    python_utils    = aws_lambda_layer_version.python_utils.layer_name
    single_runtime  = aws_lambda_layer_version.single_runtime.layer_name
    x86_layer       = aws_lambda_layer_version.x86_layer.layer_name
    arm_layer       = aws_lambda_layer_version.arm_layer.layer_name
    multi_arch      = aws_lambda_layer_version.multi_arch_layer.layer_name
  }
  description = "Layer names"
}

output "layer_arns" {
  value = {
    nodejs_utils   = aws_lambda_layer_version.nodejs_utils.arn
    python_utils   = aws_lambda_layer_version.python_utils.arn
    single_runtime = aws_lambda_layer_version.single_runtime.arn
  }
  description = "Layer ARNs with version"
}

output "layer_versions" {
  value = {
    nodejs_utils   = aws_lambda_layer_version.nodejs_utils.version
    python_utils   = aws_lambda_layer_version.python_utils.version
    single_runtime = aws_lambda_layer_version.single_runtime.version
  }
  description = "Layer versions"
}

output "functions_with_layers" {
  value = {
    single_layer = aws_lambda_function.with_single_layer.function_name
    multi_layer  = aws_lambda_function.with_multiple_layers.function_name
  }
  description = "Functions using layers"
}
