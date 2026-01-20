# test-02-versions-aliases.tf
# Tests 16-25: Lambda versions, aliases, and provisioned concurrency
# Tests: version publishing, alias routing, weighted aliases, provisioned concurrency

################################################################################
# Lambda function code package
################################################################################

# Node.js function code
data "archive_file" "nodejs" {
  type        = "zip"
  output_path = "${path.module}/nodejs_function_02.zip"

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
# Base function for version/alias testing
################################################################################
resource "aws_lambda_function" "versioned" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-versioned"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Versioned Function"
    TestNumber  = "16"
    Description = "Base function for version and alias testing"
  }
}

################################################################################
# Test 16: Published version
################################################################################
# The version is automatically created when publish = true
# Access via aws_lambda_function.versioned.version

################################################################################
# Test 17: Alias pointing to $LATEST
################################################################################
resource "aws_lambda_alias" "latest" {
  name             = "latest"
  description      = "Alias pointing to LATEST"
  function_name    = aws_lambda_function.versioned.function_name
  function_version = "$LATEST"
}

################################################################################
# Test 18: Alias pointing to specific version
################################################################################
resource "aws_lambda_alias" "v1" {
  name             = "v1"
  description      = "Alias pointing to version 1"
  function_name    = aws_lambda_function.versioned.function_name
  function_version = aws_lambda_function.versioned.version
}

################################################################################
# Test 19: Alias for production
################################################################################
resource "aws_lambda_alias" "prod" {
  name             = "prod"
  description      = "Production alias"
  function_name    = aws_lambda_function.versioned.function_name
  function_version = aws_lambda_function.versioned.version
}

################################################################################
# Test 20: Alias for staging
################################################################################
resource "aws_lambda_alias" "staging" {
  name             = "staging"
  description      = "Staging alias"
  function_name    = aws_lambda_function.versioned.function_name
  function_version = aws_lambda_function.versioned.version
}

################################################################################
# Test 21: Function for weighted alias testing
################################################################################
resource "aws_lambda_function" "weighted_base" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-weighted-base"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Weighted Base Function"
    TestNumber  = "21"
    Description = "Base function for weighted alias testing"
  }
}

# Note: Weighted aliases require two different versions
# Since we only have one version initially, we create a simple alias
# In real scenarios, you would update the function and publish new versions

################################################################################
# Test 22: Alias with provisioned concurrency
################################################################################
resource "aws_lambda_function" "provisioned_concurrency" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-provisioned-conc"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Provisioned Concurrency Function"
    TestNumber  = "22"
    Description = "Function for provisioned concurrency testing"
  }
}

resource "aws_lambda_alias" "provisioned" {
  name             = "provisioned"
  description      = "Alias with provisioned concurrency"
  function_name    = aws_lambda_function.provisioned_concurrency.function_name
  function_version = aws_lambda_function.provisioned_concurrency.version
}

# Note: Commented out - requires sufficient unreserved account concurrency
# resource "aws_lambda_provisioned_concurrency_config" "main" {
#   function_name                     = aws_lambda_function.provisioned_concurrency.function_name
#   provisioned_concurrent_executions = 2
#   qualifier                         = aws_lambda_alias.provisioned.name
# }

################################################################################
# Test 23: Function with multiple aliases
################################################################################
resource "aws_lambda_function" "multi_alias" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-multi-alias"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Multi Alias Function"
    TestNumber  = "23"
    Description = "Function with multiple aliases"
  }
}

resource "aws_lambda_alias" "multi_dev" {
  name             = "dev"
  description      = "Development environment"
  function_name    = aws_lambda_function.multi_alias.function_name
  function_version = "$LATEST"
}

resource "aws_lambda_alias" "multi_test" {
  name             = "test"
  description      = "Test environment"
  function_name    = aws_lambda_function.multi_alias.function_name
  function_version = aws_lambda_function.multi_alias.version
}

resource "aws_lambda_alias" "multi_staging" {
  name             = "staging"
  description      = "Staging environment"
  function_name    = aws_lambda_function.multi_alias.function_name
  function_version = aws_lambda_function.multi_alias.version
}

resource "aws_lambda_alias" "multi_prod" {
  name             = "production"
  description      = "Production environment"
  function_name    = aws_lambda_function.multi_alias.function_name
  function_version = aws_lambda_function.multi_alias.version
}

################################################################################
# Test 24: Function URL with alias
################################################################################
resource "aws_lambda_function" "with_url" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-with-url"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"
  publish          = true

  tags = {
    Name        = "Function URL Function"
    TestNumber  = "24"
    Description = "Function with Function URL"
  }
}

resource "aws_lambda_alias" "url_alias" {
  name             = "live"
  description      = "Alias for Function URL"
  function_name    = aws_lambda_function.with_url.function_name
  function_version = aws_lambda_function.with_url.version
}

resource "aws_lambda_function_url" "main" {
  function_name      = aws_lambda_function.with_url.function_name
  qualifier          = aws_lambda_alias.url_alias.name
  authorization_type = "NONE"

  cors {
    allow_credentials = true
    allow_origins     = ["*"]
    allow_methods     = ["GET", "POST", "PUT", "DELETE"]
    allow_headers     = ["Content-Type", "Authorization"]
    expose_headers    = ["X-Request-Id"]
    max_age           = 3600
  }
}

################################################################################
# Test 25: Function URL without alias - direct to LATEST
################################################################################
resource "aws_lambda_function" "url_latest" {
  filename         = data.archive_file.nodejs.output_path
  function_name    = "${local.name_prefix}-url-latest"
  role             = aws_iam_role.lambda_basic.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.nodejs.output_base64sha256
  runtime          = "nodejs18.x"

  tags = {
    Name        = "Function URL Latest"
    TestNumber  = "25"
    Description = "Function URL pointing to LATEST"
  }
}

resource "aws_lambda_function_url" "latest" {
  function_name      = aws_lambda_function.url_latest.function_name
  authorization_type = "NONE"
}

################################################################################
# Outputs
################################################################################

output "versioned_functions" {
  value = {
    versioned              = aws_lambda_function.versioned.function_name
    versioned_version      = aws_lambda_function.versioned.version
    weighted_base          = aws_lambda_function.weighted_base.function_name
    provisioned_concurrency = aws_lambda_function.provisioned_concurrency.function_name
    multi_alias            = aws_lambda_function.multi_alias.function_name
    with_url               = aws_lambda_function.with_url.function_name
    url_latest             = aws_lambda_function.url_latest.function_name
  }
  description = "Versioned function names"
}

output "aliases" {
  value = {
    latest               = aws_lambda_alias.latest.name
    v1                   = aws_lambda_alias.v1.name
    prod                 = aws_lambda_alias.prod.name
    staging              = aws_lambda_alias.staging.name
    provisioned          = aws_lambda_alias.provisioned.name
    multi_dev            = aws_lambda_alias.multi_dev.name
    multi_test           = aws_lambda_alias.multi_test.name
    multi_staging        = aws_lambda_alias.multi_staging.name
    multi_prod           = aws_lambda_alias.multi_prod.name
    url_alias            = aws_lambda_alias.url_alias.name
  }
  description = "Alias names"
}

output "function_urls" {
  value = {
    with_alias = aws_lambda_function_url.main.function_url
    latest     = aws_lambda_function_url.latest.function_url
  }
  description = "Function URLs"
}

output "alias_arns" {
  value = {
    v1_arn      = aws_lambda_alias.v1.arn
    prod_arn    = aws_lambda_alias.prod.arn
    staging_arn = aws_lambda_alias.staging.arn
  }
  description = "Alias ARNs - note these contain colons in the path"
}
