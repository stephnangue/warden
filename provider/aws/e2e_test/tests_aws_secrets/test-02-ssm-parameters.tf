# test-02-ssm-parameters.tf
# Tests 16-30: SSM Parameter Store
# Tests: String, SecureString, StringList, hierarchies, KMS

################################################################################
# Test 16: Basic String Parameter
################################################################################
resource "aws_ssm_parameter" "basic_string" {
  name  = "/${local.name_prefix}/basic/string"
  type  = "String"
  value = "basic-string-value"

  tags = {
    Name        = "Basic String Parameter"
    TestNumber  = "16"
    Description = "Basic string parameter"
  }
}

################################################################################
# Test 17: String Parameter with description
################################################################################
resource "aws_ssm_parameter" "with_description" {
  name        = "/${local.name_prefix}/described/param"
  type        = "String"
  value       = "described-value"
  description = "This is a test parameter with description"

  tags = {
    Name        = "Described Parameter"
    TestNumber  = "17"
    Description = "Parameter with description"
  }
}

################################################################################
# Test 18: StringList Parameter
################################################################################
resource "aws_ssm_parameter" "string_list" {
  name  = "/${local.name_prefix}/list/values"
  type  = "StringList"
  value = "value1,value2,value3,value4,value5"

  tags = {
    Name        = "StringList Parameter"
    TestNumber  = "18"
    Description = "StringList parameter"
  }
}

################################################################################
# Test 19: SecureString Parameter (default KMS)
################################################################################
resource "aws_ssm_parameter" "secure_string" {
  name  = "/${local.name_prefix}/secure/default"
  type  = "SecureString"
  value = "secure-string-value"

  tags = {
    Name        = "SecureString Parameter"
    TestNumber  = "19"
    Description = "SecureString with default KMS"
  }
}

################################################################################
# Test 20: SecureString with custom KMS key
################################################################################
resource "aws_kms_key" "ssm" {
  description             = "KMS key for SSM Parameter Store tests"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "SSM KMS Key"
    TestNumber  = "20"
    Description = "KMS key for SSM encryption"
  }
}

resource "aws_ssm_parameter" "secure_custom_kms" {
  name   = "/${local.name_prefix}/secure/custom-kms"
  type   = "SecureString"
  value  = "custom-kms-secure-value"
  key_id = aws_kms_key.ssm.arn

  tags = {
    Name        = "Custom KMS SecureString"
    TestNumber  = "20"
    Description = "SecureString with custom KMS key"
  }
}

################################################################################
# Test 21: Deep hierarchy parameter
################################################################################
resource "aws_ssm_parameter" "deep_hierarchy" {
  name  = "/${local.name_prefix}/app/prod/database/connection/string"
  type  = "SecureString"
  value = "Server=db.example.com;Database=mydb;User=admin;Password=secret"

  tags = {
    Name        = "Deep Hierarchy Parameter"
    TestNumber  = "21"
    Description = "Parameter with deep path"
  }
}

################################################################################
# Test 22: Multiple parameters in same hierarchy
################################################################################
resource "aws_ssm_parameter" "multi_1" {
  name  = "/${local.name_prefix}/config/app/setting1"
  type  = "String"
  value = "setting1-value"
  tags  = { Name = "Multi Param 1", TestNumber = "22" }
}

resource "aws_ssm_parameter" "multi_2" {
  name  = "/${local.name_prefix}/config/app/setting2"
  type  = "String"
  value = "setting2-value"
  tags  = { Name = "Multi Param 2", TestNumber = "22" }
}

resource "aws_ssm_parameter" "multi_3" {
  name  = "/${local.name_prefix}/config/app/setting3"
  type  = "String"
  value = "setting3-value"
  tags  = { Name = "Multi Param 3", TestNumber = "22" }
}

resource "aws_ssm_parameter" "multi_4" {
  name  = "/${local.name_prefix}/config/app/nested/setting4"
  type  = "String"
  value = "setting4-value"
  tags  = { Name = "Multi Param 4", TestNumber = "22" }
}

################################################################################
# Test 23: Parameter with allowed pattern
################################################################################
resource "aws_ssm_parameter" "with_pattern" {
  name            = "/${local.name_prefix}/validated/email"
  type            = "String"
  value           = "test@example.com"
  allowed_pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"

  tags = {
    Name        = "Pattern Validated Parameter"
    TestNumber  = "23"
    Description = "Parameter with allowed pattern"
  }
}

################################################################################
# Test 24: Parameter with tier (Standard)
################################################################################
resource "aws_ssm_parameter" "standard_tier" {
  name  = "/${local.name_prefix}/tier/standard"
  type  = "String"
  value = "standard-tier-value"
  tier  = "Standard"

  tags = {
    Name        = "Standard Tier Parameter"
    TestNumber  = "24"
    Description = "Standard tier parameter"
  }
}

################################################################################
# Test 25: Parameter with tier (Advanced)
################################################################################
resource "aws_ssm_parameter" "advanced_tier" {
  name  = "/${local.name_prefix}/tier/advanced"
  type  = "String"
  value = "advanced-tier-value-with-larger-capacity"
  tier  = "Advanced"

  tags = {
    Name        = "Advanced Tier Parameter"
    TestNumber  = "25"
    Description = "Advanced tier parameter"
  }
}

################################################################################
# Test 26: JSON value in String parameter
################################################################################
resource "aws_ssm_parameter" "json_string" {
  name  = "/${local.name_prefix}/json/config"
  type  = "String"
  value = jsonencode({
    feature_flags = {
      enable_new_ui  = true
      enable_beta    = false
      max_retries    = 3
    }
    endpoints = {
      api     = "https://api.example.com"
      cdn     = "https://cdn.example.com"
    }
  })

  tags = {
    Name        = "JSON String Parameter"
    TestNumber  = "26"
    Description = "JSON value in String parameter"
  }
}

################################################################################
# Test 27: Environment-specific parameters
################################################################################
resource "aws_ssm_parameter" "env_dev" {
  name  = "/${local.name_prefix}/env/dev/config"
  type  = "String"
  value = "dev-config-value"
  tags  = { Name = "Dev Config", TestNumber = "27", Environment = "dev" }
}

resource "aws_ssm_parameter" "env_staging" {
  name  = "/${local.name_prefix}/env/staging/config"
  type  = "String"
  value = "staging-config-value"
  tags  = { Name = "Staging Config", TestNumber = "27", Environment = "staging" }
}

resource "aws_ssm_parameter" "env_prod" {
  name  = "/${local.name_prefix}/env/prod/config"
  type  = "SecureString"
  value = "prod-config-value"
  tags  = { Name = "Prod Config", TestNumber = "27", Environment = "prod" }
}

################################################################################
# Test 28: Data type parameters
################################################################################
resource "aws_ssm_parameter" "datatype_text" {
  name      = "/${local.name_prefix}/datatype/text"
  type      = "String"
  value     = "plain text value"
  data_type = "text"

  tags = {
    Name        = "Text DataType Parameter"
    TestNumber  = "28"
    Description = "Parameter with text data type"
  }
}

# Data source to get a valid AMI ID
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_ssm_parameter" "datatype_ec2" {
  name      = "/${local.name_prefix}/datatype/ami"
  type      = "String"
  value     = data.aws_ami.amazon_linux.id
  data_type = "aws:ec2:image"

  tags = {
    Name        = "EC2 Image DataType Parameter"
    TestNumber  = "28"
    Description = "Parameter with EC2 image data type"
  }
}

################################################################################
# Test 29: Long value parameter
################################################################################
resource "aws_ssm_parameter" "long_value" {
  name  = "/${local.name_prefix}/long/value"
  type  = "String"
  tier  = "Advanced"
  value = join("\n", [for i in range(100) : "line-${i}: This is line number ${i} with some additional content to make it longer."])

  tags = {
    Name        = "Long Value Parameter"
    TestNumber  = "29"
    Description = "Parameter with long value"
  }
}

################################################################################
# Test 30: Special characters in value
################################################################################
resource "aws_ssm_parameter" "special_chars" {
  name  = "/${local.name_prefix}/special/chars"
  type  = "SecureString"
  value = "password!@#$%^&*()_+-=[]{}|;':\",./<>?"

  tags = {
    Name        = "Special Chars Parameter"
    TestNumber  = "30"
    Description = "Parameter with special characters"
  }
}

################################################################################
# Outputs
################################################################################

output "ssm_parameter_names" {
  value = {
    basic_string     = aws_ssm_parameter.basic_string.name
    string_list      = aws_ssm_parameter.string_list.name
    secure_string    = aws_ssm_parameter.secure_string.name
    secure_custom    = aws_ssm_parameter.secure_custom_kms.name
    deep_hierarchy   = aws_ssm_parameter.deep_hierarchy.name
    json_string      = aws_ssm_parameter.json_string.name
  }
  description = "SSM Parameter names"
}

output "ssm_parameter_arns" {
  value = {
    basic_string  = aws_ssm_parameter.basic_string.arn
    secure_string = aws_ssm_parameter.secure_string.arn
    secure_custom = aws_ssm_parameter.secure_custom_kms.arn
  }
  description = "SSM Parameter ARNs"
}

output "ssm_kms_key_arn" {
  value       = aws_kms_key.ssm.arn
  description = "KMS key ARN for SSM encryption"
}
