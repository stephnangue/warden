# test-01-secrets-manager.tf
# Tests 1-15: AWS Secrets Manager
# Tests: basic secrets, JSON secrets, rotation, KMS encryption

################################################################################
# Test 1: Basic Secret (plaintext)
################################################################################
resource "aws_secretsmanager_secret" "basic" {
  name = "${local.name_prefix}/basic"

  tags = {
    Name        = "Basic Secret"
    TestNumber  = "01"
    Description = "Basic secret creation"
  }
}

resource "aws_secretsmanager_secret_version" "basic" {
  secret_id     = aws_secretsmanager_secret.basic.id
  secret_string = "my-secret-value"
}

################################################################################
# Test 2: Secret with JSON value
################################################################################
resource "aws_secretsmanager_secret" "json" {
  name = "${local.name_prefix}/json"

  tags = {
    Name        = "JSON Secret"
    TestNumber  = "02"
    Description = "Secret with JSON value"
  }
}

resource "aws_secretsmanager_secret_version" "json" {
  secret_id = aws_secretsmanager_secret.json.id
  secret_string = jsonencode({
    username = "admin"
    password = "super-secret-password"
    host     = "db.example.com"
    port     = 5432
    database = "mydb"
  })
}

################################################################################
# Test 3: Secret with description
################################################################################
resource "aws_secretsmanager_secret" "with_description" {
  name        = "${local.name_prefix}/described"
  description = "This is a test secret with a description for Warden testing"

  tags = {
    Name        = "Described Secret"
    TestNumber  = "03"
    Description = "Secret with description"
  }
}

resource "aws_secretsmanager_secret_version" "with_description" {
  secret_id     = aws_secretsmanager_secret.with_description.id
  secret_string = "described-secret-value"
}

################################################################################
# Test 4: Secret with KMS encryption
################################################################################
resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager tests"
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
    Name        = "Secrets KMS Key"
    TestNumber  = "04"
    Description = "KMS key for secret encryption"
  }
}

resource "aws_secretsmanager_secret" "kms_encrypted" {
  name       = "${local.name_prefix}/kms-encrypted"
  kms_key_id = aws_kms_key.secrets.arn

  tags = {
    Name        = "KMS Encrypted Secret"
    TestNumber  = "04"
    Description = "Secret with custom KMS key"
  }
}

resource "aws_secretsmanager_secret_version" "kms_encrypted" {
  secret_id     = aws_secretsmanager_secret.kms_encrypted.id
  secret_string = "kms-encrypted-secret-value"
}

################################################################################
# Test 5: Secret with recovery window
################################################################################
resource "aws_secretsmanager_secret" "recovery_window" {
  name                    = "${local.name_prefix}/recovery"
  recovery_window_in_days = 7

  tags = {
    Name        = "Recovery Window Secret"
    TestNumber  = "05"
    Description = "Secret with 7-day recovery window"
  }
}

resource "aws_secretsmanager_secret_version" "recovery_window" {
  secret_id     = aws_secretsmanager_secret.recovery_window.id
  secret_string = "recovery-secret-value"
}

################################################################################
# Test 6: Secret with path hierarchy
################################################################################
resource "aws_secretsmanager_secret" "hierarchical" {
  name = "${local.name_prefix}/app/prod/database/credentials"

  tags = {
    Name        = "Hierarchical Secret"
    TestNumber  = "06"
    Description = "Secret with deep path hierarchy"
  }
}

resource "aws_secretsmanager_secret_version" "hierarchical" {
  secret_id = aws_secretsmanager_secret.hierarchical.id
  secret_string = jsonencode({
    username = "prod-user"
    password = "prod-password"
  })
}

################################################################################
# Test 7: Secret with binary value
################################################################################
resource "aws_secretsmanager_secret" "binary" {
  name = "${local.name_prefix}/binary"

  tags = {
    Name        = "Binary Secret"
    TestNumber  = "07"
    Description = "Secret with binary value"
  }
}

resource "aws_secretsmanager_secret_version" "binary" {
  secret_id     = aws_secretsmanager_secret.binary.id
  secret_binary = base64encode("binary-secret-data-for-testing")
}

################################################################################
# Test 8: Secret with replica (if multi-region)
################################################################################
resource "aws_secretsmanager_secret" "with_tags" {
  name = "${local.name_prefix}/tagged"

  tags = {
    Name        = "Tagged Secret"
    TestNumber  = "08"
    Description = "Secret with multiple tags"
    Environment = "test"
    Team        = "platform"
    CostCenter  = "12345"
  }
}

resource "aws_secretsmanager_secret_version" "with_tags" {
  secret_id     = aws_secretsmanager_secret.with_tags.id
  secret_string = "tagged-secret-value"
}

################################################################################
# Test 9: Secret with resource policy
################################################################################
resource "aws_secretsmanager_secret" "with_policy" {
  name = "${local.name_prefix}/with-policy"

  tags = {
    Name        = "Policy Secret"
    TestNumber  = "09"
    Description = "Secret with resource policy"
  }
}

resource "aws_secretsmanager_secret_version" "with_policy" {
  secret_id     = aws_secretsmanager_secret.with_policy.id
  secret_string = "policy-secret-value"
}

resource "aws_secretsmanager_secret_policy" "policy" {
  secret_arn = aws_secretsmanager_secret.with_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSameAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "secretsmanager:GetSecretValue"
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Test 10: Multiple secrets in same hierarchy
################################################################################
resource "aws_secretsmanager_secret" "multi_1" {
  name = "${local.name_prefix}/multi/secret-1"
  tags = { Name = "Multi Secret 1", TestNumber = "10" }
}

resource "aws_secretsmanager_secret_version" "multi_1" {
  secret_id     = aws_secretsmanager_secret.multi_1.id
  secret_string = "multi-secret-1-value"
}

resource "aws_secretsmanager_secret" "multi_2" {
  name = "${local.name_prefix}/multi/secret-2"
  tags = { Name = "Multi Secret 2", TestNumber = "10" }
}

resource "aws_secretsmanager_secret_version" "multi_2" {
  secret_id     = aws_secretsmanager_secret.multi_2.id
  secret_string = "multi-secret-2-value"
}

resource "aws_secretsmanager_secret" "multi_3" {
  name = "${local.name_prefix}/multi/secret-3"
  tags = { Name = "Multi Secret 3", TestNumber = "10" }
}

resource "aws_secretsmanager_secret_version" "multi_3" {
  secret_id     = aws_secretsmanager_secret.multi_3.id
  secret_string = "multi-secret-3-value"
}

################################################################################
# Test 11: Secret with special characters in name
################################################################################
resource "aws_secretsmanager_secret" "special_name" {
  name = "${local.name_prefix}/special_chars-test.secret"

  tags = {
    Name        = "Special Name Secret"
    TestNumber  = "11"
    Description = "Secret with special characters in name"
  }
}

resource "aws_secretsmanager_secret_version" "special_name" {
  secret_id     = aws_secretsmanager_secret.special_name.id
  secret_string = "special-name-secret-value"
}

################################################################################
# Test 12: Database credentials secret (common pattern)
################################################################################
resource "aws_secretsmanager_secret" "db_credentials" {
  name = "${local.name_prefix}/rds/mydb/credentials"

  tags = {
    Name        = "DB Credentials Secret"
    TestNumber  = "12"
    Description = "Database credentials pattern"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    engine   = "postgres"
    host     = "mydb.cluster-abc123.us-east-1.rds.amazonaws.com"
    username = "admin"
    password = "super-secret-db-password"
    dbname   = "mydb"
    port     = 5432
  })
}

################################################################################
# Test 13: API key secret (common pattern)
################################################################################
resource "aws_secretsmanager_secret" "api_key" {
  name = "${local.name_prefix}/api/external-service/key"

  tags = {
    Name        = "API Key Secret"
    TestNumber  = "13"
    Description = "API key pattern"
  }
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id = aws_secretsmanager_secret.api_key.id
  secret_string = jsonencode({
    api_key    = "sk-1234567890abcdef"
    api_secret = "secret-abcdef1234567890"
    endpoint   = "https://api.example.com/v1"
  })
}

################################################################################
# Test 14: OAuth credentials secret
################################################################################
resource "aws_secretsmanager_secret" "oauth" {
  name = "${local.name_prefix}/oauth/provider"

  tags = {
    Name        = "OAuth Secret"
    TestNumber  = "14"
    Description = "OAuth credentials pattern"
  }
}

resource "aws_secretsmanager_secret_version" "oauth" {
  secret_id = aws_secretsmanager_secret.oauth.id
  secret_string = jsonencode({
    client_id     = "oauth-client-id-12345"
    client_secret = "oauth-client-secret-67890"
    token_url     = "https://oauth.example.com/token"
    scope         = "read write"
  })
}

################################################################################
# Test 15: Large secret value
################################################################################
resource "aws_secretsmanager_secret" "large" {
  name = "${local.name_prefix}/large"

  tags = {
    Name        = "Large Secret"
    TestNumber  = "15"
    Description = "Secret with large value"
  }
}

resource "aws_secretsmanager_secret_version" "large" {
  secret_id = aws_secretsmanager_secret.large.id
  secret_string = jsonencode({
    data = join("", [for i in range(1000) : "line-${i}-with-some-data-padding-"])
  })
}

################################################################################
# Outputs
################################################################################

output "secret_arns" {
  value = {
    basic          = aws_secretsmanager_secret.basic.arn
    json           = aws_secretsmanager_secret.json.arn
    kms_encrypted  = aws_secretsmanager_secret.kms_encrypted.arn
    hierarchical   = aws_secretsmanager_secret.hierarchical.arn
    with_policy    = aws_secretsmanager_secret.with_policy.arn
    db_credentials = aws_secretsmanager_secret.db_credentials.arn
  }
  description = "Secrets Manager secret ARNs"
}

output "secret_names" {
  value = {
    basic        = aws_secretsmanager_secret.basic.name
    json         = aws_secretsmanager_secret.json.name
    hierarchical = aws_secretsmanager_secret.hierarchical.name
  }
  description = "Secrets Manager secret names"
}

output "kms_key_arn" {
  value       = aws_kms_key.secrets.arn
  description = "KMS key ARN for secret encryption"
}
