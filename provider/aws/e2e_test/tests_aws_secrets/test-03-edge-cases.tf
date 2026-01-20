# test-03-edge-cases.tf
# Tests 31-40: Edge cases for Secrets Manager and SSM Parameter Store
# Tests: versioning, rotation, cross-references

################################################################################
# Local resources for independence
################################################################################
resource "aws_secretsmanager_secret" "basic_03" {
  name = "${local.name_prefix}/basic-03"
  tags = { Name = "Basic Secret 03", TestNumber = "33" }
}

resource "aws_secretsmanager_secret_version" "basic_03" {
  secret_id     = aws_secretsmanager_secret.basic_03.id
  secret_string = "basic-secret-value-03"
}

resource "aws_ssm_parameter" "basic_string_03" {
  name  = "/${local.name_prefix}/basic/string-03"
  type  = "String"
  value = "basic-string-value-03"
  tags  = { Name = "Basic String 03", TestNumber = "40" }
}

resource "aws_ssm_parameter" "config_1" {
  name  = "/${local.name_prefix}/config-03/setting1"
  type  = "String"
  value = "setting1-value"
  tags  = { Name = "Config 1", TestNumber = "40" }
}

resource "aws_ssm_parameter" "config_2" {
  name  = "/${local.name_prefix}/config-03/setting2"
  type  = "String"
  value = "setting2-value"
  tags  = { Name = "Config 2", TestNumber = "40" }
}

################################################################################
# Test 31: Secret with multiple versions (simulate version history)
################################################################################
resource "aws_secretsmanager_secret" "versioned" {
  name = "${local.name_prefix}/versioned"

  tags = {
    Name        = "Versioned Secret"
    TestNumber  = "31"
    Description = "Secret to test version retrieval"
  }
}

resource "aws_secretsmanager_secret_version" "versioned" {
  secret_id     = aws_secretsmanager_secret.versioned.id
  secret_string = "current-version-value"
}

################################################################################
# Test 32: Secret with rotation configuration (Lambda placeholder)
################################################################################
resource "aws_secretsmanager_secret" "rotation_config" {
  name = "${local.name_prefix}/rotation-config"

  tags = {
    Name        = "Rotation Config Secret"
    TestNumber  = "32"
    Description = "Secret with rotation configuration"
  }
}

resource "aws_secretsmanager_secret_version" "rotation_config" {
  secret_id = aws_secretsmanager_secret.rotation_config.id
  secret_string = jsonencode({
    username = "rotated-user"
    password = "initial-password"
  })
}

################################################################################
# Test 33: Parameter referencing a secret ARN
################################################################################
resource "aws_ssm_parameter" "secret_ref" {
  name  = "/${local.name_prefix}/reference/secret-arn"
  type  = "String"
  value = aws_secretsmanager_secret.basic_03.arn

  tags = {
    Name        = "Secret Reference Parameter"
    TestNumber  = "33"
    Description = "Parameter storing secret ARN"
  }
}

################################################################################
# Test 34: Secret with very long name
################################################################################
resource "aws_secretsmanager_secret" "long_name" {
  name = "${local.name_prefix}/very/long/path/to/simulate/deep/hierarchy/levels/secret"

  tags = {
    Name        = "Long Name Secret"
    TestNumber  = "34"
    Description = "Secret with very long name"
  }
}

resource "aws_secretsmanager_secret_version" "long_name" {
  secret_id     = aws_secretsmanager_secret.long_name.id
  secret_string = "long-name-secret-value"
}

################################################################################
# Test 35: Parameter with overwrite enabled
################################################################################
resource "aws_ssm_parameter" "overwrite" {
  name      = "/${local.name_prefix}/overwrite/param"
  type      = "String"
  value     = "overwritten-value"
  overwrite = true

  tags = {
    Name        = "Overwrite Parameter"
    TestNumber  = "35"
    Description = "Parameter with overwrite enabled"
  }
}

################################################################################
# Test 36: Complex JSON in SecureString
################################################################################
resource "aws_ssm_parameter" "complex_json" {
  name = "/${local.name_prefix}/complex/json"
  type = "SecureString"
  value = jsonencode({
    database = {
      primary = {
        host     = "primary.db.example.com"
        port     = 5432
        username = "primary_user"
        password = "primary_password"
      }
      replica = {
        host     = "replica.db.example.com"
        port     = 5432
        username = "replica_user"
        password = "replica_password"
      }
    }
    cache = {
      redis = {
        host = "redis.example.com"
        port = 6379
        auth = "redis_auth_token"
      }
    }
    features = ["feature1", "feature2", "feature3"]
  })

  tags = {
    Name        = "Complex JSON Parameter"
    TestNumber  = "36"
    Description = "SecureString with complex nested JSON"
  }
}

################################################################################
# Test 37: Secret for certificate (PEM format simulation)
################################################################################
resource "aws_secretsmanager_secret" "certificate" {
  name = "${local.name_prefix}/cert/tls"

  tags = {
    Name        = "Certificate Secret"
    TestNumber  = "37"
    Description = "Secret storing TLS certificate"
  }
}

resource "aws_secretsmanager_secret_version" "certificate" {
  secret_id = aws_secretsmanager_secret.certificate.id
  secret_string = jsonencode({
    certificate = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpeg...EXAMPLE...\n-----END CERTIFICATE-----"
    private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...EXAMPLE...\n-----END PRIVATE KEY-----"
    ca_bundle   = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAw...EXAMPLE...\n-----END CERTIFICATE-----"
  })
}

################################################################################
# Test 38: Parameter store policy simulation (via tags)
################################################################################
resource "aws_ssm_parameter" "policy_tags" {
  name  = "/${local.name_prefix}/policy/tagged"
  type  = "SecureString"
  value = "policy-tagged-value"

  tags = {
    Name        = "Policy Tagged Parameter"
    TestNumber  = "38"
    Description = "Parameter with policy-like tags"
    AllowedRoles = "role1:role2:role3"
    Expiration   = "2025-12-31"
    Owner        = "platform-team"
  }
}

################################################################################
# Test 39: Secrets and parameters for microservices pattern
################################################################################
resource "aws_secretsmanager_secret" "service_a" {
  name = "${local.name_prefix}/services/service-a/secrets"
  tags = { Name = "Service A Secret", TestNumber = "39", Service = "service-a" }
}

resource "aws_secretsmanager_secret_version" "service_a" {
  secret_id = aws_secretsmanager_secret.service_a.id
  secret_string = jsonencode({
    api_key    = "service-a-api-key"
    db_password = "service-a-db-pass"
  })
}

resource "aws_ssm_parameter" "service_a_config" {
  name  = "/${local.name_prefix}/services/service-a/config"
  type  = "String"
  value = jsonencode({
    log_level   = "info"
    max_retries = 3
    timeout     = 30
  })
  tags = { Name = "Service A Config", TestNumber = "39", Service = "service-a" }
}

resource "aws_secretsmanager_secret" "service_b" {
  name = "${local.name_prefix}/services/service-b/secrets"
  tags = { Name = "Service B Secret", TestNumber = "39", Service = "service-b" }
}

resource "aws_secretsmanager_secret_version" "service_b" {
  secret_id = aws_secretsmanager_secret.service_b.id
  secret_string = jsonencode({
    api_key     = "service-b-api-key"
    oauth_token = "service-b-oauth-token"
  })
}

resource "aws_ssm_parameter" "service_b_config" {
  name  = "/${local.name_prefix}/services/service-b/config"
  type  = "String"
  value = jsonencode({
    log_level    = "debug"
    cache_ttl    = 300
    feature_flag = true
  })
  tags = { Name = "Service B Config", TestNumber = "39", Service = "service-b" }
}

################################################################################
# Test 40: Data sources to verify retrieval
################################################################################
data "aws_secretsmanager_secret" "verify_basic" {
  name = aws_secretsmanager_secret.basic_03.name

  depends_on = [aws_secretsmanager_secret_version.basic_03]
}

data "aws_ssm_parameter" "verify_basic" {
  name = aws_ssm_parameter.basic_string_03.name
}

data "aws_ssm_parameters_by_path" "verify_config" {
  path = "/${local.name_prefix}/config-03"

  depends_on = [
    aws_ssm_parameter.config_1,
    aws_ssm_parameter.config_2
  ]
}

################################################################################
# Outputs
################################################################################

output "edge_case_secret_arns" {
  value = {
    versioned       = aws_secretsmanager_secret.versioned.arn
    rotation_config = aws_secretsmanager_secret.rotation_config.arn
    certificate     = aws_secretsmanager_secret.certificate.arn
    service_a       = aws_secretsmanager_secret.service_a.arn
    service_b       = aws_secretsmanager_secret.service_b.arn
  }
  description = "Edge case secret ARNs"
}

output "edge_case_param_names" {
  value = {
    secret_ref   = aws_ssm_parameter.secret_ref.name
    complex_json = aws_ssm_parameter.complex_json.name
    policy_tags  = aws_ssm_parameter.policy_tags.name
  }
  description = "Edge case parameter names"
}

output "data_source_verification" {
  value = {
    secret_arn     = data.aws_secretsmanager_secret.verify_basic.arn
    param_value    = data.aws_ssm_parameter.verify_basic.value
    params_by_path = length(data.aws_ssm_parameters_by_path.verify_config.names)
  }
  sensitive = true
  description = "Data source verification results"
}
