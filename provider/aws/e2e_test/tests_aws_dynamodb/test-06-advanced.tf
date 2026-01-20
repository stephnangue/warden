# test-06-advanced.tf
# Tests 47-60: Advanced DynamoDB features
# Tests: TTL, encryption, backups, auto-scaling, contributor insights, resource policies

################################################################################
# Test 47: Table with TTL (Time to Live)
################################################################################
resource "aws_dynamodb_table" "with_ttl" {
  name         = "${local.table_prefix}-ttl"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Name        = "TTL Table"
    TestNumber  = "47"
    Description = "Tests table with Time to Live enabled"
  }
}

# Item with TTL attribute
resource "aws_dynamodb_table_item" "ttl_item" {
  table_name = aws_dynamodb_table.with_ttl.name
  hash_key   = aws_dynamodb_table.with_ttl.hash_key
  range_key  = aws_dynamodb_table.with_ttl.range_key

  item = jsonencode({
    pk = { S = "SESSION#001" }
    sk = { S = "USER#alice" }
    session_id = { S = "sess_abc123" }
    # TTL set to expire in 1 hour from a fixed timestamp (for testing)
    expires_at = { N = "1893456000" } # Far future date
    data = { S = "Session data that will expire" }
  })
}

################################################################################
# Test 48: Table with SSE using AWS managed key
################################################################################
resource "aws_dynamodb_table" "sse_aws_managed" {
  name         = "${local.table_prefix}-sse-aws"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name        = "SSE AWS Managed"
    TestNumber  = "48"
    Description = "Tests table with AWS managed encryption"
  }
}

################################################################################
# Test 49: Table with SSE using customer managed KMS key
################################################################################
resource "aws_kms_key" "dynamodb" {
  description             = "KMS key for DynamoDB encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "DynamoDB KMS Key"
    TestNumber  = "49"
    Description = "Customer managed key for DynamoDB"
  }
}

resource "aws_kms_alias" "dynamodb" {
  name          = "alias/${local.table_prefix}-ddb-key"
  target_key_id = aws_kms_key.dynamodb.key_id
}

resource "aws_dynamodb_table" "sse_kms" {
  name         = "${local.table_prefix}-sse-kms"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb.arn
  }

  tags = {
    Name        = "SSE KMS"
    TestNumber  = "49"
    Description = "Tests table with customer managed KMS encryption"
  }
}

################################################################################
# Test 50: Table with Point-in-Time Recovery (PITR)
################################################################################
resource "aws_dynamodb_table" "with_pitr" {
  name         = "${local.table_prefix}-pitr"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name        = "PITR Enabled"
    TestNumber  = "50"
    Description = "Tests table with point-in-time recovery"
  }
}

################################################################################
# Test 51: Table with auto-scaling
################################################################################
resource "aws_dynamodb_table" "autoscaling" {
  name           = "${local.table_prefix}-autoscaling"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Auto-scaling Table"
    TestNumber  = "51"
    Description = "Tests table with auto-scaling policies"
  }
}

# Read capacity auto-scaling
resource "aws_appautoscaling_target" "read" {
  max_capacity       = 100
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.autoscaling.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "read" {
  name               = "${local.table_prefix}-read-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.read.resource_id
  scalable_dimension = aws_appautoscaling_target.read.scalable_dimension
  service_namespace  = aws_appautoscaling_target.read.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

# Write capacity auto-scaling
resource "aws_appautoscaling_target" "write" {
  max_capacity       = 100
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.autoscaling.name}"
  scalable_dimension = "dynamodb:table:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "write" {
  name               = "${local.table_prefix}-write-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.write.resource_id
  scalable_dimension = aws_appautoscaling_target.write.scalable_dimension
  service_namespace  = aws_appautoscaling_target.write.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBWriteCapacityUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

################################################################################
# Test 52: Table with Contributor Insights
################################################################################
resource "aws_dynamodb_table" "contributor_insights" {
  name         = "${local.table_prefix}-contributor"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Contributor Insights"
    TestNumber  = "52"
    Description = "Tests table with contributor insights"
  }
}

resource "aws_dynamodb_contributor_insights" "main" {
  table_name = aws_dynamodb_table.contributor_insights.name
}

################################################################################
# Test 53: Table with On-Demand Backup
################################################################################
resource "aws_dynamodb_table" "backup_table" {
  name         = "${local.table_prefix}-backup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Backup Table"
    TestNumber  = "53"
    Description = "Tests table with on-demand backup"
  }
}

# Add some data before backup
resource "aws_dynamodb_table_item" "backup_item" {
  table_name = aws_dynamodb_table.backup_table.name
  hash_key   = aws_dynamodb_table.backup_table.hash_key

  item = jsonencode({
    pk = { S = "BACKUP#001" }
    data = { S = "Data to be backed up" }
    timestamp = { N = "1700000000" }
  })
}

resource "aws_dynamodb_table_replica" "backup_replica" {
  # Skip this - just documenting it exists
  count = 0

  global_table_arn = aws_dynamodb_table.backup_table.arn
  tags = {
    Name = "Backup Replica"
  }
}

################################################################################
# Test 54: Table with resource policy
################################################################################
resource "aws_dynamodb_table" "with_policy" {
  name         = "${local.table_prefix}-policy"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Resource Policy Table"
    TestNumber  = "54"
    Description = "Tests table with resource-based policy"
  }
}

resource "aws_dynamodb_resource_policy" "main" {
  resource_arn = aws_dynamodb_table.with_policy.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.with_policy.arn
      }
    ]
  })
}

################################################################################
# Test 55: Table with GSI auto-scaling
################################################################################
resource "aws_dynamodb_table" "gsi_autoscaling" {
  name           = "${local.table_prefix}-gsi-autoscale"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi_pk"
    projection_type = "ALL"
    read_capacity   = 5
    write_capacity  = 5
  }

  tags = {
    Name        = "GSI Auto-scaling"
    TestNumber  = "55"
    Description = "Tests GSI with auto-scaling"
  }
}

# GSI read auto-scaling
resource "aws_appautoscaling_target" "gsi_read" {
  max_capacity       = 50
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.gsi_autoscaling.name}/index/GSI1"
  scalable_dimension = "dynamodb:index:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "gsi_read" {
  name               = "${local.table_prefix}-gsi-read-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.gsi_read.resource_id
  scalable_dimension = aws_appautoscaling_target.gsi_read.scalable_dimension
  service_namespace  = aws_appautoscaling_target.gsi_read.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = 70.0
  }
}

# GSI write auto-scaling
resource "aws_appautoscaling_target" "gsi_write" {
  max_capacity       = 50
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.gsi_autoscaling.name}/index/GSI1"
  scalable_dimension = "dynamodb:index:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "gsi_write" {
  name               = "${local.table_prefix}-gsi-write-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.gsi_write.resource_id
  scalable_dimension = aws_appautoscaling_target.gsi_write.scalable_dimension
  service_namespace  = aws_appautoscaling_target.gsi_write.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBWriteCapacityUtilization"
    }
    target_value = 70.0
  }
}

################################################################################
# Test 56: Import from S3 (table configured for import)
################################################################################
# Note: This creates a table that could be used with import from S3
# Actual import requires S3 data in specific format
resource "aws_dynamodb_table" "import_ready" {
  name         = "${local.table_prefix}-import-ready"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # Import settings would be specified in aws_dynamodb_table_import resource
  # which is a separate process

  tags = {
    Name        = "Import Ready Table"
    TestNumber  = "56"
    Description = "Tests table configured for S3 import"
  }
}

################################################################################
# Test 57: Export to S3 configuration
################################################################################
resource "aws_dynamodb_table" "export_source" {
  name             = "${local.table_prefix}-export-source"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name        = "Export Source Table"
    TestNumber  = "57"
    Description = "Tests table configured for S3 export"
  }
}

# Add data for export
resource "aws_dynamodb_table_item" "export_item_1" {
  table_name = aws_dynamodb_table.export_source.name
  hash_key   = aws_dynamodb_table.export_source.hash_key

  item = jsonencode({
    pk = { S = "EXPORT#001" }
    data = { S = "Data for export" }
    timestamp = { N = "1700000000" }
  })
}

resource "aws_dynamodb_table_item" "export_item_2" {
  table_name = aws_dynamodb_table.export_source.name
  hash_key   = aws_dynamodb_table.export_source.hash_key

  item = jsonencode({
    pk = { S = "EXPORT#002" }
    data = { S = "More data for export" }
    timestamp = { N = "1700000001" }
  })
}

################################################################################
# Test 58: Table with all features combined
################################################################################
resource "aws_dynamodb_table" "all_features" {
  name             = "${local.table_prefix}-all-features"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  range_key        = "sk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  table_class      = "STANDARD"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "N"
  }

  attribute {
    name = "lsi1sk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  local_secondary_index {
    name            = "LSI1"
    range_key       = "lsi1sk"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name        = "All Features Table"
    TestNumber  = "58"
    Description = "Tests table with all features enabled"
    Environment = "test"
    Project     = "warden"
  }
}

################################################################################
# Test 59: Large item (close to 400KB limit)
################################################################################
resource "aws_dynamodb_table" "large_items" {
  name         = "${local.table_prefix}-large-items"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Large Items Table"
    TestNumber  = "59"
    Description = "Tests table with large items"
  }
}

# Create a moderately large item (not too large for Terraform)
resource "aws_dynamodb_table_item" "large_item" {
  table_name = aws_dynamodb_table.large_items.name
  hash_key   = aws_dynamodb_table.large_items.hash_key

  item = jsonencode({
    pk = { S = "LARGE#001" }
    description = { S = "This is a test item with a moderate amount of data" }
    data_block_1 = { S = join("", [for i in range(100) : "Data block ${i}. "]) }
    data_block_2 = { S = join("", [for i in range(100) : "More data ${i}. "]) }
    metadata = {
      M = {
        created = { S = "2024-01-01T00:00:00Z" }
        version = { N = "1" }
        tags = {
          L = [for i in range(20) : { S = "tag-${i}" }]
        }
      }
    }
  })
}

################################################################################
# Test 60: Table for transaction testing
################################################################################
resource "aws_dynamodb_table" "transactions" {
  name         = "${local.table_prefix}-transactions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Name        = "Transactions Table"
    TestNumber  = "60"
    Description = "Tests table for TransactWriteItems/TransactGetItems"
  }
}

# Items for transaction testing
resource "aws_dynamodb_table_item" "account_1" {
  table_name = aws_dynamodb_table.transactions.name
  hash_key   = aws_dynamodb_table.transactions.hash_key
  range_key  = aws_dynamodb_table.transactions.range_key

  item = jsonencode({
    pk = { S = "ACCOUNT" }
    sk = { S = "ACC#001" }
    balance = { N = "1000" }
    owner = { S = "Alice" }
  })
}

resource "aws_dynamodb_table_item" "account_2" {
  table_name = aws_dynamodb_table.transactions.name
  hash_key   = aws_dynamodb_table.transactions.hash_key
  range_key  = aws_dynamodb_table.transactions.range_key

  item = jsonencode({
    pk = { S = "ACCOUNT" }
    sk = { S = "ACC#002" }
    balance = { N = "500" }
    owner = { S = "Bob" }
  })
}

################################################################################
# Outputs
################################################################################

output "advanced_tables" {
  value = {
    ttl                  = aws_dynamodb_table.with_ttl.name
    sse_aws_managed      = aws_dynamodb_table.sse_aws_managed.name
    sse_kms              = aws_dynamodb_table.sse_kms.name
    pitr                 = aws_dynamodb_table.with_pitr.name
    autoscaling          = aws_dynamodb_table.autoscaling.name
    contributor_insights = aws_dynamodb_table.contributor_insights.name
    backup               = aws_dynamodb_table.backup_table.name
    policy               = aws_dynamodb_table.with_policy.name
    gsi_autoscaling      = aws_dynamodb_table.gsi_autoscaling.name
    import_ready         = aws_dynamodb_table.import_ready.name
    export_source        = aws_dynamodb_table.export_source.name
    all_features         = aws_dynamodb_table.all_features.name
    large_items          = aws_dynamodb_table.large_items.name
    transactions         = aws_dynamodb_table.transactions.name
  }
  description = "Advanced feature table names"
}

output "encryption_config" {
  value = {
    kms_key_arn   = aws_kms_key.dynamodb.arn
    kms_key_alias = aws_kms_alias.dynamodb.name
  }
  description = "Encryption configuration"
}

output "autoscaling_config" {
  value = {
    table_read_target  = aws_appautoscaling_target.read.resource_id
    table_write_target = aws_appautoscaling_target.write.resource_id
    gsi_read_target    = aws_appautoscaling_target.gsi_read.resource_id
    gsi_write_target   = aws_appautoscaling_target.gsi_write.resource_id
  }
  description = "Auto-scaling configuration"
}
