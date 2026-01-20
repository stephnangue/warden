# test-05-global-tables.tf
# Tests 43-46: DynamoDB Global Tables (Multi-Region)
# Tests: Global table creation, replica management, cross-region replication

################################################################################
# Test 43: Global Table with 2 regions (Version 2019.11.21)
################################################################################
resource "aws_dynamodb_table" "global_v2" {
  name             = "${local.table_prefix}-global-v2"
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

  # Replica in us-west-2
  replica {
    region_name = "us-west-2"
  }

  tags = {
    Name        = "Global Table V2"
    TestNumber  = "43"
    Description = "Tests Global Table with 2 regions"
  }
}

################################################################################
# Test 44: Global Table with GSI
################################################################################
resource "aws_dynamodb_table" "global_with_gsi" {
  name             = "${local.table_prefix}-global-gsi"
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

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    projection_type = "ALL"
  }

  replica {
    region_name = "us-west-2"
  }

  tags = {
    Name        = "Global Table with GSI"
    TestNumber  = "44"
    Description = "Tests Global Table with GSI replicated across regions"
  }
}

################################################################################
# Test 45: Global Table with point-in-time recovery per replica
################################################################################
resource "aws_dynamodb_table" "global_with_pitr" {
  name             = "${local.table_prefix}-global-pitr"
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

  replica {
    region_name            = "us-west-2"
    point_in_time_recovery = true
  }

  tags = {
    Name        = "Global Table with PITR"
    TestNumber  = "45"
    Description = "Tests Global Table with point-in-time recovery"
  }
}

################################################################################
# Test 46: Global Table with KMS encryption per replica
################################################################################

# KMS key for primary region
resource "aws_kms_key" "dynamodb_primary" {
  description             = "KMS key for DynamoDB Global Table - Primary"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "DynamoDB Global Table Key - Primary"
    TestNumber  = "46"
    Description = "KMS key for Global Table primary region"
  }
}

resource "aws_kms_alias" "dynamodb_primary" {
  name          = "alias/${local.table_prefix}-global-key-primary"
  target_key_id = aws_kms_key.dynamodb_primary.key_id
}

# KMS key for replica region
resource "aws_kms_key" "dynamodb_replica" {
  provider = aws.us_west_2

  description             = "KMS key for DynamoDB Global Table - Replica"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "DynamoDB Global Table Key - Replica"
    TestNumber  = "46"
    Description = "KMS key for Global Table replica region"
  }
}

resource "aws_kms_alias" "dynamodb_replica" {
  provider = aws.us_west_2

  name          = "alias/${local.table_prefix}-global-key-replica"
  target_key_id = aws_kms_key.dynamodb_replica.key_id
}

resource "aws_dynamodb_table" "global_with_kms" {
  name             = "${local.table_prefix}-global-kms"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_primary.arn
  }

  replica {
    region_name = "us-west-2"
    kms_key_arn = aws_kms_key.dynamodb_replica.arn
  }

  tags = {
    Name        = "Global Table with KMS"
    TestNumber  = "46"
    Description = "Tests Global Table with KMS encryption per replica"
  }
}

################################################################################
# Test items for global table replication
################################################################################
resource "aws_dynamodb_table_item" "global_item_1" {
  table_name = aws_dynamodb_table.global_v2.name
  hash_key   = aws_dynamodb_table.global_v2.hash_key
  range_key  = aws_dynamodb_table.global_v2.range_key

  item = jsonencode({
    pk = { S = "GLOBAL#001" }
    sk = { S = "ITEM#1" }
    region = { S = "us-east-1" }
    message = { S = "Created in primary region" }
    timestamp = { N = "1700000000" }
  })
}

resource "aws_dynamodb_table_item" "global_item_2" {
  table_name = aws_dynamodb_table.global_v2.name
  hash_key   = aws_dynamodb_table.global_v2.hash_key
  range_key  = aws_dynamodb_table.global_v2.range_key

  item = jsonencode({
    pk = { S = "GLOBAL#001" }
    sk = { S = "ITEM#2" }
    region = { S = "us-east-1" }
    message = { S = "Another item in primary region" }
    timestamp = { N = "1700000001" }
  })
}

################################################################################
# Outputs
################################################################################

output "global_tables" {
  value = {
    global_v2       = aws_dynamodb_table.global_v2.name
    global_with_gsi = aws_dynamodb_table.global_with_gsi.name
    global_with_pitr = aws_dynamodb_table.global_with_pitr.name
    global_with_kms = aws_dynamodb_table.global_with_kms.name
  }
  description = "Global table names"
}

output "global_table_arns" {
  value = {
    global_v2       = aws_dynamodb_table.global_v2.arn
    global_with_gsi = aws_dynamodb_table.global_with_gsi.arn
    global_with_pitr = aws_dynamodb_table.global_with_pitr.arn
    global_with_kms = aws_dynamodb_table.global_with_kms.arn
  }
  description = "Global table ARNs"
}

output "global_table_replicas" {
  value = {
    global_v2_replicas       = aws_dynamodb_table.global_v2.replica
    global_with_gsi_replicas = aws_dynamodb_table.global_with_gsi.replica
  }
  description = "Global table replica configurations"
}

output "kms_keys" {
  value = {
    primary_key_arn = aws_kms_key.dynamodb_primary.arn
    replica_key_arn = aws_kms_key.dynamodb_replica.arn
  }
  description = "KMS key ARNs for global table encryption"
}
