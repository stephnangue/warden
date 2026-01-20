# test-02-indexes.tf
# Tests 13-24: Global Secondary Indexes (GSI) and Local Secondary Indexes (LSI)
# Tests: index configurations, projections, capacity settings

################################################################################
# Test 13: Table with single GSI - ALL projection
################################################################################
resource "aws_dynamodb_table" "gsi_all" {
  name         = "${local.table_prefix}-gsi-all"
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

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI-All"
    hash_key        = "gsi_pk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "GSI ALL Projection"
    TestNumber  = "13"
    Description = "Tests GSI with ALL projection type"
  }
}

################################################################################
# Test 14: Table with GSI - KEYS_ONLY projection
################################################################################
resource "aws_dynamodb_table" "gsi_keys_only" {
  name         = "${local.table_prefix}-gsi-keys-only"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI-KeysOnly"
    hash_key        = "gsi_pk"
    projection_type = "KEYS_ONLY"
  }

  tags = {
    Name        = "GSI KEYS_ONLY Projection"
    TestNumber  = "14"
    Description = "Tests GSI with KEYS_ONLY projection type"
  }
}

################################################################################
# Test 15: Table with GSI - INCLUDE projection
################################################################################
resource "aws_dynamodb_table" "gsi_include" {
  name         = "${local.table_prefix}-gsi-include"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  global_secondary_index {
    name               = "GSI-Include"
    hash_key           = "gsi_pk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["email", "name", "status"]
  }

  tags = {
    Name        = "GSI INCLUDE Projection"
    TestNumber  = "15"
    Description = "Tests GSI with INCLUDE projection type"
  }
}

################################################################################
# Test 16: Table with GSI - partition key and sort key
################################################################################
resource "aws_dynamodb_table" "gsi_pk_sk" {
  name         = "${local.table_prefix}-gsi-pk-sk"
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

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  attribute {
    name = "gsi_sk"
    type = "N"
  }

  global_secondary_index {
    name            = "GSI-PKSK"
    hash_key        = "gsi_pk"
    range_key       = "gsi_sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "GSI with PK and SK"
    TestNumber  = "16"
    Description = "Tests GSI with partition key and sort key"
  }
}

################################################################################
# Test 17: Table with multiple GSIs (max 20)
################################################################################
resource "aws_dynamodb_table" "multi_gsi" {
  name         = "${local.table_prefix}-multi-gsi"
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

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi2pk"
    type = "S"
  }

  attribute {
    name = "gsi3pk"
    type = "S"
  }

  attribute {
    name = "gsi4pk"
    type = "N"
  }

  attribute {
    name = "gsi5pk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI2"
    hash_key        = "gsi2pk"
    projection_type = "KEYS_ONLY"
  }

  global_secondary_index {
    name               = "GSI3"
    hash_key           = "gsi3pk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["data"]
  }

  global_secondary_index {
    name            = "GSI4"
    hash_key        = "gsi4pk"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI5"
    hash_key        = "gsi5pk"
    range_key       = "sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "Multiple GSIs"
    TestNumber  = "17"
    Description = "Tests table with 5 GSIs"
  }
}

################################################################################
# Test 18: Table with GSI - provisioned capacity
################################################################################
resource "aws_dynamodb_table" "gsi_provisioned" {
  name           = "${local.table_prefix}-gsi-provisioned"
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
    name            = "GSI-Provisioned"
    hash_key        = "gsi_pk"
    projection_type = "ALL"
    read_capacity   = 10
    write_capacity  = 5
  }

  tags = {
    Name        = "GSI Provisioned Capacity"
    TestNumber  = "18"
    Description = "Tests GSI with provisioned capacity"
  }
}

################################################################################
# Test 19: Table with single LSI - ALL projection
################################################################################
resource "aws_dynamodb_table" "lsi_all" {
  name         = "${local.table_prefix}-lsi-all"
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

  attribute {
    name = "lsi_sk"
    type = "S"
  }

  local_secondary_index {
    name            = "LSI-All"
    range_key       = "lsi_sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "LSI ALL Projection"
    TestNumber  = "19"
    Description = "Tests LSI with ALL projection type"
  }
}

################################################################################
# Test 20: Table with LSI - KEYS_ONLY projection
################################################################################
resource "aws_dynamodb_table" "lsi_keys_only" {
  name         = "${local.table_prefix}-lsi-keys-only"
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

  attribute {
    name = "lsi_sk"
    type = "N"
  }

  local_secondary_index {
    name            = "LSI-KeysOnly"
    range_key       = "lsi_sk"
    projection_type = "KEYS_ONLY"
  }

  tags = {
    Name        = "LSI KEYS_ONLY Projection"
    TestNumber  = "20"
    Description = "Tests LSI with KEYS_ONLY projection type"
  }
}

################################################################################
# Test 21: Table with LSI - INCLUDE projection
################################################################################
resource "aws_dynamodb_table" "lsi_include" {
  name         = "${local.table_prefix}-lsi-include"
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

  attribute {
    name = "lsi_sk"
    type = "S"
  }

  local_secondary_index {
    name               = "LSI-Include"
    range_key          = "lsi_sk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["email", "status", "created_at"]
  }

  tags = {
    Name        = "LSI INCLUDE Projection"
    TestNumber  = "21"
    Description = "Tests LSI with INCLUDE projection type"
  }
}

################################################################################
# Test 22: Table with multiple LSIs (max 5)
################################################################################
resource "aws_dynamodb_table" "multi_lsi" {
  name         = "${local.table_prefix}-multi-lsi"
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

  attribute {
    name = "lsi1sk"
    type = "S"
  }

  attribute {
    name = "lsi2sk"
    type = "N"
  }

  attribute {
    name = "lsi3sk"
    type = "S"
  }

  attribute {
    name = "lsi4sk"
    type = "N"
  }

  attribute {
    name = "lsi5sk"
    type = "S"
  }

  local_secondary_index {
    name            = "LSI1"
    range_key       = "lsi1sk"
    projection_type = "ALL"
  }

  local_secondary_index {
    name            = "LSI2"
    range_key       = "lsi2sk"
    projection_type = "KEYS_ONLY"
  }

  local_secondary_index {
    name               = "LSI3"
    range_key          = "lsi3sk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["data"]
  }

  local_secondary_index {
    name            = "LSI4"
    range_key       = "lsi4sk"
    projection_type = "ALL"
  }

  local_secondary_index {
    name            = "LSI5"
    range_key       = "lsi5sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "Multiple LSIs"
    TestNumber  = "22"
    Description = "Tests table with 5 LSIs - max allowed"
  }
}

################################################################################
# Test 23: Table with both GSI and LSI
################################################################################
resource "aws_dynamodb_table" "gsi_lsi_combined" {
  name         = "${local.table_prefix}-gsi-lsi-combined"
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

  attribute {
    name = "gsi_pk"
    type = "S"
  }

  attribute {
    name = "gsi_sk"
    type = "N"
  }

  attribute {
    name = "lsi_sk"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi_pk"
    range_key       = "gsi_sk"
    projection_type = "ALL"
  }

  local_secondary_index {
    name            = "LSI1"
    range_key       = "lsi_sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "GSI + LSI Combined"
    TestNumber  = "23"
    Description = "Tests table with both GSI and LSI"
  }
}

################################################################################
# Test 24: Table with GSI using different key types
################################################################################
resource "aws_dynamodb_table" "gsi_mixed_types" {
  name         = "${local.table_prefix}-gsi-mixed-types"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "N"
  }

  attribute {
    name = "gsi_string_pk"
    type = "S"
  }

  attribute {
    name = "gsi_number_pk"
    type = "N"
  }

  attribute {
    name = "gsi_binary_pk"
    type = "B"
  }

  global_secondary_index {
    name            = "GSI-String"
    hash_key        = "gsi_string_pk"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI-Number"
    hash_key        = "gsi_number_pk"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "GSI-Binary"
    hash_key        = "gsi_binary_pk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "GSI Mixed Key Types"
    TestNumber  = "24"
    Description = "Tests GSIs with different key types String Number Binary"
  }
}

################################################################################
# Outputs
################################################################################

output "index_tables" {
  value = {
    gsi_all        = aws_dynamodb_table.gsi_all.name
    gsi_keys_only  = aws_dynamodb_table.gsi_keys_only.name
    gsi_include    = aws_dynamodb_table.gsi_include.name
    gsi_pk_sk      = aws_dynamodb_table.gsi_pk_sk.name
    multi_gsi      = aws_dynamodb_table.multi_gsi.name
    gsi_provisioned = aws_dynamodb_table.gsi_provisioned.name
    lsi_all        = aws_dynamodb_table.lsi_all.name
    lsi_keys_only  = aws_dynamodb_table.lsi_keys_only.name
    lsi_include    = aws_dynamodb_table.lsi_include.name
    multi_lsi      = aws_dynamodb_table.multi_lsi.name
    gsi_lsi_combined = aws_dynamodb_table.gsi_lsi_combined.name
    gsi_mixed_types = aws_dynamodb_table.gsi_mixed_types.name
  }
  description = "Index test table names"
}

output "gsi_arns" {
  value = {
    gsi_all_index   = "${aws_dynamodb_table.gsi_all.arn}/index/GSI-All"
    multi_gsi_index = "${aws_dynamodb_table.multi_gsi.arn}/index/GSI1"
  }
  description = "GSI ARNs for testing"
}
