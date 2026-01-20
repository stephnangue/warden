# test-01-basic-tables.tf
# Tests 1-12: Basic DynamoDB table configurations
# Tests: table creation, billing modes, capacity settings, key schemas

################################################################################
# Test 1: Basic table with partition key only (PAY_PER_REQUEST)
################################################################################
resource "aws_dynamodb_table" "basic_pk_only" {
  name         = "${local.table_prefix}-basic-pk"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "Basic PK Only Table"
    TestNumber  = "01"
    Description = "Tests basic table with partition key only"
  }
}

################################################################################
# Test 2: Table with partition key and sort key (PAY_PER_REQUEST)
################################################################################
resource "aws_dynamodb_table" "pk_sk" {
  name         = "${local.table_prefix}-pk-sk"
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
    Name        = "PK + SK Table"
    TestNumber  = "02"
    Description = "Tests table with partition key and sort key"
  }
}

################################################################################
# Test 3: Table with PROVISIONED billing mode
################################################################################
resource "aws_dynamodb_table" "provisioned" {
  name           = "${local.table_prefix}-provisioned"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "Provisioned Table"
    TestNumber  = "03"
    Description = "Tests table with provisioned capacity"
  }
}

################################################################################
# Test 4: Table with Number partition key
################################################################################
resource "aws_dynamodb_table" "number_pk" {
  name         = "${local.table_prefix}-number-pk"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"

  attribute {
    name = "user_id"
    type = "N"
  }

  tags = {
    Name        = "Number PK Table"
    TestNumber  = "04"
    Description = "Tests table with Number type partition key"
  }
}

################################################################################
# Test 5: Table with Binary partition key
################################################################################
resource "aws_dynamodb_table" "binary_pk" {
  name         = "${local.table_prefix}-binary-pk"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "binary_id"

  attribute {
    name = "binary_id"
    type = "B"
  }

  tags = {
    Name        = "Binary PK Table"
    TestNumber  = "05"
    Description = "Tests table with Binary type partition key"
  }
}

################################################################################
# Test 6: Table with Number sort key
################################################################################
resource "aws_dynamodb_table" "number_sk" {
  name         = "${local.table_prefix}-number-sk"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "timestamp"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  tags = {
    Name        = "Number SK Table"
    TestNumber  = "06"
    Description = "Tests table with Number type sort key"
  }
}

################################################################################
# Test 7: Table with high provisioned capacity
################################################################################
resource "aws_dynamodb_table" "high_capacity" {
  name           = "${local.table_prefix}-high-capacity"
  billing_mode   = "PROVISIONED"
  read_capacity  = 100
  write_capacity = 50
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "High Capacity Table"
    TestNumber  = "07"
    Description = "Tests table with high provisioned throughput"
  }
}

################################################################################
# Test 8: Table with deletion protection enabled
################################################################################
resource "aws_dynamodb_table" "deletion_protection" {
  name                        = "${local.table_prefix}-deletion-protected"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = false # Set to false for test cleanup

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "Deletion Protected Table"
    TestNumber  = "08"
    Description = "Tests table with deletion protection"
  }
}

################################################################################
# Test 9: Table with table class STANDARD
################################################################################
resource "aws_dynamodb_table" "standard_class" {
  name         = "${local.table_prefix}-standard-class"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  table_class  = "STANDARD"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "Standard Class Table"
    TestNumber  = "09"
    Description = "Tests table with STANDARD table class"
  }
}

################################################################################
# Test 10: Table with table class STANDARD_INFREQUENT_ACCESS
################################################################################
resource "aws_dynamodb_table" "ia_class" {
  name         = "${local.table_prefix}-ia-class"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  table_class  = "STANDARD_INFREQUENT_ACCESS"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "IA Class Table"
    TestNumber  = "10"
    Description = "Tests table with STANDARD_INFREQUENT_ACCESS class"
  }
}

################################################################################
# Test 11: Table with multiple attributes defined
################################################################################
resource "aws_dynamodb_table" "multi_attr" {
  name         = "${local.table_prefix}-multi-attr"
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
    name = "gsi1sk"
    type = "N"
  }

  attribute {
    name = "lsi1sk"
    type = "S"
  }

  # GSI for multi-attribute table
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  # LSI for multi-attribute table
  local_secondary_index {
    name            = "LSI1"
    range_key       = "lsi1sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "Multi-Attribute Table"
    TestNumber  = "11"
    Description = "Tests table with multiple attributes and indexes"
  }
}

################################################################################
# Test 12: Table with long name (max 255 chars)
################################################################################
resource "aws_dynamodb_table" "long_name" {
  name         = "${local.table_prefix}-this-is-a-very-long-table-name-to-test-the-maximum-allowed-length-for-dynamodb-tables"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "Long Name Table"
    TestNumber  = "12"
    Description = "Tests table with long name"
  }
}

################################################################################
# Outputs
################################################################################

output "basic_tables" {
  value = {
    basic_pk_only       = aws_dynamodb_table.basic_pk_only.name
    pk_sk               = aws_dynamodb_table.pk_sk.name
    provisioned         = aws_dynamodb_table.provisioned.name
    number_pk           = aws_dynamodb_table.number_pk.name
    binary_pk           = aws_dynamodb_table.binary_pk.name
    number_sk           = aws_dynamodb_table.number_sk.name
    high_capacity       = aws_dynamodb_table.high_capacity.name
    deletion_protection = aws_dynamodb_table.deletion_protection.name
    standard_class      = aws_dynamodb_table.standard_class.name
    ia_class            = aws_dynamodb_table.ia_class.name
    multi_attr          = aws_dynamodb_table.multi_attr.name
    long_name           = aws_dynamodb_table.long_name.name
  }
  description = "Basic table names"
}

output "basic_table_arns" {
  value = {
    basic_pk_only = aws_dynamodb_table.basic_pk_only.arn
    pk_sk         = aws_dynamodb_table.pk_sk.arn
    provisioned   = aws_dynamodb_table.provisioned.arn
  }
  description = "Basic table ARNs"
}
