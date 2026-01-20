# test-03-items.tf
# Tests 25-36: DynamoDB Item CRUD operations
# Tests: PutItem, GetItem, UpdateItem, DeleteItem, BatchWrite, Query, Scan

################################################################################
# Table for item CRUD operations
################################################################################
resource "aws_dynamodb_table" "items_crud" {
  name         = "${local.table_prefix}-items-crud"
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

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "Items CRUD Table"
    TestNumber  = "25-36"
    Description = "Table for testing item CRUD operations"
  }
}

################################################################################
# Test 25: Simple item with String attributes
################################################################################
resource "aws_dynamodb_table_item" "simple_string" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#001" }
    sk = { S = "PROFILE" }
    name = { S = "John Doe" }
    email = { S = "john.doe@example.com" }
    status = { S = "active" }
  })
}

################################################################################
# Test 26: Item with Number attributes
################################################################################
resource "aws_dynamodb_table_item" "with_numbers" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#002" }
    sk = { S = "STATS" }
    age = { N = "30" }
    score = { N = "99.5" }
    visits = { N = "1000" }
    balance = { N = "-50.25" }
  })
}

################################################################################
# Test 27: Item with Boolean attributes
################################################################################
resource "aws_dynamodb_table_item" "with_booleans" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#003" }
    sk = { S = "SETTINGS" }
    email_verified = { BOOL = true }
    notifications_enabled = { BOOL = false }
    is_premium = { BOOL = true }
  })
}

################################################################################
# Test 28: Item with List (L) attribute
################################################################################
resource "aws_dynamodb_table_item" "with_list" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#004" }
    sk = { S = "TAGS" }
    tags = {
      L = [
        { S = "developer" },
        { S = "admin" },
        { S = "premium" }
      ]
    }
    scores = {
      L = [
        { N = "95" },
        { N = "88" },
        { N = "92" }
      ]
    }
  })
}

################################################################################
# Test 29: Item with Map (M) attribute
################################################################################
resource "aws_dynamodb_table_item" "with_map" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#005" }
    sk = { S = "ADDRESS" }
    address = {
      M = {
        street = { S = "123 Main St" }
        city = { S = "New York" }
        state = { S = "NY" }
        zip = { S = "10001" }
        country = { S = "USA" }
      }
    }
  })
}

################################################################################
# Test 30: Item with nested Map and List
################################################################################
resource "aws_dynamodb_table_item" "nested_complex" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "ORDER#001" }
    sk = { S = "DETAILS" }
    order = {
      M = {
        id = { S = "ORD-12345" }
        total = { N = "299.99" }
        items = {
          L = [
            {
              M = {
                product_id = { S = "PROD-001" }
                name = { S = "Widget" }
                quantity = { N = "2" }
                price = { N = "99.99" }
              }
            },
            {
              M = {
                product_id = { S = "PROD-002" }
                name = { S = "Gadget" }
                quantity = { N = "1" }
                price = { N = "100.01" }
              }
            }
          ]
        }
        shipping = {
          M = {
            address = { S = "456 Oak Ave" }
            method = { S = "express" }
          }
        }
      }
    }
  })
}

################################################################################
# Test 31: Item with String Set (SS) attribute
################################################################################
resource "aws_dynamodb_table_item" "with_string_set" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#006" }
    sk = { S = "PERMISSIONS" }
    roles = {
      SS = ["admin", "editor", "viewer"]
    }
    allowed_actions = {
      SS = ["read", "write", "delete"]
    }
  })
}

################################################################################
# Test 32: Item with Number Set (NS) attribute
################################################################################
resource "aws_dynamodb_table_item" "with_number_set" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#007" }
    sk = { S = "SCORES" }
    high_scores = {
      NS = ["100", "95", "88", "92"]
    }
    lucky_numbers = {
      NS = ["7", "21", "42"]
    }
  })
}

################################################################################
# Test 33: Item with NULL attribute
################################################################################
resource "aws_dynamodb_table_item" "with_null" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#008" }
    sk = { S = "OPTIONAL" }
    name = { S = "Jane Smith" }
    middle_name = { NULL = true }
    nickname = { NULL = true }
    bio = { S = "Software engineer" }
  })
}

################################################################################
# Test 34: Item with GSI attributes
################################################################################
resource "aws_dynamodb_table_item" "with_gsi" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#009" }
    sk = { S = "PROFILE" }
    gsi1pk = { S = "EMAIL#alice@example.com" }
    gsi1sk = { N = "1640000000" }
    name = { S = "Alice Johnson" }
    email = { S = "alice@example.com" }
    created_at = { N = "1640000000" }
  })
}

################################################################################
# Test 35: Item with special characters in values
################################################################################
resource "aws_dynamodb_table_item" "special_chars" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "USER#010" }
    sk = { S = "SPECIAL" }
    description = { S = "Contains special chars: @#$%^&*(){}[]|\\:;\"'<>,.?/" }
    unicode = { S = "Unicode: café, 日本語, émojis: 🎉🚀" }
    newlines = { S = "Line 1\nLine 2\nLine 3" }
    tabs = { S = "Col1\tCol2\tCol3" }
  })
}

################################################################################
# Test 36: Multiple items for batch operations testing
################################################################################
resource "aws_dynamodb_table_item" "batch_item_1" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "BATCH#001" }
    sk = { S = "ITEM#1" }
    data = { S = "First batch item" }
    index = { N = "1" }
  })
}

resource "aws_dynamodb_table_item" "batch_item_2" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "BATCH#001" }
    sk = { S = "ITEM#2" }
    data = { S = "Second batch item" }
    index = { N = "2" }
  })
}

resource "aws_dynamodb_table_item" "batch_item_3" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "BATCH#001" }
    sk = { S = "ITEM#3" }
    data = { S = "Third batch item" }
    index = { N = "3" }
  })
}

resource "aws_dynamodb_table_item" "batch_item_4" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "BATCH#001" }
    sk = { S = "ITEM#4" }
    data = { S = "Fourth batch item" }
    index = { N = "4" }
  })
}

resource "aws_dynamodb_table_item" "batch_item_5" {
  table_name = aws_dynamodb_table.items_crud.name
  hash_key   = aws_dynamodb_table.items_crud.hash_key
  range_key  = aws_dynamodb_table.items_crud.range_key

  item = jsonencode({
    pk = { S = "BATCH#001" }
    sk = { S = "ITEM#5" }
    data = { S = "Fifth batch item" }
    index = { N = "5" }
  })
}

################################################################################
# Outputs
################################################################################

output "items_crud_table" {
  value       = aws_dynamodb_table.items_crud.name
  description = "Items CRUD table name"
}

output "items_crud_table_arn" {
  value       = aws_dynamodb_table.items_crud.arn
  description = "Items CRUD table ARN"
}

output "sample_item_keys" {
  value = {
    simple_string = {
      pk = "USER#001"
      sk = "PROFILE"
    }
    with_numbers = {
      pk = "USER#002"
      sk = "STATS"
    }
    nested_complex = {
      pk = "ORDER#001"
      sk = "DETAILS"
    }
    batch_partition = {
      pk = "BATCH#001"
    }
  }
  description = "Sample item keys for testing queries"
}
