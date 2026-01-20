# test-07-edge-cases.tf
# Tests 61-80: DynamoDB Edge Cases
# Tests: Special characters, reserved words, boundary conditions, encoding edge cases

################################################################################
# Edge Case Table for testing special scenarios
################################################################################
resource "aws_dynamodb_table" "edge_cases" {
  name         = "${local.table_prefix}-edge-cases"
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
    Name        = "Edge Cases Table"
    TestNumber  = "61-80"
    Description = "Table for testing DynamoDB edge cases"
  }
}

################################################################################
# Test 61: Item with DynamoDB reserved words as attribute names
################################################################################
resource "aws_dynamodb_table_item" "reserved_words" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  # These are DynamoDB reserved words that require expression attribute names
  item = jsonencode({
    pk = { S = "RESERVED#001" }
    sk = { S = "WORDS" }
    # Reserved words: name, status, data, count, size, type, value, key, index
    name = { S = "John Doe" }
    status = { S = "active" }
    data = { S = "test data" }
    count = { N = "42" }
    size = { N = "1024" }
    type = { S = "user" }
    value = { S = "important" }
    index = { N = "0" }
    year = { N = "2024" }
    month = { N = "12" }
    day = { N = "25" }
    time = { S = "12:00:00" }
    timestamp = { N = "1700000000" }
    comment = { S = "This is a comment" }
  })
}

################################################################################
# Test 62: Item with Unicode characters in keys and values
################################################################################
resource "aws_dynamodb_table_item" "unicode" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "UNICODE#日本語" }
    sk = { S = "中文#한국어" }
    japanese = { S = "これはテストです" }
    chinese = { S = "这是一个测试" }
    korean = { S = "이것은 테스트입니다" }
    arabic = { S = "هذا اختبار" }
    russian = { S = "Это тест" }
    emoji = { S = "🎉🚀💡🔥❤️" }
    mixed = { S = "Hello世界مرحبا🌍" }
    accented = { S = "Café résumé naïve" }
  })
}

################################################################################
# Test 63: Item with special characters in string values
################################################################################
resource "aws_dynamodb_table_item" "special_chars" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "SPECIAL#001" }
    sk = { S = "CHARS" }
    brackets = { S = "{}[]()<>" }
    quotes = { S = "Single' Double\" Backtick`" }
    slashes = { S = "Forward/ Back\\ Pipe|" }
    symbols = { S = "@#$%^&*+=~" }
    punctuation = { S = "!?,.:;-_" }
    whitespace = { S = "Tab\tNewline\nCarriage\rReturn" }
    url_chars = { S = "https://example.com/path?query=value&other=123#fragment" }
    json_like = { S = "{\"key\": \"value\", \"array\": [1, 2, 3]}" }
    xml_like = { S = "<tag attr=\"value\">content</tag>" }
    sql_like = { S = "SELECT * FROM table WHERE id = 'value'; DROP TABLE--" }
  })
}

################################################################################
# Test 64: Item with very long attribute values
################################################################################
resource "aws_dynamodb_table_item" "long_values" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "LONG#001" }
    sk = { S = "VALUES" }
    # String up to 400KB per item, individual attributes can be large
    long_string = { S = join("", [for i in range(1000) : "This is repetitive text block number ${i}. "]) }
    long_number_list = {
      L = [for i in range(100) : { N = tostring(i * 1000) }]
    }
  })
}

################################################################################
# Test 65: Item with empty string values (valid in DynamoDB)
################################################################################
resource "aws_dynamodb_table_item" "empty_strings" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "EMPTY#001" }
    sk = { S = "STRINGS" }
    empty_value = { S = "" }
    whitespace_only = { S = "   " }
    single_space = { S = " " }
    newline_only = { S = "\n" }
    tab_only = { S = "\t" }
  })
}

################################################################################
# Test 66: Item with very precise numbers
################################################################################
resource "aws_dynamodb_table_item" "precise_numbers" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  # DynamoDB supports 38 digits of precision
  item = jsonencode({
    pk = { S = "NUMBERS#001" }
    sk = { S = "PRECISION" }
    max_precision = { N = "99999999999999999999999999999999999999" }
    min_precision = { N = "-99999999999999999999999999999999999999" }
    decimal_precision = { N = "0.12345678901234567890123456789012345678" }
    small_decimal = { N = "0.00000000000000000000000000000000000001" }
    negative_decimal = { N = "-123.456789012345678901234567890123456" }
    scientific_small = { N = "1E-130" }
    scientific_large = { N = "9.9999999999999999999999999999999999999E+125" }
    zero = { N = "0" }
    negative_zero = { N = "-0" }
  })
}

################################################################################
# Test 67: Item with deeply nested structures
################################################################################
resource "aws_dynamodb_table_item" "deep_nesting" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  # DynamoDB supports up to 32 levels of nesting
  item = jsonencode({
    pk = { S = "NESTED#001" }
    sk = { S = "DEEP" }
    level1 = {
      M = {
        level2 = {
          M = {
            level3 = {
              M = {
                level4 = {
                  M = {
                    level5 = {
                      M = {
                        level6 = {
                          M = {
                            level7 = {
                              M = {
                                level8 = {
                                  M = {
                                    level9 = {
                                      M = {
                                        level10 = {
                                          M = {
                                            value = { S = "10 levels deep!" }
                                            number = { N = "10" }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  })
}

################################################################################
# Test 68: Item with mixed nested lists and maps
################################################################################
resource "aws_dynamodb_table_item" "mixed_nesting" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "MIXED#001" }
    sk = { S = "NESTING" }
    complex = {
      M = {
        array_of_maps = {
          L = [
            {
              M = {
                id = { N = "1" }
                nested_array = {
                  L = [
                    { S = "a" },
                    { N = "1" },
                    { BOOL = true }
                  ]
                }
              }
            },
            {
              M = {
                id = { N = "2" }
                nested_map = {
                  M = {
                    key1 = { S = "value1" }
                    key2 = {
                      L = [
                        { S = "item1" },
                        { S = "item2" }
                      ]
                    }
                  }
                }
              }
            }
          ]
        }
        map_of_arrays = {
          M = {
            strings = {
              L = [
                { S = "a" },
                { S = "b" },
                { S = "c" }
              ]
            }
            numbers = {
              L = [
                { N = "1" },
                { N = "2" },
                { N = "3" }
              ]
            }
            booleans = {
              L = [
                { BOOL = true },
                { BOOL = false }
              ]
            }
          }
        }
      }
    }
  })
}

################################################################################
# Test 69: Item with all DynamoDB data types
################################################################################
resource "aws_dynamodb_table_item" "all_types" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "TYPES#001" }
    sk = { S = "ALL" }
    # String (S)
    string_attr = { S = "Hello World" }
    # Number (N)
    number_attr = { N = "12345.6789" }
    # Binary (B) - base64 encoded
    binary_attr = { B = "SGVsbG8gV29ybGQh" }
    # Boolean (BOOL)
    bool_true = { BOOL = true }
    bool_false = { BOOL = false }
    # Null (NULL)
    null_attr = { NULL = true }
    # List (L)
    list_attr = {
      L = [
        { S = "item1" },
        { N = "42" },
        { BOOL = true }
      ]
    }
    # Map (M)
    map_attr = {
      M = {
        nested_string = { S = "nested" }
        nested_number = { N = "99" }
      }
    }
    # String Set (SS)
    string_set = { SS = ["a", "b", "c"] }
    # Number Set (NS)
    number_set = { NS = ["1", "2", "3"] }
    # Binary Set (BS) - base64 encoded values
    binary_set = { BS = ["YWJj", "ZGVm", "Z2hp"] }
  })
}

################################################################################
# Test 70: Item with boundary key lengths
################################################################################
resource "aws_dynamodb_table_item" "key_lengths" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  # Partition key max 2048 bytes, Sort key max 1024 bytes
  item = jsonencode({
    pk = { S = "KEY#${join("", [for i in range(100) : "x"])}" }
    sk = { S = "SK#${join("", [for i in range(50) : "y"])}" }
    description = { S = "Testing key length boundaries" }
  })
}

################################################################################
# Test 71: Item simulating single-table design patterns
################################################################################
resource "aws_dynamodb_table_item" "single_table_user" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "USER#user123" }
    sk = { S = "USER#user123" }
    entity_type = { S = "USER" }
    username = { S = "johndoe" }
    email = { S = "john@example.com" }
    created_at = { S = "2024-01-01T00:00:00Z" }
  })
}

resource "aws_dynamodb_table_item" "single_table_order" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "USER#user123" }
    sk = { S = "ORDER#2024-001" }
    entity_type = { S = "ORDER" }
    order_id = { S = "2024-001" }
    total = { N = "199.99" }
    status = { S = "completed" }
  })
}

resource "aws_dynamodb_table_item" "single_table_address" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "USER#user123" }
    sk = { S = "ADDRESS#home" }
    entity_type = { S = "ADDRESS" }
    street = { S = "123 Main St" }
    city = { S = "New York" }
    zip = { S = "10001" }
  })
}

################################################################################
# Test 72: Item with inverted index pattern (GSI overloading)
################################################################################
resource "aws_dynamodb_table" "gsi_overloading" {
  name         = "${local.table_prefix}-gsi-overload"
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
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "GSI Overloading"
    TestNumber  = "72"
    Description = "Tests GSI overloading pattern"
  }
}

resource "aws_dynamodb_table_item" "gsi_overload_1" {
  table_name = aws_dynamodb_table.gsi_overloading.name
  hash_key   = aws_dynamodb_table.gsi_overloading.hash_key
  range_key  = aws_dynamodb_table.gsi_overloading.range_key

  item = jsonencode({
    pk = { S = "USER#user1" }
    sk = { S = "PROFILE" }
    gsi1pk = { S = "EMAIL#john@example.com" }
    gsi1sk = { S = "USER#user1" }
    email = { S = "john@example.com" }
  })
}

resource "aws_dynamodb_table_item" "gsi_overload_2" {
  table_name = aws_dynamodb_table.gsi_overloading.name
  hash_key   = aws_dynamodb_table.gsi_overloading.hash_key
  range_key  = aws_dynamodb_table.gsi_overloading.range_key

  item = jsonencode({
    pk = { S = "ORDER#order1" }
    sk = { S = "ORDER" }
    gsi1pk = { S = "USER#user1" }
    gsi1sk = { S = "ORDER#2024-01-01T00:00:00Z" }
    order_id = { S = "order1" }
    user_id = { S = "user1" }
  })
}

################################################################################
# Test 73: Adjacency list pattern
################################################################################
resource "aws_dynamodb_table_item" "adjacency_node" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "NODE#A" }
    sk = { S = "NODE#A" }
    node_type = { S = "node" }
    label = { S = "Node A" }
  })
}

resource "aws_dynamodb_table_item" "adjacency_edge_1" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "NODE#A" }
    sk = { S = "EDGE#NODE#B" }
    node_type = { S = "edge" }
    target = { S = "NODE#B" }
    weight = { N = "1" }
  })
}

resource "aws_dynamodb_table_item" "adjacency_edge_2" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "NODE#A" }
    sk = { S = "EDGE#NODE#C" }
    node_type = { S = "edge" }
    target = { S = "NODE#C" }
    weight = { N = "2" }
  })
}

################################################################################
# Test 74: Table name with special characters (hyphens, underscores)
################################################################################
resource "aws_dynamodb_table" "special_name" {
  name         = "${local.table_prefix}-special_name-with_underscores"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Special Name Table"
    TestNumber  = "74"
    Description = "Tests table with special characters in name"
  }
}

################################################################################
# Test 75: Table with many attributes (wide item)
################################################################################
resource "aws_dynamodb_table_item" "wide_item" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode(merge(
    {
      pk = { S = "WIDE#001" }
      sk = { S = "ATTRIBUTES" }
    },
    { for i in range(50) : "attr_${format("%03d", i)}" => { S = "value_${i}" } }
  ))
}

################################################################################
# Test 76: Sparse index pattern (GSI with optional attributes)
################################################################################
resource "aws_dynamodb_table" "sparse_index" {
  name         = "${local.table_prefix}-sparse-index"
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
    name = "is_active"
    type = "S"
  }

  # Sparse GSI - only items with is_active attribute appear
  global_secondary_index {
    name            = "ActiveItems"
    hash_key        = "is_active"
    range_key       = "sk"
    projection_type = "ALL"
  }

  tags = {
    Name        = "Sparse Index Table"
    TestNumber  = "76"
    Description = "Tests sparse GSI pattern"
  }
}

# Item that appears in GSI (has is_active)
resource "aws_dynamodb_table_item" "sparse_active" {
  table_name = aws_dynamodb_table.sparse_index.name
  hash_key   = aws_dynamodb_table.sparse_index.hash_key
  range_key  = aws_dynamodb_table.sparse_index.range_key

  item = jsonencode({
    pk = { S = "USER#001" }
    sk = { S = "PROFILE" }
    is_active = { S = "true" }
    name = { S = "Active User" }
  })
}

# Item that does NOT appear in GSI (no is_active attribute)
resource "aws_dynamodb_table_item" "sparse_inactive" {
  table_name = aws_dynamodb_table.sparse_index.name
  hash_key   = aws_dynamodb_table.sparse_index.hash_key
  range_key  = aws_dynamodb_table.sparse_index.range_key

  item = jsonencode({
    pk = { S = "USER#002" }
    sk = { S = "PROFILE" }
    # No is_active attribute - will not appear in GSI
    name = { S = "Inactive User" }
  })
}

################################################################################
# Test 77: Condition expressions edge cases (table for testing)
################################################################################
resource "aws_dynamodb_table" "conditions" {
  name         = "${local.table_prefix}-conditions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "Conditions Table"
    TestNumber  = "77"
    Description = "Tests condition expressions"
  }
}

resource "aws_dynamodb_table_item" "condition_test" {
  table_name = aws_dynamodb_table.conditions.name
  hash_key   = aws_dynamodb_table.conditions.hash_key

  item = jsonencode({
    pk = { S = "CONDITION#001" }
    version = { N = "1" }
    status = { S = "pending" }
    items_count = { N = "0" }
    is_locked = { BOOL = false }
    tags = { SS = ["test", "demo"] }
  })
}

################################################################################
# Test 78: Write sharding pattern (distribute hot keys)
################################################################################
resource "aws_dynamodb_table" "write_sharding" {
  name         = "${local.table_prefix}-sharding"
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
    Name        = "Write Sharding Table"
    TestNumber  = "78"
    Description = "Tests write sharding pattern"
  }
}

# Sharded items (pk includes shard suffix)
resource "aws_dynamodb_table_item" "shard_0" {
  table_name = aws_dynamodb_table.write_sharding.name
  hash_key   = aws_dynamodb_table.write_sharding.hash_key
  range_key  = aws_dynamodb_table.write_sharding.range_key

  item = jsonencode({
    pk = { S = "COUNTER#page_views#0" }
    sk = { S = "2024-01-01" }
    count = { N = "1000" }
  })
}

resource "aws_dynamodb_table_item" "shard_1" {
  table_name = aws_dynamodb_table.write_sharding.name
  hash_key   = aws_dynamodb_table.write_sharding.hash_key
  range_key  = aws_dynamodb_table.write_sharding.range_key

  item = jsonencode({
    pk = { S = "COUNTER#page_views#1" }
    sk = { S = "2024-01-01" }
    count = { N = "1000" }
  })
}

resource "aws_dynamodb_table_item" "shard_2" {
  table_name = aws_dynamodb_table.write_sharding.name
  hash_key   = aws_dynamodb_table.write_sharding.hash_key
  range_key  = aws_dynamodb_table.write_sharding.range_key

  item = jsonencode({
    pk = { S = "COUNTER#page_views#2" }
    sk = { S = "2024-01-01" }
    count = { N = "1000" }
  })
}

################################################################################
# Test 79: Materialized aggregation pattern
################################################################################
resource "aws_dynamodb_table_item" "aggregation_detail" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "INVOICE#2024-001" }
    sk = { S = "LINE#001" }
    amount = { N = "100.00" }
    quantity = { N = "2" }
    product = { S = "Widget A" }
  })
}

resource "aws_dynamodb_table_item" "aggregation_summary" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "INVOICE#2024-001" }
    sk = { S = "SUMMARY" }
    total_amount = { N = "350.00" }
    total_lines = { N = "3" }
    status = { S = "paid" }
  })
}

################################################################################
# Test 80: Hierarchical data (self-referencing)
################################################################################
resource "aws_dynamodb_table_item" "hierarchy_root" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "ORG#company1" }
    sk = { S = "DEPT#ROOT" }
    name = { S = "Company HQ" }
    parent_id = { NULL = true }
    level = { N = "0" }
  })
}

resource "aws_dynamodb_table_item" "hierarchy_child1" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "ORG#company1" }
    sk = { S = "DEPT#engineering" }
    name = { S = "Engineering" }
    parent_id = { S = "DEPT#ROOT" }
    level = { N = "1" }
  })
}

resource "aws_dynamodb_table_item" "hierarchy_child2" {
  table_name = aws_dynamodb_table.edge_cases.name
  hash_key   = aws_dynamodb_table.edge_cases.hash_key
  range_key  = aws_dynamodb_table.edge_cases.range_key

  item = jsonencode({
    pk = { S = "ORG#company1" }
    sk = { S = "DEPT#backend" }
    name = { S = "Backend Team" }
    parent_id = { S = "DEPT#engineering" }
    level = { N = "2" }
  })
}

################################################################################
# Outputs
################################################################################

output "edge_case_tables" {
  value = {
    edge_cases     = aws_dynamodb_table.edge_cases.name
    gsi_overloading = aws_dynamodb_table.gsi_overloading.name
    special_name   = aws_dynamodb_table.special_name.name
    sparse_index   = aws_dynamodb_table.sparse_index.name
    conditions     = aws_dynamodb_table.conditions.name
    write_sharding = aws_dynamodb_table.write_sharding.name
  }
  description = "Edge case table names"
}

output "edge_case_item_keys" {
  value = {
    reserved_words = { pk = "RESERVED#001", sk = "WORDS" }
    unicode        = { pk = "UNICODE#日本語", sk = "中文#한국어" }
    special_chars  = { pk = "SPECIAL#001", sk = "CHARS" }
    deep_nesting   = { pk = "NESTED#001", sk = "DEEP" }
    all_types      = { pk = "TYPES#001", sk = "ALL" }
    wide_item      = { pk = "WIDE#001", sk = "ATTRIBUTES" }
  }
  description = "Keys for edge case items"
}
