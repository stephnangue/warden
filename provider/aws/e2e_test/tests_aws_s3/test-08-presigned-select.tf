# test-08-presigned-select.tf
# Tests 38-40: Presigned URLs and S3 Select


################################################################################
# Presigned URL Test User
################################################################################

resource "aws_iam_user" "presigned_tester" {
  name = "${local.bucket_prefix}-presigned-user"

  tags = {
    Name       = "Presigned URL Tester"
    TestNumber = "38"
  }
}

resource "aws_iam_user_policy" "presigned_tester" {
  name = "${local.bucket_prefix}-presigned-policy"
  user = aws_iam_user.presigned_tester.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.presigned_url.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.presigned_url.arn
      }
    ]
  })
}

resource "aws_iam_access_key" "presigned_tester" {
  user = aws_iam_user.presigned_tester.name
}

################################################################################
# Test 38: Presigned URL Configuration
################################################################################

resource "aws_s3_bucket" "presigned_url" {
  bucket        = "${local.bucket_prefix}-presigned"
  force_destroy = true

  tags = {
    Name        = "Presigned URL Test Bucket"
    TestNumber  = "38"
    Description = "Tests presigned URL functionality"
  }
}

# Create test objects for presigned URL testing
resource "aws_s3_object" "presigned_test_1" {
  bucket  = aws_s3_bucket.presigned_url.id
  key     = "presigned/public-file.txt"
  content = "This file can be accessed via presigned URL"

  tags = {
    Type = "presigned-test"
  }
}

resource "aws_s3_object" "presigned_test_2" {
  bucket  = aws_s3_bucket.presigned_url.id
  key     = "presigned/private-file.txt"
  content = "This private file requires presigned URL"
  acl     = "private"

  tags = {
    Type = "presigned-test"
  }
}

################################################################################
# Test 39: Presigned POST Configuration
################################################################################

resource "aws_s3_bucket" "presigned_post" {
  bucket        = "${local.bucket_prefix}-presigned-post"
  force_destroy = true

  tags = {
    Name        = "Presigned POST Test Bucket"
    TestNumber  = "39"
    Description = "Tests presigned POST functionality"
  }
}

resource "aws_s3_bucket_cors_configuration" "presigned_post" {
  bucket = aws_s3_bucket.presigned_post.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["POST", "PUT"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

################################################################################
# Test 40: S3 Select Configuration
################################################################################

resource "aws_s3_bucket" "s3_select" {
  bucket        = "${local.bucket_prefix}-select"
  force_destroy = true

  tags = {
    Name        = "S3 Select Test Bucket"
    TestNumber  = "40"
    Description = "Tests S3 Select functionality"
  }
}

# Create CSV file for S3 Select testing
resource "aws_s3_object" "select_csv" {
  bucket  = aws_s3_bucket.s3_select.id
  key     = "data/test-data.csv"
  content = <<EOF
id,name,age,city
1,Alice,30,New York
2,Bob,25,San Francisco
3,Charlie,35,Los Angeles
4,Diana,28,Chicago
5,Eve,32,Boston
EOF

  tags = {
    Type = "select-test"
  }
}

# Create JSON file for S3 Select testing
resource "aws_s3_object" "select_json" {
  bucket  = aws_s3_bucket.s3_select.id
  key     = "data/test-data.json"
  content = jsonencode([
    { id = 1, name = "Alice", age = 30, city = "New York" },
    { id = 2, name = "Bob", age = 25, city = "San Francisco" },
    { id = 3, name = "Charlie", age = 35, city = "Los Angeles" },
    { id = 4, name = "Diana", age = 28, city = "Chicago" },
    { id = 5, name = "Eve", age = 32, city = "Boston" }
  ])

  tags = {
    Type = "select-test"
  }
}
