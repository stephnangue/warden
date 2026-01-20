# test-01-basic-buckets.tf
# Tests 1-10: Basic bucket operations and configurations

################################################################################
# Test 1: Basic Bucket Operations
################################################################################

resource "aws_s3_bucket" "basic" {
  bucket = "${local.bucket_prefix}-basic"
  
  force_destroy = true

  tags = {
    Name        = "Basic Bucket Test"
    TestNumber  = "1"
    Description = "Tests basic bucket creation and deletion"
  }
}

################################################################################
# Test 2: Bucket Versioning
################################################################################

resource "aws_s3_bucket" "versioned" {
  bucket        = "${local.bucket_prefix}-versioned"
  force_destroy = true

  tags = {
    Name        = "Versioned Bucket Test"
    TestNumber  = "2"
    Description = "Tests bucket versioning configuration"
  }
}

resource "aws_s3_bucket_versioning" "versioned" {
  bucket = aws_s3_bucket.versioned.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

################################################################################
# Test 3: Server-Side Encryption
################################################################################

resource "aws_s3_bucket" "encrypted" {
  bucket        = "${local.bucket_prefix}-encrypted"
  force_destroy = true

  tags = {
    Name        = "Encrypted Bucket Test"
    TestNumber  = "3"
    Description = "Tests server-side encryption configuration"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.encrypted.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

################################################################################
# Test 4: Bucket Lifecycle Rules
################################################################################

resource "aws_s3_bucket" "lifecycle" {
  bucket        = "${local.bucket_prefix}-lifecycle"
  force_destroy = true

  tags = {
    Name        = "Lifecycle Bucket Test"
    TestNumber  = "4"
    Description = "Tests lifecycle configuration"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle" {
  bucket = aws_s3_bucket.lifecycle.id

  rule {
    id     = "archive-old-objects"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "delete-old-versions"
    status = "Enabled"

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

################################################################################
# Test 5: Public Access Block
################################################################################

resource "aws_s3_bucket" "public_access_block" {
  bucket        = "${local.bucket_prefix}-pab"
  force_destroy = true

  tags = {
    Name        = "Public Access Block Test"
    TestNumber  = "5"
    Description = "Tests public access block configuration"
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket = aws_s3_bucket.public_access_block.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# Test 6: Bucket Policy
################################################################################

resource "aws_s3_bucket" "with_policy" {
  bucket        = "${local.bucket_prefix}-policy"
  force_destroy = true

  tags = {
    Name        = "Bucket Policy Test"
    TestNumber  = "6"
    Description = "Tests bucket policy configuration"
  }
}

resource "aws_s3_bucket_policy" "policy" {
  bucket = aws_s3_bucket.with_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.with_policy.arn,
          "${aws_s3_bucket.with_policy.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

################################################################################
# Test 7: CORS Configuration
################################################################################

resource "aws_s3_bucket" "cors" {
  bucket        = "${local.bucket_prefix}-cors"
  force_destroy = true

  tags = {
    Name        = "CORS Bucket Test"
    TestNumber  = "7"
    Description = "Tests CORS configuration"
  }
}

resource "aws_s3_bucket_cors_configuration" "cors" {
  bucket = aws_s3_bucket.cors.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "HEAD", "PUT", "POST"]
    allowed_origins = ["https://example.com", "https://www.example.com"]
    expose_headers  = ["ETag", "x-amz-server-side-encryption"]
    max_age_seconds = 3000
  }

  cors_rule {
    allowed_methods = ["GET"]
    allowed_origins = ["*"]
    max_age_seconds = 3600
  }
}

################################################################################
# Test 8: Object Lock
################################################################################

resource "aws_s3_bucket" "object_lock" {
  bucket        = "${local.bucket_prefix}-lock"
  force_destroy = true
  
  object_lock_enabled = true

  tags = {
    Name        = "Object Lock Test"
    TestNumber  = "8"
    Description = "Tests object lock configuration"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "lock" {
  bucket = aws_s3_bucket.object_lock.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

################################################################################
# Test 9: Logging Configuration
################################################################################

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.bucket_prefix}-logs"
  force_destroy = true

  tags = {
    Name        = "Log Bucket"
    TestNumber  = "9"
    Description = "Bucket for storing access logs"
  }
}

resource "aws_s3_bucket" "logged" {
  bucket        = "${local.bucket_prefix}-logged"
  force_destroy = true

  tags = {
    Name        = "Logged Bucket Test"
    TestNumber  = "9"
    Description = "Tests logging configuration"
  }
}

resource "aws_s3_bucket_logging" "logging" {
  bucket = aws_s3_bucket.logged.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "log/"
}

################################################################################
# Test 10: Website Configuration
################################################################################

resource "aws_s3_bucket" "website" {
  bucket        = "${local.bucket_prefix}-website"
  force_destroy = true

  tags = {
    Name        = "Website Bucket Test"
    TestNumber  = "10"
    Description = "Tests static website hosting"
  }
}

resource "aws_s3_bucket_website_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }

  routing_rule {
    condition {
      key_prefix_equals = "docs/"
    }
    redirect {
      replace_key_prefix_with = "documents/"
    }
  }
}
