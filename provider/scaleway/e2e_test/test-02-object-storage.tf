# test-02-object-storage.tf
# Tests 4-8: Scaleway Object Storage via AWS provider (SigV4 signing)
# Validates: SigV4 auto-detection, signature verification, re-signing,
#            bucket CRUD, object upload
# Cost: ~FREE (charges only for stored data, destroyed on cleanup)
#
# The AWS provider performs real SigV4 signing using the JWT as both
# access_key and secret_key. Warden detects the AWS4-HMAC-SHA256
# Authorization header, verifies the client signature, re-signs with
# real Scaleway credentials, and forwards to s3.{region}.scw.cloud.

################################################################################
# Test 4: Create a basic S3 bucket
# Verifies SigV4 signature detection and re-signing for bucket creation
################################################################################
resource "aws_s3_bucket" "test_04" {
  bucket        = "${local.name_prefix}-basic"
  force_destroy = true

  tags = {
    Name       = "Warden S3 basic test"
    TestNumber = "04"
  }
}

################################################################################
# Test 5: Create a bucket with versioning
# Verifies complex S3 configuration through the gateway
################################################################################
resource "aws_s3_bucket" "test_05" {
  bucket        = "${local.name_prefix}-versioned"
  force_destroy = true

  tags = {
    Name       = "Warden S3 versioned test"
    TestNumber = "05"
  }
}

resource "aws_s3_bucket_versioning" "test_05" {
  bucket = aws_s3_bucket.test_05.id

  versioning_configuration {
    status = "Enabled"
  }
}

################################################################################
# Test 6: Upload a second object with different content type
# Verifies PUT object with custom headers through SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_06" {
  bucket       = aws_s3_bucket.test_04.id
  key          = "test/data.json"
  content      = jsonencode({ message = "hello", version = 1 })
  content_type = "application/json"

  tags = {
    TestNumber = "06"
  }
}

################################################################################
# Test 7: Upload a small object
# Verifies PUT object with SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_07" {
  bucket  = aws_s3_bucket.test_04.id
  key     = "test/hello.txt"
  content = "Hello from Warden Scaleway e2e test"

  tags = {
    TestNumber = "07"
  }
}

################################################################################
# Test 8: Create a bucket with CORS configuration
# Verifies complex S3 CORS rules through the gateway
################################################################################
resource "aws_s3_bucket" "test_08" {
  bucket        = "${local.name_prefix}-cors"
  force_destroy = true

  tags = {
    Name       = "Warden S3 CORS test"
    TestNumber = "08"
  }
}

resource "aws_s3_bucket_cors_configuration" "test_08" {
  bucket = aws_s3_bucket.test_08.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET"]
    allowed_origins = ["https://example.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }
}

################################################################################
# Outputs
################################################################################

output "test_04_bucket" {
  value = {
    id     = aws_s3_bucket.test_04.id
    bucket = aws_s3_bucket.test_04.bucket
    arn    = aws_s3_bucket.test_04.arn
  }
  description = "Test 4: Basic bucket"
}

output "test_05_versioned_bucket" {
  value = {
    id     = aws_s3_bucket.test_05.id
    bucket = aws_s3_bucket.test_05.bucket
  }
  description = "Test 5: Versioned bucket"
}

output "test_06_json_object" {
  value = {
    bucket = aws_s3_object.test_06.bucket
    key    = aws_s3_object.test_06.key
    etag   = aws_s3_object.test_06.etag
  }
  description = "Test 6: JSON object"
}

output "test_07_object" {
  value = {
    bucket = aws_s3_object.test_07.bucket
    key    = aws_s3_object.test_07.key
    etag   = aws_s3_object.test_07.etag
  }
  description = "Test 7: Uploaded object"
}

output "test_08_cors_bucket" {
  value = {
    id     = aws_s3_bucket.test_08.id
    bucket = aws_s3_bucket.test_08.bucket
  }
  description = "Test 8: CORS bucket"
}
