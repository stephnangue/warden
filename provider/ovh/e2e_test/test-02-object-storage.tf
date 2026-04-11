# test-02-object-storage.tf
# Tests 5-9: OVH Object Storage via AWS provider (SigV4 signing)
# Validates: SigV4 auto-detection, signature verification, re-signing,
#            bucket CRUD, object upload
# Cost: ~FREE (charges only for stored data, destroyed on cleanup)
#
# The AWS provider performs real SigV4 signing using the JWT as both
# access_key and secret_key. Warden detects the AWS4-HMAC-SHA256
# Authorization header, verifies the client signature, re-signs with
# real OVH S3 credentials, and forwards to s3.{region}.io.cloud.ovh.net.

################################################################################
# Test 5: Create a basic S3 bucket
# Verifies SigV4 signature detection and re-signing for bucket creation
################################################################################
resource "aws_s3_bucket" "test_05" {
  bucket        = "${local.name_prefix}-basic"
  force_destroy = true

  tags = {
    Name       = "Warden OVH S3 basic test"
    TestNumber = "05"
  }
}

################################################################################
# Test 6: Create a bucket with versioning
# Verifies complex S3 configuration through the gateway
################################################################################
resource "aws_s3_bucket" "test_06" {
  bucket        = "${local.name_prefix}-versioned"
  force_destroy = true

  tags = {
    Name       = "Warden OVH S3 versioned test"
    TestNumber = "06"
  }
}

resource "aws_s3_bucket_versioning" "test_06" {
  bucket = aws_s3_bucket.test_06.id

  versioning_configuration {
    status = "Enabled"
  }
}

################################################################################
# Test 7: Upload a JSON object
# Verifies PUT object with custom content type through SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_07" {
  bucket       = aws_s3_bucket.test_05.id
  key          = "test/data.json"
  content      = jsonencode({ message = "hello from warden", version = 1 })
  content_type = "application/json"

  tags = {
    TestNumber = "07"
  }
}

################################################################################
# Test 8: Upload a text object
# Verifies PUT object with SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_08" {
  bucket  = aws_s3_bucket.test_05.id
  key     = "test/hello.txt"
  content = "Hello from Warden OVH e2e test"

  tags = {
    TestNumber = "08"
  }
}

################################################################################
# Test 9: Create a bucket with CORS configuration
# Verifies complex S3 CORS rules through the gateway
################################################################################
resource "aws_s3_bucket" "test_09" {
  bucket        = "${local.name_prefix}-cors"
  force_destroy = true

  tags = {
    Name       = "Warden OVH S3 CORS test"
    TestNumber = "09"
  }
}

resource "aws_s3_bucket_cors_configuration" "test_09" {
  bucket = aws_s3_bucket.test_09.id

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

output "test_05_bucket" {
  value = {
    id     = aws_s3_bucket.test_05.id
    bucket = aws_s3_bucket.test_05.bucket
    arn    = aws_s3_bucket.test_05.arn
  }
  description = "Test 5: Basic bucket"
}

output "test_06_versioned_bucket" {
  value = {
    id     = aws_s3_bucket.test_06.id
    bucket = aws_s3_bucket.test_06.bucket
  }
  description = "Test 6: Versioned bucket"
}

output "test_07_json_object" {
  value = {
    bucket = aws_s3_object.test_07.bucket
    key    = aws_s3_object.test_07.key
    etag   = aws_s3_object.test_07.etag
  }
  description = "Test 7: JSON object"
}

output "test_08_object" {
  value = {
    bucket = aws_s3_object.test_08.bucket
    key    = aws_s3_object.test_08.key
    etag   = aws_s3_object.test_08.etag
  }
  description = "Test 8: Text object"
}

output "test_09_cors_bucket" {
  value = {
    id     = aws_s3_bucket.test_09.id
    bucket = aws_s3_bucket.test_09.bucket
  }
  description = "Test 9: CORS bucket"
}
