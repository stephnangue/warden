# test-02-r2-object-storage.tf
# Tests 7-11: R2 Object Storage via AWS provider (SigV4 signing)
# Validates: SigV4 auto-detection, signature verification, re-signing,
#            bucket CRUD, object upload
# Cost: ~FREE (charges only for stored data, destroyed on cleanup)
#
# The AWS provider performs real SigV4 signing using the JWT as both
# access_key and secret_key. Warden detects the AWS4-HMAC-SHA256
# Authorization header, verifies the client signature, re-signs with
# real Cloudflare R2 credentials, and forwards to
# <account_id>.r2.cloudflarestorage.com.
#
# R2 limitations vs full S3:
# - No versioning support
# - No object tagging
# - Region is always "auto"

################################################################################
# Test 7: Create a basic R2 bucket
# Verifies SigV4 signature detection and re-signing for bucket creation
################################################################################
resource "aws_s3_bucket" "test_07" {
  bucket        = "${local.name_prefix}-basic"
  force_destroy = true
}

################################################################################
# Test 8: Upload a JSON object
# Verifies PUT object with custom content type through SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_08" {
  bucket       = aws_s3_bucket.test_07.id
  key          = "test/data.json"
  content      = jsonencode({ message = "hello from warden", provider = "cloudflare", version = 1 })
  content_type = "application/json"
}

################################################################################
# Test 9: Upload a text object
# Verifies PUT object with SigV4 re-signing
################################################################################
resource "aws_s3_object" "test_09" {
  bucket  = aws_s3_bucket.test_07.id
  key     = "test/hello.txt"
  content = "Hello from Warden Cloudflare R2 e2e test"
}

################################################################################
# Test 10: Create a bucket with CORS configuration
# Verifies S3 CORS rules through the R2 gateway
################################################################################
resource "aws_s3_bucket" "test_10" {
  bucket        = "${local.name_prefix}-cors"
  force_destroy = true
}

resource "aws_s3_bucket_cors_configuration" "test_10" {
  bucket = aws_s3_bucket.test_10.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT"]
    allowed_origins = ["https://example.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }
}

################################################################################
# Test 11: Create a bucket with lifecycle rules
# Verifies lifecycle configuration through the R2 gateway
################################################################################
resource "aws_s3_bucket" "test_11" {
  bucket        = "${local.name_prefix}-lifecycle"
  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "test_11" {
  bucket = aws_s3_bucket.test_11.id

  rule {
    id     = "expire-old-objects"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

################################################################################
# Outputs
################################################################################

output "test_07_bucket" {
  value = {
    id     = aws_s3_bucket.test_07.id
    bucket = aws_s3_bucket.test_07.bucket
    arn    = aws_s3_bucket.test_07.arn
  }
  description = "Test 7: Basic R2 bucket"
}

output "test_08_json_object" {
  value = {
    bucket = aws_s3_object.test_08.bucket
    key    = aws_s3_object.test_08.key
    etag   = aws_s3_object.test_08.etag
  }
  description = "Test 8: JSON object"
}

output "test_09_text_object" {
  value = {
    bucket = aws_s3_object.test_09.bucket
    key    = aws_s3_object.test_09.key
    etag   = aws_s3_object.test_09.etag
  }
  description = "Test 9: Text object"
}

output "test_10_cors_bucket" {
  value = {
    id     = aws_s3_bucket.test_10.id
    bucket = aws_s3_bucket.test_10.bucket
  }
  description = "Test 10: CORS bucket"
}

output "test_11_lifecycle_bucket" {
  value = {
    id     = aws_s3_bucket.test_11.id
    bucket = aws_s3_bucket.test_11.bucket
  }
  description = "Test 11: Lifecycle bucket"
}
