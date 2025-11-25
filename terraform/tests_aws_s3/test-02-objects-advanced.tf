# test-02-objects-advanced.tf
# Tests 11-20: Object operations and advanced bucket features

################################################################################
# Test 11: Object Operations - Various Content Types
################################################################################

resource "aws_s3_bucket" "objects" {
  bucket        = "${local.bucket_prefix}-objects"
  force_destroy = true

  tags = {
    Name        = "Object Operations Test"
    TestNumber  = "11"
    Description = "Tests various object operations"
  }
}

# Plain text object
resource "aws_s3_object" "text" {
  bucket       = aws_s3_bucket.objects.id
  key          = "test-files/sample.txt"
  content      = var.test_content
  content_type = "text/plain"

  tags = {
    Type = "text"
  }
}

# JSON object
resource "aws_s3_object" "json" {
  bucket       = aws_s3_bucket.objects.id
  key          = "test-files/data.json"
  content      = jsonencode({
    test    = "data"
    version = "1.0"
    items   = ["a", "b", "c"]
  })
  content_type = "application/json"

  tags = {
    Type = "json"
  }
}

# Object with metadata
resource "aws_s3_object" "with_metadata" {
  bucket       = aws_s3_bucket.objects.id
  key          = "test-files/metadata.txt"
  content      = "File with custom metadata"
  content_type = "text/plain"

  metadata = {
    author      = "warden-test"
    version     = "1.0"
    environment = "test"
    timestamp   = "2024-01-01"
  }

  tags = {
    Type = "metadata"
  }
}

# Encrypted object
resource "aws_s3_object" "encrypted" {
  bucket                 = aws_s3_bucket.objects.id
  key                    = "test-files/encrypted.txt"
  content                = "This file is encrypted"
  content_type           = "text/plain"
  server_side_encryption = "AES256"

  tags = {
    Type = "encrypted"
  }
}

# Object with different storage class
resource "aws_s3_object" "glacier" {
  bucket        = aws_s3_bucket.objects.id
  key           = "test-files/archive.txt"
  content       = "This file uses Glacier storage"
  content_type  = "text/plain"
  storage_class = "GLACIER_IR"

  tags = {
    Type = "glacier"
  }
}

# Object with cache control
resource "aws_s3_object" "cached" {
  bucket        = aws_s3_bucket.objects.id
  key           = "test-files/cached.txt"
  content       = "This file has cache control"
  content_type  = "text/plain"
  cache_control = "max-age=3600, must-revalidate"

  tags = {
    Type = "cached"
  }
}

# Object with content encoding
resource "aws_s3_object" "gzipped" {
  bucket           = aws_s3_bucket.objects.id
  key              = "test-files/compressed.txt"
  content          = "This file has content encoding"
  content_type     = "text/plain"
  content_encoding = "gzip"

  tags = {
    Type = "compressed"
  }
}

################################################################################
# Test 12: Multipart Upload Support
################################################################################

resource "aws_s3_bucket" "multipart" {
  bucket        = "${local.bucket_prefix}-multipart"
  force_destroy = true

  tags = {
    Name        = "Multipart Upload Test"
    TestNumber  = "12"
    Description = "Tests multipart upload support"
  }
}

# Create a larger object to test multipart handling
resource "aws_s3_object" "large" {
  bucket  = aws_s3_bucket.multipart.id
  key     = "large-files/test-file.txt"
  content = join("\n", [for i in range(1000) : "Line ${i}: ${var.test_content}"])

  tags = {
    Type = "large"
  }
}

################################################################################
# Test 13: Object Tagging
################################################################################

resource "aws_s3_bucket" "tagged_objects" {
  bucket        = "${local.bucket_prefix}-tagged"
  force_destroy = true

  tags = {
    Name        = "Tagged Objects Test"
    TestNumber  = "13"
    Description = "Tests object tagging"
  }
}

resource "aws_s3_object" "tagged" {
  bucket  = aws_s3_bucket.tagged_objects.id
  key     = "tagged/sample.txt"
  content = "Object with multiple tags"

  tags = {
    Environment = "test"
    Project     = "warden"
    Category    = "sample"
    Priority    = "high"
    Version     = "1.0"
  }
}

################################################################################
# Test 14: Bucket Replication (Destination)
################################################################################

resource "aws_s3_bucket" "replication_dest" {
  bucket        = "${local.bucket_prefix}-repl-dest"
  force_destroy = true

  tags = {
    Name        = "Replication Destination Test"
    TestNumber  = "14"
    Description = "Tests replication destination configuration"
  }
}

resource "aws_s3_bucket_versioning" "replication_dest" {
  bucket = aws_s3_bucket.replication_dest.id

  versioning_configuration {
    status = "Enabled"
  }
}

################################################################################
# Test 15: Intelligent Tiering
################################################################################

resource "aws_s3_bucket" "intelligent_tiering" {
  bucket        = "${local.bucket_prefix}-intelligent"
  force_destroy = true

  tags = {
    Name        = "Intelligent Tiering Test"
    TestNumber  = "15"
    Description = "Tests intelligent tiering configuration"
  }
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "intelligent" {
  bucket = aws_s3_bucket.intelligent_tiering.id
  name   = "EntireBucket"

  status = "Enabled"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}

################################################################################
# Test 16: Request Metrics
################################################################################

resource "aws_s3_bucket" "metrics" {
  bucket        = "${local.bucket_prefix}-metrics"
  force_destroy = true

  tags = {
    Name        = "Request Metrics Test"
    TestNumber  = "16"
    Description = "Tests request metrics configuration"
  }
}

resource "aws_s3_bucket_metric" "metrics" {
  bucket = aws_s3_bucket.metrics.id
  name   = "EntireBucket"
}

################################################################################
# Test 17: Inventory Configuration
################################################################################

resource "aws_s3_bucket" "inventory_source" {
  bucket        = "${local.bucket_prefix}-inv-source"
  force_destroy = true

  tags = {
    Name        = "Inventory Source Test"
    TestNumber  = "17"
    Description = "Tests inventory configuration"
  }
}

resource "aws_s3_bucket" "inventory_dest" {
  bucket        = "${local.bucket_prefix}-inv-dest"
  force_destroy = true

  tags = {
    Name        = "Inventory Destination"
    TestNumber  = "17"
  }
}

resource "aws_s3_bucket_inventory" "inventory" {
  bucket = aws_s3_bucket.inventory_source.id
  name   = "EntireBucketDaily"

  included_object_versions = "All"

  schedule {
    frequency = "Daily"
  }

  destination {
    bucket {
      format     = "CSV"
      bucket_arn = aws_s3_bucket.inventory_dest.arn
      prefix     = "inventory"
    }
  }
}

################################################################################
# Test 18: Acceleration Configuration
################################################################################

resource "aws_s3_bucket" "accelerated" {
  bucket        = "${local.bucket_prefix}-accelerated"
  force_destroy = true

  tags = {
    Name        = "Transfer Acceleration Test"
    TestNumber  = "18"
    Description = "Tests transfer acceleration"
  }
}

resource "aws_s3_bucket_accelerate_configuration" "accelerate" {
  bucket = aws_s3_bucket.accelerated.id
  status = "Enabled"
}

################################################################################
# Test 19: Request Payment Configuration
################################################################################

resource "aws_s3_bucket" "requester_pays" {
  bucket        = "${local.bucket_prefix}-reqpays"
  force_destroy = true

  tags = {
    Name        = "Requester Pays Test"
    TestNumber  = "19"
    Description = "Tests requester pays configuration"
  }
}

resource "aws_s3_bucket_request_payment_configuration" "requester_pays" {
  bucket = aws_s3_bucket.requester_pays.id
  payer  = "Requester"
}

################################################################################
# Test 20: ACL Configuration
################################################################################

resource "aws_s3_bucket" "acl_test" {
  bucket        = "${local.bucket_prefix}-acl"
  force_destroy = true

  tags = {
    Name        = "ACL Test"
    TestNumber  = "20"
    Description = "Tests ACL configuration"
  }
}

resource "aws_s3_bucket_ownership_controls" "acl_test" {
  bucket = aws_s3_bucket.acl_test.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "acl" {
  depends_on = [aws_s3_bucket_ownership_controls.acl_test]

  bucket = aws_s3_bucket.acl_test.id
  acl    = "private"
}
