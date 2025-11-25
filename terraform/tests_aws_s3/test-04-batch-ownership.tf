# test-04-batch-ownership.tf
# Tests 26-29: Batch operations and object ownership


################################################################################
# Batch Operations IAM Role
################################################################################

resource "aws_iam_role" "batch_operations" {
  name = "${local.bucket_prefix}-batch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "batchoperations.s3.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name       = "S3 Batch Operations Role"
    TestNumber = "26"
  }
}

resource "aws_iam_role_policy" "batch_operations" {
  name = "${local.bucket_prefix}-batch-policy"
  role = aws_iam_role.batch_operations.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:PutObjectTagging",
          "s3:DeleteObjectTagging",
          "s3:InitiateReplication",
          "s3:GetObjectLegalHold",
          "s3:PutObjectLegalHold",
          "s3:GetObjectRetention",
          "s3:PutObjectRetention"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Test 26: Batch Operations
################################################################################

resource "aws_s3_bucket" "batch_operations" {
  bucket        = "${local.bucket_prefix}-batch-ops"
  force_destroy = true

  tags = {
    Name        = "Batch Operations Bucket"
    TestNumber  = "26"
    Description = "Tests S3 Batch Operations setup"
  }
}

# Create manifest file for batch operations
resource "aws_s3_object" "batch_manifest" {
  bucket  = aws_s3_bucket.batch_operations.id
  key     = "manifests/batch-manifest.csv"
  content = join("\n", [
    "${aws_s3_bucket.batch_operations.id},test-files/file1.txt",
    "${aws_s3_bucket.batch_operations.id},test-files/file2.txt",
    "${aws_s3_bucket.batch_operations.id},test-files/file3.txt"
  ])

  tags = {
    Type = "manifest"
  }
}

################################################################################
# Test 27: Object Ownership Controls - BucketOwnerEnforced
################################################################################

resource "aws_s3_bucket" "ownership_enforced" {
  bucket        = "${local.bucket_prefix}-ownership-enforced"
  force_destroy = true

  tags = {
    Name        = "Ownership Enforced Test"
    TestNumber  = "27"
    Description = "Tests BucketOwnerEnforced ownership"
  }
}

resource "aws_s3_bucket_ownership_controls" "ownership_enforced" {
  bucket = aws_s3_bucket.ownership_enforced.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

################################################################################
# Test 28: Object Ownership Controls - BucketOwnerPreferred
################################################################################

resource "aws_s3_bucket" "ownership_preferred" {
  bucket        = "${local.bucket_prefix}-ownership-preferred"
  force_destroy = true

  tags = {
    Name        = "Ownership Preferred Test"
    TestNumber  = "28"
    Description = "Tests BucketOwnerPreferred ownership"
  }
}

resource "aws_s3_bucket_ownership_controls" "ownership_preferred" {
  bucket = aws_s3_bucket.ownership_preferred.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Need to disable public access block to use ACLs
resource "aws_s3_bucket_public_access_block" "ownership_preferred" {
  bucket = aws_s3_bucket.ownership_preferred.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "ownership_preferred" {
  depends_on = [
    aws_s3_bucket_ownership_controls.ownership_preferred,
    aws_s3_bucket_public_access_block.ownership_preferred
  ]

  bucket = aws_s3_bucket.ownership_preferred.id
  acl    = "private"
}

################################################################################
# Test 29: Object Ownership Controls - ObjectWriter
################################################################################

resource "aws_s3_bucket" "ownership_writer" {
  bucket        = "${local.bucket_prefix}-ownership-writer"
  force_destroy = true

  tags = {
    Name        = "Ownership ObjectWriter Test"
    TestNumber  = "29"
    Description = "Tests ObjectWriter ownership"
  }
}

resource "aws_s3_bucket_ownership_controls" "ownership_writer" {
  bucket = aws_s3_bucket.ownership_writer.id

  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_public_access_block" "ownership_writer" {
  bucket = aws_s3_bucket.ownership_writer.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "ownership_writer" {
  depends_on = [
    aws_s3_bucket_ownership_controls.ownership_writer,
    aws_s3_bucket_public_access_block.ownership_writer
  ]

  bucket = aws_s3_bucket.ownership_writer.id
  acl    = "private"
}
