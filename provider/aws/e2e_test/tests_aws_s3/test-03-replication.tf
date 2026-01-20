# test-03-replication.tf
# Tests 21-25: All types of S3 replication

################################################################################
# Replication IAM Role
################################################################################

resource "aws_iam_role" "replication" {
  name = "${local.bucket_prefix}-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "S3 Replication Role"
  }
}

resource "aws_iam_role_policy" "replication" {
  name = "${local.bucket_prefix}-replication-policy"
  role = aws_iam_role.replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.srr_source.arn,
          aws_s3_bucket.crr_source.arn,
          aws_s3_bucket.repl_prefix_source.arn,
          aws_s3_bucket.repl_tag_source.arn,
          aws_s3_bucket.repl_delete_source.arn
        ]
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.srr_source.arn}/*",
          "${aws_s3_bucket.crr_source.arn}/*",
          "${aws_s3_bucket.repl_prefix_source.arn}/*",
          "${aws_s3_bucket.repl_tag_source.arn}/*",
          "${aws_s3_bucket.repl_delete_source.arn}/*"
        ]
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.srr_destination.arn}/*",
          "${aws_s3_bucket.crr_destination.arn}/*",
          "${aws_s3_bucket.repl_prefix_dest.arn}/*",
          "${aws_s3_bucket.repl_tag_dest.arn}/*",
          "${aws_s3_bucket.repl_delete_dest.arn}/*"
        ]
      }
    ]
  })
}

################################################################################
# Test 21: Same-Region Replication (SRR)
################################################################################

# SRR Source Bucket
resource "aws_s3_bucket" "srr_source" {
  bucket        = "${local.bucket_prefix}-srr-source"
  force_destroy = true

  tags = {
    Name        = "SRR Source Bucket"
    TestNumber  = "21"
    Description = "Tests Same-Region Replication source"
  }
}

resource "aws_s3_bucket_versioning" "srr_source" {
  bucket = aws_s3_bucket.srr_source.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SRR Destination Bucket
resource "aws_s3_bucket" "srr_destination" {
  bucket        = "${local.bucket_prefix}-srr-dest"
  force_destroy = true

  tags = {
    Name        = "SRR Destination Bucket"
    TestNumber  = "21"
    Description = "Tests Same-Region Replication destination"
  }
}

resource "aws_s3_bucket_versioning" "srr_destination" {
  bucket = aws_s3_bucket.srr_destination.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SRR Configuration
resource "aws_s3_bucket_replication_configuration" "srr" {
  depends_on = [aws_s3_bucket_versioning.srr_source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.srr_source.id

  rule {
    id     = "replicate-all"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.srr_destination.arn
      storage_class = "STANDARD"
    }
  }
}

################################################################################
# Test 22: Cross-Region Replication (CRR)
################################################################################

# CRR Source Bucket (us-east-1)
resource "aws_s3_bucket" "crr_source" {
  bucket        = "${local.bucket_prefix}-crr-source"
  force_destroy = true

  tags = {
    Name        = "CRR Source Bucket"
    TestNumber  = "22"
    Description = "Tests Cross-Region Replication source"
  }
}

resource "aws_s3_bucket_versioning" "crr_source" {
  bucket = aws_s3_bucket.crr_source.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CRR Destination Bucket (us-west-2)
resource "aws_s3_bucket" "crr_destination" {
  provider = aws.us_west_2

  bucket        = "${local.bucket_prefix}-crr-dest"
  force_destroy = true

  tags = {
    Name        = "CRR Destination Bucket"
    TestNumber  = "22"
    Description = "Tests Cross-Region Replication destination"
  }
}

resource "aws_s3_bucket_versioning" "crr_destination" {
  provider = aws.us_west_2

  bucket = aws_s3_bucket.crr_destination.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CRR Configuration
resource "aws_s3_bucket_replication_configuration" "crr" {
  depends_on = [
    aws_s3_bucket_versioning.crr_source,
    aws_s3_bucket_versioning.crr_destination
  ]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.crr_source.id

  rule {
    id     = "replicate-all-crr"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.crr_destination.arn
      storage_class = "STANDARD_IA"
      
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
  }
}

################################################################################
# Test 23: Replication with Prefix Filter
################################################################################

resource "aws_s3_bucket" "repl_prefix_source" {
  bucket        = "${local.bucket_prefix}-repl-prefix-src"
  force_destroy = true

  tags = {
    Name        = "Replication Prefix Source"
    TestNumber  = "23"
    Description = "Tests replication with prefix filtering"
  }
}

resource "aws_s3_bucket_versioning" "repl_prefix_source" {
  bucket = aws_s3_bucket.repl_prefix_source.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "repl_prefix_dest" {
  bucket        = "${local.bucket_prefix}-repl-prefix-dst"
  force_destroy = true

  tags = {
    Name        = "Replication Prefix Destination"
    TestNumber  = "23"
  }
}

resource "aws_s3_bucket_versioning" "repl_prefix_dest" {
  bucket = aws_s3_bucket.repl_prefix_dest.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "prefix_filter" {
  depends_on = [aws_s3_bucket_versioning.repl_prefix_source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.repl_prefix_source.id

  rule {
    id     = "replicate-documents"
    status = "Enabled"

    filter {
      prefix = "documents/"
    }

    delete_marker_replication {
      status = "Enabled"
    }

    priority = 1

    destination {
      bucket        = aws_s3_bucket.repl_prefix_dest.arn
      storage_class = "STANDARD"
    }
  }

  rule {
    id     = "replicate-images"
    status = "Enabled"

    filter {
      prefix = "images/"
    }

    delete_marker_replication {
      status = "Enabled"
    }

    priority = 2

    destination {
      bucket        = aws_s3_bucket.repl_prefix_dest.arn
      storage_class = "INTELLIGENT_TIERING"
    }
  }
}


################################################################################
# Test 24: Replication with Tag Filter
################################################################################

resource "aws_s3_bucket" "repl_tag_source" {
  bucket        = "${local.bucket_prefix}-repl-tag-src"
  force_destroy = true

  tags = {
    Name        = "Replication Tag Source"
    TestNumber  = "24"
    Description = "Tests replication with tag filtering"
  }
}

resource "aws_s3_bucket_versioning" "repl_tag_source" {
  bucket = aws_s3_bucket.repl_tag_source.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "repl_tag_dest" {
  bucket        = "${local.bucket_prefix}-repl-tag-dst"
  force_destroy = true

  tags = {
    Name        = "Replication Tag Destination"
    TestNumber  = "24"
  }
}

resource "aws_s3_bucket_versioning" "repl_tag_dest" {
  bucket = aws_s3_bucket.repl_tag_dest.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "tag_filter" {
  depends_on = [aws_s3_bucket_versioning.repl_tag_source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.repl_tag_source.id

  rule {
    id     = "replicate-important"
    status = "Enabled"

    filter {
    }

    delete_marker_replication {
      status = "Enabled"  # or "Disabled" if you don't want to replicate delete markers
    }

    destination {
      bucket        = aws_s3_bucket.repl_tag_dest.arn
      storage_class = "STANDARD"
    }
  }
}

################################################################################
# Test 25: Replication with Delete Marker Replication
################################################################################

resource "aws_s3_bucket" "repl_delete_source" {
  bucket        = "${local.bucket_prefix}-repl-del-src"
  force_destroy = true

  tags = {
    Name        = "Replication Delete Marker Source"
    TestNumber  = "25"
    Description = "Tests delete marker replication"
  }
}

resource "aws_s3_bucket_versioning" "repl_delete_source" {
  bucket = aws_s3_bucket.repl_delete_source.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "repl_delete_dest" {
  bucket        = "${local.bucket_prefix}-repl-del-dst"
  force_destroy = true

  tags = {
    Name        = "Replication Delete Marker Destination"
    TestNumber  = "25"
  }
}

resource "aws_s3_bucket_versioning" "repl_delete_dest" {
  bucket = aws_s3_bucket.repl_delete_dest.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "delete_marker" {
  depends_on = [aws_s3_bucket_versioning.repl_delete_source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.repl_delete_source.id

  rule {
    id     = "replicate-with-deletes"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.repl_delete_dest.arn
      storage_class = "STANDARD"
    }
  }
}
