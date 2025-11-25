# test-05-access-points.tf
# Tests 30-32: S3 Access Points

################################################################################
# Test 30: S3 Access Point with CRUD Operations
################################################################################

resource "aws_s3_bucket" "access_point" {
  bucket        = "${local.bucket_prefix}-access-point"
  force_destroy = true

  tags = {
    Name        = "Access Point Test Bucket"
    TestNumber  = "30"
    Description = "Tests S3 Access Point with CRUD operations"
  }
}

resource "aws_s3_access_point" "main" {
  bucket = aws_s3_bucket.access_point.id
  name   = "${local.bucket_prefix}-ap-main"

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

# Access Point Policy with full CRUD permissions
resource "aws_s3control_access_point_policy" "main" {
  access_point_arn = aws_s3_access_point.main.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_access_point.main.arn}/object/*",
          aws_s3_access_point.main.arn
        ]
      }
    ]
  })
}

# Test object - CREATE via Access Point
resource "aws_s3_object" "ap_test_create" {
  bucket = aws_s3_access_point.main.arn
  key    = "test-files/access-point-create.txt"
  content = jsonencode({
    message     = "Created via Access Point"
    timestamp   = timestamp()
    test_number = "30"
    operation   = "CREATE"
  })
  content_type = "application/json"

  tags = {
    CreatedVia = "AccessPoint"
    TestNumber = "30"
    Operation  = "CREATE"
  }
}

# Test object - UPDATE via Access Point (same key, different content)
resource "aws_s3_object" "ap_test_update" {
  bucket = aws_s3_access_point.main.arn
  key    = "test-files/access-point-update.txt"
  content = jsonencode({
    message     = "Updated via Access Point"
    timestamp   = timestamp()
    test_number = "30"
    operation   = "UPDATE"
    version     = "2"
  })
  content_type = "application/json"

  tags = {
    CreatedVia = "AccessPoint"
    TestNumber = "30"
    Operation  = "UPDATE"
  }

  depends_on = [aws_s3_object.ap_test_create]
}

# Multiple test objects for LIST operation
resource "aws_s3_object" "ap_test_list" {
  count = 3

  bucket = aws_s3_access_point.main.arn
  key    = "test-files/list-test-${count.index}.txt"
  content = jsonencode({
    message = "File ${count.index} for LIST test"
    index   = count.index
  })
  content_type = "application/json"

  tags = {
    CreatedVia = "AccessPoint"
    TestNumber = "30"
    Operation  = "LIST"
    Index      = tostring(count.index)
  }
}

################################################################################
# Test 31: Multi-Region Access Point (MRAP) with CRUD
################################################################################

resource "aws_s3_bucket" "mrap_east" {
  bucket        = "${local.bucket_prefix}-mrap-east"
  force_destroy = true

  tags = {
    Name        = "MRAP East Bucket"
    TestNumber  = "31"
    Description = "Tests Multi-Region Access Point - East with CRUD"
  }
}

resource "aws_s3_bucket_versioning" "mrap_east" {
  bucket = aws_s3_bucket.mrap_east.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "mrap_west" {
  provider = aws.us_west_2

  bucket        = "${local.bucket_prefix}-mrap-west"
  force_destroy = true

  tags = {
    Name        = "MRAP West Bucket"
    TestNumber  = "31"
    Description = "Tests Multi-Region Access Point - West with CRUD"
  }
}

resource "aws_s3_bucket_versioning" "mrap_west" {
  provider = aws.us_west_2

  bucket = aws_s3_bucket.mrap_west.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3control_multi_region_access_point" "main" {
  details {
    name = "${local.bucket_prefix}-mrap"

    region {
      bucket = aws_s3_bucket.mrap_east.id
    }

    region {
      bucket = aws_s3_bucket.mrap_west.id
    }

    public_access_block {
      block_public_acls       = true
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true
    }
  }
}

# MRAP Policy with CRUD permissions
resource "aws_s3control_multi_region_access_point_policy" "main" {
  details {
    name = aws_s3control_multi_region_access_point.main.details[0].name
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Principal = {
            AWS = data.aws_caller_identity.current.account_id
          }
          Action = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket"
          ]
          Resource = [
            "${aws_s3control_multi_region_access_point.main.arn}/object/*",
            aws_s3control_multi_region_access_point.main.arn
          ]
        }
      ]
    })
  }
}

# Test objects via MRAP - CREATE
resource "aws_s3_object" "mrap_test_east" {
  bucket = aws_s3control_multi_region_access_point.main.arn
  key    = "mrap-test/east-region.txt"
  content = jsonencode({
    message       = "Created via MRAP"
    region        = "us-east-1"
    test_number   = "31"
    operation     = "CREATE"
    multi_region  = true
  })
  content_type = "application/json"

  tags = {
    CreatedVia = "MRAP"
    TestNumber = "31"
    Region     = "us-east-1"
  }

  depends_on = [aws_s3control_multi_region_access_point_policy.main]
}

################################################################################
# Test 32: Access Point with VPC Configuration and CRUD
################################################################################

# Create VPC for testing
resource "aws_vpc" "access_point" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name       = "Access Point VPC"
    TestNumber = "32"
  }
}

resource "aws_subnet" "access_point" {
  vpc_id            = aws_vpc.access_point.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name       = "Access Point Subnet"
    TestNumber = "32"
  }
}

resource "aws_s3_bucket" "vpc_access_point" {
  bucket        = "${local.bucket_prefix}-vpc-ap"
  force_destroy = true

  tags = {
    Name        = "VPC Access Point Bucket"
    TestNumber  = "32"
    Description = "Tests VPC-restricted Access Point with CRUD"
  }
}

resource "aws_s3_access_point" "vpc" {
  bucket = aws_s3_bucket.vpc_access_point.id
  name   = "${local.bucket_prefix}-vpc-ap"

  vpc_configuration {
    vpc_id = aws_vpc.access_point.id
  }

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

# VPC Access Point Policy with CRUD permissions
resource "aws_s3control_access_point_policy" "vpc" {
  access_point_arn = aws_s3_access_point.vpc.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.account_id
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_access_point.vpc.arn}/object/*",
          aws_s3_access_point.vpc.arn
        ]
        Condition = {
          StringEquals = {
            "s3:DataAccessPointAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Test objects via VPC Access Point - CREATE
resource "aws_s3_object" "vpc_ap_test" {
  bucket = aws_s3_access_point.vpc.arn
  key    = "vpc-test/vpc-restricted.txt"
  content = jsonencode({
    message     = "Created via VPC Access Point"
    vpc_id      = aws_vpc.access_point.id
    test_number = "32"
    operation   = "CREATE"
  })
  content_type = "application/json"

  tags = {
    CreatedVia = "VPCAccessPoint"
    TestNumber = "32"
    VPCId      = aws_vpc.access_point.id
  }
}

################################################################################
# Outputs for Testing CRUD Operations
################################################################################

output "access_point_arn" {
  value       = aws_s3_access_point.main.arn
  description = "ARN of the main access point for CRUD testing"
}

output "access_point_alias" {
  value       = aws_s3_access_point.main.alias
  description = "Alias of the main access point"
}

output "mrap_arn" {
  value       = aws_s3control_multi_region_access_point.main.arn
  description = "ARN of the Multi-Region Access Point"
}

output "mrap_alias" {
  value       = aws_s3control_multi_region_access_point.main.alias
  description = "Alias of the Multi-Region Access Point"
}

output "vpc_access_point_arn" {
  value       = aws_s3_access_point.vpc.arn
  description = "ARN of the VPC-restricted access point"
}

output "test_objects_created" {
  value = {
    access_point_create = aws_s3_object.ap_test_create.key
    access_point_update = aws_s3_object.ap_test_update.key
    access_point_list   = [for obj in aws_s3_object.ap_test_list : obj.key]
    mrap_east          = aws_s3_object.mrap_test_east.key
    vpc_ap             = aws_s3_object.vpc_ap_test.key
  }
  description = "List of test objects created via access points"
}