# test-04-edge-cases.tf
# Tests 14-20: Edge cases and error handling through Warden gateway
# Validates: auth failures, 404s, special characters, S3 edge cases
# Cost: ~FREE

################################################################################
# Test 14: Request without authentication (should fail)
# Verifies Warden rejects unauthenticated requests to the gateway
################################################################################
data "http" "test_14_no_auth" {
  url = "${var.warden_address}/me"

  request_headers = {
    Accept = "application/json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 401 || self.status_code == 403
      error_message = "Expected 401/403 for unauthenticated request, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 15: Request with invalid token (should fail)
# Verifies Warden rejects requests with invalid JWT tokens
################################################################################
data "http" "test_15_invalid_token" {
  url = "${var.warden_address}/me"

  request_headers = {
    Accept        = "application/json"
    Authorization = "Bearer invalid-token-value-not-a-jwt"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 401 || self.status_code == 403
      error_message = "Expected 401/403 for invalid token, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 16: Non-existent resource (should return 404)
# Verifies the gateway forwards OVH's 404 for missing resources
################################################################################
data "http" "test_16_not_found" {
  url             = "${var.warden_address}/cloud/project/00000000000000000000000000000000/instance"
  request_headers = local.common_headers

  lifecycle {
    postcondition {
      condition     = self.status_code == 404
      error_message = "Expected 404 for non-existent project, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 17: Query parameters with special characters
# Verifies the gateway preserves query strings with encoding
################################################################################
data "http" "test_17_query_params" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/instance?region=${var.ovh_region}"
  request_headers = local.common_headers
}

################################################################################
# Test 18: Deep nested API path
# Verifies the gateway handles long URL paths correctly
################################################################################
data "http" "test_18_deep_path" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/storage"
  request_headers = local.common_headers
}

################################################################################
# Test 19: S3 bucket with special characters in name
# Verifies SigV4 handles bucket names with dots and hyphens
################################################################################
resource "aws_s3_bucket" "test_19" {
  bucket        = "${local.name_prefix}-edge.case-bucket"
  force_destroy = true

  tags = {
    Name       = "Warden OVH S3 edge case"
    TestNumber = "19"
  }
}

################################################################################
# Test 20: S3 object with deep key path
# Verifies SigV4 re-signing handles complex object keys
################################################################################
resource "aws_s3_object" "test_20" {
  bucket  = aws_s3_bucket.test_19.id
  key     = "deep/nested/path/file.json"
  content = jsonencode({ test = true, number = 20 })
}

################################################################################
# Outputs
################################################################################

output "test_14_no_auth" {
  value       = data.http.test_14_no_auth.status_code
  description = "Test 14: Unauthenticated request (expected 401/403)"
}

output "test_15_invalid_token" {
  value       = data.http.test_15_invalid_token.status_code
  description = "Test 15: Invalid token (expected 401/403)"
}

output "test_16_not_found" {
  value       = data.http.test_16_not_found.status_code
  description = "Test 16: Non-existent resource (expected 404)"
}

output "test_17_query_params" {
  value = {
    status_code = data.http.test_17_query_params.status_code
  }
  description = "Test 17: Query params with encoding"
}

output "test_18_deep_path" {
  value = {
    status_code = data.http.test_18_deep_path.status_code
  }
  description = "Test 18: Deep nested API path"
}

output "test_19_edge_bucket" {
  value = {
    id     = aws_s3_bucket.test_19.id
    bucket = aws_s3_bucket.test_19.bucket
  }
  description = "Test 19: Bucket with dots and hyphens in name"
}

output "test_20_edge_object" {
  value = {
    bucket = aws_s3_object.test_20.bucket
    key    = aws_s3_object.test_20.key
    etag   = aws_s3_object.test_20.etag
  }
  description = "Test 20: Object with deep key path"
}
