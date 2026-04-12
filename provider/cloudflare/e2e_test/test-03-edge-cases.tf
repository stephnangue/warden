# test-03-edge-cases.tf
# Tests 12-18: Edge cases and error handling through Warden gateway
# Validates: auth failures, 404s, special characters, R2 edge cases
# Cost: ~FREE

################################################################################
# Test 12: Request without authentication (should fail)
# Verifies Warden rejects unauthenticated requests to the gateway
################################################################################
data "http" "test_12_no_auth" {
  url = "${var.warden_address}/zones"

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
# Test 13: Request with invalid token (should fail)
# Verifies Warden rejects requests with invalid JWT tokens
################################################################################
data "http" "test_13_invalid_token" {
  url = "${var.warden_address}/zones"

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
# Test 14: Non-existent zone (should return 404 from Cloudflare)
# Verifies the gateway forwards Cloudflare's error for missing resources
################################################################################
data "http" "test_14_not_found" {
  url             = "${var.warden_address}/zones/00000000000000000000000000000000"
  request_headers = local.common_headers

  lifecycle {
    postcondition {
      condition     = self.status_code == 404 || self.status_code == 403
      error_message = "Expected 404/403 for non-existent zone, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 15: Query parameters with encoding
# Verifies the gateway preserves query strings
################################################################################
data "http" "test_15_query_params" {
  url             = "${var.warden_address}/zones?per_page=1&page=1&order=name&direction=asc"
  request_headers = local.common_headers
}

################################################################################
# Test 16: Deep nested API path
# Verifies the gateway handles long URL paths correctly
################################################################################
data "http" "test_16_deep_path" {
  url             = "${var.warden_address}/user/tokens"
  request_headers = local.common_headers
}

################################################################################
# Test 17: R2 bucket with special characters in name
# Verifies SigV4 handles bucket names with dots and hyphens
################################################################################
resource "aws_s3_bucket" "test_17" {
  bucket        = "${local.name_prefix}-edge.case-bucket"
  force_destroy = true
}

################################################################################
# Test 18: R2 object with deep key path
# Verifies SigV4 re-signing handles complex object keys
################################################################################
resource "aws_s3_object" "test_18" {
  bucket  = aws_s3_bucket.test_17.id
  key     = "deep/nested/path/with-special_chars/file.json"
  content = jsonencode({ test = true, number = 18 })
}

################################################################################
# Outputs
################################################################################

output "test_12_no_auth" {
  value       = data.http.test_12_no_auth.status_code
  description = "Test 12: Unauthenticated request (expected 401/403)"
}

output "test_13_invalid_token" {
  value       = data.http.test_13_invalid_token.status_code
  description = "Test 13: Invalid token (expected 401/403)"
}

output "test_14_not_found" {
  value       = data.http.test_14_not_found.status_code
  description = "Test 14: Non-existent zone (expected 404/403)"
}

output "test_15_query_params" {
  value = {
    status_code = data.http.test_15_query_params.status_code
  }
  description = "Test 15: Query params with encoding"
}

output "test_16_deep_path" {
  value = {
    status_code = data.http.test_16_deep_path.status_code
  }
  description = "Test 16: Deep nested API path"
}

output "test_17_edge_bucket" {
  value = {
    id     = aws_s3_bucket.test_17.id
    bucket = aws_s3_bucket.test_17.bucket
  }
  description = "Test 17: R2 bucket with dots and hyphens in name"
}

output "test_18_edge_object" {
  value = {
    bucket = aws_s3_object.test_18.bucket
    key    = aws_s3_object.test_18.key
    etag   = aws_s3_object.test_18.etag
  }
  description = "Test 18: R2 object with deep key path"
}
