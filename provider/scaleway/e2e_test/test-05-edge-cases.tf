# test-05-edge-cases.tf
# Tests 18-25: Edge cases and error handling through Warden gateway
# Validates: auth failures, 404s, special characters, S3 edge cases
# Cost: ~FREE

################################################################################
# Test 18: Request without authentication (should fail)
# Verifies Warden rejects unauthenticated requests to the gateway
################################################################################
data "http" "test_18_no_auth" {
  url = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/servers"

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
# Test 19: Request with invalid token (should fail)
# Verifies Warden rejects requests with invalid JWT tokens
################################################################################
data "http" "test_19_invalid_token" {
  url = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/servers"

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
# Test 20: Non-existent resource (should return 404)
# Verifies the gateway forwards Scaleway's 404 for missing resources
################################################################################
data "http" "test_20_not_found" {
  url             = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/servers/00000000-0000-0000-0000-000000000000"
  request_headers = local.common_headers

  lifecycle {
    postcondition {
      condition     = self.status_code == 404
      error_message = "Expected 404 for non-existent server, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 21: Query parameters with special characters
# Verifies the gateway preserves query strings with encoding
################################################################################
data "http" "test_21_query_params" {
  url             = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/servers?per_page=1&page=1&name=nonexistent%20server"
  request_headers = local.common_headers
}

################################################################################
# Test 22: Deep nested API path (Kubernetes)
# Verifies the gateway handles long URL paths correctly
################################################################################
data "http" "test_22_deep_path" {
  url             = "${var.warden_address}/k8s/v1/regions/${var.scaleway_region}/clusters?page_size=1"
  request_headers = local.common_headers
}

################################################################################
# Test 23: Different API product — DNS
# Verifies the gateway works across different Scaleway API products
################################################################################
data "http" "test_23_dns" {
  url             = "${var.warden_address}/domain/v2beta1/dns-zones?page_size=1"
  request_headers = local.common_headers
}

################################################################################
# Test 24: S3 bucket with special characters in name
# Verifies SigV4 handles bucket names with dots and hyphens
################################################################################
resource "aws_s3_bucket" "test_24" {
  bucket        = "${local.name_prefix}-edge.case-bucket"
  force_destroy = true

  tags = {
    Name       = "Warden S3 edge case"
    TestNumber = "24"
  }
}

################################################################################
# Test 25: S3 object with deep key path
# Verifies SigV4 re-signing handles complex object keys
################################################################################
resource "aws_s3_object" "test_25" {
  bucket  = aws_s3_bucket.test_24.id
  key     = "deep/nested/path/file.json"
  content = jsonencode({ test = true, number = 25 })
}

################################################################################
# Outputs
################################################################################

output "test_18_no_auth" {
  value       = data.http.test_18_no_auth.status_code
  description = "Test 18: Unauthenticated request (expected 401/403)"
}

output "test_19_invalid_token" {
  value       = data.http.test_19_invalid_token.status_code
  description = "Test 19: Invalid token (expected 401/403)"
}

output "test_20_not_found" {
  value       = data.http.test_20_not_found.status_code
  description = "Test 20: Non-existent resource (expected 404)"
}

output "test_21_query_params" {
  value = {
    status_code = data.http.test_21_query_params.status_code
  }
  description = "Test 21: Query params with encoding"
}

output "test_22_deep_path" {
  value = {
    status_code = data.http.test_22_deep_path.status_code
  }
  description = "Test 22: Deep nested API path (K8s)"
}

output "test_23_dns" {
  value = {
    status_code = data.http.test_23_dns.status_code
  }
  description = "Test 23: DNS API product"
}

output "test_24_edge_bucket" {
  value = {
    id     = aws_s3_bucket.test_24.id
    bucket = aws_s3_bucket.test_24.bucket
  }
  description = "Test 24: Bucket with dots and hyphens in name"
}

output "test_25_edge_object" {
  value = {
    bucket = aws_s3_object.test_25.bucket
    key    = aws_s3_object.test_25.key
    etag   = aws_s3_object.test_25.etag
  }
  description = "Test 25: Object with deep key path"
}
