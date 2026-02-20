# test-05-edge-cases.tf
# Tests 19-24: Edge cases and validation through Warden gateway
# Validates: error handling, auth failures, non-existent resources, special paths

################################################################################
# Test 19: Request without authentication (should fail)
# Verifies Warden rejects unauthenticated requests to the gateway
################################################################################
data "http" "test_19_no_auth" {
  url = "${var.warden_address}/user"

  request_headers = {
    Accept = "application/vnd.github+json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 401 || self.status_code == 403
      error_message = "Expected 401/403 for unauthenticated request, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 20: Request with invalid token (should fail)
# Verifies Warden rejects requests with invalid JWT tokens
################################################################################
data "http" "test_20_invalid_token" {
  url = "${var.warden_address}/user"

  request_headers = {
    Accept        = "application/vnd.github+json"
    Authorization = "Bearer invalid-token-value"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 401 || self.status_code == 403
      error_message = "Expected 401/403 for invalid token, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 21: Non-existent repository (should return 404)
# Verifies the gateway forwards GitHub's 404 response for missing resources
################################################################################
data "http" "test_21_not_found" {
  url             = "${var.warden_address}/repos/${var.github_owner}/nonexistent-repo-${random_id.suffix.hex}"
  request_headers = local.common_headers

  lifecycle {
    postcondition {
      condition     = self.status_code == 404
      error_message = "Expected 404 for non-existent repository, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 22: Get GitHub API Zen message
# Verifies the gateway proxies the /zen endpoint (returns plain text)
################################################################################
data "http" "test_22_zen" {
  url             = "${var.warden_address}/zen"
  request_headers = local.common_headers
}

################################################################################
# Test 23: Get GitHub API Octocat ASCII art
# Verifies the gateway proxies the /octocat endpoint (returns plain text)
################################################################################
data "http" "test_23_octocat" {
  url             = "${var.warden_address}/octocat?s=warden"
  request_headers = local.common_headers
}

################################################################################
# Test 24: Read a well-known public repository
# Verifies the gateway can access public repos with an authenticated token
################################################################################
data "http" "test_24_public_repo" {
  url             = "${var.warden_address}/repos/octocat/Hello-World"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_19_no_auth_status" {
  value       = data.http.test_19_no_auth.status_code
  description = "Test 19: Unauthenticated request status (expected 401/403)"
}

output "test_20_invalid_token_status" {
  value       = data.http.test_20_invalid_token.status_code
  description = "Test 20: Invalid token request status (expected 401/403)"
}

output "test_21_not_found_status" {
  value       = data.http.test_21_not_found.status_code
  description = "Test 21: Non-existent repo status (expected 404)"
}

output "test_22_zen" {
  value = {
    status_code = data.http.test_22_zen.status_code
    has_body    = length(data.http.test_22_zen.response_body) > 0
  }
  description = "Test 22: GitHub Zen message"
}

output "test_23_octocat" {
  value = {
    status_code = data.http.test_23_octocat.status_code
    has_body    = length(data.http.test_23_octocat.response_body) > 0
  }
  description = "Test 23: Octocat ASCII art with query param"
}

output "test_24_public_repo" {
  value = {
    status_code = data.http.test_24_public_repo.status_code
    full_name   = try(jsondecode(data.http.test_24_public_repo.response_body).full_name, "")
    description = try(jsondecode(data.http.test_24_public_repo.response_body).description, "")
  }
  description = "Test 24: Public repository read"
}
