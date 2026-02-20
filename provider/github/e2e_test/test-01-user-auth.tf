# test-01-user-auth.tf
# Tests 1-4: User authentication and read-only API endpoints
# Validates: token injection, GET proxying, query parameter forwarding

################################################################################
# Test 1: Get authenticated user information
# Verifies the gateway injects a valid GitHub token and proxies GET /user
################################################################################
data "http" "test_01_user_info" {
  url             = "${var.warden_address}/user"
  request_headers = local.common_headers
}

################################################################################
# Test 2: Check API rate limit
# Verifies the gateway forwards the rate limit endpoint correctly
################################################################################
data "http" "test_02_rate_limit" {
  url             = "${var.warden_address}/rate_limit"
  request_headers = local.common_headers
}

################################################################################
# Test 3: Get GitHub API metadata
# Verifies the gateway proxies the /meta endpoint (IP ranges, SSH keys, etc.)
################################################################################
data "http" "test_03_api_meta" {
  url             = "${var.warden_address}/meta"
  request_headers = local.common_headers
}

################################################################################
# Test 4: List authenticated user repositories with query parameters
# Verifies the gateway forwards query parameters (per_page, sort, direction)
################################################################################
data "http" "test_04_user_repos" {
  url             = "${var.warden_address}/user/repos?per_page=5&sort=updated&direction=desc"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_01_user_info" {
  value = {
    status_code = data.http.test_01_user_info.status_code
    login       = try(jsondecode(data.http.test_01_user_info.response_body).login, "")
    type        = try(jsondecode(data.http.test_01_user_info.response_body).type, "")
  }
  description = "Test 1: Authenticated user info"
}

output "test_02_rate_limit" {
  value = {
    status_code    = data.http.test_02_rate_limit.status_code
    core_limit     = try(jsondecode(data.http.test_02_rate_limit.response_body).rate.limit, 0)
    core_remaining = try(jsondecode(data.http.test_02_rate_limit.response_body).rate.remaining, 0)
  }
  description = "Test 2: Rate limit status"
}

output "test_03_api_meta" {
  value = {
    status_code   = data.http.test_03_api_meta.status_code
    has_hooks_ips = try(length(jsondecode(data.http.test_03_api_meta.response_body).hooks) > 0, false)
  }
  description = "Test 3: API meta information"
}

output "test_04_user_repos" {
  value = {
    status_code = data.http.test_04_user_repos.status_code
    count       = try(length(jsondecode(data.http.test_04_user_repos.response_body)), 0)
  }
  description = "Test 4: User repositories list"
}
