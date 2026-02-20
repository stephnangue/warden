# test-04-search-query.tf
# Tests 16-18: Search API and advanced query parameter handling
# Validates: complex query strings, URL encoding, search endpoint proxying

################################################################################
# Test 16: Search for test repositories by name
# Verifies the gateway proxies the search API with complex query parameters
################################################################################
data "http" "test_16_search_repos" {
  url             = "${var.warden_address}/search/repositories?q=${local.name_prefix}+in:name&sort=updated&order=desc&per_page=5"
  request_headers = local.common_headers

  depends_on = [
    restapi_object.test_05_repo_basic,
    restapi_object.test_06_repo_configured,
    restapi_object.test_07_repo_licensed,
  ]
}

################################################################################
# Test 17: Search for code in test repository
# Verifies the gateway proxies the code search API
################################################################################
data "http" "test_17_search_code" {
  url             = "${var.warden_address}/search/code?q=README+repo:${var.github_owner}/${local.name_prefix}-basic"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 18: List user repositories with multiple filter parameters
# Verifies the gateway correctly forwards multiple query parameters
################################################################################
data "http" "test_18_filtered_repos" {
  url             = "${var.warden_address}/user/repos?type=owner&sort=full_name&direction=asc&per_page=2&page=1"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_16_search_repos" {
  value = {
    status_code = data.http.test_16_search_repos.status_code
    total_count = try(jsondecode(data.http.test_16_search_repos.response_body).total_count, 0)
  }
  description = "Test 16: Search repositories by name"
}

output "test_17_search_code" {
  value = {
    status_code = data.http.test_17_search_code.status_code
    total_count = try(jsondecode(data.http.test_17_search_code.response_body).total_count, 0)
  }
  description = "Test 17: Search code in repository"
}

output "test_18_filtered_repos" {
  value = {
    status_code = data.http.test_18_filtered_repos.status_code
    count       = try(length(jsondecode(data.http.test_18_filtered_repos.response_body)), 0)
  }
  description = "Test 18: Filtered repository listing"
}
