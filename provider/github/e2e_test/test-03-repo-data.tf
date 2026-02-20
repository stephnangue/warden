# test-03-repo-data.tf
# Tests 10-15: Repository data reads through Warden gateway
# Validates: nested endpoint proxying, path construction, response forwarding

################################################################################
# Test 10: List branches in test repository
# Verifies the gateway proxies GET /repos/{owner}/{repo}/branches
################################################################################
data "http" "test_10_branches" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic/branches"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 11: Get default branch details
# Verifies the gateway handles branch name in URL path
################################################################################
data "http" "test_11_default_branch" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic/branches/main"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 12: List commits on default branch
# Verifies the gateway proxies commit listing with pagination params
################################################################################
data "http" "test_12_commits" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic/commits?per_page=5"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 13: Get README contents
# Verifies the gateway proxies the contents API and handles base64 data
################################################################################
data "http" "test_13_readme" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic/readme"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 14: List repository languages
# Verifies the gateway proxies GET /repos/{owner}/{repo}/languages
################################################################################
data "http" "test_14_languages" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-licensed/languages"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_07_repo_licensed]
}

################################################################################
# Test 15: Get repository license
# Verifies the gateway proxies the license API endpoint
################################################################################
data "http" "test_15_license" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-licensed/license"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_07_repo_licensed]
}

################################################################################
# Outputs
################################################################################

output "test_10_branches" {
  value = {
    status_code = data.http.test_10_branches.status_code
    count       = try(length(jsondecode(data.http.test_10_branches.response_body)), 0)
  }
  description = "Test 10: Repository branches"
}

output "test_11_default_branch" {
  value = {
    status_code = data.http.test_11_default_branch.status_code
    name        = try(jsondecode(data.http.test_11_default_branch.response_body).name, "")
    protected   = try(jsondecode(data.http.test_11_default_branch.response_body).protected, false)
  }
  description = "Test 11: Default branch details"
}

output "test_12_commits" {
  value = {
    status_code = data.http.test_12_commits.status_code
    count       = try(length(jsondecode(data.http.test_12_commits.response_body)), 0)
    latest_sha  = try(jsondecode(data.http.test_12_commits.response_body)[0].sha, "")
  }
  description = "Test 12: Repository commits"
}

output "test_13_readme" {
  value = {
    status_code = data.http.test_13_readme.status_code
    name        = try(jsondecode(data.http.test_13_readme.response_body).name, "")
    encoding    = try(jsondecode(data.http.test_13_readme.response_body).encoding, "")
  }
  description = "Test 13: README contents"
}

output "test_14_languages" {
  value = {
    status_code = data.http.test_14_languages.status_code
  }
  description = "Test 14: Repository languages"
}

output "test_15_license" {
  value = {
    status_code = data.http.test_15_license.status_code
    license     = try(jsondecode(data.http.test_15_license.response_body).license.spdx_id, "")
  }
  description = "Test 15: Repository license"
}
