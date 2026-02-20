# test-02-repositories.tf
# Tests 5-9: Repository CRUD operations through Warden gateway
# Validates: POST/GET/PATCH/DELETE proxying, JSON body handling, resource lifecycle

################################################################################
# Test 5: Create a basic private repository
# Verifies the gateway proxies POST /user/repos with JSON body
################################################################################
resource "restapi_object" "test_05_repo_basic" {
  path         = "/user/repos"
  read_path    = "${local.repos_base}/${local.name_prefix}-basic"
  update_path  = "${local.repos_base}/${local.name_prefix}-basic"
  destroy_path = "${local.repos_base}/${local.name_prefix}-basic"

  data = jsonencode({
    name        = "${local.name_prefix}-basic"
    description = "Warden GitHub gateway e2e test: basic private repository"
    private     = true
    auto_init   = true
  })
}

################################################################################
# Test 6: Create a repository with extended settings
# Verifies the gateway handles complex JSON payloads correctly
################################################################################
resource "restapi_object" "test_06_repo_configured" {
  path         = "/user/repos"
  read_path    = "${local.repos_base}/${local.name_prefix}-configured"
  update_path  = "${local.repos_base}/${local.name_prefix}-configured"
  destroy_path = "${local.repos_base}/${local.name_prefix}-configured"

  data = jsonencode({
    name                = "${local.name_prefix}-configured"
    description         = "Warden GitHub gateway e2e test: configured repository"
    private             = true
    auto_init           = true
    has_issues          = true
    has_projects        = false
    has_wiki            = false
    allow_squash_merge  = true
    allow_merge_commit  = false
    allow_rebase_merge  = true
    delete_branch_on_merge = true
  })
}

################################################################################
# Test 7: Create a repository with a license template
# Verifies the gateway handles auto_init + license_template parameters
################################################################################
resource "restapi_object" "test_07_repo_licensed" {
  path         = "/user/repos"
  read_path    = "${local.repos_base}/${local.name_prefix}-licensed"
  update_path  = "${local.repos_base}/${local.name_prefix}-licensed"
  destroy_path = "${local.repos_base}/${local.name_prefix}-licensed"

  data = jsonencode({
    name             = "${local.name_prefix}-licensed"
    description      = "Warden GitHub gateway e2e test: repository with MIT license"
    private          = true
    auto_init        = true
    license_template = "mit"
    gitignore_template = "Go"
  })
}

################################################################################
# Test 8: Read repository details (via data source)
# Verifies the gateway proxies GET /repos/{owner}/{repo} correctly
################################################################################
data "http" "test_08_read_repo" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Test 9: List repository topics
# Verifies the gateway proxies nested repo endpoints
################################################################################
data "http" "test_09_repo_topics" {
  url             = "${var.warden_address}${local.repos_base}/${local.name_prefix}-basic/topics"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_05_repo_basic]
}

################################################################################
# Outputs
################################################################################

output "test_05_repo_basic" {
  value = {
    name      = try(jsondecode(restapi_object.test_05_repo_basic.api_response).name, "")
    full_name = try(jsondecode(restapi_object.test_05_repo_basic.api_response).full_name, "")
    private   = try(jsondecode(restapi_object.test_05_repo_basic.api_response).private, false)
  }
  description = "Test 5: Basic repository creation"
}

output "test_06_repo_configured" {
  value = {
    name               = try(jsondecode(restapi_object.test_06_repo_configured.api_response).name, "")
    has_wiki           = try(jsondecode(restapi_object.test_06_repo_configured.api_response).has_wiki, true)
    has_projects       = try(jsondecode(restapi_object.test_06_repo_configured.api_response).has_projects, true)
    allow_squash_merge = try(jsondecode(restapi_object.test_06_repo_configured.api_response).allow_squash_merge, false)
  }
  description = "Test 6: Configured repository creation"
}

output "test_07_repo_licensed" {
  value = {
    name    = try(jsondecode(restapi_object.test_07_repo_licensed.api_response).name, "")
    license = try(jsondecode(restapi_object.test_07_repo_licensed.api_response).license.spdx_id, "")
  }
  description = "Test 7: Licensed repository creation"
}

output "test_08_read_repo" {
  value = {
    status_code   = data.http.test_08_read_repo.status_code
    full_name     = try(jsondecode(data.http.test_08_read_repo.response_body).full_name, "")
    default_branch = try(jsondecode(data.http.test_08_read_repo.response_body).default_branch, "")
  }
  description = "Test 8: Read repository details"
}

output "test_09_repo_topics" {
  value = {
    status_code = data.http.test_09_repo_topics.status_code
  }
  description = "Test 9: Repository topics"
}

output "repo_names" {
  value = {
    basic      = "${local.name_prefix}-basic"
    configured = "${local.name_prefix}-configured"
    licensed   = "${local.name_prefix}-licensed"
  }
  description = "Repository names created by tests"
}
