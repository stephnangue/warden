# test-04-direct-api.tf
# Tests 14-17: Direct HTTP API calls through the Warden gateway (zero cost)
# Validates: raw HTTP proxying, query parameters, various API products

################################################################################
# Test 14: List instances via direct API call
# Verifies raw GET proxying with X-Auth-Token injection
################################################################################
data "http" "test_14_instances" {
  url             = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/servers?per_page=1"
  request_headers = local.common_headers
}

################################################################################
# Test 15: List IAM API keys via direct API call
# Verifies IAM API proxying (v1alpha1 path)
################################################################################
data "http" "test_15_iam" {
  url             = "${var.warden_address}/iam/v1alpha1/api-keys?page_size=1"
  request_headers = local.common_headers
}

################################################################################
# Test 16: List projects via Account API
# Verifies a different API product through the same gateway
################################################################################
data "http" "test_16_account" {
  url             = "${var.warden_address}/account/v3/projects?page_size=1"
  request_headers = local.common_headers
}

################################################################################
# Test 17: List container registry namespaces
# Verifies yet another API product
################################################################################
data "http" "test_17_registry" {
  url             = "${var.warden_address}/registry/v1/regions/${var.scaleway_region}/namespaces?page_size=1"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_14_instances" {
  value = {
    status_code = data.http.test_14_instances.status_code
  }
  description = "Test 14: Direct Instance API call"
}

output "test_15_iam" {
  value = {
    status_code = data.http.test_15_iam.status_code
  }
  description = "Test 15: Direct IAM API call"
}

output "test_16_account" {
  value = {
    status_code = data.http.test_16_account.status_code
  }
  description = "Test 16: Direct Account API call"
}

output "test_17_registry" {
  value = {
    status_code = data.http.test_17_registry.status_code
  }
  description = "Test 17: Direct Registry API call"
}
