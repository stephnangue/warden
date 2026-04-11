# test-01-cloud-project.tf
# Tests 1-4: OVH Cloud Project operations via ovh provider and http (zero cost)
# Validates: Bearer token injection, GET proxying, Cloud Project read operations

################################################################################
# Test 1: Read Cloud Project details
# Verifies the gateway injects the Bearer token and proxies GET requests
# Cost: FREE (read-only)
################################################################################
data "ovh_cloud_project" "test_01" {
  service_name = var.ovh_service_name
}

################################################################################
# Test 2: List Cloud Project regions
# Verifies GET with nested resource path
# Cost: FREE (read-only)
################################################################################
data "ovh_cloud_project_regions" "test_02" {
  service_name = var.ovh_service_name
}

################################################################################
# Test 3: Read account info via direct HTTP
# Verifies raw HTTP proxying with Bearer token injection
# Cost: FREE (read-only)
################################################################################
data "http" "test_03_me" {
  url             = "${var.warden_address}/me"
  request_headers = local.common_headers
}

################################################################################
# Test 4: List Cloud Project users
# Verifies list endpoint proxying
# Cost: FREE (read-only)
################################################################################
data "http" "test_04_users" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/user"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_01_cloud_project" {
  value = {
    project_id  = data.ovh_cloud_project.test_01.project_id
    description = data.ovh_cloud_project.test_01.description
    status      = data.ovh_cloud_project.test_01.status
  }
  description = "Test 1: Cloud Project details"
}

output "test_02_regions" {
  value = {
    count = length(data.ovh_cloud_project_regions.test_02.names)
  }
  description = "Test 2: Cloud Project regions"
}

output "test_03_me" {
  value = {
    status_code = data.http.test_03_me.status_code
    nichandle   = try(jsondecode(data.http.test_03_me.response_body).nichandle, "")
  }
  description = "Test 3: Account info"
}

output "test_04_users" {
  value = {
    status_code = data.http.test_04_users.status_code
  }
  description = "Test 4: Cloud Project users"
}
