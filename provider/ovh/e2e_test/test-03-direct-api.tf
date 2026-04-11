# test-03-direct-api.tf
# Tests 10-13: Direct HTTP API calls through the Warden gateway (zero cost)
# Validates: raw HTTP proxying, query parameters, various OVH API endpoints

################################################################################
# Test 10: List Cloud Project instances
# Verifies raw GET proxying with Bearer token injection
################################################################################
data "http" "test_10_instances" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/instance"
  request_headers = local.common_headers
}

################################################################################
# Test 11: List Cloud Project volumes
# Verifies another API product through the same gateway
################################################################################
data "http" "test_11_volumes" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/volume"
  request_headers = local.common_headers
}

################################################################################
# Test 12: List Cloud Project networks
# Verifies private network API proxying
################################################################################
data "http" "test_12_networks" {
  url             = "${var.warden_address}/cloud/project/${var.ovh_service_name}/network/private"
  request_headers = local.common_headers
}

################################################################################
# Test 13: List domains
# Verifies domain API proxying (different API product)
################################################################################
data "http" "test_13_domains" {
  url             = "${var.warden_address}/domain"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_10_instances" {
  value = {
    status_code = data.http.test_10_instances.status_code
  }
  description = "Test 10: Cloud Project instances"
}

output "test_11_volumes" {
  value = {
    status_code = data.http.test_11_volumes.status_code
  }
  description = "Test 11: Cloud Project volumes"
}

output "test_12_networks" {
  value = {
    status_code = data.http.test_12_networks.status_code
  }
  description = "Test 12: Cloud Project networks"
}

output "test_13_domains" {
  value = {
    status_code = data.http.test_13_domains.status_code
  }
  description = "Test 13: Domain listing"
}
