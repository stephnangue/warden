# test-06-edge-cases.tf
# Tests 34-40: Edge cases and validation through Warden gateway
# Validates: host allowlist enforcement, error handling, query params, large payloads

################################################################################
# Test 34: Request to a blocked host (should fail)
# *.example.com is not in the default allowed_hosts list
################################################################################
data "http" "blocked_host" {
  url = "${var.warden_address}/api.example.com/v1/test"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 403 || self.status_code == 400
      error_message = "Expected 403/400 for blocked host, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 35: Request without authentication (should fail)
################################################################################
data "http" "no_auth" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/resourcegroups?api-version=${local.rg_api_version}"

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
# Test 36: Request with invalid token (should fail)
################################################################################
data "http" "invalid_token" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/resourcegroups?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer invalid-token-value"
    Accept         = "application/json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 401 || self.status_code == 403
      error_message = "Expected 401/403 for invalid token, got ${self.status_code}"
    }
  }
}

################################################################################
# Test 37: Request with complex query parameters
################################################################################
data "http" "complex_query" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/resourcegroups?api-version=${local.rg_api_version}&$filter=tagName eq 'Project' and tagValue eq 'warden-azure-tests'&$top=5"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.rg_basic]
}

################################################################################
# Test 38: Request to subscription-level resource providers
################################################################################
data "http" "resource_providers" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/providers?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Test 39: Request via Authorization Bearer header (fallback auth)
################################################################################
data "http" "bearer_auth" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/resourcegroups?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept        = "application/json"
  }

  depends_on = [restapi_object.rg_basic]
}

################################################################################
# Test 40: Non-existent resource (should return 404 from Azure)
################################################################################
data "http" "not_found" {
  url = "${var.warden_address}/management.azure.com${local.arm_base}/resourceGroups/nonexistent-rg-${random_id.suffix.hex}?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 404
      error_message = "Expected 404 for non-existent resource, got ${self.status_code}"
    }
  }
}

################################################################################
# Outputs
################################################################################

output "blocked_host_status" {
  value       = data.http.blocked_host.status_code
  description = "Blocked host request status (expected 403/400)"
}

output "no_auth_status" {
  value       = data.http.no_auth.status_code
  description = "Unauthenticated request status (expected 401/403)"
}

output "invalid_token_status" {
  value       = data.http.invalid_token.status_code
  description = "Invalid token request status (expected 401/403)"
}

output "complex_query_status" {
  value       = data.http.complex_query.status_code
  description = "Complex query parameter request status"
}

output "resource_providers_status" {
  value       = data.http.resource_providers.status_code
  description = "Resource providers list status"
}

output "bearer_auth_status" {
  value       = data.http.bearer_auth.status_code
  description = "Bearer auth fallback request status"
}

output "not_found_status" {
  value       = data.http.not_found.status_code
  description = "Non-existent resource status (expected 404)"
}
